"""Owned process-tree supervision and bounded capture for host execution."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from uuid import uuid4


LIMIT = 1024 * 1024
_reaper_lock = threading.Lock()
_reaper_users = 0
_previous_reaper = 0


def _subreaper(acquire, *, deadline=None):
    """Adopt for owned runs; optionally bound the shared lease lock wait."""
    global _reaper_users, _previous_reaper
    if not sys.platform.startswith('linux'):
        return
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if deadline is None:
        _reaper_lock.acquire()
    else:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not _reaper_lock.acquire(timeout=remaining):
            raise TimeoutError('subreaper lease lock deadline')
    try:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError('subreaper lease lock deadline')
        if acquire:
            if not _reaper_users:
                previous = ctypes.c_int()
                if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) or libc.prctl(36, 1, 0, 0, 0):
                    raise OSError(ctypes.get_errno(), 'cannot enable owned child reaping')
                _previous_reaper = previous.value
            _reaper_users += 1
        else:
            if deadline is None:
                _reaper_users -= 1
                if not _reaper_users:
                    libc.prctl(36, _previous_reaper, 0, 0, 0)
            else:
                if _reaper_users <= 0:
                    raise RuntimeError('subreaper lease not held')
                if _reaper_users == 1 and libc.prctl(36, _previous_reaper, 0, 0, 0):
                    raise OSError(ctypes.get_errno(), 'cannot restore owned child reaping')
                _reaper_users -= 1
    finally:
        _reaper_lock.release()


def redacted(data: bytes, secrets, truncated=False) -> str:
    if truncated and secrets:
        trim = max(len(secret.encode()) for secret in secrets) - 1
        if trim:
            data = data[:-trim]
    text = data.decode('utf-8', 'replace')
    for secret in sorted(set(secrets) - {''}, key=len, reverse=True):
        text = text.replace(secret, '[REDACTED]')
    return text


def bounded_redacted(data, secrets, truncated=False):
    text = redacted(data, secrets, truncated)
    encoded = text.encode('utf-8')
    return encoded[:LIMIT].decode('utf-8', 'ignore'), truncated or len(encoded) > LIMIT


def write_process_logs(owner, output, phase, secrets, *, marker=False):
    evidence = {}
    for index, name in enumerate(('stdout', 'stderr')):
        text, truncated = bounded_redacted(bytes(owner.capture.buffers[index]), secrets, owner.capture.truncated[index])
        if marker and truncated:
            text = text.encode()[:LIMIT - 13].decode('utf-8', 'ignore') + '\n[TRUNCATED]\n'
        (output / (phase + '.' + name + '.log')).write_text(text)
        evidence[name + '_truncated'] = truncated
    return evidence


class _Capture:
    # Nonblocking capture (deliberate): supervised processes can outlive any
    # deadline and must be abortable mid-drain, so readers poll nonblocking
    # fds under a stop event and retain a 1 MiB prefix per stream. Short
    # docker CLI control calls use the simpler blocking capture in docker.py.
    def __init__(self, streams, limit):
        self.buffers = [bytearray() for _ in streams]
        self.truncated = [False for _ in streams]
        self.eof = [False for _ in streams]
        self.errors = [False for _ in streams]
        self.stop = threading.Event()
        self.readers = []
        for index, stream in enumerate(streams):
            os.set_blocking(stream.fileno(), False)
            def drain(stream=stream, index=index):
                try:
                    while True:
                        try:
                            chunk = os.read(stream.fileno(), 65536)
                        except BlockingIOError:
                            if self.stop.wait(0.01):
                                break
                            continue
                        if not chunk:
                            self.eof[index] = True
                            break
                        room = max(0, limit - len(self.buffers[index]))
                        self.buffers[index].extend(chunk[:room])
                        self.truncated[index] |= len(chunk) > room
                        if self.stop.is_set():
                            break
                except OSError:
                    self.errors[index] = True
                finally:
                    stream.close()
            reader = threading.Thread(target=drain, name='p11lab-capture', daemon=True)
            reader.start()
            self.readers.append(reader)

    def finish(self, deadline):
        for reader in self.readers:
            reader.join(max(0, deadline - time.monotonic()))
        self.stop.set()
        for reader in self.readers:
            reader.join(0.2)
        return all(self.eof) and not any(self.errors) and not any(r.is_alive() for r in self.readers)


def _linux_processes():
    processes = {}
    if not sys.platform.startswith('linux'):
        return processes
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
            processes[int(path.name)] = (int(fields[1]), fields[19], fields[0])
        except (OSError, IndexError, ValueError):
            continue
    return processes


class SupervisedProcess:
    """Capture never writes logs; the owner writes only the completed snapshot.

    POSIX sessions contain ordinary children. Linux additionally follows owned
    ancestry and an inherited random marker to find orphaned setsid children.
    Windows places the process in a kill-on-close job and uses taskkill /T.
    PID start identities prevent signaling a reused, unrelated PID.
    """
    def __init__(self, argv, *, cwd, env, limit=LIMIT):
        self.marker = uuid4().hex
        self.env_marker = ('P11LAB_SUPERVISION_ID=' + self.marker).encode()
        _subreaper(True)
        try:
            self.process = subprocess.Popen(
                argv, cwd=cwd, env=dict(env, P11LAB_SUPERVISION_ID=self.marker),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=os.name != 'nt',
                # A suspended Windows child cannot spawn before job assignment.
                creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP | 0x4) if os.name == 'nt' else 0)
        except BaseException:
            _subreaper(False)
            raise
        try:
            self.capture = _Capture((self.process.stdout, self.process.stderr), limit)
        except BaseException:
            self.process.kill()
            self.process.wait(timeout=2)
            _subreaper(False)
            raise
        self.owned = {}
        self.errors = []
        self.job = None
        self.stragglers = False
        if os.name == 'nt':
            try:
                self.job = _WindowsJob(self.process)
            except OSError:
                # No application may continue without its containment boundary.
                self._signal_tree(force=True)
                self.process.wait(timeout=2)
                self.capture.finish(time.monotonic() + 1)
                _subreaper(False)
                raise
        self._discover()

    @property
    def pid(self):
        return self.process.pid

    def poll(self):
        self._discover()
        return self.process.poll()

    def _discover(self):
        processes = _linux_processes()
        if not processes:
            return []
        roots = {pid for pid, start in self.owned.items()
                 if processes.get(pid, (None, None))[1] == start}
        if self.process.poll() is None:
            roots.add(self.pid)
        # The marker also finds a child that was orphaned before the first poll.
        for pid, (_, start, state) in processes.items():
            if pid == os.getpid() or state == 'Z':
                continue
            try:
                tagged = self.env_marker in (Path('/proc') / str(pid) / 'environ').read_bytes().split(b'\0')
            except OSError:
                tagged = False
            if tagged:
                roots.add(pid)
                self.owned[pid] = start
        changed = True
        while changed:
            changed = False
            for pid, (parent, start, state) in processes.items():
                if parent in roots and pid not in roots:
                    roots.add(pid)
                    self.owned[pid] = start
                    changed = True
        return [pid for pid, start in self.owned.items()
                if pid != self.pid and processes.get(pid, (None, None, 'Z'))[1] == start
                and processes[pid][2] != 'Z']

    def _signal_tree(self, *, force):
        children = self._discover()
        if os.name == 'nt':
            if self.process.poll() is None:
                try:
                    task = subprocess.run(['taskkill', '/PID', str(self.pid), '/T', '/F'],
                                          capture_output=True, timeout=2)
                    if task.returncode and self.process.poll() is None:
                        self.errors.append('taskkill failed')
                except (OSError, subprocess.SubprocessError):
                    self.errors.append('taskkill failed')
            if self.job is not None:
                try:
                    self.job.terminate()
                except OSError:
                    self.errors.append('Windows job termination failed')
            return
        number = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.killpg(self.pid, number)
        except ProcessLookupError:
            pass
        except OSError:
            self.errors.append('process group termination failed')
        for pid in children:
            # Refresh the start identity immediately before signaling escapees.
            if _linux_processes().get(pid, (None, None))[1] != self.owned[pid]:
                continue
            try:
                os.kill(pid, number)
            except ProcessLookupError:
                pass
            except OSError:
                self.errors.append('descendant termination failed')

    def finish(self, *, stop=False, timed_out=False):
        children = self._discover()
        try:
            if self.job is not None:
                active = self.job.active()
                self.stragglers |= active > (1 if self.process.poll() is None else 0)
            self.stragglers |= bool(children)
        except OSError:
            self.errors.append('Windows job status unavailable')
        # Even a successful parent can leave children with inherited pipes.
        if stop or children or not all(self.capture.eof):
            self._signal_tree(force=False)
        end = time.monotonic() + 1
        while time.monotonic() < end:
            if self.process.poll() is not None and not self._discover() and all(self.capture.eof):
                break
            time.sleep(0.01)
        self._signal_tree(force=True)
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.errors.append('owned process could not be reaped')
        remaining = self._discover()
        end = time.monotonic() + 1
        while remaining and time.monotonic() < end:
            time.sleep(0.01)
            remaining = self._discover()
        for pid in self.owned:
            if pid == self.pid:
                continue
            try:
                os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, ProcessLookupError):
                pass
        drain_complete = self.capture.finish(time.monotonic() + 1)
        if self.job is not None:
            try:
                if self.job.active():
                    self.errors.append('Windows job still has active processes')
            except OSError:
                self.errors.append('Windows job status unavailable')
            self.job.close()
        _subreaper(False)
        return {
            'stdout_truncated': self.capture.truncated[0],
            'stderr_truncated': self.capture.truncated[1],
            'drain_complete': drain_complete,
            'stragglers_detected': self.stragglers,
            'stragglers_remaining': remaining,
            'supervision_errors': list(dict.fromkeys(self.errors)),
        }


def supervised_exec(argv, *, cwd, env, timeout, interrupted=lambda: False, limit=LIMIT):
    owner = SupervisedProcess(argv, cwd=cwd, env=env, limit=limit)
    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        while owner.poll() is None:
            if interrupted() or time.monotonic() >= deadline:
                timed_out = not bool(interrupted())
                break
            time.sleep(0.02)
    finally:
        evidence = owner.finish(stop=owner.process.poll() is None, timed_out=timed_out)
    status = owner.process.returncode
    status = 124 if timed_out else status if status is not None and status >= 0 else 128 - status if status is not None else 1
    return status, timed_out, owner, evidence


class _WindowsJob:
    def __init__(self, process):
        import ctypes
        from ctypes import wintypes as w
        class BASIC(ctypes.Structure):
            _fields_ = [('PerProcessUserTimeLimit', ctypes.c_int64), ('PerJobUserTimeLimit', ctypes.c_int64),
                        ('LimitFlags', w.DWORD), ('MinimumWorkingSetSize', ctypes.c_size_t),
                        ('MaximumWorkingSetSize', ctypes.c_size_t), ('ActiveProcessLimit', w.DWORD),
                        ('Affinity', ctypes.c_size_t), ('PriorityClass', w.DWORD), ('SchedulingClass', w.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ('ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount', 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]
        class EXTENDED(ctypes.Structure):
            _fields_ = [('BasicLimitInformation', BASIC), ('IoInfo', IO),
                        ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                        ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = w.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.kernel.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
        self.kernel.QueryInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p]
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        if (not self.handle or not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info))
                or not self.kernel.AssignProcessToJobObject(self.handle, w.HANDLE(int(process._handle)))):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())
        nt = ctypes.WinDLL('ntdll')
        nt.NtResumeProcess.argtypes = [w.HANDLE]
        nt.NtResumeProcess.restype = ctypes.c_long
        if nt.NtResumeProcess(w.HANDLE(int(process._handle))) != 0:
            self.close()
            raise OSError('cannot resume owned Windows process')

    def active(self):
        import ctypes
        # BASIC_ACCOUNTING_INFORMATION: four LARGE_INTEGERs then four DWORDs.
        data = (ctypes.c_uint64 * 6)()
        if not self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(data), ctypes.sizeof(data), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.cast(ctypes.byref(data, 40), ctypes.POINTER(ctypes.c_uint32)).contents.value

    def terminate(self):
        if not self.kernel.TerminateJobObject(self.handle, 1):
            import ctypes
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None
