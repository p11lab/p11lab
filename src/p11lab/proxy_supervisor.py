"""Bound trusted proxy input work with an owned Linux process, never threads."""
from __future__ import annotations

import json
import os
import select
import signal
import sys
import time
from typing import Callable

_MAX_IPC = 2 * 1024 * 1024
_LEASE_CLEANUP_SECONDS = 0.25
_ACTIVE = False


class ProxyWorkerError(RuntimeError):
    """The owned proxy worker failed; details are intentionally bounded."""
    def __init__(self, category: str, pid: int, reaped: bool | None, status: int | None, native_errno: int | None = None):
        super().__init__('proxy worker failed: ' + category)
        self.category, self.worker_pid, self.worker_reaped, self.wait_status = category, pid, reaped, status
        self.native_errno = native_errno


class ProxyDeadlineExceeded(TimeoutError):
    """The owned worker exceeded its wall-clock budget."""
    def __init__(self, pid: int, reaped: bool, status: int | None):
        super().__init__('proxy worker deadline exceeded')
        self.category, self.worker_pid, self.worker_reaped, self.wait_status = 'timeout', pid, reaped, status
        self.native_errno = None


class ProxyCleanupUnconfirmed(ProxyWorkerError):
    """The owned worker ended, but its shared subreaper lease is unresolved."""
    def __init__(self, pid: int, reaped: bool | None, status: int | None, operation_category: str,
                 native_errno: int | None, cleanup_errno: int | None):
        super().__init__('subreaper-release-unconfirmed', pid, reaped, status, native_errno)
        self.operation_category = operation_category
        self.lease_cleanup = 'unconfirmed'
        self.cleanup_errno = cleanup_errno


def _cleanup_error(witness: dict | None, operation: BaseException | None, error: BaseException) -> ProxyCleanupUnconfirmed:
    number = error.errno if isinstance(error, OSError) else None
    cleanup_errno = number if type(number) is int and 0 <= number <= 4095 else None
    if witness is not None:
        return ProxyCleanupUnconfirmed(witness['worker_pid'], witness['worker_reaped'], witness['wait_status'],
                                       'completed', None, cleanup_errno)
    operation_errno = getattr(operation, 'native_errno', None)
    if operation_errno is None and isinstance(operation, OSError):
        operation_errno = operation.errno
    operation_errno = operation_errno if type(operation_errno) is int and 0 <= operation_errno <= 4095 else None
    category = getattr(operation, 'category', 'os-error' if isinstance(operation, OSError) else 'interrupted')
    return ProxyCleanupUnconfirmed(getattr(operation, 'worker_pid', 0), getattr(operation, 'worker_reaped', None),
                                   getattr(operation, 'wait_status', None), category, operation_errno, cleanup_errno)


def inside_proxy_worker() -> bool:
    return _ACTIVE


def _stop_and_reap(pid: int) -> tuple[bool, int | None]:
    # The unreaped leader reserves pid/pgid until waitpid; its session contains
    # this trusted worker and any ordinary descendants. The pid fallback covers
    # a timeout before setsid has completed.
    for target in ('group', 'pid'):
        try:
            if target == 'group':
                os.killpg(pid, signal.SIGKILL)
            else:
                os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            pass
    end = time.monotonic() + 2
    leader_status = None
    while time.monotonic() < end:
        empty = False
        while True:
            try:
                found, status = os.waitpid(-pid, os.WNOHANG)
            except ChildProcessError:
                empty = True
                break
            if found == 0:
                break
            if found == pid:
                leader_status = status
        if leader_status is None:
            try:
                found, status = os.waitpid(pid, os.WNOHANG)
                if found == pid:
                    leader_status = status
            except ChildProcessError:
                pass
        if leader_status is not None and empty:
            return True, leader_status
        time.sleep(0.005)
    return False, leader_status


def run_proxy_worker(action: Callable[[], dict], *, deadline: float, include_witness: bool = False) -> dict:
    """Run one trusted operation in a bounded, killed-and-reaped process group.

    Candidate binaries are never executed here. Nested calls run inline inside
    the existing boundary, so an outer deadline contains the entire operation.
    """
    global _ACTIVE
    if _ACTIVE:
        if include_witness:
            raise ProxyWorkerError('nested-witness-unsupported', 0, False, None)
        return action()
    if sys.platform != 'linux' or not hasattr(os, 'fork') or not hasattr(os, 'waitid'):
        raise ProxyWorkerError('unsupported-platform', 0, True, None)
    if time.monotonic() >= deadline:
        raise ProxyDeadlineExceeded(0, True, None)
    from .process import _subreaper
    try:
        _subreaper(True, deadline=deadline)
    except TimeoutError:
        raise ProxyDeadlineExceeded(0, True, None) from None
    try:
        if time.monotonic() >= deadline:
            raise ProxyDeadlineExceeded(0, True, None)
        witness = _run_proxy_worker(action, deadline=deadline, include_witness=True)
    except BaseException as operation:
        try:
            _subreaper(False, deadline=time.monotonic() + _LEASE_CLEANUP_SECONDS)
        except BaseException as error:
            raise _cleanup_error(None, operation, error) from None
        raise
    try:
        _subreaper(False, deadline=time.monotonic() + _LEASE_CLEANUP_SECONDS)
    except BaseException as error:
        raise _cleanup_error(witness, None, error) from None
    return witness if include_witness else witness['result']


def _run_proxy_worker(action: Callable[[], dict], *, deadline: float, include_witness: bool) -> dict:
    global _ACTIVE
    reader, writer = os.pipe()
    try:
        pid = os.fork()
    except BaseException:
        os.close(reader)
        os.close(writer)
        raise
    if pid == 0:
        os.close(reader)
        try:
            os.setsid()
            _ACTIVE = True
            try:
                result = action()
                packet = {'ok': True, 'result': result}
            except BaseException as error:
                category = ('timeout' if isinstance(error, TimeoutError) else
                            'input' if isinstance(error, ValueError) else
                            'os-error' if isinstance(error, OSError) else 'internal-error')
                number = error.errno if isinstance(error, OSError) else None
                number = number if type(number) is int and 0 <= number <= 4095 else None
                packet = {'ok': False, 'category': category, 'native_errno': number}
            encoded = json.dumps(packet, separators=(',', ':'), allow_nan=False).encode()
            if len(encoded) > _MAX_IPC:
                encoded = b'{"ok":false,"category":"ipc-limit"}'
            while encoded:
                count = os.write(writer, encoded)
                if count <= 0:
                    break
                encoded = encoded[count:]
        except BaseException:
            pass
        finally:
            os.close(writer)
            os._exit(0)
    os.close(writer)
    data = bytearray()
    reaped = False
    status = None
    try:
        os.set_blocking(reader, False)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reaped, status = _stop_and_reap(pid)
                raise ProxyDeadlineExceeded(pid, reaped, status)
            ready, _, _ = select.select([reader], [], [], min(remaining, 0.05))
            if ready:
                part = os.read(reader, min(65536, _MAX_IPC + 1 - len(data)))
                if part:
                    data.extend(part)
                    if len(data) > _MAX_IPC:
                        reaped, status = _stop_and_reap(pid)
                        raise ProxyWorkerError('ipc-limit', pid, reaped, status)
                else:
                    while os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                        if time.monotonic() >= deadline:
                            reaped, status = _stop_and_reap(pid)
                            raise ProxyDeadlineExceeded(pid, reaped, status)
                        time.sleep(0.005)
                    # Kill any remaining ordinary descendants before reaping
                    # the session leader; the leader's pid cannot yet be reused.
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except OSError as error:
                        reaped, status = _stop_and_reap(pid)
                        raise ProxyWorkerError('cleanup-unconfirmed', pid, reaped, status) from error
                    reaped, status = _stop_and_reap(pid)
                    if not reaped or status is None or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                        raise ProxyWorkerError('worker-exit', pid, reaped, status)
                    if time.monotonic() >= deadline:
                        raise ProxyDeadlineExceeded(pid, True, status)
                    try:
                        packet = json.loads(data)
                    except (ValueError, UnicodeError) as error:
                        raise ProxyWorkerError('worker-result-unavailable', pid, True, status) from error
                    if not isinstance(packet, dict) or packet.get('ok') is not True or not isinstance(packet.get('result'), dict):
                        reason = packet.get('category', 'worker-result-invalid') if isinstance(packet, dict) else 'worker-result-invalid'
                        if not isinstance(reason, str) or reason not in {'timeout', 'input', 'os-error', 'internal-error', 'ipc-limit'}:
                            category = 'worker-result-invalid'
                        else:
                            category = reason
                        packet_number = packet.get('native_errno') if isinstance(packet, dict) else None
                        native_errno = packet_number if type(packet_number) is int and 0 <= packet_number <= 4095 else None
                        raise ProxyWorkerError(category, pid, True, status, native_errno)
                    payload_result = packet['result']
                    assert isinstance(payload_result, dict)
                    if include_witness:
                        return {'result': payload_result, 'worker_pid': pid, 'worker_reaped': True,
                                'wait_status': status, 'group_cleanup': 'confirmed'}
                    return payload_result
    except BaseException as error:
        if not reaped:
            reaped, status = _stop_and_reap(pid)
        if not hasattr(error, 'worker_pid') or reaped:
            error.worker_pid = pid  # type: ignore[attr-defined]
            error.worker_reaped = reaped  # type: ignore[attr-defined]
            error.wait_status = status  # type: ignore[attr-defined]
        raise
    finally:
        os.close(reader)
