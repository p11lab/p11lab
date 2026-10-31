"""Opaque transport must reject bad destinations before contacting them."""
import hashlib
import http.client
import importlib
import io
from pathlib import Path
from urllib.request import HTTPSHandler, Request

import pytest

URL = 'https://snapshot.debian.org/archive/debian/20260918T000000Z/pool/main/f/fixture.deb'


def module(): return importlib.import_module('p11lab.tool_downloads')


def record(data=b'abc'):
    return {'path': 'fixture.deb', 'url': URL, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


class Response(io.BytesIO):
    def __init__(self, data, headers=None, url=URL, read=None):
        super().__init__(data)
        self.headers = headers or {}
        self.url = url
        self.read_hook = read
    def geturl(self): return self.url
    def read1(self, count):
        if self.read_hook: self.read_hook()
        return super().read(min(count, 1))


def fake_transport(monkeypatch, data=b'abc', headers=None, redirects=(), read=None):
    m = module()
    contacted = []
    def build(handler, *other_handlers):
        class Opener:
            def open(self, request, timeout):
                contacted.append(request.full_url)
                for url in redirects:
                    request = handler.redirect_request(request, None, 302, 'Found', {}, url)
                    contacted.append(request.full_url)
                return Response(data, headers, request.full_url, read)
        return Opener()
    monkeypatch.setattr(m, 'build_opener', build)
    return m, contacted


def test_exact_opaque_file_is_promoted_without_extraction(monkeypatch, tmp_path):
    m, contacted = fake_transport(monkeypatch, headers={'Content-Length': '3'})
    result = m.download_locked_file(record(), tmp_path/'fixture.deb')
    assert result['size'] == 3 and result['sha256'] == record()['sha256']
    assert (tmp_path/'fixture.deb').read_bytes() == b'abc'
    assert list(tmp_path.iterdir()) == [tmp_path/'fixture.deb']
    assert contacted == [URL]


@pytest.mark.parametrize('url', ['http://snapshot.debian.org/file/x', 'https://evil.example/file/x',
    'https://user:pass@snapshot.debian.org/file/x', 'https://snapshot.debian.org:444/file/x',
    'https://snapshot.debian.org/file/x?token=x', 'file:///etc/passwd'])
def test_forbidden_redirect_is_rejected_before_target_fetch(monkeypatch, tmp_path, url):
    m, contacted = fake_transport(monkeypatch, redirects=[url])
    with pytest.raises(ValueError, match='redirect|URL|origin'):
        m.download_locked_file(record(), tmp_path/'fixture.deb')
    assert contacted == [URL]
    assert not (tmp_path/'fixture.deb').exists()


def test_allowed_redirect_is_recorded(monkeypatch, tmp_path):
    destination = 'https://snapshot.debian.org/file/'+'a'*40
    m, contacted = fake_transport(monkeypatch, redirects=[destination])
    assert m.download_locked_file(record(), tmp_path/'fixture.deb')['final_url'] == destination
    assert contacted == [URL, destination]


def test_redirect_followup_uses_remaining_deadline(monkeypatch):
    m = module()
    monkeypatch.setattr(m.time, 'monotonic', lambda: 899.0)
    handler = m._Redirects(deadline=900.0)
    calls = []
    class Parent:
        def open(self, request, *, timeout):
            calls.append((request.full_url, timeout))
            return 'redirected'
    handler.parent = Parent()
    request = Request(URL)
    request.timeout = 60.0
    destination = 'https://snapshot.debian.org/file/' + 'a'*40
    assert handler.http_error_302(request, io.BytesIO(), 302, 'Found', {'location': destination}) == 'redirected'
    assert calls == [(destination, 1.0)]


@pytest.mark.parametrize('code', [301, 302, 303, 307, 308])
def test_redirect_body_is_discarded_without_unbounded_read(monkeypatch, code):
    m = module()
    monkeypatch.setattr(m.time, 'monotonic', lambda: 899.0)
    handler = m._Redirects(deadline=900.0)
    calls = []
    class Parent:
        def open(self, request, *, timeout):
            calls.append(timeout)
            return 'redirected'
    class RedirectResponse(io.BytesIO):
        def read(self, *args):
            raise AssertionError('unbounded redirect body read')
    handler.parent = Parent()
    request = Request(URL); request.timeout = 60.0
    response = RedirectResponse()
    destination = 'https://snapshot.debian.org/file/' + 'a'*40
    assert getattr(handler, f'http_error_{code}')(request, response, code, 'Redirect', {'location': destination}) == 'redirected'
    assert response.closed and calls == [1.0]


@pytest.mark.parametrize('code', [301, 302, 303, 307, 308])
def test_no_drain_redirect_path_still_checks_origin_before_follow(monkeypatch, code):
    m = module()
    monkeypatch.setattr(m.time, 'monotonic', lambda: 0.0)
    handler = m._Redirects(deadline=900.0)
    class Parent:
        def open(self, *args, **kwargs):
            raise AssertionError('unapproved redirect followed')
    handler.parent = Parent()
    request = Request(URL); request.timeout = 60.0
    response = io.BytesIO(b'ignored redirect body')
    with pytest.raises(ValueError, match='origin|URL|redirect'):
        getattr(handler, f'http_error_{code}')(request, response, code, 'Redirect', {'location': 'https://forbidden.invalid/file'})
    assert response.closed


def test_redirect_depth_is_bounded(monkeypatch, tmp_path):
    urls = ['https://snapshot.debian.org/file/'+str(i)*40 for i in range(6)]
    m, contacted = fake_transport(monkeypatch, redirects=urls)
    with pytest.raises(ValueError, match='redirect'):
        m.download_locked_file(record(), tmp_path/'fixture.deb')
    assert len(contacted) == 6  # Original plus five approved hops, never the sixth.


@pytest.mark.parametrize('data,headers', [(b'ab', {}), (b'abcd', {}), (b'xxx', {}),
    (b'abc', {'Content-Length': '2'}), (b'abc', {'Content-Encoding': 'gzip'})])
def test_size_hash_and_encoding_failures_never_promote(monkeypatch, tmp_path, data, headers):
    m, _ = fake_transport(monkeypatch, data, headers)
    with pytest.raises(ValueError):
        m.download_locked_file(record(), tmp_path/'fixture.deb')
    assert not (tmp_path/'fixture.deb').exists()


def test_header_does_not_choose_destination(monkeypatch, tmp_path):
    m, _ = fake_transport(monkeypatch, headers={'Content-Disposition': 'attachment; filename=../escape'})
    m.download_locked_file(record(), tmp_path/'fixture.deb')
    assert not (tmp_path.parent/'escape').exists()


def test_partial_timeout_keeps_bounded_failure_not_success(monkeypatch, tmp_path):
    count = [0]
    def timeout():
        count[0] += 1
        if count[0] == 3: raise TimeoutError('synthetic timeout')
    m, _ = fake_transport(monkeypatch, read=timeout)
    with pytest.raises((OSError, ValueError)):
        m.download_locked_file(record(), tmp_path/'fixture.deb')
    assert not (tmp_path/'fixture.deb').exists()
    assert sum(p.stat().st_size for p in tmp_path.iterdir()) <= 3


@pytest.mark.parametrize('attempt_deadline', [None, 5.0])
def test_slow_progress_cannot_evade_monotonic_deadline(monkeypatch, tmp_path, attempt_deadline):
    now = [0.0]
    def advance(): now[0] += 600.0
    m, _ = fake_transport(monkeypatch, read=advance)
    monkeypatch.setattr(m.time, 'monotonic', lambda: now[0])
    with pytest.raises(ValueError, match='deadline'):
        m.download_locked_file(record(), tmp_path/'fixture.deb', deadline=attempt_deadline)
    assert not (tmp_path/'fixture.deb').exists()


@pytest.mark.parametrize('phase', ['status', 'headers', 'chunk-extension', 'trailers', 'fixed-body', 'chunked-body'])
def test_real_http_framing_cannot_hide_slow_progress(monkeypatch, tmp_path, phase):
    m = module()
    now = [0.0]
    status = b'HTTP/1.1 200 OK\r\n'
    if phase == 'status': status = b'HTTP/1.1 200 ' + b'x'*2000 + b'\r\n'
    headers = b'Transfer-Encoding: chunked\r\n'
    if phase == 'headers': headers += b'X-Slow: ' + b'x'*2000 + b'\r\n'
    body = b'3' + (b';' + b'x'*2000 if phase == 'chunk-extension' else b'') + b'\r\nabc\r\n0\r\n'
    body += (b'X-Trailer: ' + b'x'*2000 + b'\r\n' if phase == 'trailers' else b'') + b'\r\n'
    if phase == 'fixed-body':
        headers, body = b'Content-Length: 3\r\n', b'abc'
    data = status + headers + b'\r\n' + body
    slow_after = 0 if phase == 'status' else len(status) if phase == 'headers' else len(status + headers + b'\r\n')
    if phase in {'fixed-body', 'chunked-body'}: slow_after = len(data)
    class Raw(io.RawIOBase):
        pos = 0
        def readable(self): return True
        def readinto(self, buffer):
            if self.pos == len(data): return 0
            buffer[0] = data[self.pos]; self.pos += 1
            if self.pos > slow_after: now[0] += 0.5
            return 1
    raw = Raw()
    class Socket:
        def makefile(self, *args): return io.BufferedReader(raw)
        def settimeout(self, value): assert 0 < value <= 5.0
    def build(*handlers):
        class Opener:
            def open(self, request, timeout):
                def do_open(connection_factory, request, **kwargs):
                    import ssl
                    connection = connection_factory('snapshot.debian.org', timeout=timeout, **kwargs)
                    assert connection._context.check_hostname
                    assert connection._context.verify_mode == ssl.CERT_REQUIRED
                    response = connection.response_class(Socket())
                    try: response.begin()
                    except BaseException:
                        response.close()
                        raise
                    response.geturl = lambda: URL
                    return response
                bounded = next((h for h in handlers if isinstance(h, HTTPSHandler)), None)
                if bounded is None: return do_open(http.client.HTTPSConnection, request)
                bounded.do_open = do_open
                return bounded.https_open(request)
        return Opener()
    monkeypatch.setattr(m, 'build_opener', build)
    monkeypatch.setattr(m.time, 'monotonic', lambda: now[0])
    if phase in {'fixed-body', 'chunked-body'}:
        assert m.download_locked_file(record(), tmp_path/'fixture.deb', deadline=5.0)['size'] == 3
        assert (tmp_path/'fixture.deb').read_bytes() == b'abc'
    else:
        with pytest.raises((ValueError, TimeoutError), match='deadline'):
            m.download_locked_file(record(), tmp_path/'fixture.deb', deadline=5.0)
        assert not (tmp_path/'fixture.deb').exists()
    assert now[0] <= 5.5, 'HTTP framing bypassed the monotonic deadline'
    assert raw.closed


def test_https_proxy_connect_uses_the_same_header_deadline(monkeypatch):
    m = module()
    now = [0.0]
    status = b'HTTP/1.1 200 Connection established\r\n'
    data = status + b'X-Slow: ' + b'x'*2000 + b'\r\n\r\n'
    class Raw(io.RawIOBase):
        pos = 0
        def readable(self): return True
        def readinto(self, buffer):
            if self.pos == len(data): return 0
            buffer[0] = data[self.pos]; self.pos += 1
            if self.pos > len(status): now[0] += 0.5
            return 1
    raw = Raw()
    class Socket:
        def makefile(self, *args): return io.BufferedReader(raw)
        def settimeout(self, value): assert 0 < value <= 5.0
        def sendall(self, data): assert data.startswith(b'CONNECT snapshot.debian.org:443 ')
    handler = m._HTTPS(deadline=5.0)
    handler.do_open = lambda factory, request, **kwargs: factory('proxy.invalid', **kwargs)
    connection = handler.https_open(Request(URL))
    connection.set_tunnel('snapshot.debian.org', 443)
    connection.sock = Socket()
    monkeypatch.setattr(m.time, 'monotonic', lambda: now[0])
    with pytest.raises((ValueError, TimeoutError), match='deadline'):
        connection._tunnel()
    assert now[0] <= 5.5 and raw.closed


def bounded_connection(context, *, deadline=5.0, **options):
    handler = module()._HTTPS(deadline=deadline)
    handler.do_open = lambda factory, request, **kwargs: factory(
        'snapshot.debian.org', **(kwargs | {'context': context, 'timeout': 5.0} | options))
    return handler.https_open(Request(URL))


@pytest.mark.parametrize('proxy', [False, True])
def test_tcp_tls_and_request_send_refresh_remaining_budget(monkeypatch, proxy):
    m = module()
    now, tls, sent, options = [0.0], [], [], []
    class Socket:
        timeout = 5.0
        def settimeout(self, value): self.timeout = value
        def setsockopt(self, *args): options.append(args)
        def sendall(self, data): sent.append((data, now[0], self.timeout))
        def makefile(self, *args):
            now[0] += 2.0
            return io.BytesIO(b'HTTP/1.1 200 Connection established\r\n\r\n')
    sock = Socket()
    class Context:
        def wrap_socket(self, selected, *, server_hostname):
            assert selected is sock
            tls.append((now[0], sock.timeout, server_hostname))
            now[0] += 0.25
            return sock
    connection = bounded_connection(Context())
    def tcp(*args):
        now[0] += 2.0 if proxy else 4.0
        return sock
    connection._create_connection = tcp
    if proxy: connection.set_tunnel('snapshot.debian.org', 443)
    monkeypatch.setattr(m.time, 'monotonic', lambda: now[0])
    connection.connect()
    connection.send(b'GET / HTTP/1.1\r\n\r\n')
    assert tls == [(4.0, 1.0, 'snapshot.debian.org')]
    assert sent[-1][1:] == (4.25, 0.75)
    assert options  # HTTPConnection still applies its normal TCP_NODELAY option.
    if proxy:
        assert sent[0][0].startswith(b'CONNECT snapshot.debian.org:443 ')
        assert sent[0][1:] == (2.0, 3.0)


@pytest.mark.parametrize('phase', ['tcp', 'tls', 'send'])
def test_expired_connection_phase_never_continues(monkeypatch, phase):
    m = module()
    now, tls, sent = [0.0], [], []
    class Socket:
        def settimeout(self, value): pass
        def setsockopt(self, *args): pass
        def sendall(self, data):
            sent.append(data)
            if phase == 'send': now[0] = 6.0
    sock = Socket()
    class Context:
        def wrap_socket(self, selected, **kwargs):
            tls.append(True)
            if phase == 'tls': now[0] = 6.0
            return sock
    connection = bounded_connection(Context())
    def tcp(*args):
        if phase == 'tcp': now[0] = 6.0
        return sock
    connection._create_connection = tcp
    monkeypatch.setattr(m.time, 'monotonic', lambda: now[0])
    with pytest.raises((ValueError, TimeoutError), match='deadline'):
        connection.connect()
        connection.send(b'GET / HTTP/1.1\r\n\r\n')
    if phase == 'tcp': assert not tls
    if phase != 'send': assert not sent


@pytest.mark.parametrize('dns_seconds,first_seconds', [(0.0, 4.0), (0.0, 5.0), (6.0, 0.0)])
def test_each_resolved_address_has_only_remaining_budget(monkeypatch, dns_seconds, first_seconds):
    import socket
    m = module()
    now, sockets, attempts, tls = [0.0], [], [], []
    class Context:
        def wrap_socket(self, selected, **kwargs):
            tls.append(selected.timeout)
            return selected
    connection = bounded_connection(Context(), source_address=('127.0.0.1', 0))
    class Socket:
        closed = False
        def __init__(self, *args): sockets.append(self); self.number = len(sockets)
        def settimeout(self, value): self.timeout = value
        def bind(self, source): assert source == ('127.0.0.1', 0)
        def connect(self, address):
            attempts.append(self.timeout)
            if self.number == 1:
                now[0] += first_seconds
                raise OSError('first address failed')
            now[0] += 0.5
        def setsockopt(self, *args): pass
        def close(self): self.closed = True
    def addresses(*args):
        now[0] += dns_seconds
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.' + str(i), 443)) for i in (1, 2)]
    monkeypatch.setattr(socket, 'getaddrinfo', addresses)
    monkeypatch.setattr(socket, 'socket', Socket)
    monkeypatch.setattr(m.time, 'monotonic', lambda: now[0])
    if dns_seconds + first_seconds >= 5:
        with pytest.raises((ValueError, TimeoutError), match='deadline'):
            connection.connect()
        assert len(sockets) == (0 if dns_seconds else 1)
        assert not tls
    else:
        connection.connect()
        assert attempts == [5.0, 1.0]
        assert tls == [0.5]
    if sockets: assert sockets[0].closed


@pytest.mark.parametrize('kind', ['destination', 'partial', 'symlink', 'parent-symlink', 'fifo'])
def test_preexisting_or_unsafe_destinations_rejected_before_network(monkeypatch, tmp_path, kind):
    m, contacted = fake_transport(monkeypatch)
    path = tmp_path/'fixture.deb'
    if kind == 'destination': path.write_bytes(b'old')
    elif kind == 'partial': (tmp_path/'fixture.deb.part').write_bytes(b'old')
    elif kind == 'symlink': path.symlink_to(tmp_path/'absent')
    elif kind == 'parent-symlink':
        target = tmp_path/'target'; target.mkdir(); (tmp_path/'link').symlink_to(target, target_is_directory=True); path = tmp_path/'link'/'fixture.deb'
    else:
        import os
        if not hasattr(os, 'mkfifo'): pytest.skip('FIFO unavailable')
        os.mkfifo(path)
    with pytest.raises((ValueError, FileExistsError)):
        m.download_locked_file(record(), path)
    assert not contacted

@pytest.mark.parametrize('url', [
    'https://codeload.github.com/mingulov/pkcs11-check/tar.gz/9df03bd8b811966fa7856394b19e3f57ffcd8a40',
    'https://files.pythonhosted.org/packages/ab/cd/' + 'a'*60 + '/package-1.0-py3-none-any.whl',
])
def test_transport_allows_only_narrow_official_upstream_artifact_paths(url):
    from p11lab.tool_downloads import _target
    _target(url)


@pytest.mark.parametrize('url', [
    'https://files.pythonhosted.org.evil/packages/ab/cd/' + 'a'*60 + '/x.whl',
    'https://user@files.pythonhosted.org/packages/ab/cd/' + 'a'*60 + '/x.whl',
    'http://files.pythonhosted.org/packages/ab/cd/' + 'a'*60 + '/x.whl',
    'https://files.pythonhosted.org/packages/ab/cd/' + 'a'*60 + '/x.whl?x=1',
    'https://codeload.github.com/mingulov/pkcs11-check/tar.gz/main',
    'https://codeload.github.com/other/project/tar.gz/' + 'a'*40,
    'https://files.pythonhosted.org/simple/package/',
])
def test_transport_rejects_credential_mutable_or_cross_origin_upstream_redirect(url):
    from p11lab.tool_downloads import _target
    with pytest.raises(ValueError): _target(url)


def test_debian_record_cannot_be_relabelled_as_an_upstream_wheel(monkeypatch, tmp_path):
    m, contacted = fake_transport(monkeypatch)
    rec = record() | {'url': 'https://files.pythonhosted.org/packages/ab/cd/' + 'a'*60 + '/x.whl'}
    with pytest.raises(ValueError): m.download_locked_file(rec, tmp_path/'bad')
    assert not contacted


def test_approved_origins_cannot_redirect_between_artifact_families(monkeypatch, tmp_path):
    url = 'https://files.pythonhosted.org/packages/ab/cd/' + 'a'*60 + '/x.whl'
    m, contacted = fake_transport(monkeypatch, redirects=[url])
    with pytest.raises(ValueError, match='cross-family'): m.download_locked_file(record(), tmp_path/'bad')
    assert contacted == [URL]


def test_proxy_download_hard_deadline_kills_blocked_dns_without_network(
    monkeypatch, tmp_path
):
    import os
    import socket
    import time
    from p11lab.tool_downloads import ProxyInputRecord, download_proxy_file

    marker = tmp_path / "dns-pid"

    def blocked(*args):
        marker.write_text(str(os.getpid()))
        time.sleep(10)
        raise AssertionError("DNS resumed")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    record = ProxyInputRecord(
        "rust/rustc.tar.xz",
        "https://static.rust-lang.org/dist/2026-09-03/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz",
        "a" * 64,
        1,
        "proxy-rust-dist",
    )
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        download_proxy_file(record, tmp_path / "out", deadline=start + 0.5)
    assert time.monotonic() - start < 3
    pid = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize('deadline', [float('nan'), float('inf'), -float('inf'), True])
def test_proxy_download_rejects_invalid_deadline_before_start(tmp_path, deadline):
    from p11lab.tool_downloads import ProxyInputRecord, download_proxy_file
    record = ProxyInputRecord('rust/rustc.tar.xz',
        'https://static.rust-lang.org/dist/2026-09-03/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz',
        'a' * 64, 1, 'proxy-rust-dist')
    with pytest.raises(ValueError):
        download_proxy_file(record, tmp_path/'out', deadline=deadline)
    assert not (tmp_path/'out').exists()


def test_direct_proxy_download_does_not_hide_reaper_cleanup_uncertainty(
    tmp_path, monkeypatch
):
    import threading
    import time
    from p11lab import process
    from p11lab.proxy_supervisor import ProxyCleanupUnconfirmed
    from p11lab.tool_downloads import ProxyInputRecord, download_proxy_file

    initial = process._reaper_users
    marker, held = tmp_path / "worker-ready", tmp_path / "lock-held"
    release = threading.Event()

    def holder():
        end = time.monotonic() + 2
        while not marker.exists() and time.monotonic() < end:
            time.sleep(0.005)
        with process._reaper_lock:
            held.write_text("held")
            release.wait(0.8)

    thread = threading.Thread(target=holder)
    thread.start()

    def download(record, destination, *, deadline):
        marker.write_text("ready")
        end = time.monotonic() + 2
        while not held.exists() and time.monotonic() < end:
            time.sleep(0.005)
        return {"size": 1, "sha256": "a" * 64, "final_url": record["url"]}

    monkeypatch.setattr(module(), "download_locked_file", download)
    record = ProxyInputRecord(
        "rust/rustc.tar.xz",
        "https://static.rust-lang.org/dist/2026-09-03/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz",
        "a" * 64,
        1,
        "proxy-rust-dist",
    )
    try:
        with pytest.raises(ProxyCleanupUnconfirmed) as error:
            download_proxy_file(record, tmp_path / "out", deadline=time.monotonic() + 2)
        assert (
            error.value.worker_reaped is True
            and error.value.operation_category == "completed"
        )
    finally:
        release.set()
        thread.join(timeout=2)
        if process._reaper_users == initial + 1:
            process._subreaper(False)
    assert not thread.is_alive() and process._reaper_users == initial
