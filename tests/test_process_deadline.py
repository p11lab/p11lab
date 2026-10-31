"""Pin the _subreaper deadline lease paths (Linux-only, zero real prctl)."""
import ctypes
import sys
import threading
import time

import pytest

from p11lab import process as proc
from p11lab import proxy_supervisor
from p11lab.process import _subreaper
from p11lab.proxy_supervisor import ProxyDeadlineExceeded

pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux'), reason='subreaper lease is Linux-only')


class _FakeLibc:
    """CDLL double: records prctl ops, never touches the kernel."""

    def __init__(self):
        self.calls: list = []
        self.fail_set = False

    def prctl(self, op, *args):
        self.calls.append((op, args[0] if args else None))
        return 1 if op == 36 and self.fail_set else 0


@pytest.fixture
def lease(monkeypatch):
    users, prev = proc._reaper_users, proc._previous_reaper
    assert not proc._reaper_lock.locked()
    fake = _FakeLibc()
    monkeypatch.setattr(ctypes, 'CDLL', lambda *args, **kwargs: fake)
    yield fake
    try:
        assert not proc._reaper_lock.locked()
        assert (proc._reaper_users, proc._previous_reaper) == (users, prev)
    finally:
        proc._reaper_users, proc._previous_reaper = users, prev


def _at(monkeypatch, *values):
    vals = list(values)
    monkeypatch.setattr(time, 'monotonic', lambda: vals.pop(0) if len(vals) > 1 else vals[0])


def test_acquire_deadline_ok_then_release(lease, monkeypatch):
    _at(monkeypatch, 50.0)
    _subreaper(True, deadline=100.0)
    assert proc._reaper_users == 1
    assert [op for op, _ in lease.calls] == [37, 36]
    _subreaper(False, deadline=100.0)
    assert proc._reaper_users == 0


def test_acquire_deadline_expired(lease, monkeypatch):
    _at(monkeypatch, 200.0)
    with pytest.raises(TimeoutError, match='^subreaper lease lock deadline$'):
        _subreaper(True, deadline=100.0)
    assert proc._reaper_users == 0
    assert not proc._reaper_lock.locked()
    assert lease.calls == []


def test_acquire_deadline_contended(lease):
    holding, release = threading.Event(), threading.Event()

    def holder():
        proc._reaper_lock.acquire()
        holding.set()
        release.wait(timeout=10)
        proc._reaper_lock.release()

    thread = threading.Thread(target=holder, daemon=True)
    thread.start()
    try:
        assert holding.wait(timeout=10)
        with pytest.raises(TimeoutError, match='^subreaper lease lock deadline$'):
            _subreaper(True, deadline=time.monotonic() + 1.0)
        assert proc._reaper_users == 0
        assert lease.calls == []
    finally:
        release.set()
        thread.join(timeout=10)
        assert not thread.is_alive()


def test_acquire_deadline_post_acquire_expiry(lease, monkeypatch):
    _at(monkeypatch, 50.0, 100.0)
    with pytest.raises(TimeoutError, match='^subreaper lease lock deadline$'):
        _subreaper(True, deadline=100.0)
    assert proc._reaper_users == 0
    assert not proc._reaper_lock.locked()
    assert lease.calls == []


def test_release_deadline_restores(lease, monkeypatch):
    old = proc._reaper_users, proc._previous_reaper
    proc._reaper_users, proc._previous_reaper = 1, 7
    _at(monkeypatch, 50.0)
    _subreaper(False, deadline=100.0)
    assert proc._reaper_users == 0
    assert (36, 7) in lease.calls
    proc._reaper_users, proc._previous_reaper = old


def test_release_deadline_unheld(lease, monkeypatch):
    _at(monkeypatch, 50.0)
    with pytest.raises(RuntimeError, match='^subreaper lease not held$'):
        _subreaper(False, deadline=100.0)
    assert proc._reaper_users == 0
    assert lease.calls == []


def test_release_deadline_failing_restore(lease, monkeypatch):
    old = proc._reaper_users, proc._previous_reaper
    proc._reaper_users, proc._previous_reaper = 1, 0
    lease.fail_set = True
    _at(monkeypatch, 50.0)
    with pytest.raises(OSError, match='cannot restore owned child reaping'):
        _subreaper(False, deadline=100.0)
    assert proc._reaper_users == 1
    proc._reaper_users, proc._previous_reaper = old


def test_release_deadline_shared_no_restore(lease, monkeypatch):
    old = proc._reaper_users, proc._previous_reaper
    proc._reaper_users = 2
    _at(monkeypatch, 50.0)
    _subreaper(False, deadline=100.0)
    assert proc._reaper_users == 1
    assert lease.calls == []
    proc._reaper_users, proc._previous_reaper = old


def test_proxy_deadline_timeout_maps_pre_fork(lease, monkeypatch):
    monkeypatch.setattr(proxy_supervisor, '_ACTIVE', False)

    def boom(acquire, *, deadline=None):
        raise TimeoutError('subreaper lease lock deadline')

    monkeypatch.setattr('p11lab.process._subreaper', boom)
    with pytest.raises(ProxyDeadlineExceeded):
        proxy_supervisor.run_proxy_worker(lambda: {}, deadline=time.monotonic() + 30)
    assert proc._reaper_users == 0
