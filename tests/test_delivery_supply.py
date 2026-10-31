"""Post-M9 review fixups: delivery supply pins and provider hardening.

Covers T5 (ORAS curl proto), E5 (bouncyhsm pidfile), M6k (kmsp11 archive
hashes), M7n (NSPR tag annotation), M8r (nethsm registry qualification),
and the action.yml python pin. Hermetic: no network, no Docker.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROVIDERS = ROOT / "src" / "p11lab" / "data" / "providers"


def test_install_oras_forces_https_redirects():
    """T5: curl follows redirects to https only (hash checks stay backstop)."""
    shell = (ROOT / "src" / "p11lab" / "data" / "delivery" / "install-oras.sh").read_text()
    assert "--proto '=https'" in shell


def test_bouncy_entrypoint_has_no_pidfile_check():
    """E5: no pidfile gates readiness (nothing writes it; kill -0 is TOCTOU)."""
    text = (PROVIDERS / "bouncyhsm" / "entrypoint.sh").read_text()
    assert "server.pid" not in text


def test_nss_dockerfile_marks_nspr_tag_evidence_only():
    """M7n: NSPR_TAG must not be mistaken for a pin (fetch is revision-bound)."""
    text = (PROVIDERS / "nss" / "Dockerfile").read_text()
    assert "NSPR_TAG" in text and "evidence-only" in text


def test_nethsm_dockerfile_qualifies_registries():
    """M8r: no implicit Docker Hub in FROM refs (digests unchanged)."""
    text = (PROVIDERS / "nethsm" / "Dockerfile").read_text()
    for ref in ("docker.io/library/alpine@sha256:28bd5fe8",
                "docker.io/library/rust@sha256:7cc1c22d",
                "docker.io/nitrokey/nethsm@sha256:4c9cf630"):
        assert ref in text, ref
    for bare in ("=alpine@", "FROM rust@", "FROM nitrokey/nethsm@"):
        assert bare not in text, bare
    for digest in ("28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
                   "7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f",
                   "4c9cf630aab7d4b9a76c7247844635d3dd1b78c34ff4fd473115cc59419f6e9b"):
        assert digest in text, digest


def test_all_git_sources_carry_archive_hashes():
    """M6k: every locked git source records its archive digest (no gaps)."""
    gaps = []
    for lock_path in sorted(PROVIDERS.glob("*/*.lock.json")):
        lock = json.loads(lock_path.read_text())
        for roster in ("sources", "dependencies"):
            for entry in lock.get(roster, []):
                if entry.get("kind") == "git" and "archive_sha256" not in entry:
                    gaps.append(f"{lock_path.parent.name}/{lock_path.name}:{roster}")
    assert gaps == [], gaps


def test_action_pins_patch_python():
    """action.yml python must be patch-pinned like the workflows."""
    text = (ROOT / "action.yml").read_text()
    assert "python-version: '3.12.14'" in text


def _write_server_ready_script(tmp_path, http_stub, native_stub):
    """E5: redirect a real entrypoint copy at fixture state with stubbed I/O.

    Only the transport (http_request) and the PKCS#11 probe (native_slots)
    are stubbed; label validation, static state, marker comparison, slot
    selection, and the readiness waiters run unmodified.
    """
    import re

    from p11lab.catalog import package_data

    state, control = tmp_path / "state", tmp_path / "control"
    owned = state / "bouncyhsm"
    owned.mkdir(parents=True)
    control.mkdir()
    runtime_id = tmp_path / "runtime-id"
    runtime_id.write_text("test-artifact\n")
    (owned / "complete").write_text("schema=1\nprovider=bouncyhsm\nartifact=test-artifact\n"
                                    "label=P11Lab\nslot=0\nbackend=litedb\n")
    (owned / "BouncyHsm.db").write_bytes(b"db")
    (control / "server.log").write_text("")
    text = package_data("providers/bouncyhsm/entrypoint.sh").read_text()
    text = text.replace(". /usr/share/p11lab/common.sh", package_data("runtime/common.sh").read_text())
    for original, redirect in [("/var/lib/p11lab", state), ("/run/p11lab", control),
                               ("/usr/share/p11lab/runtime-id", runtime_id)]:
        text = text.replace(original, str(redirect))
    for name, stub in (("http_request", http_stub), ("native_slots", native_stub)):
        spliced, count = re.subn(r"\n%s\(\) \{.*?\n\}\n" % name, "\n%s\n" % stub, text,
                                 count=1, flags=re.DOTALL)
        assert count == 1, name
        text = spliced
    script = tmp_path / "provider"
    script.write_text(text)
    return script


def test_bouncy_server_ready_succeeds_when_healthy(tmp_path):
    """E5: server-ready exits 0 for a supervised server (no PID exists here)."""
    import os
    import subprocess

    script = _write_server_ready_script(
        tmp_path,
        'http_request() { if [ "$2" = "/Slot" ]; then '
        'printf \'%s\' \'[{"SlotId":0,"Label":"P11Lab"}]\'; fi; return 0; }',
        'native_slots() { printf \'1 1\\n\'; }')
    result = subprocess.run(["bash", str(script), "server-ready"], capture_output=True, text=True,
                            timeout=60, env=os.environ | {"P11LAB_LABEL": "P11Lab"})
    assert result.returncode == 0, result.stderr
    assert "exited during startup" not in result.stderr, result.stderr


def test_bouncy_server_ready_fails_without_pid_gate(tmp_path):
    """E5: an unhealthy supervised server fails on HTTP, never on a PID."""
    import os
    import subprocess

    script = _write_server_ready_script(
        tmp_path,
        'http_request() { return 1; }',
        'native_slots() { printf \'1 1\\n\'; }')
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "sleep").write_text("#!/bin/sh\nexit 0\n")
    (bindir / "sleep").chmod(0o755)
    env = os.environ | {"P11LAB_LABEL": "P11Lab", "PATH": "%s:%s" % (bindir, os.environ["PATH"])}
    result = subprocess.run(["bash", str(script), "server-ready"], capture_output=True, text=True,
                            timeout=60, env=env)
    assert result.returncode != 0
    assert "externally supervised server HTTP health did not become ready" in result.stderr
    assert "exited during startup" not in result.stderr, result.stderr
