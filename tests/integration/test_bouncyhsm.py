"""BouncyHSM Linux container/native and Windows native acceptance.

Dual-mode module. Under pytest this file orchestrates env-gated lanes; as a
script (``python test_bouncyhsm.py <step> ...``) it executes hermetic native
steps anywhere P11Lab is installed (Debian container for Linux native, the
Windows host for Windows native). Step execution never needs pytest.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    import pytest
except ImportError:  # pragma: no cover - step-execution contexts

    class _Shim:
        def __call__(self, *args, **kwargs):
            if len(args) == 1 and callable(args[0]) and not kwargs:
                return args[0]
            return lambda func: func

        def __getattr__(self, name):
            return _Shim()

    pytest = _Shim()

def _work_dir(start):
    """Repo root for checkout layouts; own directory for flat copies.

    The direct lane copies this file flat to /workspace, where parents[2]
    does not exist. Flat copies run where P11Lab is installed (the image),
    so a missing WORK/src entry is harmless: nonexistent sys.path entries
    are ignored at import.
    """
    resolved = Path(start).resolve()
    parents = resolved.parents
    return parents[2] if len(parents) > 2 else resolved.parent


WORK = _work_dir(__file__)
if str(WORK / "src") not in sys.path:
    sys.path.insert(0, str(WORK / "src"))

from p11lab.catalog import package_data  # noqa: E402 - sys.path bootstrap above is load-bearing for flat copies

# Script steps run from caller-owned paths such as /workspace/test_bouncyhsm.py.
# Resolve the installed package's resources without assuming a checkout depth.
CONSUMER_DIR = package_data('consumer/verify.py').parent


def _env_json(name):
    raw = os.environ.get(name)
    return json.loads(raw) if raw else None


def _docker(*args, timeout=120):
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )


def _step_python():
    return [sys.executable, str(Path(__file__).resolve())]


# ---------------------------------------------------------------------------
# Hermetic native steps (no pytest, no docker; stdlib plus installed p11lab).
# ---------------------------------------------------------------------------


def step_install(args):
    """Install one bundle archive; print manifest identity and preflight."""
    from p11lab.models import ArtifactRef
    from p11lab.native import install_bouncyhsm_bundle

    archive = Path(args["archive"])
    want = args["sha256"]
    if hashlib.sha256(archive.read_bytes()).hexdigest() != want:
        raise ValueError("bundle archive sha256 mismatch")
    artifact = ArtifactRef("bundle", str(archive), want, args["platform"])
    installed = install_bouncyhsm_bundle(
        artifact, Path(args["prefix"]), environment="bouncyhsm", channel=args["channel"]
    )
    from p11lab.native import preflight_bouncyhsm

    host = preflight_bouncyhsm(installed.prefix, installed.manifest)
    host.pop("dotnet_runtimes", None)
    host.pop("closure", None)
    return {
        "manifest_sha256": installed.manifest_sha256,
        "receipt_sha256": installed.receipt_sha256,
        "module": installed.manifest["module"],
        "target": installed.manifest["target"],
        "host": host,
    }


def step_readback(args):
    """Reverify an installation including host/ABI preflight."""
    from p11lab.native import load_bouncyhsm_installation

    installed = load_bouncyhsm_installation(
        Path(args["prefix"]),
        environment="bouncyhsm",
        channel=args["channel"],
        platform=args["platform"],
    )
    return {"manifest_sha256": installed.manifest_sha256}


def step_run_app(args, extra):
    """Run one native application; print the receipt summary."""
    from p11lab.models import ArtifactRef, RunSpec
    from p11lab.native import load_bouncyhsm_installation, run_native_bouncyhsm

    archive = Path(args["archive"])
    artifact = ArtifactRef(
        "bundle",
        str(archive),
        hashlib.sha256(archive.read_bytes()).hexdigest(),
        args["platform"],
    )
    installed = load_bouncyhsm_installation(
        Path(args["prefix"]),
        environment="bouncyhsm",
        channel=args["channel"],
        platform=args["platform"],
    )
    if installed.artifact != artifact:
        raise ValueError("step bundle differs from installed artifact")
    inputs = {}
    for key in (
        "P11LAB_PIN",
        "P11LAB_SO_PIN",
        "P11LAB_PIN_FILE",
        "P11LAB_SO_PIN_FILE",
        "P11LAB_LABEL",
        "P11LAB_STATE_DIR",
        "P11LAB_CONTROL_DIR",
        "P11LAB_HTTP_PORT",
        "P11LAB_TCP_PORT",
    ):
        if args.get(key):
            inputs[key] = args[key]
    spec = RunSpec(
        "bouncyhsm",
        args["channel"],
        "native",
        artifact,
        "host",
        None,
        None,
        tuple(extra),
        inputs,
        Path(args["output"]),
        Path(args["cwd"]),
        int(args.get("timeout", "300")),
        Path(args["prefix"]),
    )
    result = run_native_bouncyhsm(spec, installed)
    receipt = json.loads(Path(result.receipt_path).read_text())
    return {
        "exit_code": result.exit_code,
        "app_returncode": result.app_returncode,
        "lifecycle_errors": list(result.lifecycle_errors),
        "cleanup_errors": list(result.cleanup_errors),
        "slot": receipt["state"]["slot"],
        "stages": [s["phase"] for s in receipt["stages"]],
        "native_probes": {s["phase"]: s["native_probe"] for s in receipt["stages"] if "native_probe" in s},
        "http_port": receipt["execution"]["http_port"],
        "tcp_port": receipt["execution"]["tcp_port"],
    }


def step_checker_driver(args, extra):
    """Run the installed checker CLI inside a provisioned run.

    Executed as the application argv of a native run (or direct-lane exec):
    the provider is provisioned and the environment carries the module path
    and BOUNCY_HSM_CFG_STRING. This mirrors the frozen execute_checker
    protocol exactly (identity, collection, flags, bounds, redaction,
    receipts, frozen validator) except documented deviations: direct driving
    is required because the library boundary scrubs provider transport
    variables (T6 precedent) and is POSIX-only (start_new_session/killpg),
    so the transport is preserved and Windows supervision uses taskkill on
    the owned tree. Windows identity replaces the POSIX image seal with a
    source-checkout binding; the Linux direct lane uses the seal.
    Collection and the test run execute with cwd at the installed root:
    pytest anchors displayed node paths to the invocation directory, so any
    other cwd yields install-relative ids the frozen validator cannot
    resolve. Durable artifacts stay absolute under the output dir, and the
    pytest cache provider is off so no cache state leaks into the shared
    install (the checker already disables it for its own children).
    """
    import importlib.metadata
    import threading
    from uuid import uuid4

    from p11lab.checker import (
        SOURCE,
        canonical_node,
        checker_environment,
        load_profile,
        source_inventory,
        validate_results,
    )
    from p11lab.receipts import write_receipt

    module = Path(os.environ["P11LAB_MODULE"])
    transport = os.environ.get("BOUNCY_HSM_CFG_STRING")
    if not transport:
        raise ValueError("checker run misses the provider transport")
    label = os.environ.get("P11LAB_LABEL", "P11Lab")
    output = Path(args["output"]).resolve()
    nodes = list(load_profile("smoke-v1")["nodes"])
    try:
        import pkcs11_check.testcases as tests
    except ImportError as error:
        raise ValueError("installed checker tests are not importable") from error
    installed_root = Path(tests.__file__).resolve().parent
    version = importlib.metadata.version("pkcs11-check")
    if version != "0.2.3":
        raise ValueError(f"checker version mismatch: {version!r}")
    checkout = args.get("checker_src")
    if checkout:  # Windows host binding: installed tree equals the pinned checkout.
        src = Path(checkout)
        head = subprocess.run(
            ["git", "-C", str(src), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if head.returncode or head.stdout.strip() != SOURCE:
            raise ValueError("checker source checkout is not the pinned revision")
        for installed in sorted(installed_root.rglob("*.py")):
            rel = installed.relative_to(installed_root)
            candidate = src / "src" / "pkcs11_check" / "testcases" / rel
            if (
                not candidate.is_file()
                or candidate.read_bytes() != installed.read_bytes()
            ):
                raise ValueError(f"installed checker file differs from source: {rel}")
        identity = {
            "source_revision": SOURCE,
            "version": version,
            "installed_root": str(installed_root),
            "checkout": str(src),
            "binding": "installed-tree-matches-pinned-checkout",
        }
    else:  # Linux direct lane: the frozen image seal applies.
        from p11lab.checker import installed_identity

        identity = installed_identity()
        if Path(identity["installed_root"]).resolve() != installed_root:
            raise ValueError("checker seal root differs from this interpreter")
    sources = source_inventory(installed_root, nodes)
    output.mkdir(parents=True, exist_ok=False)
    try:
        output.chmod(0o700)
    except OSError:
        pass
    targets = [str(installed_root / node) for node in nodes]

    def secret(name):
        if name + "_FILE" in os.environ:
            return Path(os.environ[name + "_FILE"]).read_text().rstrip("\n")
        return os.environ[name]

    pin = secret("P11LAB_PIN")
    so_pin = secret("P11LAB_SO_PIN")
    # Token translation mirrors _main: exactly one token-present slot.
    from pkcs11_check.core.loader import load_module

    p11 = load_module(module, interface="auto")
    slots = p11.get_slots(token_present=True)
    selected = [
        (i, s.slot_id) for i, s in enumerate(slots) if s.get_token().label == label
    ]
    if len(selected) != 1:
        raise ValueError("token identity must select exactly one token-present slot")
    slot, native_id = selected[0]
    from pkcs11_check.raw.rv import expect_rv
    from pkcs11_check.raw.types_std import CKR_OK

    expect_rv(p11.raw.C_Finalize(None), CKR_OK)
    env = checker_environment(output, pin, so_pin)
    env["BOUNCY_HSM_CFG_STRING"] = transport
    env["PYTEST_ADDOPTS"] = "-v -p no:cacheprovider"
    prefix = [sys.executable, "-m", "pkcs11_check"]
    collect = subprocess.run(
        [*prefix, "list-tests", "--include-disabled", *targets],
        cwd=installed_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    (output / "collection.stdout.log").write_text(collect.stdout)
    (output / "collection.stderr.log").write_text(collect.stderr)
    collected = [canonical_node(n, installed_root) for n in collect.stdout.splitlines()]
    if (
        collect.returncode
        or len(collected) != len(targets)
        or set(collected) != set(targets)
    ):
        raise ValueError("installed collection differs from frozen selection")
    (output / "collection.json").write_text(
        json.dumps(
            {
                "nodes": nodes,
                "installed_nodes": collected,
                "returncode": collect.returncode,
            },
            indent=2,
        )
    )
    argv = [
        *prefix,
        "test",
        "--module",
        str(module),
        "--slot",
        str(slot),
        "--interface",
        "auto",
        "--isolation",
        "file",
        "--timeout",
        "180",
        "--ignore-disabled-tests",
        "--no-collection-cache",
        "--key-inject",
        "off",
        "--recover-mode",
        "off",
        "--output",
        "json",
        "--output-file",
        str(output / "results.json"),
        "--state-file",
        str(output / "state.json"),
        "--policy-file",
        str(output / "policy.json"),
        *targets,
    ]
    proc = subprocess.Popen(
        argv,
        cwd=installed_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=(os.name != "nt"),
    )
    logs = {}

    def drain(stream, name):
        retained = bytearray()
        truncated = False
        while chunk := stream.read(65536):
            room = 1024 * 1024 - len(retained)
            retained.extend(chunk[:room])
            truncated |= len(chunk) > room
        stream.close()
        if truncated and (pin or so_pin):
            trim = max(len(pin.encode()), len(so_pin.encode())) - 1
            if trim:
                del retained[-trim:]
        log = retained.decode("utf-8", "replace")
        for secret_value in sorted({pin, so_pin} - {""}, key=len, reverse=True):
            log = log.replace(secret_value, "[REDACTED]")
        if truncated:
            log += "\n[TRUNCATED]\n"
        logs[name] = truncated
        (output / name).write_text(log)

    readers = [
        threading.Thread(target=drain, args=(stream, name))
        for stream, name in (
            (proc.stdout, "checker.stdout.log"),
            (proc.stderr, "checker.stderr.log"),
        )
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        proc.wait(timeout=900)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                timeout=60,
            )
        else:
            import signal

            os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    capture_output=True,
                    timeout=60,
                )
            else:
                import signal

                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
    for reader in readers:
        reader.join(timeout=2)
    record = {
        "schema_version": 1,
        "attempt_id": uuid4().hex,
        "nodes": nodes,
        "sources": sources,
        "checker": identity,
        "slot_index": slot,
        "token": {
            "label": label,
            "native_slot_id": native_id,
            "token_present_index": slot,
        },
        "returncode": 124 if timed_out else proc.returncode,
        "timeout": timed_out,
        "logs_truncated": logs,
        "settings": {
            "interface": "auto",
            "isolation": "file",
            "timeout": 180,
            "key_inject": "off",
            "recover_mode": "off",
            "ignore_disabled_tests": True,
            "pytest_addopts": "-v -p no:cacheprovider",
        },
        "driver": "test_bouncyhsm.checker-driver mirrors frozen execute_checker; "
        "preserves BOUNCY_HSM_CFG_STRING (T6 env-scrub precedent); "
        "Windows supervision via taskkill on the owned tree",
    }
    write_receipt(output / "checker-receipt.json", record)
    assessment = validate_results(output, nodes, installed_root)
    record["evidence"] = assessment
    write_receipt(output / "checker-receipt.json", record)
    summary = assessment["summary"]
    return {
        "complete": assessment["complete"],
        "passed": summary["passed"],
        "failed": summary["failed"],
        "selected": len(nodes),
        "returncode": record["returncode"],
    }


def step_hold_ports(args, extra):
    """Bind and listen on two loopback ports until the deadline or release."""
    import socket

    ready = Path(args["ready"])
    deadline = time.monotonic() + int(args.get("seconds", "60"))
    servers = []
    for key in ("http", "tcp"):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", int(args[key])))
        server.listen(1)
        servers.append(server)
    ready.write_text("listening")
    try:
        while time.monotonic() < deadline:
            time.sleep(0.1)
    finally:
        for server in servers:
            server.close()
    return {"held": True}


_STEPS = {
    "install": step_install,
    "readback": step_readback,
    "run-app": step_run_app,
    "checker-driver": step_checker_driver,
    "hold-ports": step_hold_ports,
}


def _main(argv):
    if len(argv) < 2 or argv[1] not in _STEPS:
        print(
            "usage: test_bouncyhsm.py <install|readback|run-app|checker-driver|hold-ports> k=v... [-- ...]",
            file=sys.stderr,
        )
        return 2
    args: dict = {}
    extra: list = []
    rest = argv[2:]
    if "--" in rest:
        cut = rest.index("--")
        extra = rest[cut + 1 :]
        rest = rest[:cut]
    for item in rest:
        key, sep, value = item.partition("=")
        if not sep:
            print(f"bad argument: {item}", file=sys.stderr)
            return 2
        args[key] = value
    try:
        if argv[1] in ("run-app", "checker-driver", "hold-ports"):
            result = _STEPS[argv[1]](args, extra)
        else:
            result = _STEPS[argv[1]](args)
    except Exception as error:  # steps report, never traceback
        print(json.dumps({"ok": False, "error": f"{type(error).__name__}: {error}"}))
        return 1
    print(json.dumps({"ok": True, "result": result}))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))


# ---------------------------------------------------------------------------
# Pytest orchestration (env-gated lanes; skipped without explicit inputs).
# ---------------------------------------------------------------------------

CHANNELS = ("release", "rolling")


def _need(name):
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} is not set")
    return value


def _print_app_stderr(output_dir):
    """Surface the redacted application log tail on lane failure.

    The native/direct runners already redact provisioned secrets in these
    logs; without this the driver's report is discarded with tmp_path and
    a bare exit code is the only CI evidence.
    """
    err_log = Path(output_dir) / "application.stderr.log"
    if not err_log.is_file():
        print(f"no application.stderr.log under {output_dir}")
        return
    tail = err_log.read_text()[-4000:]
    print(f"--- application.stderr.log tail ({err_log}) ---\n{tail}")


def _write_pins(directory):
    pin = directory / "pin"
    so_pin = directory / "so-pin"
    pin.write_bytes(b"1234")
    so_pin.write_bytes(b"12345678")
    try:
        pin.chmod(0o600)
        so_pin.chmod(0o600)
    except OSError:
        pass
    return pin, so_pin


def _oracle(output_dir):
    completed = subprocess.run(
        [sys.executable, str(CONSUMER_DIR / "verify.py"), str(output_dir)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    assert "altered message rejected" in completed.stdout


def _openssl_version():
    completed = subprocess.run(
        ["openssl", "version"], capture_output=True, text=True, timeout=30
    )
    assert completed.returncode == 0
    return completed.stdout.strip()


class NativeLane:
    """Native step execution: in-process on Windows, Debian container on Linux."""

    def __init__(self, tmp_path):
        self.host_work = Path(tmp_path)
        self.tools = None
        self._holder = None
        if os.name == "nt":
            self.tools = Path(_need("P11LAB_TEST_BOUNCYHSM_TOOLS"))
            self.bundles = json.loads(_need("P11LAB_TEST_BOUNCYHSM_NATIVE"))
        else:
            self.image = _need("P11LAB_TEST_BOUNCYHSM_NATIVE_IMAGE")
            self.bundles = json.loads(_need("P11LAB_TEST_BOUNCYHSM_NATIVE"))
            self.bundles_host = Path(_need("P11LAB_TEST_BOUNCYHSM_NATIVE_DIR"))

    def smoke(self):
        if os.name == "nt":
            return str(self.tools / "p11lab-smoke.exe")
        return "/opt/t7/bin/p11lab-smoke"

    def provision(self):
        if os.name == "nt":
            return str(self.tools / "provision.exe")
        return "/opt/t7/bin/provision"

    def cpath(self, host_path):
        if os.name == "nt":
            return str(Path(host_path))
        return "/work/" + Path(host_path).relative_to(self.host_work).as_posix()

    def bundle_args(self, channel):
        entry = self.bundles[channel]
        if os.name == "nt":
            return {"archive": entry["archive"], "sha256": entry["sha256"]}
        return {
            "archive": "/bundles/" + Path(entry["archive"]).name,
            "sha256": entry["sha256"],
        }

    def run_step(self, step, args, extra=(), timeout=600):
        if os.name == "nt":
            envelope = self._inline(step, args, extra)
        else:
            envelope = self._docker(step, args, extra, timeout)
        assert envelope["ok"], envelope.get("error")
        return envelope["result"]

    def run_step_raw(self, step, args, extra=(), timeout=600):
        if os.name == "nt":
            return self._inline(step, args, extra)
        return self._docker(step, args, extra, timeout)

    def _inline(self, step, args, extra):
        try:
            if step in ("run-app", "checker-driver", "hold-ports"):
                result = _STEPS[step](dict(args), list(extra))
            else:
                result = _STEPS[step](dict(args))
        except Exception as error:
            return {"ok": False, "error": f"{type(error).__name__}: {error}"}
        return {"ok": True, "result": result}

    def _docker(self, step, args, extra, timeout):
        uid = os.getuid()
        gid = os.getgid()
        # A held-port check joins the holder's network namespace; every other
        # step keeps its own isolated loopback.
        network = f"container:{self._holder}" if self._holder else "none"
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            network,
            "--user",
            f"{uid}:{gid}",
            "--mount",
            f"type=bind,src={self.host_work},dst=/work",
            "--mount",
            f"type=bind,src={self.bundles_host},dst=/bundles,readonly",
            self.image,
            "python3",
            "/opt/t7/test_bouncyhsm.py",
            step,
            *[f"{k}={v}" for k, v in args.items()],
            *(["--", *extra] if extra else []),
        ]
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
        if completed.returncode not in (0, 1):
            raise AssertionError(
                f"step container failed: {completed.returncode}\n{completed.stdout}\n{completed.stderr}"
            )
        try:
            return json.loads(completed.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            raise AssertionError(
                f"step produced no envelope:\n{completed.stdout}\n{completed.stderr}"
            )

    def hold_ports(self, http, tcp, seconds=60):
        """Occupy two loopback ports; returns a releaser. Holder survives runs.

        Linux steps run one container per step, each with its own loopback,
        so the holder is a named container whose network namespace later
        steps join until release. The ready file proves the bind; a holder
        that dies before the check fails the refusal assertion itself.
        """
        ready = self.host_work / f"hold-{http}-{tcp}.ready"
        if os.name == "nt":
            proc = subprocess.Popen(
                [
                    *_step_python(),
                    "hold-ports",
                    f"http={http}",
                    f"tcp={tcp}",
                    f"seconds={seconds}",
                    f"ready={ready}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            def release():
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=30)

            deadline = time.monotonic() + 30
            while not ready.exists() and time.monotonic() < deadline:
                assert proc.poll() is None, "port holder exited early"
                time.sleep(0.1)
            assert ready.exists(), "port holder did not bind"
            return release
        assert self._holder is None, "one port holder at a time"
        uid = os.getuid()
        gid = os.getgid()
        name = f"p11lab-t7-hold-{os.getpid()}-{http}-{tcp}"
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)
        started = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "--network",
                "none",
                "--user",
                f"{uid}:{gid}",
                "--mount",
                f"type=bind,src={self.host_work},dst=/work",
                self.image,
                "python3",
                "/opt/t7/test_bouncyhsm.py",
                "hold-ports",
                f"http={http}",
                f"tcp={tcp}",
                f"seconds={seconds}",
                f"ready=/work/{ready.name}",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert started.returncode == 0, started.stderr

        def running():
            state = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return state.returncode == 0 and state.stdout.strip() == "true"

        deadline = time.monotonic() + 30
        while not ready.exists() and time.monotonic() < deadline:
            assert running(), "port holder exited early"
            time.sleep(0.1)
        assert ready.exists(), "port holder did not bind"
        self._holder = name

        def release():
            try:
                subprocess.run(
                    ["docker", "rm", "-f", name], capture_output=True, timeout=60
                )
            finally:
                self._holder = None

        return release


def _direct_images():
    return json.loads(_need("P11LAB_TEST_BOUNCYHSM_DIRECT"))


@pytest.mark.parametrize("channel", CHANNELS)
def test_direct_crypto_generated(tmp_path, channel):
    """Linux direct lane: provision, C consumer crypto, independent oracle."""
    from p11lab.models import ArtifactRef, RunSpec
    from p11lab.run import run_application

    images = _direct_images()
    pin, so_pin = _write_pins(tmp_path)
    caller = tmp_path / "caller"
    caller.mkdir()
    output = tmp_path / "output"
    image = images[channel]
    spec = RunSpec(
        "bouncyhsm",
        channel,
        "direct",
        ArtifactRef(
            "docker-local", image, image.removeprefix("sha256:"), "linux/amd64"
        ),
        "provider",
        None,
        None,
        (
            "p11lab-smoke",
            "--module",
            "/usr/local/lib/p11lab/libBouncyHsm.Pkcs11.so",
            "--token-label",
            "P11Lab",
            "--pin-file",
            "/run/p11lab-input/P11LAB_PIN_FILE",
            "--output",
            "/p11lab-output/smoke",
            "--key-mode",
            "generated",
        ),
        {"P11LAB_PIN_FILE": str(pin), "P11LAB_SO_PIN_FILE": str(so_pin)},
        output,
        caller,
        600,
    )
    result = run_application(spec)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    assert result.app_returncode == 0
    assert not result.lifecycle_errors and not result.cleanup_errors
    _oracle(output / "smoke")
    receipt = json.loads(Path(result.receipt_path).read_text())
    assert [s["phase"] for s in receipt["stages"]] == [
        "init",
        "ready",
        "application",
        "post-health",
    ]


def _phase(image, state, secrets, args, output=None, env=(), user=None):
    user = user or f"{os.getuid()}:{os.getgid()}"
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        user,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        f"/run/p11lab:rw,nosuid,nodev,uid={user.split(':')[0]},"
        f"gid={user.split(':')[1]},mode=0700",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "--mount",
        f"type=bind,src={state},dst=/var/lib/p11lab",
        "--mount",
        f"type=bind,src={secrets},dst=/run/secrets,readonly",
    ]
    for key, value in env:
        cmd += ["-e", f"{key}={value}"]
    if output is not None:
        cmd += ["--mount", f"type=bind,src={output},dst=/p11lab-output"]
    return _docker(*cmd[1:], image, *args, timeout=300)


@pytest.mark.parametrize('channel', CHANNELS)
@pytest.mark.parametrize('terminator', [b'', b'\n'])
def test_container_pin_json_round_trip(tmp_path, channel, terminator):
    image = _direct_images()[channel]
    state, secrets, output = tmp_path / 'state', tmp_path / 'secrets', tmp_path / 'output'
    for directory in (state, secrets, output):
        directory.mkdir()
    pin = 'quote"slash\\utf8\u00e4'.encode()
    (secrets / 'pin').write_bytes(pin + terminator)
    (secrets / 'so-pin').write_bytes(b'so"slash\\12345678' + terminator)
    # This C consumer explicitly takes raw bytes; provider files use text framing.
    (secrets / 'consumer-pin').write_bytes(pin)
    env = (('P11LAB_PIN_FILE', '/run/secrets/pin'), ('P11LAB_SO_PIN_FILE', '/run/secrets/so-pin'))
    initialized = _phase(image, state, secrets, ['init'], env=env)
    assert initialized.returncode == 0, initialized.stderr
    result = _phase(image, state, secrets, ['exec', '--', 'p11lab-smoke', '--module',
                    '/usr/local/lib/p11lab/libBouncyHsm.Pkcs11.so', '--token-label', 'P11Lab',
                    '--pin-file', '/run/secrets/consumer-pin', '--output', '/p11lab-output/smoke',
                    '--key-mode', 'generated'], output=output, env=env)
    assert result.returncode == 0, result.stderr
    _oracle(output / 'smoke')


def test_direct_existing_key_persistence(tmp_path):
    """Linux direct lane: persistent token object survives container restarts."""
    images = _direct_images()
    image = images["release"]
    state = tmp_path / "state"
    state.mkdir()
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "pin").write_bytes(b"1234")
    (secrets / "so-pin").write_bytes(b"12345678")
    env = (
        ("P11LAB_PIN_FILE", "/run/secrets/pin"),
        ("P11LAB_SO_PIN_FILE", "/run/secrets/so-pin"),
    )
    completed = _phase(image, state, secrets, ["init"], env=env)
    assert completed.returncode == 0, completed.stderr
    completed = _phase(
        image,
        state,
        secrets,
        [
            "exec",
            "--",
            "provision",
            "--module",
            "/usr/local/lib/p11lab/libBouncyHsm.Pkcs11.so",
            "--token-label",
            "P11Lab",
            "--pin-file",
            "/run/secrets/pin",
            "--key-id",
            "42",
        ],
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    pubs = []
    for attempt in ("first", "second"):
        out = tmp_path / f"out-{attempt}"
        out.mkdir()
        completed = _phase(
            image,
            state,
            secrets,
            [
                "exec",
                "--",
                "p11lab-smoke",
                "--module",
                "/usr/local/lib/p11lab/libBouncyHsm.Pkcs11.so",
                "--token-label",
                "P11Lab",
                "--pin-file",
                "/run/secrets/pin",
                "--output",
                "/p11lab-output/smoke",
                "--key-mode",
                "existing",
                "--key-id",
                "42",
            ],
            output=out,
            env=env,
        )
        assert completed.returncode == 0, completed.stderr
        _oracle(out / "smoke")
        pubs.append((out / "smoke" / "public-key.der").read_bytes())
    assert pubs[0] == pubs[1] and len(pubs[0]) == 91
    completed = _phase(image, state, secrets, ["health"])
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("channel", CHANNELS)
def test_proxy_crypto_container(tmp_path, channel):
    """Linux proxy/container lane: shim transport, C crypto, oracle."""
    from p11lab.models import ArtifactRef, RunSpec
    from p11lab.run import run_application

    daemons = json.loads(_need("P11LAB_TEST_BOUNCYHSM_PROXY"))
    caller_image = _need("P11LAB_TEST_BOUNCYHSM_CALLER")
    clients = json.loads(_need("P11LAB_TEST_BOUNCYHSM_CLIENTS"))
    pin, so_pin = _write_pins(tmp_path)
    caller = tmp_path / "caller"
    caller.mkdir()
    output = tmp_path / "output"
    daemon = daemons[channel]
    bundle = Path(clients[channel])
    spec = RunSpec(
        "bouncyhsm",
        channel,
        "proxy",
        ArtifactRef(
            "docker-local", daemon, daemon.removeprefix("sha256:"), "linux/amd64"
        ),
        "container",
        ArtifactRef(
            "docker-local",
            caller_image,
            caller_image.removeprefix("sha256:"),
            "linux/amd64",
        ),
        ArtifactRef(
            "bundle",
            str(bundle),
            hashlib.sha256(bundle.read_bytes()).hexdigest(),
            "linux/amd64",
        ),
        (
            "/usr/local/bin/p11lab-smoke",
            "--module",
            "/run/p11lab-client/libpkcs11_proxy_ng_shim.so",
            "--token-label",
            "P11Lab",
            "--pin-file",
            "/run/p11lab-input/P11LAB_PIN_FILE",
            "--output",
            "/p11lab-output/smoke",
            "--key-mode",
            "generated",
        ),
        {"P11LAB_PIN_FILE": str(pin), "P11LAB_SO_PIN_FILE": str(so_pin)},
        output,
        caller,
        600,
    )
    result = run_application(spec)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    assert result.app_returncode == 0
    _oracle(output / "smoke")


def test_proxy_crypto_host(tmp_path):
    """Linux proxy/host lane: host consumer through the shim transport."""
    from p11lab.models import ArtifactRef, RunSpec
    from p11lab.run import run_application

    daemons = json.loads(_need("P11LAB_TEST_BOUNCYHSM_PROXY"))
    clients = json.loads(_need("P11LAB_TEST_BOUNCYHSM_CLIENTS"))
    pin, so_pin = _write_pins(tmp_path)
    caller = tmp_path / "caller"
    caller.mkdir()
    output = tmp_path / "output"
    host_bin = Path(_need("P11LAB_TEST_BOUNCYHSM_HOST_SMOKE"))
    daemon = daemons["release"]
    bundle = Path(clients["release"])
    # The runner hands the installed shim to host apps via P11LAB_SHIM; the
    # wrapper resolves it (T6 host convention), keeping argv literal.
    script = (
        'exec "$0" --module "$P11LAB_SHIM" --token-label P11Lab '
        '--pin-file "$1" --output "$P11LAB_OUTPUT_DIR/smoke" '
        "--key-mode generated"
    )
    spec = RunSpec(
        "bouncyhsm",
        "release",
        "proxy",
        ArtifactRef(
            "docker-local", daemon, daemon.removeprefix("sha256:"), "linux/amd64"
        ),
        "host",
        None,
        ArtifactRef(
            "bundle",
            str(bundle),
            hashlib.sha256(bundle.read_bytes()).hexdigest(),
            "linux/amd64",
        ),
        ("sh", "-c", script, str(host_bin), str(pin)),
        {"P11LAB_PIN_FILE": str(pin), "P11LAB_SO_PIN_FILE": str(so_pin)},
        output,
        caller,
        600,
    )
    result = run_application(spec)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    _oracle(output / "smoke")


def test_direct_lifecycle_negatives(tmp_path):
    """Linux direct lane: partial state, credential conflict, label mismatch."""
    images = _direct_images()
    image = images["release"]
    # Partial state refuses initialization.
    state = tmp_path / "partial"
    state.mkdir()
    (state / "junk").write_text("foreign")
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "pin").write_bytes(b"1234")
    (secrets / "so-pin").write_bytes(b"12345678")
    completed = _phase(
        image,
        state,
        secrets,
        ["init"],
        env=(
            ("P11LAB_PIN_FILE", "/run/secrets/pin"),
            ("P11LAB_SO_PIN_FILE", "/run/secrets/so-pin"),
        ),
    )
    assert completed.returncode == 1
    assert "partial state" in completed.stderr
    # Conflicting scalar/file credentials fail before provisioning.
    state2 = tmp_path / "conflict"
    state2.mkdir()
    completed = _phase(
        image,
        state2,
        secrets,
        ["init"],
        env=(
            ("P11LAB_PIN", "1234"),
            ("P11LAB_PIN_FILE", "/run/secrets/pin"),
            ("P11LAB_SO_PIN_FILE", "/run/secrets/so-pin"),
        ),
    )
    assert completed.returncode == 1
    assert "conflicting" in completed.stderr
    # An initialized token refuses a mismatched label without reset.
    state3 = tmp_path / "labeled"
    state3.mkdir()
    completed = _phase(
        image,
        state3,
        secrets,
        ["init"],
        env=(
            ("P11LAB_PIN_FILE", "/run/secrets/pin"),
            ("P11LAB_SO_PIN_FILE", "/run/secrets/so-pin"),
        ),
    )
    assert completed.returncode == 0, completed.stderr
    before = {str(p.relative_to(state3)): p.read_bytes() for p in state3.rglob('*') if p.is_file()}
    completed = _phase(
        image,
        state3,
        secrets,
        ["init"],
        env=(
            ("P11LAB_LABEL", "Other"),
            ("P11LAB_PIN_FILE", "/run/secrets/pin"),
            ("P11LAB_SO_PIN_FILE", "/run/secrets/so-pin"),
        ),
    )
    assert completed.returncode == 1
    assert "incompatible non-secret initialization configuration" in completed.stderr
    assert {str(p.relative_to(state3)): p.read_bytes() for p in state3.rglob('*') if p.is_file()} == before
    assert (state3 / "bouncyhsm" / "complete").read_text().splitlines()[
        3
    ] == "label=P11Lab"


@pytest.mark.parametrize("channel", CHANNELS)
def test_native_install_readback(tmp_path, channel):
    """Native install plus readback; platform bundle identity is exact."""
    lane = NativeLane(tmp_path)
    prefix = tmp_path / "prefix"
    args = lane.bundle_args(channel) | {
        "prefix": lane.cpath(prefix),
        "channel": channel,
        "platform": "windows/amd64" if os.name == "nt" else "linux/amd64",
    }
    installed = lane.run_step("install", args)
    assert installed["target"] == (
        "windows-amd64" if os.name == "nt" else "debian13-amd64"
    )
    assert installed["module"].endswith(
        "BouncyHsm.Pkcs11Lib.dll" if os.name == "nt" else "libBouncyHsm.Pkcs11.so"
    )
    assert installed["host"]["module_load"].startswith("version=")
    readback = lane.run_step("readback", args)
    assert readback["manifest_sha256"] == installed["manifest_sha256"]
    # A changed payload is rejected before any provisioning.
    module = prefix / "payload" / installed["module"].replace("/", os.sep)
    module.write_bytes(b"tampered-by-test")
    envelope = lane.run_step_raw("readback", args)
    assert not envelope["ok"]
    assert "mismatch" in envelope["error"], envelope


@pytest.mark.parametrize("channel", CHANNELS)
def test_native_crypto_persistence(tmp_path, channel):
    """Native crypto, persistent key reuse across restarts, no-creds reuse."""
    lane = NativeLane(tmp_path)
    pin, so_pin = _write_pins(tmp_path)
    prefix = tmp_path / "prefix"
    base = lane.bundle_args(channel) | {
        "prefix": lane.cpath(prefix),
        "channel": channel,
        "platform": "windows/amd64" if os.name == "nt" else "linux/amd64",
    }
    lane.run_step("install", base)
    state = tmp_path / "token state"
    state.mkdir()
    common = {
        "prefix": lane.cpath(prefix),
        "channel": channel,
        "platform": base["platform"],
        **lane.bundle_args(channel),
        "cwd": lane.cpath(tmp_path),
        "P11LAB_STATE_DIR": lane.cpath(state),
        "P11LAB_PIN_FILE": lane.cpath(pin),
        "P11LAB_SO_PIN_FILE": lane.cpath(so_pin),
    }
    module = (
        prefix
        / "payload"
        / (
            "bin/BouncyHsm.Pkcs11Lib.dll"
            if os.name == "nt"
            else "lib/libBouncyHsm.Pkcs11.so"
        ).replace("/", os.sep)
    )
    # Run 1 provisions the slot and a persistent key.
    out1 = tmp_path / "out 1"
    result = lane.run_step(
        "run-app",
        common | {"output": lane.cpath(out1)},
        [
            lane.provision(),
            "--module",
            lane.cpath(module),
            "--token-label",
            "P11Lab",
            "--pin-file",
            lane.cpath(pin),
            "--key-id",
            "42",
        ],
    )
    assert result["exit_code"] == 0, result
    assert result["stages"] == [
        "server-start",
        "init-probe",
        "init",
        "ready-probe",
        "ready",
        "application",
        "post-health-probe",
        "post-health",
        "server-stop",
    ]
    assert result["native_probes"] == {
        "init-probe": {"slots": 0, "present": 0},
        "ready-probe": {"slots": 1, "present": 1},
        "post-health-probe": {"slots": 1, "present": 1},
    }
    assert result["slot"] == 1
    # Runs 2 and 3 reuse the persistent key across restarts; run 3 has no creds.
    pubs = []
    for index, with_creds in ((2, True), (3, False)):
        out = tmp_path / f"out {index}"
        smoke_out = lane.cpath(out / "smoke")
        step_args = common | {"output": lane.cpath(out)}
        if not with_creds:
            step_args.pop("P11LAB_PIN_FILE")
            step_args.pop("P11LAB_SO_PIN_FILE")
        result = lane.run_step(
            "run-app",
            step_args,
            [
                lane.smoke(),
                "--module",
                lane.cpath(module),
                "--token-label",
                "P11Lab",
                "--pin-file",
                lane.cpath(pin),
                "--output",
                smoke_out,
                "--key-mode",
                "existing",
                "--key-id",
                "42",
            ],
        )
        assert result["exit_code"] == 0, result
        assert result["slot"] == 1
        assert result["native_probes"] == {
            phase: {"slots": 1, "present": 1}
            for phase in ("init-probe", "ready-probe", "post-health-probe")
        }
        _oracle(out / "smoke")
        pubs.append((out / "smoke" / "public-key.der").read_bytes())
    assert pubs[0] == pubs[1] and len(pubs[0]) == 91
    print(f"openssl oracle: {_openssl_version()}")


def test_native_ports_and_cleanup(tmp_path):
    """Per-instance ports, occupied refusal, spaces paths, owned cleanup."""
    import threading

    lane = NativeLane(tmp_path)
    pin, so_pin = _write_pins(tmp_path)
    prefix = tmp_path / "prefix with spaces"
    base = lane.bundle_args("release") | {
        "prefix": lane.cpath(prefix),
        "channel": "release",
        "platform": "windows/amd64" if os.name == "nt" else "linux/amd64",
    }
    lane.run_step("install", base)
    module = (
        prefix
        / "payload"
        / (
            "bin/BouncyHsm.Pkcs11Lib.dll"
            if os.name == "nt"
            else "lib/libBouncyHsm.Pkcs11.so"
        ).replace("/", os.sep)
    )

    def crypto_run(name, http, tcp, state):
        out = tmp_path / name
        return lane.run_step(
            "run-app",
            {
                **lane.bundle_args("release"),
                "prefix": lane.cpath(prefix),
                "channel": "release",
                "platform": base["platform"],
                "cwd": lane.cpath(tmp_path),
                "output": lane.cpath(out),
                "P11LAB_STATE_DIR": lane.cpath(state),
                "P11LAB_HTTP_PORT": str(http),
                "P11LAB_TCP_PORT": str(tcp),
                "P11LAB_PIN_FILE": lane.cpath(pin),
                "P11LAB_SO_PIN_FILE": lane.cpath(so_pin),
            },
            [
                lane.smoke(),
                "--module",
                lane.cpath(module),
                "--token-label",
                "P11Lab",
                "--pin-file",
                lane.cpath(pin),
                "--output",
                lane.cpath(out / "smoke"),
                "--key-mode",
                "generated",
            ],
        )

    # Two simultaneous instances on distinct ports and state dirs.
    states = [tmp_path / "a state", tmp_path / "b state"]
    for state in states:
        state.mkdir()
    results = {}
    errors = {}

    def worker(index, http, tcp):
        try:
            results[index] = crypto_run(f"sim {index}", http, tcp, states[index])
        except Exception as error:  # report, never hang the suite
            errors[index] = error

    threads = [
        threading.Thread(target=worker, args=(0, 18081, 18771)),
        threading.Thread(target=worker, args=(1, 18082, 18772)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=600)
    assert not errors, errors
    assert all(t.is_alive() is False for t in threads)
    for index in (0, 1):
        assert results[index]["exit_code"] == 0, results[index]
        _oracle(tmp_path / f"sim {index}" / "smoke")
    # An occupied fixed port is refused instead of attached to.
    release = lane.hold_ports(18083, 18773, seconds=120)
    try:
        envelope = lane.run_step_raw(
            "run-app",
            {
                **lane.bundle_args("release"),
                "prefix": lane.cpath(prefix),
                "channel": "release",
                "platform": base["platform"],
                "cwd": lane.cpath(tmp_path),
                "output": lane.cpath(tmp_path / "occupied"),
                "P11LAB_STATE_DIR": lane.cpath(tmp_path / "a state"),
                "P11LAB_HTTP_PORT": "18083",
                "P11LAB_TCP_PORT": "18773",
                "P11LAB_PIN_FILE": lane.cpath(pin),
                "P11LAB_SO_PIN_FILE": lane.cpath(so_pin),
            },
            [
                lane.smoke(),
                "--module",
                lane.cpath(module),
                "--token-label",
                "P11Lab",
                "--pin-file",
                lane.cpath(pin),
                "--output",
                lane.cpath(tmp_path / "occupied" / "smoke"),
                "--key-mode",
                "generated",
            ],
        )
        assert not envelope["ok"], envelope
        assert "occupied" in envelope["error"], envelope
        assert not (tmp_path / "occupied").exists()
    finally:
        release()
    # Ports are released: the same fixed ports run cleanly afterwards.
    state2 = tmp_path / "c state"
    state2.mkdir()
    result = crypto_run("reuse ports", 18083, 18773, state2)
    assert result["exit_code"] == 0, result
    _oracle(tmp_path / "reuse ports" / "smoke")


@pytest.mark.parametrize("channel", CHANNELS)
def test_direct_checker_smoke(tmp_path, channel):
    """Linux direct checker lane: frozen smoke profile through the driver."""
    from p11lab.run import run_application
    from p11lab.models import ArtifactRef, RunSpec

    images = json.loads(_need("P11LAB_TEST_BOUNCYHSM_CHECKER"))
    pin, so_pin = _write_pins(tmp_path)
    caller = tmp_path / "caller"
    caller.mkdir()
    shutil.copy(Path(__file__).resolve(), caller / "test_bouncyhsm.py")
    output = tmp_path / "output"
    image = images[channel]
    spec = RunSpec(
        "bouncyhsm",
        channel,
        "direct",
        ArtifactRef(
            "docker-local", image, image.removeprefix("sha256:"), "linux/amd64"
        ),
        "provider",
        None,
        None,
        (
            "/opt/p11lab-checker/bin/python",
            "/workspace/test_bouncyhsm.py",
            "checker-driver",
            "output=/p11lab-output/checker",
        ),
        {"P11LAB_PIN_FILE": str(pin), "P11LAB_SO_PIN_FILE": str(so_pin)},
        output,
        caller,
        1500,
    )
    result = run_application(spec)
    if result.exit_code != 0:
        _print_app_stderr(output)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    record = json.loads((output / "checker" / "checker-receipt.json").read_text())
    assert record["evidence"]["complete"] is True, record["evidence"]
    summary = record["evidence"]["summary"]
    print(
        f"checker direct/{channel}: passed={summary['passed']} "
        f"failed={summary['failed']}"
    )


@pytest.mark.parametrize("channel", CHANNELS)
def test_native_checker_smoke(tmp_path, channel):
    """Native checker lane: frozen smoke profile through the driver."""
    if os.name != "nt":
        pytest.skip("native checker lane runs on Windows; Linux uses the direct lane")
    lane = NativeLane(tmp_path)
    pin, so_pin = _write_pins(tmp_path)
    prefix = tmp_path / "prefix"
    base = lane.bundle_args(channel) | {
        "prefix": lane.cpath(prefix),
        "channel": channel,
        "platform": "windows/amd64" if os.name == "nt" else "linux/amd64",
    }
    lane.run_step("install", base)
    state = tmp_path / "checker state"
    state.mkdir()
    out = tmp_path / "checker out"
    driver = [sys.executable, str(Path(__file__).resolve()), "checker-driver"]
    driver_args = {"output": lane.cpath(out / "checker")}
    if os.name == "nt":
        driver_args["checker_src"] = _need("P11LAB_TEST_CHECKER_SRC")
    result = lane.run_step(
        "run-app",
        {
            **lane.bundle_args(channel),
            "prefix": lane.cpath(prefix),
            "channel": channel,
            "platform": base["platform"],
            "cwd": lane.cpath(tmp_path),
            "output": lane.cpath(out),
            "P11LAB_STATE_DIR": lane.cpath(state),
            "P11LAB_PIN_FILE": lane.cpath(pin),
            "P11LAB_SO_PIN_FILE": lane.cpath(so_pin),
            "timeout": "1500",
        },
        [*driver, *[f"{k}={v}" for k, v in driver_args.items()]],
        timeout=1600,
    )
    if result["exit_code"] != 0:
        _print_app_stderr(out)
    assert result["exit_code"] == 0, result
    record = json.loads((out / "checker" / "checker-receipt.json").read_text())
    assert record["evidence"]["complete"] is True, record["evidence"]
    summary = record["evidence"]["summary"]
    print(
        f"checker native/{channel}: passed={summary['passed']} "
        f"failed={summary['failed']}"
    )
