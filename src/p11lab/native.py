"""Selected Debian SoftHSM bundles, system-runtime preflight and native lifecycle."""

from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import threading
import time
from uuid import uuid4

from .bundle import (
    InstalledBundle,
    inspect_bundle,
    install_bundle,
    read_installation,
    validate_writable_paths,
)
from .catalog import load_native_target, packaged_asset, package_data
from .identity import artifact_key, public_identity
from .models import ArtifactRef, RunSpec, RunResult
from .receipts import write_receipt
from .sources import checksum
from .secrets import credential_text, snapshot_credentials
from .process import SupervisedProcess, bounded_redacted, supervised_exec, write_process_logs

TARGET = "debian13-amd64"
MODULE = "lib/libsofthsm2.so"
UTILITY = "bin/softhsm2-util"
ADAPTER = "bin/p11lab-provider"

# Native-client role (proxy shim/CLI bundle). Provider N2 behavior above is
# unchanged. Client bundles are proxy-versioned, not provider-versioned; the
# environment/channel select and namespace the bundle for run verification.
CLIENT_TARGET = "debian13-amd64"
CLIENT_MODULE = "lib/libpkcs11_proxy_ng_shim.so"
CLIENT_CLI = "bin/pkcs11-proxy-ng-cli"
CLIENT_HOST_REQUIREMENTS = {
    "os": "debian",
    "major_version": "13",
    "architecture": "x86_64",
    "platform": "linux/amd64",
    "loader": "/lib64/ld-linux-x86-64.so.2",
    "packages": ["libc6", "libgcc-s1"],
    "symbol_floors": {"GLIBC": "2.34"},
}


def _selection(environment, channel, platform):
    return dict(environment=environment, channel=channel, platform=platform)


def build_native_bundle(spec: dict, output_dir: Path) -> ArtifactRef:
    """Export only sealed shipped bytes from the frozen notice-only parent.

    Docker is a build-time byte acquisition tool, never a native consumer runtime.
    No source selector resolution, stripping, linking or SoftHSM rebuild occurs.
    """
    spec = load_native_target(
        spec["id"], spec["channel"], spec.get("native_target", TARGET)
    )
    lock = spec["native_lock"]
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    parent = lock["parent"]
    observation = json.loads(
        subprocess.run(
            ["docker", "image", "inspect", parent["reference"]],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout
    )[0]
    if (
        observation["Id"] != parent["reference"]
        or observation["Os"] + "/" + observation["Architecture"] != lock["platform"]
    ):
        raise ValueError("frozen native parent identity/platform mismatch")
    recipe = json.loads(packaged_asset(spec["id"], "native.recipe.json").read_text())
    expected = recipe["export"]
    exported = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--entrypoint",
            "tar",
            parent["reference"],
            "-C",
            "/",
            "-cf",
            "-",
            *expected.values(),
        ],
        capture_output=True,
        check=True,
        timeout=60,
    ).stdout
    (output_dir / "selected-files.tar").write_bytes(exported)
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(exported)) as archive:
        members = archive.getmembers()
        if (
            {m.name for m in members} != set(expected.values())
            or len(members) != len(expected)
            or any(not m.isfile() for m in members)
        ):
            raise ValueError("native export roster/type mismatch")
        for destination, source in expected.items():
            contents[destination] = archive.extractfile(source).read()
    for binary in lock["binaries"]:
        if hashlib.sha256(contents[binary["path"]]).hexdigest() != binary["sha256"]:
            raise ValueError("native provider bytes differ from sealed staging")
    evidence = lock["sources"][0]["license_evidence"][0]
    if (
        hashlib.sha256(contents["share/licenses/softhsm2/LICENSE"]).hexdigest()
        != evidence["sha256"]
    ):
        raise ValueError("upstream license bytes mismatch")
    inputs = {
        "sources": lock["sources"],
        "binaries": lock["binaries"],
        "dependencies": [],
        "toolchain": lock["toolchain"],
        "recipe": hashlib.sha256(
            json.dumps(
                {
                    "mapping": checksum(
                        packaged_asset(spec["id"], "native.recipe.json")
                    ),
                    "implementation": checksum(Path(__file__)),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest(),
        "platform": lock["platform"],
        "features": {
            "target": TARGET,
            "patches": lock["patches"],
            "compilation": lock["compilation"],
            "assets": lock["assets"],
            "target_lock_sha256": hashlib.sha256(
                packaged_asset(
                    spec["id"],
                    spec["native_target_spec"]["channels"][spec["channel"]]["lock"],
                ).read_bytes()
            ).hexdigest(),
            "host_requirements": lock["host_requirements"],
            "payload_assets": {
                name: hashlib.sha256(data).hexdigest()
                for name, data in {
                    "common.sh": package_data("runtime/common.sh").read_bytes(),
                    "provider.json": packaged_asset(
                        spec["id"], "provider.json"
                    ).read_bytes(),
                    "LICENSE": package_data("runtime/LICENSE").read_bytes(),
                }.items()
            },
        },
    }
    key = artifact_key("native", inputs)
    contents.update(
        {
            ADAPTER: packaged_asset(spec["id"], "native.sh").read_bytes(),
            "share/licenses/softhsm2/FILE-NOTICES.txt": packaged_asset(
                spec["id"], spec["channel"] + ".native-notices.txt"
            ).read_bytes(),
            "share/p11lab/common.sh": package_data("runtime/common.sh").read_bytes(),
            "share/p11lab/native-id": (key + "\n").encode(),
            "share/p11lab/provider.json": packaged_asset(
                spec["id"], "provider.json"
            ).read_bytes(),
            "share/licenses/p11lab/LICENSE": package_data(
                "runtime/LICENSE"
            ).read_bytes(),
            "share/p11lab/THIRD-PARTY-NOTICES.txt": b"P11Lab native adapter: Apache-2.0. SoftHSMv2: BSD-2-Clause; see share/licenses/softhsm2/LICENSE. Host runtime packages are prerequisites, not redistributed. Source and patch identities are recorded in manifest.json. Public admission is a separate artifact-bound gate.\n",
        }
    )
    roster = [
        {
            "path": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "mode": 0o755 if name.startswith("bin/") else 0o644,
            "role": "module"
            if name == MODULE
            else "utility"
            if name == UTILITY
            else "adapter"
            if name == ADAPTER
            else "notice",
        }
        for name, data in sorted(contents.items())
    ]
    manifest = {
        "schema_version": 1,
        "role": "native-runtime",
        "environment": spec["id"],
        "channel": spec["channel"],
        "platform": lock["platform"],
        "target": TARGET,
        "module": MODULE,
        "lifecycle": {"adapter": ADAPTER},
        "source": {
            "sources": lock["sources"],
            "patches": lock["patches"],
            "notice_provenance": lock["notice_provenance"],
        },
        "build": {"key": key, "identity": public_identity("native", inputs)},
        "host_requirements": lock["host_requirements"],
        "tested_prerequisites": lock["tested_prerequisites"],
        "licenses": [
            "share/licenses/softhsm2/LICENSE",
            "share/licenses/p11lab/LICENSE",
            "share/licenses/softhsm2/FILE-NOTICES.txt",
        ],
        "source_references": [
            {"parent": parent, "source_companion": lock["source_companion"]}
        ],
        "files": roster,
        "admission": "unreviewed; native actual-content admission is separate from container admission",
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    archive_path = output_dir / "softhsm2-native.tar.gz"
    # Fixed tar headers and gzip timestamp; native identity includes all packaged bytes.
    import gzip

    with (
        archive_path.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped,
        tarfile.open(fileobj=zipped, mode="w") as archive,
    ):
        for name, data, mode in [
            ("manifest.json", manifest_bytes, 0o644),
            *[("payload/" + r["path"], contents[r["path"]], r["mode"]) for r in roster],
        ]:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = mode
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
    artifact = ArtifactRef(
        "bundle", str(archive_path), checksum(archive_path), lock["platform"]
    )
    inspect_bundle(
        artifact, **_selection(spec["id"], spec["channel"], lock["platform"])
    )
    write_receipt(
        output_dir / "artifact.json",
        {
            "schema_version": 1,
            "artifact": asdict(artifact),
            "build_key": key,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "parent": parent,
            "source_companion": lock["source_companion"],
            "payload_bytes": sum(r["size"] for r in roster),
            "archive_bytes": archive_path.stat().st_size,
            "files": roster,
            "admission": "unreviewed",
        },
    )
    (output_dir / "manifest.json").write_bytes(manifest_bytes)
    (output_dir / "parent-inspect.json").write_text(
        json.dumps(observation, indent=2) + "\n"
    )
    return artifact


def _validate_manifest(manifest, environment, channel):
    target = load_native_target(environment, channel, TARGET)
    lock = target["native_lock"]
    if (
        manifest.get("target") != TARGET
        or manifest.get("role") != "native-runtime"
        or manifest.get("host_requirements") != lock["host_requirements"]
        or manifest.get("module") != MODULE
        or manifest.get("lifecycle") != {"adapter": ADAPTER}
    ):
        raise ValueError(
            "native manifest does not match selected target/host requirements"
        )
    return target


def preflight_native(prefix: Path, manifest: dict) -> dict:
    """Use the Debian system loader to verify both ELFs, including symbol versions."""
    release = platform.freedesktop_os_release()
    if (
        platform.system() != "Linux"
        or platform.machine() != "x86_64"
        or release.get("ID") != "debian"
        or release.get("VERSION_ID", "").split(".")[0] != "13"
    ):
        raise ValueError("native SoftHSM requires Debian 13 amd64 (debian13-amd64)")
    closure = {}
    for relative in (MODULE, UTILITY):
        binary = prefix / "payload" / relative
        result = subprocess.run(
            ["/lib64/ld-linux-x86-64.so.2", "--list", str(binary)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode or "not found" in result.stdout + result.stderr:
            raise ValueError(
                "missing or incompatible native runtime prerequisite: "
                + relative
                + "; "
                + result.stderr.strip()
            )
        resolved = []
        for line in result.stdout.splitlines():
            fields = line.split()
            name = (
                fields[2]
                if len(fields) > 2 and fields[1] == "=>"
                else fields[0]
                if fields
                else ""
            )
            if name.startswith("/"):
                path = Path(name).resolve()
                resolved.append({"path": str(path), "sha256": checksum(path)})
        closure[relative] = {"loader_output": result.stdout, "resolved": resolved}
    version = subprocess.run(
        [str(prefix / "payload" / UTILITY), "--version"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if version.returncode:
        raise ValueError("native utility launch failed")
    packages = subprocess.run(
        [
            "dpkg-query",
            "-W",
            "-f=${Package}\t${Version}\t${Architecture}\n",
            *manifest["host_requirements"]["packages"],
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if packages.returncode:
        raise ValueError("declared Debian runtime package prerequisites absent")
    return {
        "os_release": release,
        "architecture": platform.machine(),
        "closure": closure,
        "packages": packages.stdout,
        "utility_version": version.stdout.strip(),
    }


def staging_parent(path: Path) -> Path:
    """Use the destination filesystem for executable preflight, including noexec /tmp hosts."""
    parent = Path(path).resolve().parent
    while not parent.exists():
        parent = parent.parent
    return parent


def install_native_bundle(
    artifact: ArtifactRef, prefix: Path, *, environment: str, channel: str
) -> InstalledBundle:
    selection = _selection(environment, channel, artifact.platform)
    manifest = inspect_bundle(artifact, **selection)
    _validate_manifest(manifest, environment, channel)
    # Inert N1 extraction into private temporary placement; no manifest-chosen script.
    # Host preflight precedes creation of the user's requested prefix or ancestors.
    with tempfile.TemporaryDirectory(
        prefix=".p11lab-native-preflight-", dir=staging_parent(prefix)
    ) as temporary:
        staged = install_bundle(artifact, Path(temporary) / "prefix", **selection)
        preflight_native(staged.prefix, manifest)
    return install_bundle(artifact, prefix, **selection)


def run_native_softhsm(spec: RunSpec, installed: InstalledBundle) -> RunResult:
    """Reverify original provenance and installed payload before any native action."""
    if (
        spec.mode != "native"
        or spec.execution_location != "host"
        or spec.consumer_artifact
        or spec.client_artifact
    ):
        raise ValueError(
            "native requires host execution without consumer/client container options"
        )
    if spec.artifact != installed.artifact:
        raise ValueError("run artifact differs from installed artifact")
    if (
        spec.installed_prefix is not None
        and spec.installed_prefix.resolve() != installed.prefix.resolve()
    ):
        raise ValueError("run installed prefix differs from selected installation")
    if (
        spec.artifact.platform != "linux/amd64"
        or not spec.argv
        or any(not isinstance(a, str) or "\0" in a for a in spec.argv)
    ):
        raise ValueError("native requires linux/amd64 and literal application argv")
    if spec.timeout_seconds <= 0 or not spec.cwd.is_dir() or spec.output_dir.exists():
        raise ValueError(
            "positive timeout, caller cwd and fresh output directory required"
        )
    installed = read_installation(
        installed.prefix,
        **_selection(spec.environment, spec.channel, spec.artifact.platform),
    )
    if installed.artifact != spec.artifact:
        raise ValueError("verified receipt artifact differs from run artifact")
    descriptor = _validate_manifest(installed.manifest, spec.environment, spec.channel)
    unknown = (
        set(spec.inputs)
        - set(descriptor["inputs"])
        - {"P11LAB_STATE_DIR", "P11LAB_CONTROL_DIR"}
    )
    if unknown or any(
        not isinstance(v, str) or any(c in v for c in "\n\r\0")
        for v in spec.inputs.values()
    ):
        raise ValueError("native inputs must be allowlisted single-line strings")
    for name in ("P11LAB_PIN", "P11LAB_SO_PIN"):
        if name in spec.inputs and name + "_FILE" in spec.inputs:
            raise ValueError("conflicting scalar/file credential inputs")
    output = spec.output_dir.resolve()
    cwd = spec.cwd.resolve()
    state = Path(spec.inputs.get("P11LAB_STATE_DIR", str(output / "state"))).resolve()
    control = Path(
        spec.inputs.get("P11LAB_CONTROL_DIR", str(output / "control"))
    ).resolve()
    validate_writable_paths(installed.prefix, (state, control, output))
    if (
        state == control
        or state.is_relative_to(control)
        or control.is_relative_to(state)
    ):
        raise ValueError("state and control paths overlap")
    if any(
        "#" in str(p) or any(c in str(p) for c in "\n\r\0")
        for p in (installed.prefix, state, control)
    ):
        raise ValueError("path cannot be represented in SoftHSM configuration")
    if "P11LAB_STATE_DIR" in spec.inputs and not state.is_dir():
        raise ValueError("explicit persistent state directory must already exist")
    # Validate credentials before resource creation; snapshot private file inputs.
    credentials, secrets = snapshot_credentials(spec.inputs, descriptor)
    runtime = preflight_native(installed.prefix, installed.manifest)
    output.mkdir(parents=True, mode=0o700)
    lifecycle = []
    cleanup = []
    stages = []
    app = None
    completed = False
    timed_out = False
    interrupted = 0
    deadline = time.monotonic() + spec.timeout_seconds
    handlers = {}

    def on_signal(number, frame):
        nonlocal interrupted
        interrupted = number

    if threading.current_thread() is threading.main_thread():
        for number in (signal.SIGINT, signal.SIGTERM):
            handlers[number] = signal.signal(number, on_signal)
    try:
        with tempfile.TemporaryDirectory(prefix="p11lab-native-input-") as private:
            # Ambient provider, credential and loader controls cannot override inputs.
            env = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith(("P11LAB_", "SOFTHSM", "LD_"))
            }
            env.update(
                {k: v for k, v in spec.inputs.items() if k in descriptor["inputs"]}
            )
            for key, data in credentials.items():
                if key.endswith("_FILE"):
                    snapshot = Path(private) / key
                    snapshot.write_bytes(data)
                    snapshot.chmod(0o600)
                    env[key] = str(snapshot)
            env.update(
                P11LAB_OUTPUT_DIR=str(output),
                P11LAB_MODULE=str(installed.prefix / "payload" / MODULE),
                SOFTHSM2_CONF=str(control / "softhsm2.conf"),
            )
            adapter = [
                str(installed.prefix / "payload" / ADAPTER),
                "--prefix",
                str(installed.prefix),
                "--state",
                str(state),
                "--control",
                str(control),
            ]
            for phase, args in [
                ("init", ["init"]),
                ("ready", ["health"]),
                ("application", ["exec", "--", *spec.argv]),
                ("post-health", ["health"]),
            ]:
                if interrupted or time.monotonic() >= deadline:
                    timed_out = not bool(interrupted)
                    lifecycle.append("interrupted" if interrupted else "timeout")
                    break
                status, stage_timeout, owner, logs = supervised_exec(
                    [*adapter, *args], cwd=cwd, env=env,
                    timeout=max(.01, deadline - time.monotonic()), interrupted=lambda: interrupted)
                process = owner.process
                logs.update(write_process_logs(owner, output, phase, secrets))
                supervision_complete = logs['drain_complete'] and not logs['stragglers_remaining'] and not logs['supervision_errors']
                if not supervision_complete:
                    lifecycle.append(phase + ' supervision incomplete')
                timed_out |= stage_timeout
                stages.append(
                    {
                        "phase": phase,
                        "pid": process.pid,
                        "returncode": status,
                        "timed_out": stage_timeout,
                        **logs,
                    }
                )
                if phase == "application":
                    app = status
                    completed = not stage_timeout and not interrupted and supervision_complete
                elif status:
                    lifecycle.append(phase + " failed")
                    break
                if stage_timeout or interrupted or not supervision_complete:
                    break
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        lifecycle.append(
            "native runner operation failed (" + type(error).__name__ + ")"
        )
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
    code = (
        app
        if completed and app
        else 128 + interrupted
        if interrupted
        else 124
        if timed_out
        else app
        if app
        else 1
        if lifecycle or cleanup
        else 0
    )
    receipt = output / "receipt.json"
    write_receipt(
        receipt,
        {
            "schema_version": 1,
            "attempt_id": uuid4().hex,
            "environment": spec.environment,
            "channel": spec.channel,
            "mode": "native",
            "execution_location": "host",
            "artifacts": {
                "provider": asdict(spec.artifact),
                "consumer": None,
                "client": None,
            },
            "installation": {
                "prefix": str(installed.prefix),
                "manifest_sha256": installed.manifest_sha256,
                "receipt_path": str(installed.receipt_path),
                "receipt_sha256": installed.receipt_sha256,
            },
            "runtime": runtime,
            "execution": {
                "module": str(installed.prefix / "payload" / MODULE),
                "configuration": str(control / "softhsm2.conf"),
                "cwd": str(cwd),
                "argv_count": len(spec.argv),
            },
            "state": {
                "path": str(state),
                "control": str(control),
                "persistent_caller_directory": "P11LAB_STATE_DIR" in spec.inputs,
            },
            "stages": stages,
            "app_returncode": app,
            "app_completed": completed,
            "timeout": timed_out,
            "interrupted_signal": interrupted,
            "lifecycle_errors": lifecycle,
            "cleanup_errors": cleanup,
            "exit_code": code,
        },
    )
    return RunResult(app, tuple(lifecycle), tuple(cleanup), code, receipt)


def _validate_client_manifest(manifest, environment, channel):
    """Client bundles carry proxy component identities; no catalog target lock."""
    from .tls import PROXY_CARGO_LOCK_SHA256, PROXY_SOURCE_REVISION

    if (
        manifest.get("role") != "native-client"
        or manifest.get("target") != CLIENT_TARGET
        or manifest.get("module") != CLIENT_MODULE
        or manifest.get("host_requirements") != CLIENT_HOST_REQUIREMENTS
    ):
        raise ValueError(
            "native manifest does not match the client target/host requirements"
        )
    proxy = manifest.get("source", {}).get("proxy", {})
    if (
        proxy.get("source_revision") != PROXY_SOURCE_REVISION
        or proxy.get("cargo_lock_sha256") != PROXY_CARGO_LOCK_SHA256
    ):
        raise ValueError("native client proxy component identity mismatch")
    roster = {entry["path"]: entry for entry in manifest.get("files", [])}
    if (
        roster.get(CLIENT_MODULE, {}).get("sha256") != proxy.get("shim_sha256")
        or roster.get(CLIENT_CLI, {}).get("sha256") != proxy.get("cli_sha256")
    ):
        raise ValueError("native client component bytes differ from declared proxy")
    return manifest


def build_native_client_bundle(
    *,
    proxy: dict,
    shim: Path,
    cli: Path,
    licenses: dict,
    output_dir: Path,
    environment: str,
    channel: str,
) -> ArtifactRef:
    """Package verified pinned-proxy client bytes as a native-client bundle.

    No compilation occurs here. The shim/CLI bytes were built from the pinned
    proxy source and are hash-verified against the declared component
    identities, which enter the build key: a proxy component change
    invalidates the client identity.
    """
    from .tls import PROXY_CARGO_LOCK_SHA256, PROXY_SOURCE_REVISION

    for key in (
        "source_revision",
        "cargo_lock_sha256",
        "source_archive_sha256",
        "shim_sha256",
        "cli_sha256",
        "toolchain",
    ):
        if not proxy.get(key):
            raise ValueError("client build requires proxy " + key)
    if (
        proxy["source_revision"] != PROXY_SOURCE_REVISION
        or proxy["cargo_lock_sha256"] != PROXY_CARGO_LOCK_SHA256
    ):
        raise ValueError("client build proxy component identity mismatch")
    shim_bytes = Path(shim).read_bytes()
    cli_bytes = Path(cli).read_bytes()
    if hashlib.sha256(shim_bytes).hexdigest() != proxy["shim_sha256"]:
        raise ValueError("client shim bytes differ from declared proxy component")
    if hashlib.sha256(cli_bytes).hexdigest() != proxy["cli_sha256"]:
        raise ValueError("client CLI bytes differ from declared proxy component")
    if set(licenses) != {
        "share/licenses/proxy-ng/LICENSE-APACHE",
        "share/licenses/proxy-ng/LICENSE-MIT",
    }:
        raise ValueError("client build requires pinned proxy license texts")
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    inputs = {
        "sources": [{"revision": proxy["source_revision"]}],
        "binaries": [
            {"path": CLIENT_MODULE, "sha256": proxy["shim_sha256"]},
            {"path": CLIENT_CLI, "sha256": proxy["cli_sha256"]},
        ],
        "dependencies": [],
        "toolchain": [],
        "recipe": hashlib.sha256(
            json.dumps(
                {"implementation": checksum(Path(__file__))}, sort_keys=True
            ).encode()
        ).hexdigest(),
        "platform": "linux/amd64",
        "features": {
            "target": CLIENT_TARGET,
            "host_requirements": CLIENT_HOST_REQUIREMENTS,
            "proxy": {
                key: proxy[key]
                for key in (
                    "source_revision",
                    "cargo_lock_sha256",
                    "source_archive_sha256",
                    "shim_sha256",
                    "cli_sha256",
                )
            },
            "toolchain": proxy["toolchain"],
            "licenses": {
                name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                for name, path in sorted(licenses.items())
            },
        },
    }
    key = artifact_key("client", inputs)
    contents = {
        CLIENT_MODULE: shim_bytes,
        CLIENT_CLI: cli_bytes,
        "share/p11lab/native-id": (key + "\n").encode(),
        "share/licenses/p11lab/LICENSE": package_data("runtime/LICENSE").read_bytes(),
        "share/p11lab/THIRD-PARTY-NOTICES.txt": (
            "P11Lab native client packaging: Apache-2.0. "
            "pkcs11-proxy-ng shim/CLI: Apache-2.0 OR MIT; see "
            "share/licenses/proxy-ng/. Host runtime packages are "
            "prerequisites, not redistributed. Proxy source and component "
            "identities are recorded in manifest.json. Public admission is a "
            "separate artifact-bound gate.\n"
        ).encode(),
    }
    for name, path in licenses.items():
        contents[name] = Path(path).read_bytes()
    roster = [
        {
            "path": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "mode": 0o755 if name.startswith("bin/") else 0o644,
            "role": "module"
            if name == CLIENT_MODULE
            else "cli"
            if name == CLIENT_CLI
            else "notice",
        }
        for name, data in sorted(contents.items())
    ]
    manifest = {
        "schema_version": 1,
        "role": "native-client",
        "environment": environment,
        "channel": channel,
        "platform": "linux/amd64",
        "target": CLIENT_TARGET,
        "module": CLIENT_MODULE,
        "source": {
            "proxy": {
                "repository": "https://github.com/mingulov/pkcs11-proxy-ng",
                "source_revision": proxy["source_revision"],
                "source_archive_sha256": proxy["source_archive_sha256"],
                "cargo_lock_sha256": proxy["cargo_lock_sha256"],
                "shim_sha256": proxy["shim_sha256"],
                "cli_sha256": proxy["cli_sha256"],
            }
        },
        "build": {"key": key, "identity": public_identity("client", inputs)},
        "host_requirements": CLIENT_HOST_REQUIREMENTS,
        "tested_prerequisites": ["debian13-amd64 system loader resolution"],
        "licenses": [
            "share/licenses/proxy-ng/LICENSE-APACHE",
            "share/licenses/proxy-ng/LICENSE-MIT",
            "share/licenses/p11lab/LICENSE",
        ],
        "source_references": [
            {
                "repository": "https://github.com/mingulov/pkcs11-proxy-ng",
                "revision": proxy["source_revision"],
            }
        ],
        "files": roster,
        "admission": "unreviewed; native actual-content admission is separate from container admission",
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    archive_path = output_dir / "proxy-client-native.tar.gz"
    import gzip

    with (
        archive_path.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped,
        tarfile.open(fileobj=zipped, mode="w") as archive,
    ):
        for name, data, mode in [
            ("manifest.json", manifest_bytes, 0o644),
            *[("payload/" + r["path"], contents[r["path"]], r["mode"]) for r in roster],
        ]:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = mode
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
    artifact = ArtifactRef(
        "bundle", str(archive_path), checksum(archive_path), "linux/amd64"
    )
    inspect_bundle(
        artifact, **_selection(environment, channel, "linux/amd64")
    )
    write_receipt(
        output_dir / "artifact.json",
        {
            "schema_version": 1,
            "artifact": asdict(artifact),
            "build_key": key,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "proxy": manifest["source"]["proxy"],
            "payload_bytes": sum(r["size"] for r in roster),
            "archive_bytes": archive_path.stat().st_size,
            "files": roster,
            "admission": "unreviewed",
        },
    )
    (output_dir / "manifest.json").write_bytes(manifest_bytes)
    return artifact


def preflight_native_client(prefix: Path, manifest: dict) -> dict:
    """Resolve the shim closure with the host system loader; no provider needed."""
    _validate_client_manifest(
        manifest, manifest.get("environment"), manifest.get("channel")
    )
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("native proxy client requires Linux x86_64")
    loader = manifest["host_requirements"]["loader"]
    shim = prefix / "payload" / CLIENT_MODULE
    result = subprocess.run(
        [loader, "--list", str(shim)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode or "not found" in result.stdout + result.stderr:
        raise ValueError(
            "missing or incompatible native client runtime prerequisite: "
            + CLIENT_MODULE
            + "; "
            + result.stderr.strip()
        )
    resolved = []
    for line in result.stdout.splitlines():
        fields = line.split()
        name = (
            fields[2]
            if len(fields) > 2 and fields[1] == "=>"
            else fields[0]
            if fields
            else ""
        )
        if name.startswith("/"):
            path = Path(name).resolve()
            resolved.append({"path": str(path), "sha256": checksum(path)})
    launch = subprocess.run(
        [str(prefix / "payload" / CLIENT_CLI), "--version"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if launch.returncode:
        raise ValueError("native client CLI launch failed")
    return {
        "loader": loader,
        "architecture": platform.machine(),
        "closure": {CLIENT_MODULE: {"loader_output": result.stdout, "resolved": resolved}},
        "cli_version": launch.stdout.strip(),
    }


def install_native_client_bundle(
    artifact: ArtifactRef, prefix: Path, *, environment: str, channel: str
) -> InstalledBundle:
    selection = _selection(environment, channel, artifact.platform)
    manifest = inspect_bundle(artifact, **selection)
    _validate_client_manifest(manifest, environment, channel)
    # Inert N1 extraction into private temporary placement. Host preflight
    # precedes creation of the requested prefix or ancestors.
    with tempfile.TemporaryDirectory(
        prefix=".p11lab-client-preflight-", dir=staging_parent(prefix)
    ) as temporary:
        staged = install_bundle(artifact, Path(temporary) / "prefix", **selection)
        preflight_native_client(staged.prefix, manifest)
    return install_bundle(artifact, prefix, **selection)


def load_client_installation(
    prefix: Path, *, environment: str, channel: str, platform: str = "linux/amd64"
) -> InstalledBundle:
    """Reverify an installed client bundle and its host/ABI preflight."""
    installed = read_installation(
        prefix, environment=environment, channel=channel, platform=platform
    )
    _validate_client_manifest(installed.manifest, environment, channel)
    preflight_native_client(installed.prefix, installed.manifest)
    return installed


# BouncyHSM native delivery (M5). SoftHSM/client behavior above is unchanged.
# A BouncyHSM bundle carries the native client module, the managed server
# tree, and a small PKCS#11 probe; the host supplies .NET 10 (SDK or runtime
# with ASP.NET Core) and, on Windows, the x64 VC runtime. Supervision,
# provisioning, and readiness live in run_native_bouncyhsm; the shipped
# probe performs every native operation so no calling convention is
# reimplemented per platform.
BOUNCY_LINUX_TARGET = "debian13-amd64"
BOUNCY_WINDOWS_TARGET = "windows-amd64"
BOUNCY_LINUX_MODULE = "lib/libBouncyHsm.Pkcs11.so"
BOUNCY_WINDOWS_MODULE = "bin/BouncyHsm.Pkcs11Lib.dll"
BOUNCY_LINUX_PROBE = "bin/bouncyhsm-probe"
BOUNCY_WINDOWS_PROBE = "bin/bouncyhsm-probe.exe"
BOUNCY_LINUX_SERVER = "server/BouncyHsm.dll"
BOUNCY_WINDOWS_SERVER = "server/BouncyHsm.exe"
BOUNCY_SOURCE_REVISIONS = {
    "release": "27bc4987237eda064b1c4b82177942b859cb2027",
    "rolling": "f09ab9a342741c56bb56621a707c1b94dfdeac4b",
}
BOUNCY_DOTNET_RUNTIME_FLOOR = (10, 0, 12)
BOUNCY_NATIVE_EXTRAS = (
    "P11LAB_STATE_DIR",
    "P11LAB_CONTROL_DIR",
    "P11LAB_HTTP_PORT",
    "P11LAB_TCP_PORT",
)
BOUNCY_LABEL_DEFAULT = "P11Lab"


def load_bouncyhsm_target(environment: str, channel: str, target: str) -> dict:
    """Load a BouncyHSM native target lock; container locks never substitute.

    This loader is BouncyHSM-specific (module/lifecycle/host contract); the
    SoftHSM loader above is untouched. The catalogue packaged-target path is
    SoftHSM-only by a frozen boundary, so this contract reads its own lock
    files by name and verifies the full tuple plus every asset hash itself.
    """
    from .catalog import CatalogError, load_environment, packaged_asset

    if environment != "bouncyhsm":
        raise CatalogError("bouncyhsm native loader serves only bouncyhsm")
    if channel not in ("release", "rolling") or target not in (
        BOUNCY_LINUX_TARGET,
        BOUNCY_WINDOWS_TARGET,
    ):
        raise CatalogError("unknown bouncyhsm native target or channel")
    spec = load_environment(environment, channel)
    selected = spec.get("native_targets", {}).get(target, {})
    try:
        lock = json.loads(
            packaged_asset(environment, f"{channel}.{target}.lock.json").read_text()
        )
    except (FileNotFoundError, NotADirectoryError) as error:
        raise CatalogError("bouncyhsm native target lock is missing") from error
    if (
        lock.get("schema_version") != 1
        or lock.get("target") != target
        or lock.get("channel") != channel
        or lock.get("platform") != selected.get("platform")
    ):
        raise CatalogError("native target lock tuple mismatch")
    expected_module = (
        BOUNCY_LINUX_MODULE if target == BOUNCY_LINUX_TARGET else BOUNCY_WINDOWS_MODULE
    )
    if (
        not isinstance(lock.get("host_requirements"), dict)
        or not lock["host_requirements"]
        or selected.get("module_path") != expected_module
        or lock.get("module") != expected_module
        or lock.get("lifecycle")
        != {
            "server": BOUNCY_LINUX_SERVER
            if target == BOUNCY_LINUX_TARGET
            else BOUNCY_WINDOWS_SERVER,
            "probe": BOUNCY_LINUX_PROBE
            if target == BOUNCY_LINUX_TARGET
            else BOUNCY_WINDOWS_PROBE,
        }
    ):
        raise CatalogError("invalid bouncyhsm native target contract")
    if lock.get("source", {}).get("revision") != BOUNCY_SOURCE_REVISIONS[channel]:
        raise CatalogError("bouncyhsm native lock source revision mismatch")
    for entry in lock.get("binaries", []):
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "sha256"}
            or not isinstance(entry["path"], str)
            or not entry["path"]
        ):
            raise CatalogError("invalid bouncyhsm native binary pin")
    for asset in lock.get("assets", []):
        if hashlib.sha256(
            packaged_asset(environment, asset["path"]).read_bytes()
        ).hexdigest() != asset.get("sha256"):
            raise CatalogError("native asset sha256 mismatch")
    return spec | {
        "native_target": target,
        "native_target_spec": selected,
        "native_lock": lock,
    }


def _validate_bouncyhsm_manifest(
    manifest: dict, environment: str, channel: str
) -> dict:
    """Require the installed manifest to match the locked target contract."""
    target = manifest.get("target")
    if target not in (BOUNCY_LINUX_TARGET, BOUNCY_WINDOWS_TARGET):
        raise ValueError("bouncyhsm manifest target is not a packaged native target")
    selected = load_bouncyhsm_target(environment, channel, target)
    lock = selected["native_lock"]
    if (
        manifest.get("role") != "native-runtime"
        or manifest.get("platform") != lock["platform"]
        or manifest.get("module") != lock["module"]
        or manifest.get("lifecycle") != lock["lifecycle"]
        or manifest.get("host_requirements") != lock["host_requirements"]
    ):
        raise ValueError(
            "bouncyhsm manifest does not match selected target/host requirements"
        )
    if manifest.get("source", {}).get("revision") != lock["source"]["revision"]:
        raise ValueError(
            "bouncyhsm manifest source revision differs from locked source"
        )
    if manifest.get("toolchain") != lock["toolchain"]:
        raise ValueError("bouncyhsm manifest toolchain differs from locked toolchain")
    return selected


def _dotnet_runtime_versions(text: str) -> dict:
    """Parse `dotnet --list-runtimes` into framework -> sorted version tuples."""
    versions: dict = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in (
            "Microsoft.NETCore.App",
            "Microsoft.AspNetCore.App",
        ):
            try:
                versions.setdefault(parts[0], []).append(
                    tuple(int(p) for p in parts[1].split("."))
                )
            except ValueError:
                continue
    return {name: sorted(candidates) for name, candidates in versions.items()}


def preflight_bouncyhsm(prefix: Path, manifest: dict) -> dict:
    """Explicit runtime/ABI preflight for the installed BouncyHSM bundle.

    Linux checks Debian 13 amd64 identity, the system-loader closure of the
    module and probe, a real module load, and the host .NET runtimes.
    Windows checks x64 identity, a real DLL load through the shipped probe
    (which proves the VC-runtime/UCRT closure), and the host .NET runtimes.
    """
    platform_name = manifest.get("platform")
    if platform_name == "linux/amd64" and platform.system() != "Linux":
        raise ValueError("linux/amd64 bouncyhsm bundle requires a Linux host")
    if platform_name == "windows/amd64" and platform.system() != "Windows":
        raise ValueError("windows/amd64 bouncyhsm bundle requires a Windows host")
    if platform_name not in ("linux/amd64", "windows/amd64"):
        raise ValueError("unsupported bouncyhsm bundle platform")
    module = prefix / "payload" / manifest["module"]
    probe = prefix / "payload" / manifest["lifecycle"]["probe"]
    server = prefix / "payload" / manifest["lifecycle"]["server"]
    for path in (module, probe, server):
        if not path.is_file() or path.is_symlink():
            raise ValueError("bouncyhsm payload entry is not a regular file")
    if platform.system() == "Linux":
        release = platform.freedesktop_os_release()
        if (
            platform.machine() != "x86_64"
            or release.get("ID") != "debian"
            or release.get("VERSION_ID", "").split(".")[0] != "13"
        ):
            raise ValueError(
                "native BouncyHSM requires Debian 13 amd64 (debian13-amd64)"
            )
        closure = {}
        for relative in (manifest["module"], manifest["lifecycle"]["probe"]):
            binary = prefix / "payload" / relative
            result = subprocess.run(
                ["/lib64/ld-linux-x86-64.so.2", "--list", str(binary)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode or "not found" in result.stdout + result.stderr:
                raise ValueError(
                    "missing or incompatible native runtime prerequisite: "
                    + relative
                    + "; "
                    + result.stderr.strip()
                )
            resolved = []
            for line in result.stdout.splitlines():
                fields = line.split()
                name = (
                    fields[2]
                    if len(fields) > 2 and fields[1] == "=>"
                    else fields[0]
                    if fields
                    else ""
                )
                if name.startswith("/"):
                    path = Path(name).resolve()
                    resolved.append({"path": str(path), "sha256": checksum(path)})
            closure[relative] = {"loader_output": result.stdout, "resolved": resolved}
        host: dict = {
            "os_release": release,
            "architecture": platform.machine(),
            "closure": closure,
        }
    else:
        if platform.machine().lower() not in ("amd64", "x86_64"):
            raise ValueError("native BouncyHSM requires Windows x64 (windows-amd64)")
        host = {
            "os_release": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
            },
            "architecture": platform.machine(),
        }
        system_vc = Path(os.path.expandvars(r"%SystemRoot%\System32\vcruntime140.dll"))
        host["system_vcruntime"] = (
            {
                "path": str(system_vc),
                "sha256": checksum(system_vc),
                "size": system_vc.stat().st_size,
            }
            if system_vc.is_file()
            else None
        )
    loaded = subprocess.run(
        [str(probe), "--module", str(module), "--load-only"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if loaded.returncode or not loaded.stdout.startswith("version="):
        raise ValueError(
            "native module load failed: "
            + (loaded.stderr.strip() or loaded.stdout.strip())
        )
    dotnet = shutil.which("dotnet")
    if not dotnet:
        raise ValueError("host .NET 10 runtime is required but dotnet was not found")
    runtimes = subprocess.run(
        [dotnet, "--list-runtimes"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if runtimes.returncode:
        raise ValueError("host dotnet runtime listing failed")
    versions = _dotnet_runtime_versions(runtimes.stdout)
    floor = BOUNCY_DOTNET_RUNTIME_FLOOR
    for framework in ("Microsoft.NETCore.App", "Microsoft.AspNetCore.App"):
        candidates = [
            v
            for v in versions.get(framework, [])
            if len(v) >= 3 and v[:2] == floor[:2] and v >= floor
        ]
        if not candidates:
            raise ValueError(
                f"host {framework} 10.0.12 or later is required; "
                + runtimes.stdout.strip().replace("\n", "; ")
            )
    host.update(
        {
            "module_load": loaded.stdout.strip(),
            "dotnet": dotnet,
            "dotnet_runtimes": runtimes.stdout,
            "dotnet_minimum": ".".join(str(p) for p in floor),
        }
    )
    return host


def install_bouncyhsm_bundle(
    artifact: ArtifactRef, prefix: Path, *, environment: str, channel: str
) -> InstalledBundle:
    """Install a verified BouncyHSM bundle reusing the reviewed N1 installer.

    Archive verification, payload readback, and atomic no-replace placement
    are bundle.py's; only the BouncyHSM target contract and host/ABI
    preflight are provider-specific. Host preflight precedes creation of the
    requested prefix or ancestors.
    """
    selection = _selection(environment, channel, artifact.platform)
    manifest = inspect_bundle(artifact, **selection)
    _validate_bouncyhsm_manifest(manifest, environment, channel)
    with tempfile.TemporaryDirectory(
        prefix=".p11lab-bouncy-preflight-", dir=staging_parent(prefix)
    ) as temporary:
        staged = install_bundle(artifact, Path(temporary) / "prefix", **selection)
        preflight_bouncyhsm(staged.prefix, manifest)
    return install_bundle(artifact, prefix, **selection)


def load_bouncyhsm_installation(
    prefix: Path, *, environment: str, channel: str, platform: str
) -> InstalledBundle:
    """Reverify a BouncyHSM installation and its host/ABI preflight."""
    installed = read_installation(
        prefix, environment=environment, channel=channel, platform=platform
    )
    _validate_bouncyhsm_manifest(installed.manifest, environment, channel)
    preflight_bouncyhsm(installed.prefix, installed.manifest)
    return installed


def _bouncy_bundle_notice(
    environment: str, channel: str, target: str, module: str, server: str
) -> str:
    return (
        "P11Lab BouncyHSM native bundle (%s %s %s).\n"
        "Module %s, managed server %s, and the P11Lab PKCS#11 probe.\n"
        "Upstream LICENSE and FILE-NOTICES.txt sit beside this file under\n"
        "share/licenses/bouncyhsm/. Admission: unreviewed; this bundle is an\n"
        "acceptance input, not a distributable artifact.\n"
    ) % (environment, channel, target, module, server)


def build_bouncyhsm_bundle(
    *,
    environment: str,
    channel: str,
    target: str,
    output_dir: Path,
    archive: Path | None = None,
    payload_dir: Path | None = None,
    probe_exe: Path | None = None,
    build_meta: dict | None = None,
) -> ArtifactRef:
    """Assemble a BouncyHSM native bundle from verified inputs.

    Linux exports the recipe roster from the locked parent image by digest
    and compares every byte to the lock (sealed staging). Windows release
    verifies the upstream archive plus its full inner roster and adds the
    CI-built probe; Windows rolling verifies pinned source/toolchain claims
    in build_meta and records the staged output bytes in the manifest.
    """
    from .catalog import CatalogError, packaged_asset

    selected = load_bouncyhsm_target(environment, channel, target)
    lock = selected["native_lock"]
    if target == BOUNCY_LINUX_TARGET and (archive or payload_dir or probe_exe):
        raise ValueError("linux bundles export from the locked parent image only")
    if (
        target == BOUNCY_WINDOWS_TARGET
        and channel == "release"
        and (archive is None or probe_exe is None or payload_dir is not None)
    ):
        raise ValueError("windows release bundles need the upstream archive plus probe")
    if (
        target == BOUNCY_WINDOWS_TARGET
        and channel == "rolling"
        and (payload_dir is None or build_meta is None or archive is not None)
    ):
        raise ValueError("windows rolling bundles need a payload dir plus build meta")
    output_dir.mkdir(parents=True, exist_ok=False)
    recipe = json.loads(packaged_asset(environment, "native.recipe.json").read_text())
    payload: list = []  # (payload path, bytes, mode)
    acquisition: dict

    def add_payload(relative: str, data: bytes, mode: int) -> None:
        if not relative or relative.startswith("/") or ".." in Path(relative).parts:
            raise ValueError("unsafe payload path")
        payload.append((relative, data, mode))

    if target == BOUNCY_LINUX_TARGET:
        export_map = recipe["linux"]["export"]
        parent = lock["parent"]
        try:
            observation = json.loads(
                subprocess.run(
                    ["docker", "image", "inspect", parent["reference"]],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                ).stdout
            )[0]
        except (subprocess.SubprocessError, KeyError, IndexError) as error:
            raise ValueError("docker engine unavailable for sealed export") from error
        if observation.get("Id") != "sha256:" + parent["sha256"]:
            raise CatalogError("native parent image identity mismatch")
        container = (
            subprocess.run(
                [
                    "docker",
                    "create",
                    "--platform",
                    "linux/amd64",
                    parent["reference"],
                    "true",
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=60,
            )
            .stdout.strip()
            .splitlines()[0]
        )
        try:
            blob = subprocess.run(
                ["docker", "export", container],
                capture_output=True,
                check=True,
                timeout=300,
            ).stdout
        finally:
            subprocess.run(["docker", "rm", container], capture_output=True, timeout=60)
        reader = tarfile.open(fileobj=io.BytesIO(blob))
        exported = {}
        for member in reader.getmembers():
            if not member.isfile():
                continue
            name = member.name.lstrip("./")
            for root in export_map:
                if name == root or name.startswith(root + "/"):
                    exported[name] = (reader.extractfile(member).read(), member.mode)
        expected = {entry["path"]: entry["sha256"] for entry in lock["binaries"]}
        observed = {
            name: hashlib.sha256(data).hexdigest()
            for name, (data, _) in exported.items()
        }
        if observed != expected:
            raise CatalogError("exported bytes differ from locked native binaries")
        for name, (data, mode) in sorted(exported.items()):
            relative = None
            for root, mapped in export_map.items():
                if name == root or name.startswith(root + "/"):
                    relative = mapped + name[len(root) :]
                    break
            if relative is None:
                raise CatalogError("exported file has no recipe mapping")
            add_payload(relative, data, 0o755 if mode & 0o111 else 0o644)
        acquisition = {"method": "docker-export", "parent": parent}
    elif channel == "release":
        import zipfile

        roster_doc = json.loads(
            packaged_asset(environment, "windows.release.files.json").read_text()
        )
        parent = lock["parent"]
        archive_bytes = Path(archive).read_bytes()
        if (
            hashlib.sha256(archive_bytes).hexdigest() != parent["sha256"]
            or len(archive_bytes) != parent["size"]
        ):
            raise CatalogError("upstream release archive does not match the lock")
        members = {}
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as reader:
            for info in reader.infolist():
                if info.is_dir():
                    continue
                members[info.filename] = reader.read(info.filename)
        expected = {entry["path"]: entry["sha256"] for entry in roster_doc["files"]}
        observed = {
            name: hashlib.sha256(data).hexdigest() for name, data in members.items()
        }
        if observed != expected:
            raise CatalogError("release archive members differ from the locked roster")
        section = recipe["windows"]
        chosen = {}
        chosen[section["module_payload_path"]] = members[section["module"]]
        for name, data in members.items():
            if name == "License.txt" or any(
                name.startswith(prefix) for prefix in section["server_exclude_prefixes"]
            ):
                continue
            chosen[section["server_prefix"] + name] = data
        chosen[section["license_payload_path"]] = members["License.txt"]
        expected_payload = {
            entry["path"]: entry["sha256"] for entry in lock["binaries"]
        }
        observed_payload = {
            name: hashlib.sha256(data).hexdigest() for name, data in chosen.items()
        }
        if observed_payload != expected_payload:
            raise CatalogError("selected release payload differs from the lock")
        for name, data in sorted(chosen.items()):
            add_payload(
                name,
                data,
                0o755 if name == section["server_prefix"] + "BouncyHsm.exe" else 0o644,
            )
        add_payload(section["probe_payload_path"], Path(probe_exe).read_bytes(), 0o755)
        acquisition = {
            "method": "verified-archive",
            "archive_sha256": parent["sha256"],
            "probe": "ci-built from locked probe.c with MSVC v145; bytes recorded below",
        }
    else:
        staged = Path(payload_dir)
        section = recipe["windows"]
        if (
            build_meta.get("source_revision") != lock["source"]["revision"]
            or build_meta.get("sdk_version") != "10.0.401"
            or build_meta.get("toolset") != "v145"
        ):
            raise CatalogError("rolling build meta does not match locked inputs")
        server_root = staged / "server"
        module_file = staged / "BouncyHsm.Pkcs11Lib.dll"
        probe_file = staged / "bouncyhsm-probe.exe"
        license_file = staged / "LICENSE"
        if (
            not server_root.is_dir()
            or not module_file.is_file()
            or not probe_file.is_file()
            or not license_file.is_file()
        ):
            raise ValueError(
                "rolling payload dir misses server, module, probe, or LICENSE"
            )
        server_files = sorted(
            p for p in server_root.rglob("*") if p.is_file() and not p.is_symlink()
        )
        if not server_files or not (server_root / "BouncyHsm.exe").is_file():
            raise ValueError("rolling server tree is empty or misses the host")
        add_payload(section["module_payload_path"], module_file.read_bytes(), 0o644)
        add_payload(section["probe_payload_path"], probe_file.read_bytes(), 0o755)
        for path in server_files:
            relative = (
                section["server_prefix"] + path.relative_to(server_root).as_posix()
            )
            executable = path.name.lower() == "bouncyhsm.exe"
            add_payload(relative, path.read_bytes(), 0o755 if executable else 0o644)
        add_payload(section["license_payload_path"], license_file.read_bytes(), 0o644)
        acquisition = {
            "method": "source-build",
            "source_revision": build_meta["source_revision"],
            "sdk_version": build_meta["sdk_version"],
            "toolset": build_meta["toolset"],
            "compiler": build_meta.get("compiler"),
            "publish": build_meta.get("publish"),
        }
    provider_asset = packaged_asset(environment, "provider.json").read_bytes()
    p11lab_license = package_data("runtime/LICENSE").read_bytes()
    notices = packaged_asset(environment, f"FILE-NOTICES-{channel}.txt").read_bytes()
    add_payload("share/p11lab/provider.json", provider_asset, 0o644)
    add_payload("share/licenses/p11lab/LICENSE", p11lab_license, 0o644)
    add_payload("share/licenses/bouncyhsm/FILE-NOTICES.txt", notices, 0o644)
    add_payload(
        "share/p11lab/THIRD-PARTY-NOTICES.txt",
        _bouncy_bundle_notice(
            environment, channel, target, lock["module"], lock["lifecycle"]["server"]
        ).encode(),
        0o644,
    )

    def payload_role(relative: str) -> str:
        if relative == lock["module"]:
            return "module"
        if relative == lock["lifecycle"]["probe"]:
            return "probe"
        if relative == lock["lifecycle"]["server"] or relative.startswith("server/"):
            return "server"
        return "notice"

    binaries = sorted(
        (
            {
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            for relative, data, _ in payload
        ),
        key=lambda entry: entry["path"],
    )
    implementation = json.dumps(
        {
            "recipe": hashlib.sha256(
                packaged_asset(environment, "native.recipe.json").read_bytes()
            ).hexdigest(),
            "probe_c": hashlib.sha256(
                packaged_asset(environment, "probe.c").read_bytes()
            ).hexdigest(),
            "notices": hashlib.sha256(notices).hexdigest(),
        },
        sort_keys=True,
    ).encode()
    # Identity pins byte-addressable inputs only. Host toolset claims (MSVC
    # v145, exact SDK version) stay in the manifest and acquisition record,
    # and the bytes they produced are pinned through `binaries`.
    identity_toolchain = [
        entry
        for entry in lock["toolchain"]
        if isinstance(entry, dict)
        and (
            re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", ""))
            or re.fullmatch(r"[0-9a-f]{40}", entry.get("revision", ""))
        )
    ]
    identity_inputs = {
        "sources": [lock["source"]],
        "binaries": binaries,
        "dependencies": [],
        "toolchain": identity_toolchain,
        "recipe": hashlib.sha256(implementation).hexdigest(),
        "platform": lock["platform"],
        "features": {
            "target": target,
            "acquisition": acquisition,
            "host_requirements": lock["host_requirements"],
            "target_lock": f"{channel}.{target}.lock.json",
            "notice_provenance": lock["notice_provenance"],
        },
    }
    key = artifact_key("native", identity_inputs)
    add_payload("share/p11lab/native-id", key.encode(), 0o644)
    manifest = {
        "schema_version": 1,
        "role": "native-runtime",
        "environment": environment,
        "channel": channel,
        "platform": lock["platform"],
        "target": target,
        "module": lock["module"],
        "lifecycle": lock["lifecycle"],
        "source": {
            "sources": [lock["source"]],
            "acquisition": acquisition,
            "revision": lock["source"]["revision"],
            "notice_provenance": lock["notice_provenance"],
        },
        "toolchain": lock["toolchain"],
        "host_requirements": lock["host_requirements"],
        "tested_prerequisites": lock["tested_prerequisites"],
        "build": {
            "key": key,
            "identity": public_identity("native", identity_inputs),
        },
        "licenses": [
            "share/licenses/p11lab/LICENSE",
            "share/licenses/bouncyhsm/FILE-NOTICES.txt",
            "share/licenses/bouncyhsm/LICENSE",
        ],
        "source_references": ["share/p11lab/provider.json"],
        "files": [
            {
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "mode": mode,
                "role": payload_role(relative),
            }
            for relative, data, mode in sorted(payload)
        ],
        "admission": "unreviewed; acceptance input only, no distribution qualification",
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    archive_path = output_dir / ("bouncyhsm-native-%s-%s.tar.gz" % (channel, target))
    contents = {relative: (data, mode) for relative, data, mode in payload}
    # Fixed tar headers and gzip timestamp; native identity includes all packaged bytes.
    import gzip

    with (
        archive_path.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped,
        tarfile.open(fileobj=zipped, mode="w") as writer,
    ):
        entries = [("manifest.json", manifest_bytes, 0o644)] + [
            ("payload/" + relative, contents[relative][0], contents[relative][1])
            for relative in sorted(contents)
        ]
        for name, data, mode in entries:
            entry_info = tarfile.TarInfo(name)
            entry_info.size = len(data)
            entry_info.mode = mode
            entry_info.mtime = 0
            writer.addfile(entry_info, io.BytesIO(data))
    artifact = ArtifactRef(
        "bundle", str(archive_path), checksum(archive_path), lock["platform"]
    )
    inspect_bundle(artifact, **_selection(environment, channel, lock["platform"]))
    write_receipt(
        output_dir / "artifact.json",
        {
            "schema_version": 1,
            "attempt_id": uuid4().hex,
            "environment": environment,
            "channel": channel,
            "role": "native",
            "target": target,
            "build_key": key,
            "artifact": {
                "kind": "bundle",
                "reference": str(archive_path),
                "sha256": checksum(archive_path),
                "platform": lock["platform"],
            },
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "payload_files": len(payload),
            "payload_bytes": sum(len(data) for _, data, _ in payload),
        },
    )
    return artifact


def _bouncy_free_port() -> int:
    """Select a currently free loopback port; the server bind is the arbiter."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _bouncy_port_occupied(port: int) -> bool:
    """Connect-probe: a completed connection means the port is owned already."""
    import socket

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(2)
        return probe.connect_ex(("127.0.0.1", port)) == 0
    finally:
        probe.close()


def _bouncy_http(
    method: str,
    url: str,
    payload: dict | None,
    timeout: int,
    *,
    expect_json: bool = True,
) -> object:
    """One management call, no retries; failures preserve status and reason."""
    import urllib.error
    import urllib.request

    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise ValueError(
                    f"management {method} {url} returned {response.status}"
                )
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("management response exceeds 1 MiB bound")
            if not expect_json:
                return raw.decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as error:
        raise ValueError(f"management {method} {url} returned {error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ValueError(
            f"management {method} {url} failed ({type(error).__name__})"
        ) from error


def _bouncy_probe_slots(
    probe: Path, module: Path, port: int, *, timeout: int
) -> tuple[int, int]:
    """Run the shipped probe; native errors are preserved, never normalized."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("BOUNCY_", "LD_", "P11LAB_"))
    }
    try:
        completed = subprocess.run(
            [
                str(probe),
                "--module",
                str(module),
                "--server",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as error:
        raise NativeStageTimeout("native slot probe timed out") from error
    if completed.returncode:
        detail = (completed.stderr.strip() or completed.stdout.strip())[:500]
        raise ValueError("native slot probe failed: " + detail)
    fields = {}
    for token in completed.stdout.strip().split():
        if "=" in token:
            key, _, value = token.partition("=")
            fields[key] = value
    try:
        return int(fields["slots"]), int(fields["present"])
    except (KeyError, ValueError) as error:
        raise ValueError("native slot probe returned unparsable output") from error


def _bouncy_label(inputs: dict, descriptor: dict) -> str:
    label = inputs.get("P11LAB_LABEL", "P11Lab")
    if (
        not label
        or len(label) > 32
        or any(
            c
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-"
            for c in label
        )
    ):
        raise ValueError(
            "label must use printable ASCII letters, digits, spaces, dot, underscore or hyphen within 32 bytes"
        )
    return label


def _bouncy_marker(manifest_sha256: str, label: str, slot: int) -> str:
    return (
        "schema=1\nprovider=bouncyhsm\nartifact="
        + manifest_sha256
        + "\nlabel="
        + label
        + "\nslot="
        + str(slot)
        + "\nbackend=litedb\n"
    )


class NativeStageTimeout(TimeoutError):
    """The lifecycle deadline expired; preserve stage and exit 124."""


def _bouncy_static_state(state: Path, manifest_sha256: str, label: str) -> int | None:
    """Validate the original state before LiteDB can open or create anything."""
    if state.is_symlink() or (state.exists() and not state.is_dir()):
        raise ValueError('partial or unsafe state')
    if not state.exists() or not any(state.iterdir()):
        return None
    if {p.name for p in state.iterdir()} != {'bouncyhsm'}:
        raise ValueError('partial state: unknown files or initialization lock')
    owned = state / 'bouncyhsm'
    if owned.is_symlink() or not owned.is_dir():
        raise ValueError('partial or unsafe state')
    if hasattr(os, 'getuid') and owned.stat().st_uid != os.getuid():
        raise ValueError('state directory ownership mismatch')
    names = {p.name for p in owned.iterdir()}
    if not {'complete', 'BouncyHsm.db'} <= names or names - {'complete', 'BouncyHsm.db', 'BouncyHsm-log.db'}:
        raise ValueError('partial state: missing or unknown owned files')
    for path in owned.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError('partial state: database and marker must be regular files')
    marker = _read_bouncy_marker(owned / 'complete')
    match = re.fullmatch(rb'schema=1\nprovider=bouncyhsm\nartifact=[0-9a-f]{64}\nlabel=[^\r\n]*\nslot=([0-9]+)\nbackend=litedb\n', marker)
    if match is None:
        raise ValueError('incompatible non-secret initialization configuration')
    slot = int(match[1])
    if marker != _bouncy_marker(manifest_sha256, label, slot).encode():
        raise ValueError('incompatible non-secret initialization configuration')
    return slot


def _read_bouncy_marker(path: Path) -> bytes:
    with path.open('rb') as stream:
        return stream.read(4097)


def run_native_bouncyhsm(spec: RunSpec, installed: InstalledBundle) -> RunResult:
    """Supervise an owned BouncyHSM server and run one application against it.

    The caller artifact must equal the installed receipt artifact, and the
    installed payload is reverified before any provisioning. One token per
    state directory: existing compatible state is reused without credentials,
    anything foreign, ambiguous, or partial fails without reset. HTTP health
    alone is never readiness: every stage requires a native probe plus the
    provisioned slot. Only owned server/application trees are signaled.
    """
    if (
        spec.mode != "native"
        or spec.execution_location != "host"
        or spec.consumer_artifact
        or spec.client_artifact
    ):
        raise ValueError(
            "native requires host execution without consumer/client container options"
        )
    if spec.artifact != installed.artifact:
        raise ValueError("run artifact differs from installed artifact")
    if (
        spec.installed_prefix is not None
        and spec.installed_prefix.resolve() != installed.prefix.resolve()
    ):
        raise ValueError("run installed prefix differs from selected installation")
    if (
        spec.artifact.platform not in ("linux/amd64", "windows/amd64")
        or not spec.argv
        or any(not isinstance(a, str) or "\0" in a for a in spec.argv)
    ):
        raise ValueError(
            "native requires linux/amd64 or windows/amd64 and literal application argv"
        )
    if spec.timeout_seconds <= 0 or not spec.cwd.is_dir() or spec.output_dir.exists():
        raise ValueError(
            "positive timeout, caller cwd and fresh output directory required"
        )
    installed = read_installation(
        installed.prefix,
        **_selection(spec.environment, spec.channel, spec.artifact.platform),
    )
    if installed.artifact != spec.artifact:
        raise ValueError("verified receipt artifact differs from run artifact")
    descriptor = _validate_bouncyhsm_manifest(
        installed.manifest, spec.environment, spec.channel
    )
    unknown = set(spec.inputs) - set(descriptor["inputs"]) - set(BOUNCY_NATIVE_EXTRAS)
    if unknown or any(
        not isinstance(v, str) or any(c in v for c in "\n\r\0")
        for v in spec.inputs.values()
    ):
        raise ValueError("native inputs must be allowlisted single-line strings")
    for name in ("P11LAB_PIN", "P11LAB_SO_PIN"):
        if name in spec.inputs and name + "_FILE" in spec.inputs:
            raise ValueError("conflicting scalar/file credential inputs")
    label = _bouncy_label(spec.inputs, descriptor)
    ports = {}
    for key, name in (("P11LAB_HTTP_PORT", "http"), ("P11LAB_TCP_PORT", "tcp")):
        if key in spec.inputs:
            try:
                ports[name] = int(spec.inputs[key])
            except ValueError:
                raise ValueError(f"{key} must be a TCP port number") from None
            if not 1 <= ports[name] <= 65535:
                raise ValueError(f"{key} must be a TCP port number")
    if "http" not in ports:
        ports["http"] = _bouncy_free_port()
    if "tcp" not in ports:
        candidate = _bouncy_free_port()
        if candidate == ports["http"]:
            candidate = _bouncy_free_port()
        ports["tcp"] = candidate
    if ports["http"] == ports["tcp"]:
        raise ValueError("HTTP and native TCP ports must differ")
    # Refuse an occupied requested endpoint instead of attaching to it. This
    # runs before any output, state, or server side effect.
    for name in ("http", "tcp"):
        if _bouncy_port_occupied(ports[name]):
            raise ValueError(f"requested {name} port is already occupied")
    output = spec.output_dir.resolve()
    cwd = spec.cwd.resolve()
    state = Path(spec.inputs.get("P11LAB_STATE_DIR", str(output / "state"))).resolve()
    control = Path(
        spec.inputs.get("P11LAB_CONTROL_DIR", str(output / "control"))
    ).resolve()
    validate_writable_paths(installed.prefix, (state, control, output))
    if (
        state == control
        or state.is_relative_to(control)
        or control.is_relative_to(state)
    ):
        raise ValueError("state and control paths overlap")
    if "P11LAB_STATE_DIR" in spec.inputs and not state.is_dir():
        raise ValueError("explicit persistent state directory must already exist")
    # Validate credentials before resource creation; snapshot private file inputs.
    credentials, secrets = snapshot_credentials(spec.inputs, descriptor)
    original_slot = _bouncy_static_state(state, installed.manifest_sha256, label)
    runtime = preflight_bouncyhsm(installed.prefix, installed.manifest)
    output.mkdir(parents=True, mode=0o700)
    module = installed.prefix / "payload" / installed.manifest["module"]
    probe = installed.prefix / "payload" / installed.manifest["lifecycle"]["probe"]
    server_file = (
        installed.prefix / "payload" / installed.manifest["lifecycle"]["server"]
    )
    owned = state / "bouncyhsm"
    base = f"http://127.0.0.1:{ports['http']}"
    lifecycle: list = []
    cleanup: list = []
    stages: list = []
    app = None
    completed = False
    timed_out = False
    interrupted = 0
    slot: int | None = None
    deadline = time.monotonic() + spec.timeout_seconds
    handlers = {}

    def on_signal(number, frame):
        nonlocal interrupted
        interrupted = number

    if threading.current_thread() is threading.main_thread():
        for number in (signal.SIGINT, signal.SIGTERM):
            handlers[number] = signal.signal(number, on_signal)

    def redact(text: str) -> str:
        for secret in sorted(secrets, key=len, reverse=True):
            text = text.replace(secret, "[REDACTED]")
        return text

    active_phase = 'server-start'

    def remaining() -> float:
        if time.monotonic() >= deadline:
            raise NativeStageTimeout('native lifecycle deadline expired')
        return max(.01, deadline - time.monotonic())

    server = None
    server_log = None
    server_capture = None
    try:
        with tempfile.TemporaryDirectory(prefix="p11lab-bouncy-input-") as private:
            env = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith(
                    ("P11LAB_", "BOUNCY_", "DOTNET_", "ASPNETCORE_", "SOFTHSM", "LD_")
                )
            }
            env.update(
                {k: v for k, v in spec.inputs.items() if k in descriptor["inputs"]}
            )
            for key, data in credentials.items():
                if key.endswith("_FILE"):
                    snapshot = Path(private) / key
                    snapshot.write_bytes(data)
                    snapshot.chmod(0o600)
                    env[key] = str(snapshot)
            server_env = dict(
                env,
                ASPNETCORE_URLS=base,
                ASPNETCORE_ENVIRONMENT="Production",
                BouncyHsm_PersistenceStorageType="LiteDb",
                BouncyHsm_LiteDbPersistentRepositorySetup__DbFilePath=str(
                    owned / "BouncyHsm.db"
                ),
                BouncyHsm_BouncyHsmSetup__TcpEndpoint__Endpoint=(
                    f"127.0.0.1:{ports['tcp']}"
                ),
                DOTNET_CLI_TELEMETRY_OPTOUT="1",
                DOTNET_NOLOGO="1",
                DOTNET_ROLL_FORWARD="LatestPatch",
                # A private writable home keeps framework key/file probes
                # inside owned state on hosts without a usable HOME.
                HOME=str(control),
            )
            if spec.artifact.platform == "linux/amd64":
                server_argv = [runtime["dotnet"], str(server_file)]
            else:
                server_argv = [str(server_file)]
            control.mkdir(parents=True, mode=0o700)
            # The managed server never creates the database parent: health
            # opens LiteDB immediately, so the owned directory must exist
            # before launch on both fresh and reused state.
            try:
                owned.mkdir(parents=True, mode=0o700, exist_ok=True)
            except OSError as error:
                raise ValueError("partial or unsafe state") from error
            # Keep the opened descriptor; an application cannot redirect final capture.
            fd = os.open(control / 'server.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            server_log = os.fdopen(fd, 'wb')
            start = time.monotonic()
            try:
                server_capture = SupervisedProcess(server_argv, cwd=server_file.parent, env=server_env)
                server = server_capture.process
            except OSError as error:
                raise ValueError("owned server launch failed") from error
            stages.append(
                {
                    "phase": "server-start",
                    "pid": server.pid,
                    "http_port": ports["http"],
                    "tcp_port": ports["tcp"],
                    "elapsed_seconds": round(time.monotonic() - start, 3),
                }
            )

            def server_alive() -> bool:
                return server_capture is not None and server_capture.poll() is None

            def await_health() -> None:
                """Bounded HTTP wait; native proof always follows separately."""
                while time.monotonic() < deadline and not interrupted:
                    if not server_alive():
                        raise ValueError("owned server exited before becoming ready")
                    try:
                        _bouncy_http(
                            "GET", base + "/health", None, min(5, remaining()), expect_json=False
                        )
                        return
                    except ValueError:
                        time.sleep(0.3)
                if interrupted:
                    raise ValueError("interrupted")
                raise NativeStageTimeout("owned server HTTP health did not become ready")

            def live_slot() -> int | None:
                """Single-slot policy: exactly our labeled slot, else refuse."""
                slots = _bouncy_http("GET", base + "/Slot", None, remaining())
                if not isinstance(slots, list):
                    raise ValueError("slot listing returned an unexpected shape")
                if not slots:
                    return None
                matches = [
                    entry
                    for entry in slots
                    if isinstance(entry, dict)
                    and isinstance(entry.get("Token"), dict)
                    and entry["Token"].get("Label") == label
                ]
                if len(slots) != 1 or len(matches) != 1:
                    raise ValueError("partial state: foreign or ambiguous slots")
                found = matches[0].get("SlotId")
                if not isinstance(found, int):
                    raise ValueError("slot listing returned an unexpected shape")
                return found

            def native_counts(expected):
                counts = _bouncy_probe_slots(probe, module, ports['tcp'], timeout=remaining())
                stages.append({'phase': active_phase + '-probe', 'native_probe': {'slots': counts[0], 'present': counts[1]}})
                if counts != expected:
                    raise ValueError('native slot counts contradict the single-token state contract')
                return counts

            def verify_state(expect: int | None) -> int:
                native_counts((1, 1))
                found = live_slot()
                if found is None:
                    raise ValueError("partial state: expected slot is absent")
                if expect is not None and found != expect:
                    raise ValueError(
                        "incompatible non-secret initialization configuration"
                    )
                marker = owned / "complete"
                if not marker.is_file() or marker.is_symlink() or _read_bouncy_marker(marker) != _bouncy_marker(
                    installed.manifest_sha256, label, found
                ).encode():
                    raise ValueError(
                        "incompatible non-secret initialization configuration"
                    )
                return found

            # init: reuse compatible state without credentials, else provision.
            state.mkdir(parents=True, mode=0o700, exist_ok=True)
            active_phase = 'init'
            if original_slot is not None:
                await_health()
                slot = verify_state(original_slot)
            else:
                pin = credentials.get("P11LAB_PIN_FILE", credentials.get("P11LAB_PIN"))
                so_pin = credentials.get(
                    "P11LAB_SO_PIN_FILE", credentials.get("P11LAB_SO_PIN")
                )
                if pin is None or so_pin is None:
                    raise ValueError("required credential input is absent")
                pin_text = credential_text(pin, file='P11LAB_PIN_FILE' in credentials)
                so_pin_text = credential_text(so_pin, file='P11LAB_SO_PIN_FILE' in credentials)
                try:
                    (state / ".init-lock").mkdir(exist_ok=False)
                except FileExistsError:
                    raise ValueError(
                        "state initialization is already in progress"
                    ) from None
                try:
                    await_health()
                    native_counts((0, 0))
                    if live_slot() is not None:
                        raise ValueError(
                            "partial state: refusing to provision over existing slots"
                        )
                    _bouncy_http(
                        "POST",
                        base + "/Slot",
                        {
                            "IsHwDevice": False,
                            "IsRemovableDevice": False,
                            "Description": label,
                            "Token": {
                                "Label": label,
                                "SerialNumber": "0001",
                                "SimulateHwRng": True,
                                "SimulateHwMechanism": True,
                                "SimulateQualifiedArea": False,
                                "SimulateProtectedAuthPath": False,
                                "SpeedMode": "WithoutRestriction",
                                "UserPin": pin_text,
                                "SoPin": so_pin_text,
                            },
                        },
                        remaining(),
                    )
                    slot = live_slot()
                    if slot is None:
                        raise ValueError("slot provisioning failed")
                    owned.mkdir(mode=0o700, exist_ok=True)
                    staging = owned / ".complete.staging"
                    staging.write_bytes(
                        _bouncy_marker(installed.manifest_sha256, label, slot).encode()
                    )
                    staging.replace(owned / "complete")
                finally:
                    (state / ".init-lock").rmdir()
            stages.append({"phase": "init", "slot": slot})
            active_phase = 'ready'
            # ready: HTTP health, native operation, provisioned slot.
            _bouncy_http("GET", base + "/health", None, remaining(), expect_json=False)
            slot = verify_state(slot)
            stages.append({"phase": "ready", "slot": slot})
            # application: exact argv with the provisioned module and transport.
            app_env = dict(
                env,
                P11LAB_OUTPUT_DIR=str(output),
                P11LAB_MODULE=str(module),
                BOUNCY_HSM_CFG_STRING=f"Server=127.0.0.1;Port={ports['tcp']};",
            )
            active_phase = 'application'
            status, stage_timeout, owner, logs = supervised_exec(
                list(spec.argv), cwd=cwd, env=app_env, timeout=remaining(), interrupted=lambda: interrupted)
            process = owner.process
            logs.update(write_process_logs(owner, output, 'application', secrets))
            if not logs['drain_complete'] or logs['stragglers_remaining'] or logs['supervision_errors']:
                lifecycle.append('application supervision incomplete')
            timed_out |= stage_timeout
            app = status
            completed = not stage_timeout and not interrupted and logs['drain_complete'] and not logs['stragglers_remaining'] and not logs['supervision_errors']
            stages.append(
                {
                    "phase": "application",
                    "pid": process.pid,
                    "returncode": status,
                    "timed_out": stage_timeout,
                    **logs,
                }
            )
            if stage_timeout or interrupted:
                lifecycle.append("interrupted" if interrupted else "timeout")
            else:
                active_phase = 'post-health'
                # post-health: the provisioned slot survives the application.
                _bouncy_http(
                    "GET", base + "/health", None, remaining(), expect_json=False
                )
                verify_state(slot)
                stages.append({"phase": "post-health", "slot": slot})
    except NativeStageTimeout as error:
        timed_out = True
        lifecycle.append(redact(str(error)))
        stages.append({'phase': active_phase, 'timed_out': True, 'returncode': 124})
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        lifecycle.append(
            "native runner operation failed ("
            + type(error).__name__
            + "): "
            + redact(str(error))[:300]
        )
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
        if server_capture is not None:
            server_evidence = server_capture.finish(stop=True)
            if not server_evidence['drain_complete'] or server_evidence['stragglers_remaining'] or server_evidence['supervision_errors']:
                cleanup.append('owned server supervision incomplete')
            if _bouncy_port_occupied(ports['tcp']) or _bouncy_port_occupied(ports['http']):
                cleanup.append('owned server endpoints are still occupied')
            stages.append({'phase': 'server-stop', 'pid': server.pid, **server_evidence})
        if server_log is not None:
            if server_capture is not None:
                # Combined durable bound is one MiB, not one MiB per stream.
                captured = bytes(server_capture.capture.buffers[0]) + bytes(server_capture.capture.buffers[1])
                truncated = any(server_capture.capture.truncated) or len(captured) > 1024 * 1024
                text, truncated = bounded_redacted(captured[:1024 * 1024], secrets, truncated)
                server_log.write(text.encode())
                stages[-1]['server_log_truncated'] = truncated
            server_log.close()
    code = (
        app
        if completed and app
        else 128 + interrupted
        if interrupted
        else 124
        if timed_out
        else app
        if app
        else 1
        if lifecycle or cleanup
        else 0
    )
    receipt = output / "receipt.json"
    write_receipt(
        receipt,
        {
            "schema_version": 1,
            "attempt_id": uuid4().hex,
            "environment": spec.environment,
            "channel": spec.channel,
            "mode": "native",
            "execution_location": "host",
            "artifacts": {
                "provider": asdict(spec.artifact),
                "consumer": None,
                "client": None,
            },
            "installation": {
                "prefix": str(installed.prefix),
                "manifest_sha256": installed.manifest_sha256,
                "receipt_path": str(installed.receipt_path),
                "receipt_sha256": installed.receipt_sha256,
            },
            "runtime": runtime,
            "execution": {
                "module": str(
                    installed.prefix / "payload" / installed.manifest["module"]
                ),
                "server": str(
                    installed.prefix
                    / "payload"
                    / installed.manifest["lifecycle"]["server"]
                ),
                "probe": str(
                    installed.prefix
                    / "payload"
                    / installed.manifest["lifecycle"]["probe"]
                ),
                "http_port": ports["http"],
                "tcp_port": ports["tcp"],
                "cwd": str(cwd),
                "argv_count": len(spec.argv),
            },
            "state": {
                "path": str(state),
                "control": str(control),
                "persistent_caller_directory": "P11LAB_STATE_DIR" in spec.inputs,
                "slot": slot,
                "label": label,
            },
            "stages": stages,
            "app_returncode": app,
            "app_completed": completed,
            "timeout": timed_out,
            "interrupted_signal": interrupted,
            "lifecycle_errors": lifecycle,
            "cleanup_errors": cleanup,
            "exit_code": code,
        },
    )
    return RunResult(app, tuple(lifecycle), tuple(cleanup), code, receipt)


# Per-environment native lifecycles wired through `p11lab run`/`install`.
# Each entry is (install, preflight, run); the install/run entry points own
# their provider-specific target contract, so the generic CLI/runner path
# carries no provider constants. Environments without an entry are not
# executable natively, independent of their catalogue packaging status.
NATIVE_LIFECYCLES = {
    "softhsm2": (install_native_bundle, preflight_native, run_native_softhsm),
    "bouncyhsm": (install_bouncyhsm_bundle, preflight_bouncyhsm, run_native_bouncyhsm),
}

# Human-readable install report of each lifecycle's runtime configuration
# location. Keys always match NATIVE_LIFECYCLES (test-enforced).
NATIVE_CONFIGURATION = {
    "softhsm2": "chosen control directory/softhsm2.conf at runtime",
    "bouncyhsm": "chosen control directory (managed server home and log) at runtime",
}


def native_lifecycle(environment: str):
    """Return the (install, preflight, run) lifecycle for a native environment."""
    try:
        return NATIVE_LIFECYCLES[environment]
    except KeyError:
        raise ValueError(
            f"native execution is not packaged for environment: {environment}"
        ) from None
