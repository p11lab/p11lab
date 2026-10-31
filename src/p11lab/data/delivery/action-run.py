#!/usr/bin/env python3
"""Reusable-action core: fetch a handoff by digest and run the caller app.

Invoked by action.yml after p11lab and ORAS are installed. All acquisition
uses immutable digest references; tags are never trusted. The child `p11lab
run` receives a scrubbed environment plus only the declared provider inputs:
the host environment and publisher credentials are never forwarded into
providers. The application exit code propagates unchanged.
"""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
import signal
import time
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


# OS essentials allowed into the child process; everything else (including
# CI/publisher credentials) stays outside the provider boundary.
ALLOWED_ENV = {"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR",
               "USERPROFILE", "COMSPEC", "LANG", "LC_ALL", "TZ"}


def _is_loopback(registry: str) -> bool:
    host = urlsplit("//" + registry).hostname or ""
    return host in {"localhost", "127.0.0.1", "::1"}


def _local_proof_allowed() -> bool:
    """--local-proof overrides a blocked verdict for local mechanics only.

    Pasting the flag into a CI debug step would silently run blocked or
    unreviewed content, so any CI marker refuses it. Locality beyond the
    CI markers (loopback-only, no push) stays the operator's job.
    """
    return not os.environ.get("CI") and not os.environ.get("GITHUB_ACTIONS")


def _display(argv):
    """Render argv for logs with `--input` values redacted to names only.

    Provider inputs travel as `--input NAME=VALUE`; values may be secrets
    when callers pass them inline instead of by file path, so logs carry
    `NAME=***` while the executed argv keeps the real values.
    """
    shown = []
    mask = False
    index = 0
    total = len(argv)
    while index < total:
        word = argv[index]
        if word == "--":
            # Everything past the separator is consumer argv, which may
            # carry inline secrets: name the executable, count the rest.
            rest = argv[index + 1:]
            shown.append("--")
            if rest:
                shown.append(rest[0])
                shown.append(f"({len(rest) - 1} args)")
            return shown
        if mask:
            shown.append(word.split("=", 1)[0] + "=***")
            mask = False
        elif word == "--input":
            shown.append(word)
            mask = True
        elif word.startswith("--input="):
            shown.append("--input=" + word[len("--input="):].split("=", 1)[0] + "=***")
        else:
            shown.append(word)
        index += 1
    return shown


# Separate finite acquisition bounds leave the public timeout's lifecycle meaning intact.
ACQUISITION_TIMEOUT = 300
CLEANUP_GRACE = 180
_active_signals = None


@contextmanager
def _signal_scope():
    global _active_signals
    if _active_signals is not None:
        yield _active_signals
        return
    state = {"number": None}
    previous = {}
    def received(number, frame):
        # First cancellation wins; repeated signals must not bypass owned cleanup.
        if state["number"] is None:
            state["number"] = number
    try:
        numbers = [signal.SIGINT, signal.SIGTERM]
        if hasattr(signal, "SIGHUP"):
            numbers.append(signal.SIGHUP)
        for number in numbers:
            previous[number] = signal.signal(number, received)
        _active_signals = state
        yield state
    finally:
        _active_signals = None
        for number, handler in previous.items():
            signal.signal(number, handler)


def _capture(argv, *, env, cwd, timeout=ACQUISITION_TIMEOUT, lifecycle=False):
    """Bound owned calls without killing the lifecycle before its cleanup grace.

    Shared SupervisedProcess owns capture, descendant identity and final reaping.
    Forward to the immediate lifecycle PID first: it owns Docker state and must
    handle cancellation itself. Only an unresponsive child exhausts the grace.
    A lifecycle owns its normal final status, including during cleanup;
    acquisition deadline expiry remains a wrapper timeout.
    """
    from p11lab.process import SupervisedProcess
    with _signal_scope() as state:
        if state["number"]:
            return subprocess.CompletedProcess(argv, 128 + state["number"], b"", b"")
        try:
            owner = SupervisedProcess(argv, env=env, cwd=cwd)
        except OSError as error:
            # Never print argv, env or arbitrary exception text containing secrets.
            print(f"action-run: cannot start executable ({type(error).__name__}, errno={error.errno})",
                  file=sys.stderr)
            return subprocess.CompletedProcess(argv, 127, b"", b"")
        deadline = time.monotonic() + timeout
        forwarded = None
        timed_out = False
        try:
            while owner.poll() is None:
                number = state["number"]
                if forwarded is None and (number or time.monotonic() >= deadline):
                    timed_out = not bool(number)
                    if timed_out:
                        print("action-run: owned child deadline expired; requesting cleanup", file=sys.stderr)
                    forwarded = number or signal.SIGTERM
                    try:
                        owner.process.send_signal(forwarded)
                    except ProcessLookupError:
                        pass
                    deadline = time.monotonic() + CLEANUP_GRACE
                elif forwarded is not None and time.monotonic() >= deadline:
                    print("action-run: owned child exceeded cleanup grace; forcing owned-tree cleanup", file=sys.stderr)
                    break
                time.sleep(.02)
        finally:
            evidence = owner.finish(stop=owner.process.poll() is None, timed_out=timed_out)
        incomplete = (evidence["supervision_errors"] or evidence["stragglers_remaining"]
                      or evidence["stragglers_detected"] or not evidence["drain_complete"])
        if incomplete:
            print("action-run: owned child supervision incomplete", file=sys.stderr)
        for index, name in enumerate(("stdout", "stderr")):
            if owner.capture.truncated[index]:
                print(f"action-run: {name} capture truncated at 1 MiB", file=sys.stderr)
        code = owner.process.returncode
        # The shared lifecycle owns completed-app precedence, including a normal
        # exit during watchdog cleanup or the final soft stop. An actual signal
        # termination (negative status) or missing status supplies no native result.
        native_result = lifecycle and code is not None and code >= 0
        code = 124 if timed_out and not native_result else code if code is not None and code >= 0 else 128 - code if code else 1
        if incomplete and code == 0:
            code = 1
        return subprocess.CompletedProcess(argv, code, bytes(owner.capture.buffers[0]), bytes(owner.capture.buffers[1]))


def _run(argv, *, env, cwd):
    print("+ " + " ".join(_display(argv)), flush=True)
    lifecycle = argv[1:4] == ["-m", "p11lab", "run"]
    timeout = int(argv[argv.index("--timeout") + 1]) + CLEANUP_GRACE if lifecycle else ACQUISITION_TIMEOUT
    result = _capture(argv, env=env, cwd=cwd, timeout=timeout, lifecycle=lifecycle)
    print(result.stdout.decode("utf-8", "replace"), end="")
    print(result.stderr.decode("utf-8", "replace"), end="", file=sys.stderr)
    return result.returncode


def resolve_caller_working_directory(workspace, requested):
    """Resolve the declared relative path before any remote acquisition."""
    if Path(requested).is_absolute():
        raise ValueError("working-directory must be relative to the caller checkout")
    root = Path(workspace).resolve(strict=True)
    work = (root / requested).resolve(strict=True)
    if not root.is_dir() or not work.is_dir() or not work.is_relative_to(root):
        raise ValueError("working-directory must resolve inside the caller checkout")
    return work


def _emit_outputs(outputs):
    text = "".join(f"{key}={value}\n" for key, value in outputs.items())
    if output_file := os.environ.get("GITHUB_OUTPUT"):
        with open(output_file, "a", encoding="utf-8") as stream:
            stream.write(text)
    if not outputs["receipt-path"]:
        message = "action-run: evidence incomplete: no validated lifecycle receipt"
        print(message, file=sys.stderr)
        if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(summary, "a", encoding="utf-8") as stream:
                stream.write(message + "\n")
    print(json.dumps(outputs, indent=2, sort_keys=True))


def _finalize(run_dir, outputs):
    text = "".join(f"{key}={value}\n" for key, value in outputs.items())
    (run_dir / "action-outputs.env").write_text(text, encoding="utf-8")
    _emit_outputs(outputs)


def _regular(path, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("unsafe evidence path")


def collect(directory):
    """Always emit the four outputs; revalidate selected evidence at collection.

    Fresh invocation directories bind attempts. These host-side shape checks do
    not authenticate receipts against a malicious process controlling the host.
    """
    outputs = {"exit-code": "1", "app-returncode": "", "receipt-path": "", "handoff-sha256": ""}
    try:
        if not directory:
            raise ValueError("no attempt directory")
        run_dir = Path(directory)
        _regular(run_dir.parent, directory=True)
        _regular(run_dir, directory=True)
        path = run_dir / "action-outputs.env"
        _regular(path)
        lines = path.read_text(encoding="utf-8").splitlines()
        pairs = [line.split("=", 1) for line in lines]
        if len(pairs) != 4 or any(len(pair) != 2 for pair in pairs):
            raise ValueError("malformed output record")
        recorded = dict(pairs)
        if set(recorded) != set(outputs) or not re.fullmatch(r"[0-9]{1,3}", recorded["exit-code"]) \
                or int(recorded["exit-code"]) > 255 \
                or not re.fullmatch(r"(?:[0-9a-f]{64})?", recorded["handoff-sha256"]):
            raise ValueError("invalid output fields")
        outputs.update(recorded)
        outputs["receipt-path"] = outputs["app-returncode"] = ""
        if recorded["receipt-path"]:
            receipt = run_dir / "run-output" / "receipt.json"
            if recorded["receipt-path"] != str(receipt):
                raise ValueError("unexpected receipt path")
            context_path = run_dir / "action-context.json"
            _regular(context_path)
            context = json.loads(context_path.read_text(encoding="utf-8"))
            selected, app_code = _receipt_outputs(receipt, values=context["values"], provider=context["provider"],
                                                  code=int(outputs["exit-code"]))
            if app_code != recorded["app-returncode"]:
                raise ValueError("changed receipt")
            outputs.update({"receipt-path": selected, "app-returncode": app_code})
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        outputs = {"exit-code": "1", "app-returncode": "", "receipt-path": "", "handoff-sha256": ""}
        print("action-run: output evidence absent, unsafe or malformed", file=sys.stderr)
    _emit_outputs(outputs)
    return int(outputs["exit-code"])


class _AcquisitionFailure(Exception):
    def __init__(self, code):
        self.code = code


def _acquisition_failure(code):
    if _active_signals and _active_signals["number"]:
        return 128 + _active_signals["number"]
    return 124 if code == 124 else 1


def _receipt_outputs(receipt, *, values, provider, code):
    """Export only a regular, complete receipt bound to this invocation.

    These are the core schema-v1 fields written by run.py and the native
    lifecycle writers, not authenticity verification of caller-controlled
    host processes. Native receipts have an attempt ID but no run ID.
    """
    def require(condition):
        if not condition:
            raise ValueError("invalid run receipt")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("non-finite receipt value")

    try:
        for path, expected_type in ((receipt.parent, stat.S_ISDIR), (receipt, stat.S_ISREG)):
            info = path.lstat()
            require(expected_type(info.st_mode)
                    and not getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        record = json.loads(receipt.read_text(encoding="utf-8"),
                            object_pairs_hook=unique_pairs, parse_constant=reject_constant)
        require(isinstance(record, dict))
        required = {"schema_version", "attempt_id", "environment", "channel", "mode",
                    "execution_location", "artifacts", "execution", "state", "stages",
                    "app_returncode", "app_completed", "timeout", "interrupted_signal",
                    "lifecycle_errors", "cleanup_errors", "exit_code"}
        require(required <= record.keys())
        require(type(record["schema_version"]) is int and record["schema_version"] == 1)
        require(all(record[key] == values[key] for key in ("environment", "channel", "mode")))
        require(record["execution_location"] == ("provider" if values["mode"] == "direct" else "host"))
        require(isinstance(record["attempt_id"], str) and re.fullmatch(r"[0-9a-f]{32}", record["attempt_id"]))
        require(record["artifacts"] == {"provider": provider, "consumer": None, "client": None})
        require(type(record["exit_code"]) is int and record["exit_code"] == code)
        require(record["app_returncode"] is None or type(record["app_returncode"]) is int)
        require(type(record["app_completed"]) is bool and type(record["timeout"]) is bool)
        require(record["interrupted_signal"] is None or type(record["interrupted_signal"]) is int)
        require(all(isinstance(record[key], dict) for key in ("execution", "state")))
        require(type(record["execution"].get("argv_count")) is int
                and record["execution"]["argv_count"] == len(values["command_argv"]))
        require(isinstance(record["stages"], list) and all(isinstance(stage, dict) for stage in record["stages"]))
        require(all(isinstance(record[key], list) and all(isinstance(error, str) for error in record[key])
                    for key in ("lifecycle_errors", "cleanup_errors")))
        if values["mode"] == "direct":
            require(isinstance(record.get("run_id"), str) and re.fullmatch(r"[0-9a-f]{32}", record["run_id"]))
            observation = record.get("image_observation")
            require(isinstance(observation, dict) and observation.get("Id") == provider["reference"]
                    and observation.get("platform") == provider["platform"])
            require(isinstance(record.get("inputs"), dict))
            require(all(isinstance(record.get(key), list) and all(isinstance(item, dict) for item in record[key])
                        for key in ("owned_resources", "uncertain_resources")))
        else:
            require(all(isinstance(record.get(key), dict) for key in ("installation", "runtime")))
    except FileNotFoundError:
        return "", ""
    except (OSError, ValueError, RecursionError):
        print("action-run: receipt is unsafe, malformed, or does not match this invocation; not exporting it",
              file=sys.stderr)
        return "", ""
    return str(receipt), "" if record["app_returncode"] is None else str(record["app_returncode"])


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--collect":
        collector = argparse.ArgumentParser(description="Collect this Action attempt's evidence.")
        collector.add_argument("--collect", required=True)
        return collect(collector.parse_args(argv).collect)
    parser = argparse.ArgumentParser(description="Run a caller app from a P11Lab handoff.")
    parser.add_argument("--environment", required=True)
    parser.add_argument("--channel", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--handoff-digest", required=True)
    parser.add_argument("--transport-evidence-digest", default="")
    parser.add_argument("--promotion-evidence-digest", default="")
    parser.add_argument("--evidence-registry", default="")
    parser.add_argument("--command", required=True)
    parser.add_argument("--inputs", default="")
    parser.add_argument("--state-dir", default="")
    parser.add_argument("--timeout", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--working-directory", required=True)
    parser.add_argument("--oras", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--local-proof", action="store_true",
                        help="Proceed past a blocked verdict for local mechanics proof only; never used by action.yml.")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except OSError:
        print(f"action-run: run directory must be fresh and writable: {run_dir}", file=sys.stderr)
        return 2
    outputs = {"exit-code": "1", "app-returncode": "", "receipt-path": "", "handoff-sha256": ""}
    with _signal_scope():
        try:
            code = _attempt(args, run_dir, outputs)
        except (OSError, ValueError) as error:
            print(f"action-run: attempt failed ({type(error).__name__})", file=sys.stderr)
            code = 1
        outputs["exit-code"] = str(code)
        _finalize(run_dir, outputs)
        return code


def _fetch_evidence(oras, auth, plain_http, work, run_dir, values):
    """Pull evidence packages and provision the sealed verifier for the gate.

    Returns None when both digests are empty (the gate refuses the
    unproven handoff), else the gate kwargs with absent legs as None so
    the gate refuses with its typed texts. Raises _AcquisitionFailure on
    pull/provisioning failure and ValueError on a non-digest evidence
    reference (never a tag).
    """
    from p11lab.acquisition import TRUSTED_ROOT
    from p11lab.promotion import PROMOTION_TRUSTED_ROOT
    from p11lab.publish import require_digest_reference
    digests = (values["transport-evidence-digest"], values["promotion-evidence-digest"])
    if not digests[0] and not digests[1]:
        return None
    registry = values["evidence_registry"]
    refs = [registry + "@" + digest if digest else None for digest in digests]
    for ref in refs:
        if ref is not None:
            require_digest_reference(ref)
    pulled = []
    for name, ref in (("transport-evidence", refs[0]), ("promotion-evidence", refs[1])):
        if ref is None:
            pulled.append(None)
            continue
        target = run_dir / name
        target.mkdir()
        code = _run([oras, "pull", "--registry-config", str(auth), "--no-tty", "-o", str(target),
                     *plain_http, ref], env=dict(os.environ), cwd=str(work))
        if code:
            print(f"action-run: anonymous {name} fetch failed", file=sys.stderr)
            raise _AcquisitionFailure(code)
        pulled.append(target)
    # The sealed gh verifier is provisioned per attempt from the packaged
    # installer; the gate still enforces the executable pin before running
    # it, so installer compromise fails closed. The installer deliberately
    # carries no `--noproxy` flag (unlike the provider-delivery.yml:170
    # pipeline download): proxy bypass is runner-specific, and a user-side
    # installer must respect proxy environment — hence the full environment
    # here instead of the scrubbed child env. Do not "repair" the gap.
    installer = Path(__file__).resolve().parent / "install-gh.sh"
    verifier_dir = run_dir / "verifier"
    installed = _capture(["sh", str(installer), "--output-dir", str(verifier_dir)],
                         env=dict(os.environ), cwd=str(work))
    if installed.returncode:
        print(installed.stderr.decode("utf-8", "replace"), end="", file=sys.stderr)
        print("action-run: sealed verifier provisioning failed", file=sys.stderr)
        raise _AcquisitionFailure(installed.returncode)
    lines = installed.stdout.decode("utf-8", "replace").strip().splitlines()
    if not lines:
        print("action-run: sealed verifier provisioning produced no path", file=sys.stderr)
        raise _AcquisitionFailure(1)
    executable = Path(lines[-1])
    legs = ((pulled[0], "evidence_dir", "executable", "trusted_root", "output_dir",
             TRUSTED_ROOT, "transport-staging"),
            (pulled[1], "promotion_dir", "promotion_executable", "promotion_trusted_root",
             "promotion_output_dir", PROMOTION_TRUSTED_ROOT, "promotion-staging"))
    kwargs = {}
    for directory, dir_key, exe_key, root_key, out_key, member, staging in legs:
        if directory is None:
            kwargs[dir_key] = kwargs[exe_key] = kwargs[root_key] = kwargs[out_key] = None
        else:
            kwargs[dir_key] = directory
            kwargs[exe_key] = executable
            kwargs[root_key] = directory / member
            kwargs[out_key] = run_dir / staging
    return kwargs


def _attempt(args, run_dir, outputs):
    from p11lab.publish import (require_digest_reference, require_eligible_handoff, show_handoff,
                                validate_action_inputs, verify_acquired_image, verify_acquired_bundle)

    try:
        values = validate_action_inputs({
            "environment": args.environment, "channel": args.channel, "mode": args.mode,
            "registry": args.registry, "handoff-digest": args.handoff_digest, "command": args.command,
            "inputs": args.inputs, "state-dir": args.state_dir, "timeout": args.timeout,
            "working-directory": args.working_directory,
            "transport-evidence-digest": args.transport_evidence_digest,
            "promotion-evidence-digest": args.promotion_evidence_digest,
            "evidence-registry": args.evidence_registry})
    except ValueError as error:
        print(f"action-run: {error}", file=sys.stderr)
        return 2
    if os.name == "nt" and values["mode"] == "direct":
        print("action-run: direct mode requires Linux runners with Docker", file=sys.stderr)
        return 2
    try:
        work = resolve_caller_working_directory(args.workspace, values["working-directory"])
    except (OSError, ValueError) as error:
        print(f"action-run: working directory is missing or outside the caller checkout ({type(error).__name__})",
              file=sys.stderr)
        return 2
    oras = args.oras
    handoff_ref = values["registry"] + "@" + values["handoff-digest"]
    try:
        require_digest_reference(handoff_ref)
    except ValueError as error:
        print(f"action-run: {error}", file=sys.stderr)
        return 2
    plain_http = ["--plain-http"] if _is_loopback(values["registry"]) else []
    auth = run_dir / "oras-auth.json"
    auth.write_text('{"auths":{}}\n')
    handoff_dir = run_dir / "handoff"
    handoff_dir.mkdir()
    pull = [oras, "pull", "--registry-config", str(auth), "--no-tty", "-o", str(handoff_dir),
            *plain_http, handoff_ref]
    code = _run(pull, env=dict(os.environ), cwd=str(work))
    if code:
        print("action-run: anonymous handoff fetch failed", file=sys.stderr)
        return _acquisition_failure(code)
    handoff_file = handoff_dir / "handoff.json"
    if not handoff_file.is_file():
        print("action-run: pulled handoff has no handoff.json", file=sys.stderr)
        return 1
    try:
        handoff = show_handoff(handoff_file)
    except ValueError as error:
        print(f"action-run: {error}", file=sys.stderr)
        return 1
    outputs["handoff-sha256"] = hashlib.sha256(handoff_file.read_bytes()).hexdigest()
    catalogue = handoff["catalogue"]
    if handoff["registry"] != values["registry"] or catalogue["environment"] != values["environment"] \
            or catalogue["channel"] != values["channel"]:
        print("action-run: handoff binds a different registry/environment/channel", file=sys.stderr)
        return 1
    expected_role = "runtime" if values["mode"] == "direct" else "native"
    if catalogue.get("runtime_role") != expected_role:
        print(f"action-run: handoff runtime role {catalogue.get('runtime_role')} does not serve mode {values['mode']}",
              file=sys.stderr)
        return 1
    if args.local_proof:
        if not _local_proof_allowed():
            print("action-run: --local-proof refused: CI is set; local mechanics proof only", file=sys.stderr)
            return 1
        print("action-run: LOCAL-PROOF DIAGNOSTIC: no public acquisition eligibility asserted")
    else:
        try:
            evidence = _fetch_evidence(oras, auth, plain_http, work, run_dir, values)
        except _AcquisitionFailure as error:
            return _acquisition_failure(error.code)
        except ValueError as error:
            print(f"action-run: {error}", file=sys.stderr)
            return 2
        try:
            if evidence is None:
                # No evidence digests: the historical one-arg shape, which
                # the gate treats exactly as all-None kwargs (typed R4).
                require_eligible_handoff(handoff)
            else:
                require_eligible_handoff(
                    handoff, evidence["evidence_dir"], executable=evidence["executable"],
                    trusted_root=evidence["trusted_root"], output_dir=evidence["output_dir"],
                    promotion_dir=evidence["promotion_dir"],
                    promotion_executable=evidence["promotion_executable"],
                    promotion_trusted_root=evidence["promotion_trusted_root"],
                    promotion_output_dir=evidence["promotion_output_dir"])
        except ValueError as error:
            print(f"action-run: {error}", file=sys.stderr)
            return 1
    try:
        binary = require_digest_reference(handoff["binary"]["reference"])
    except ValueError as error:
        print(f"action-run: {error}", file=sys.stderr)
        return 1
    if binary["repository"] != values["registry"]:
        print("action-run: handoff binary points outside the selected registry", file=sys.stderr)
        return 1
    child_env = {key: value for key, value in os.environ.items() if key in ALLOWED_ENV}
    output_dir = run_dir / "run-output"
    command = [sys.executable, "-m", "p11lab", "run", values["environment"], "--channel", values["channel"],
               "--mode", values["mode"], "--output-dir", str(output_dir), "--cwd", str(work),
               "--timeout", str(values["timeout_seconds"])]
    if values["mode"] == "direct":
        docker_config = run_dir / "docker-config"
        docker_config.mkdir()
        fetch_env = dict(child_env, DOCKER_CONFIG=str(docker_config))
        code = _run(["docker", "pull", handoff["binary"]["reference"]], env=fetch_env, cwd=str(work))
        if code:
            print("action-run: anonymous binary pull failed", file=sys.stderr)
            return _acquisition_failure(code)
        inspected = _capture(["docker", "image", "inspect", handoff["binary"]["reference"]],
                             env=fetch_env, cwd=str(work))
        if inspected.returncode:
            print(inspected.stderr.decode("utf-8", "replace"), end="", file=sys.stderr)
            print("action-run: pulled binary inspect failed", file=sys.stderr)
            return _acquisition_failure(inspected.returncode)
        manifest_path = run_dir / "binary-manifest.json"
        selected_path = None
        try:
            def fetch_manifest(reference, path):
                result = _capture([oras, "manifest", "fetch", "--registry-config", str(auth),
                                   *plain_http, reference], env=dict(os.environ), cwd=str(work))
                if result.returncode:
                    print(result.stderr.decode("utf-8", "replace"), end="", file=sys.stderr)
                    print("action-run: anonymous binary manifest fetch failed", file=sys.stderr)
                    raise _AcquisitionFailure(result.returncode)
                path.write_bytes(result.stdout)
            fetch_manifest(handoff["binary"]["reference"], manifest_path)
            root = json.loads(manifest_path.read_bytes())
            if not isinstance(root, dict):
                raise ValueError("acquired binary manifest must be a JSON object")
            if root.get("mediaType") in {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}:
                selected_digest = handoff["binary"].get("platform_manifest_sha256", "")
                require_digest_reference(values["registry"] + "@sha256:" + selected_digest)
                selected_path = run_dir / "binary-platform-manifest.json"
                fetch_manifest(values["registry"] + "@sha256:" + selected_digest, selected_path)
            provider = verify_acquired_image(handoff, json.loads(inspected.stdout), manifest_path=manifest_path,
                                             platform_manifest_path=selected_path)
        except _AcquisitionFailure as error:
            return _acquisition_failure(error.code)
        except (ValueError, OSError, TypeError) as error:
            print(f"action-run: {error}", file=sys.stderr)
            return 1
        engine_id = provider["reference"]
        print(f"action-run: binary {handoff['binary']['reference']} resolves to verified engine {engine_id}")
        command += ["--artifact", engine_id]
        child_env = fetch_env
    else:
        bundle_dir = run_dir / "bundle"
        bundle_dir.mkdir()
        code = _run([oras, "pull", "--registry-config", str(auth), "--no-tty", "-o", str(bundle_dir),
                     *plain_http, handoff["binary"]["reference"]], env=dict(os.environ), cwd=str(work))
        if code:
            print("action-run: anonymous bundle pull failed", file=sys.stderr)
            return _acquisition_failure(code)
        archives = sorted(bundle_dir.glob("*.tar.gz"))
        if len(archives) != 1:
            print("action-run: pulled bundle must contain exactly one archive", file=sys.stderr)
            return 1
        try:
            provider = verify_acquired_bundle(handoff, archives[0])
        except ValueError as error:
            print(f"action-run: {error}", file=sys.stderr)
            return 1
        prefix = run_dir / "prefix"
        install = [sys.executable, "-m", "p11lab", "install", values["environment"],
                   "--channel", values["channel"], "--artifact", str(archives[0]),
                   "--sha256", handoff["binary"]["file_sha256"], "--platform", handoff["binary"]["platform"],
                   "--prefix", str(prefix)]
        print("+ " + " ".join(install), flush=True)
        installed = _capture(install, env=child_env, cwd=str(work))
        print(installed.stdout.decode("utf-8", "replace"), end="")
        if installed.returncode:
            print(installed.stderr.decode("utf-8", "replace"), end="", file=sys.stderr)
            print("action-run: native bundle installation failed", file=sys.stderr)
            return installed.returncode
        command += ["--installed-prefix", str(prefix), "--platform", handoff["binary"]["platform"]]
    for entry in values["input_entries"]:
        command += ["--input", entry]
    if values["state-dir"]:
        command += ["--state-dir", values["state-dir"]]
    command += ["--", *values["command_argv"]]
    print(f"action-run: inputs: {', '.join(e.split('=', 1)[0] for e in values['input_entries']) or '(none)'}")
    # Consumer argv may carry inline secrets: log the executable and the
    # argument count, never the arguments themselves.
    print(f"action-run: command: {values['command_argv'][0]} ({len(values['command_argv']) - 1} args)")
    # Persist only receipt-binding fields; consumer argv and provider inputs may
    # contain secrets and must never enter this collector context.
    context = {"values": {key: values[key] for key in ("environment", "channel", "mode")}, "provider": provider}
    context["values"]["command_argv"] = [""] * len(values["command_argv"])
    (run_dir / "action-context.json").write_text(json.dumps(context), encoding="utf-8")
    code = _run(command, env=child_env, cwd=str(work))
    receipt, app_returncode = _receipt_outputs(
        output_dir / "receipt.json", values=values, provider=provider, code=code)
    outputs.update({"app-returncode": app_returncode, "receipt-path": receipt})
    return code


if __name__ == "__main__":
    sys.exit(main())
