"""Explicit live local proof. No implicit skip/default Docker qualification.

Invoke with installed Python and three positional paths: verified W01 output,
this authority fixture directory, and a fresh retained proof directory.
"""

import hashlib
import io
import json
from pathlib import Path
import signal
import sys
import tarfile
import time

from p11lab.docker import Docker, DockerError
from p11lab.round_core.inputs import (
    LocalProducerEvent,
    ProtectedSelection,
    SealedToolInputs,
    VerifiedSource,
    freeze_candidate_context,
    freeze_comparison_expectation,
    digest,
)
from p11lab.round_core.worker import (
    SandboxPolicy,
    inspect_source_archive,
    produce_candidate,
    source_tree,
)

BASE = "sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c"
LAYER = "sha256:a6dc765193a52cbaede3c93a9ff48b9540948dd0774bbe7031fcb5847606f9ac"
sealed, fixtures, output = map(Path, sys.argv[1:4])
output.mkdir(parents=True, exist_ok=False)
tools = SealedToolInputs.from_evaluator(sealed)
expectation = freeze_comparison_expectation(
    json.loads((fixtures / "checker-authorized.json").read_bytes())[
        "protected_expected"
    ]
)
revision = expectation.as_dict()["protected"]["selected_candidate_source_sha"]
results = {}


class RecordingDocker(Docker):
    def command(self, args, timeout=15, *, check=True, **kwargs):
        observed = super().command(args, timeout, check=False, **kwargs)
        record = {
            "argv": args,
            "returncode": observed.returncode,
            "stdout": observed.stdout,
            "stderr": observed.stderr,
            "timed_out": observed.timed_out,
        }
        with (output / "docker-commands.jsonl").open("a") as stream:
            stream.write(json.dumps(record) + "\n")
        if check and (
            observed.returncode or observed.timed_out or observed.stdout_truncated
        ):
            raise DockerError("Docker operation failed: " + args[0])
        return observed


for case in sys.argv[4:] or (
    "success",
    "unsafe-output",
    "timeout",
    "cancel",
    "quota-bytes",
    "quota-inodes",
    "pth-exception",
    "pth-exception-noise",
):
    archive_path = output / (case + ".tar")
    with tarfile.open(archive_path, "w") as archive:
        for path in sorted((fixtures / "candidate").rglob("*")):
            if not path.is_file():
                continue
            content = path.read_bytes()
            if path.name == "backend.py":
                if case == "pth-exception-noise":
                    content = content.replace(
                        b"import runpy; runpy.run_path('/inputs/source/canary.py')['probe']('pth-startup')",
                        b"import sys; sys.stderr.write('x'*131072); raise RuntimeError('M05_REVIEW_STARTUP_FAILURE')",
                    )
                if case == "pth-exception":
                    content = content.replace(
                        b"import runpy; runpy.run_path('/inputs/source/canary.py')['probe']('pth-startup')",
                        b"import sys; raise RuntimeError('M05_REVIEW_STARTUP_FAILURE')",
                    )
                if case == "unsafe-output":
                    content += b"\nif not Path('/out/unsafe-link.json').is_symlink(): Path('/out/unsafe-link.json').symlink_to('/inputs/context.json')\n"
                if case == "quota-bytes":
                    content += b"\nfor i in range(2):\n with open('/out/large'+str(i), 'wb') as f:\n  for j in range(64): f.write(b'x'*1048576)\n"
                if case == "quota-inodes":
                    content += (
                        b"\nfor i in range(10001): Path('/out/inode'+str(i)).touch()\n"
                    )
                if case in ("timeout", "cancel"):
                    content += b"\nimport time\ntime.sleep(120)\n"
            entry = tarfile.TarInfo(path.relative_to(fixtures / "candidate").as_posix())
            entry.size = len(content)
            entry.mode = (
                0o400
                if path.name == "credential"
                else 0o444
                if path.name == "GITHUB_OUTPUT"
                else 0o644
            )
            archive.addfile(entry, io.BytesIO(content))
    source = VerifiedSource(
        archive_path,
        hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        revision,
        source_tree(archive_path),
        inspect_source_archive(archive_path),
    )
    context = freeze_candidate_context(
        ProtectedSelection(
            expectation,
            BASE,
            (LAYER,),
            1,
            digest(
                {
                    "Env": [
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                    ],
                    "Cmd": ["bash"],
                }
            ),
        ),
        LocalProducerEvent(
            "https://github.com/p11lab/synthetic-authority-fixture", revision, case
        ),
        source,
        tools,
    )
    policy = SandboxPolicy(
        "authority_canary-0.0.0-py3-none-any.whl",
        ("backend-import.json", "backend-hook.json"),
        () if case.startswith("pth-exception") else ("pth-startup.json",),
        timeout_seconds=3 if case == "timeout" else 45,
    )
    started = time.monotonic()

    def cancelled():
        return (
            signal.SIGINT
            if case == "cancel" and time.monotonic() - started > 4
            else None
        )

    result = produce_candidate(
        context, policy, output / case, interrupted=cancelled, engine=RecordingDocker()
    )
    engine = Docker()
    absent = {
        row["container_id"]: engine.command(
            ["container", "inspect", row["container_id"]], check=False
        ).returncode
        != 0
        for row in result["stages"]
        if "container_id" in row
    }
    for row in result["stages"]:
        if "holder_id" in row:
            identity = row["holder_id"]
            absent[identity] = (
                engine.command(
                    ["container", "inspect", identity], check=False
                ).returncode
                != 0
            )
        if "volume_inspection" in row:
            name = row["volume_inspection"]["Name"]
            absent[name] = (
                engine.command(["volume", "inspect", name], check=False).returncode != 0
            )
            assert row["volume_inspection"]["Options"] == {
                "type": "tmpfs",
                "device": "tmpfs",
                "o": "size=100663296,nr_inodes=10000,mode=1777,uid=65532,gid=65532",
            }, row
    result["independent_absent_after_cleanup"] = absent
    assert absent and all(absent.values()), result
    assert (
        result["protected_originals_before"] == result["protected_originals_after"]
    ), result
    assert not result["cleanup_errors"], result
    if case == "success":
        for stage in result["stages"]:
            before, after = stage["inspect_before"], stage["inspect_stopped"]
            assert before["Config"]["User"] == "65532:65532"
            host = before["HostConfig"]
            assert host["PidMode"] in ("", "private") and host["IpcMode"] == "private"
            assert host["ReadonlyRootfs"] and not host["Privileged"]
            assert host["NetworkMode"] == "none" and host["CapDrop"] == ["ALL"]
            assert host["SecurityOpt"] == ["no-new-privileges=true"]
            assert host["Memory"] == host["MemorySwap"] == 402653184
            assert host["PidsLimit"] == 64 and host["NanoCpus"] == 1000000000
            assert (
                after["State"]["Pid"] == 0
                and not after["State"]["Running"]
                and after["State"]["ExitCode"] == 0
            )
            assert all(
                m["RW"] == (m["Destination"] == "/out") for m in before["Mounts"]
            )
            assert (
                next(m for m in before["Mounts"] if m["Destination"] == "/out")["Type"]
                == "volume"
            )
            assert stage["holder_inspection"]["Config"]["Entrypoint"] == ["/bin/sleep"]
            assert stage["holder_stopped"]["State"]["Pid"] == 0
            assert stage["holder_cleanup"] == "removed-exact-owned-container"
            assert stage["volume_cleanup"] == "removed-exact-owned-volume"
            assert (
                stage["readback"]["returncode"] == 0
                and stage["readback"]["drain_complete"]
            )
        assert result["status"] == "produced", result
        for phase, directory in [
            ("backend-import", "build"),
            ("backend-hook", "build"),
            ("pth-startup", "startup"),
        ]:
            observation = json.loads(
                (output / case / directory / (phase + ".json")).read_bytes()
            )
            assert observation["uid"] == 65532 and observation["gid"] == 65532, (
                observation
            )
            assert all(row["denied"] for row in observation["attempts"]), observation
            assert (
                not observation["forbidden_env_present"]
                and not observation["docker_socket_present"]
            ), observation
            assert observation["proc_status"] == {
                "CapEff": "0000000000000000",
                "NoNewPrivs": "1",
            }, observation
        assert all(stage["stopped_before_readback"] for stage in result["stages"])
    else:
        if case == "unsafe-output":
            assert result["stages"][0]["execution"]["returncode"] == 0, result
            assert result["stages"][0]["stopped_before_readback"], result
            assert "unsafe output type/link/mode" in result.get("error", ""), result
        assert result["status"] == "infrastructure-error", result
        if case in ("quota-bytes", "quota-inodes"):
            assert (
                "No space left on device" in result["stages"][0]["execution"]["stderr"]
            ), result
        if case == "pth-exception":
            startup = result["stages"][-1]
            assert (
                startup["phase"] == "startup"
                and startup["execution"]["returncode"] == 0
            ), result
            assert "M05_REVIEW_STARTUP_FAILURE" in startup["execution"]["stderr"], (
                result
            )
            assert "Remainder of file ignored" in startup["execution"]["stderr"], result
            assert (
                "site processing" in result.get("error", "")
                and "product" not in startup
            ), result
        if case == "pth-exception-noise":
            startup = result["stages"][-1]
            assert (
                startup["phase"] == "startup"
                and startup["execution"]["returncode"] == 0
            ), result
            assert (
                startup["execution"]["stderr_truncated"] and "product" not in startup
            ), result
            assert "site processing evidence incomplete" in result.get("error", ""), (
                result
            )
        if case == "timeout":
            assert result["stages"][0]["execution"]["timed_out"], result
        if case == "cancel":
            assert result["interrupted_signal"] == signal.SIGINT, result
    results[case] = result
    (output / "proof-results.json").write_text(json.dumps(results, indent=2) + "\n")
print(
    json.dumps(
        {
            case: {
                "status": value["status"],
                "absent": value["independent_absent_after_cleanup"],
            }
            for case, value in results.items()
        }
    )
)
