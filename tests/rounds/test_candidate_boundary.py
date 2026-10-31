"""Bounded inert inspection and producer lifecycle counterexamples."""

import io
import json
import os
import tarfile
import zipfile

import pytest

from p11lab.round_core import evidence, worker
from p11lab.round_core.inputs import canonical


def test_readback_hashes_actual_bytes_and_rejects_roster_drift(tmp_path):
    (tmp_path / "wheel").write_bytes(b"actual")
    result = evidence.read_products(tmp_path, ("wheel",), max_bytes=64)
    assert result == [
        {
            "path": "wheel",
            "size": 6,
            "mode": 420,
            "sha256": "e5c6fde86910ded72db5cc7afc32f850440d4ef7caa5dbb69f5bdc0d3e39cb3b",
        }
    ]
    (tmp_path / "extra").write_text("unexpected")
    with pytest.raises(ValueError, match="roster"):
        evidence.read_products(tmp_path, ("wheel",), max_bytes=64)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "oversize", "mode"])
def test_readback_rejects_unsafe_outputs(tmp_path, kind):
    target = tmp_path / "product"
    if kind == "symlink":
        target.symlink_to("/etc/passwd")
    if kind == "hardlink":
        (tmp_path / "other").write_text("x")
        os.link(tmp_path / "other", target)
    if kind == "fifo":
        os.mkfifo(target)
    if kind == "oversize":
        target.write_bytes(b"x" * 65)
    if kind == "mode":
        target.write_text("x")
        target.chmod(0o4755)
    with pytest.raises(ValueError):
        evidence.read_products(tmp_path, ("product",), max_bytes=64)


@pytest.mark.parametrize(
    "kind", ["traversal", "link", "duplicate", "oversize", "requires"]
)
def test_inert_wheel_admission_rejects_unsafe_or_unsealed_metadata(tmp_path, kind):
    path = tmp_path / "candidate.whl"
    with zipfile.ZipFile(path, "w") as archive:
        if kind == "traversal":
            archive.writestr("../outside", "x")
        if kind == "link":
            info = zipfile.ZipInfo("link")
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "outside")
        if kind == "duplicate":
            archive.writestr("x", "a")
            with pytest.warns(UserWarning, match="Duplicate name"):
                archive.writestr("x", "b")
        if kind == "oversize":
            archive.writestr("big", "x" * 1000)
        archive.writestr(
            "canary-0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: canary\nVersion: 0\n"
            + ("Requires-Dist: online-package\n" if kind == "requires" else ""),
        )
    with pytest.raises(ValueError):
        evidence.inspect_wheel(path, max_bytes=512)


def test_candidate_observation_cannot_self_assert_stopped(tmp_path):
    with pytest.raises(TypeError):
        evidence.verify_candidate_product(None, tmp_path, {"stopped": True})


@pytest.mark.parametrize("kind", ["traversal", "duplicate", "link", "device"])
def test_source_archive_inspection_is_inert_and_closed(tmp_path, kind):
    path = tmp_path / "source.tar"
    with tarfile.open(path, "w") as archive:
        member = tarfile.TarInfo("../escape" if kind == "traversal" else "backend.py")
        if kind == "link":
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
        elif kind == "device":
            member.type = tarfile.CHRTYPE
        else:
            member.size = 1
        archive.addfile(member, io.BytesIO(b"x") if member.isfile() else None)
        if kind == "duplicate":
            archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ValueError):
        worker.inspect_source_archive(path)


def test_source_membership_binds_modes_bytes_and_no_execution(tmp_path):
    path = tmp_path / "source.tar"
    with tarfile.open(path, "w") as archive:
        member = tarfile.TarInfo("backend.py")
        member.size = 20
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(b"raise RuntimeError()"))
    rows = worker.inspect_source_archive(path)
    assert len(rows) == 1 and json.loads(rows[0])["path"] == "backend.py"
    assert json.loads(rows[0])["size"] == 20


def test_typed_stop_witness_rejects_running_or_wrong_owned_identity(tmp_path):
    from p11lab.round_core.inputs import FrozenCandidateContext

    context = FrozenCandidateContext(b"{}", None, None)
    import hashlib

    context_hash = hashlib.sha256(b"{}").hexdigest()
    for state, identity, label in [
        ({"Running": True, "Pid": 1}, "a" * 64, "owned"),
        ({"Running": False, "Pid": 0}, "b" * 64, "owned"),
        ({"Running": False, "Pid": 0}, "a" * 64, "foreign"),
    ]:
        witness = evidence.StoppedProducer(
            context_hash,
            "a" * 64,
            (("owner", "owned"),),
            canonical(
                {"Id": identity, "State": state, "Config": {"Labels": {"owner": label}}}
            ),
            (),
            64,
        )
        with pytest.raises(ValueError):
            evidence.verify_candidate_product(context, tmp_path, witness)


def test_no_candidate_authority_from_policy_argv_or_mounts():
    with pytest.raises(TypeError):
        worker.SandboxPolicy(argv=("sh",), mounts=("/var/run/docker.sock",))


@pytest.fixture
def producer_context(tmp_path):
    import hashlib
    from pathlib import Path
    from p11lab.round_core.bootstrap import inventory
    from p11lab.round_core.inputs import (
        LocalProducerEvent,
        ProtectedSelection,
        SealedToolInputs,
        VerifiedSource,
        freeze_candidate_context,
        freeze_comparison_expectation,
    )

    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w") as bundle:
        for name, content in [
            (
                "pyproject.toml",
                b'[build-system]\nrequires=[]\nbuild-backend="backend"\nbackend-path=["."]\n',
            ),
            ("backend.py", b'raise AssertionError("must never run on host")\n'),
        ]:
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            entry.mode = 0o644
            bundle.addfile(entry, io.BytesIO(content))
    toolroot = tmp_path / "tools"
    (toolroot / "python/bin").mkdir(parents=True)
    (toolroot / "python/bin/python3").write_bytes(b"no host execution")
    (toolroot / "downloads/build-wheels").mkdir(parents=True)
    wheel = toolroot / "downloads/build-wheels/pip.whl"
    wheel.write_bytes(b"inert test-only sealed input")
    spec = {
        "name": "pip",
        "version": "1",
        "filename": "pip.whl",
        "size": wheel.stat().st_size,
        "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
    }
    tools = SealedToolInputs(
        toolroot,
        "a" * 64,
        tuple(canonical(row) for row in inventory(toolroot, toolroot / "python")),
        (canonical(spec),),
        f"pip==1 --hash=sha256:{spec['sha256']}\n".encode(),
        ("pip==1",),
    )
    data = json.loads(
        (
            Path(__file__).parent / "fixtures/authority/checker-authorized.json"
        ).read_bytes()
    )["protected_expected"]
    revision = data["protected"]["selected_candidate_source_sha"]
    source = VerifiedSource(
        archive,
        hashlib.sha256(archive.read_bytes()).hexdigest(),
        revision,
        worker.source_tree(archive),
        worker.inspect_source_archive(archive),
    )
    return freeze_candidate_context(
        ProtectedSelection(
            freeze_comparison_expectation(data),
            "sha256:" + "b" * 64,
            ("sha256:" + "c" * 64,),
            1,
            hashlib.sha256(canonical({"Env": ["PATH=/usr/bin:/bin"]})).hexdigest(),
        ),
        LocalProducerEvent("https://github.com/p11lab/fixture", revision, "test"),
        source,
        tools,
    )


class FailedDocker:
    """Complete minimal engine state, without executing candidate fixture code."""

    def __init__(self, failure="exit"):
        self.failure = failure
        self.identity = "d" * 64
        self.running = False
        self.removed = False
        self.candidate_removed = False
        self.options = None
        self.labels = {}
        self.resources = {}
        self.volumes = {}

    def image(self, artifact):
        return {
            "RootFS": {"Layers": ["sha256:" + "c" * 64]},
            "Config": {"Env": ["PATH=/usr/bin:/bin"]},
        }

    def create(self, image, argv, options, labels, name):
        from p11lab.docker import DockerError

        holder = name.endswith("-holder")
        identity = "e" * 64 if holder else self.identity
        if not holder:
            self.options = options
        self.labels = labels
        if not holder and self.failure == "creation-uncertain":
            raise DockerError(
                "create uncertain", uncertain_resource=("container", name)
            )
        self.resources[identity] = {
            "Id": identity,
            "Image": image,
            "Config": {
                "Labels": labels,
                "User": "65532:65532",
                "Entrypoint": ["/bin/sleep"]
                if holder
                else ["/inputs/python/bin/python3"],
            },
            "HostConfig": {"PidMode": ""},
            "State": {"Running": False, "Pid": 0},
        }
        if not holder and self.failure == "creation-recovered":
            raise DockerError("create response lost", resource=("container", identity))
        return identity

    def execute(self, identity, timeout, interrupted):
        from p11lab.docker import CommandResult

        self.running = True
        self.resources[identity]["State"] = {"Running": True, "Pid": 1}
        if self.failure == "crash":
            raise OSError("control connection lost")
        return CommandResult(
            124 if self.failure == "timeout" else 1, "", "", self.failure == "timeout"
        )

    def stop(self, identity, labels):
        assert self.resources[identity]["Config"]["Labels"] == labels
        self.resources[identity]["State"] = {"Running": False, "Pid": 0}
        if identity == self.identity:
            self.running = False

    def remove(self, kind, identity, labels):
        if self.failure == "cleanup":
            raise OSError("cleanup failed")
        if kind == "container":
            assert not self.resources[identity]["State"]["Running"]
            assert self.resources[identity]["Config"]["Labels"] == labels
            del self.resources[identity]
            self.removed = True
            if identity == self.identity:
                self.candidate_removed = True
        else:
            assert self.volumes[identity]["Labels"] == labels
            del self.volumes[identity]

    def command(self, args):
        from p11lab.docker import CommandResult

        if args[:2] == ["volume", "create"]:
            name = args[args.index("--name") + 1]
            options, labels = {}, {}
            for index, item in enumerate(args[:-1]):
                if item in ("--opt", "--label"):
                    key, value = args[index + 1].split("=", 1)
                    (options if item == "--opt" else labels)[key] = value
            self.volumes[name] = {
                "Name": name,
                "Driver": "local",
                "Options": options,
                "Labels": labels,
            }
            return CommandResult(0, name, "")
        if args[:2] == ["volume", "inspect"]:
            return CommandResult(0, json.dumps([self.volumes[args[-1]]]), "")
        if args[0] == "start":
            self.resources[args[1]]["State"] = {"Running": True, "Pid": 1}
            return CommandResult(0, args[1], "")
        return CommandResult(0, json.dumps([self.resources[args[-1]]]), "")


@pytest.mark.parametrize(
    "failure",
    ["exit", "timeout", "crash", "cleanup", "creation-recovered", "creation-uncertain"],
)
def test_failed_execution_records_owned_cleanup_without_readback(
    producer_context, tmp_path, failure
):
    engine = FailedDocker(failure)
    result = worker.produce_candidate(
        producer_context,
        worker.SandboxPolicy("candidate-0-py3-none-any.whl"),
        tmp_path / "attempt",
        engine=engine,
    )
    assert result["status"] == "infrastructure-error"
    assert not engine.running
    assert not any("product" in stage for stage in result["stages"])
    if failure == "cleanup":
        assert result["cleanup_errors"] and not engine.removed
    elif failure == "creation-uncertain":
        assert (
            result["stages"][0]["uncertain_resource"][0] == "container"
            and not engine.candidate_removed
        )
    else:
        assert engine.removed and not result["cleanup_errors"]
    for option in [
        "--read-only",
        "--cap-drop",
        "--security-opt",
        "--memory",
        "--pids-limit",
        "--network",
        "--user",
    ]:
        assert option in engine.options
    assert engine.options[engine.options.index("--user") + 1] == "65532:65532"
    assert engine.options[engine.options.index("--network") + 1] == "none"
    assert result["protected_originals_before"] == result["protected_originals_after"]


@pytest.mark.parametrize(
    "changed", ["source", "tree", "python", "wheel", "lock", "requirement"]
)
def test_inert_input_drift_stops_before_any_candidate_container(
    producer_context, tmp_path, changed
):
    from dataclasses import replace

    context = producer_context
    if changed == "source":
        context.source.archive.write_bytes(b"drift")
    if changed == "python":
        (context.tools.root / "python/bin/python3").write_bytes(b"drift")
    if changed == "wheel":
        (context.tools.root / "downloads/build-wheels/pip.whl").write_bytes(b"drift")
    if changed == "lock":
        context = replace(context, tools=replace(context.tools, lock=b"online-dep"))
    if changed == "tree":
        value = context.as_dict()
        value["source"]["tree"] = "e" * 40
        context = replace(context, serialized=canonical(value))
    if changed == "requirement":
        context = replace(
            context, tools=replace(context.tools, requirements=("unsealed",))
        )
        # An immutable closure disagreement itself must fail, even with no declared source requirements.
    engine = FailedDocker()
    result = worker.produce_candidate(
        context,
        worker.SandboxPolicy("candidate-0-py3-none-any.whl"),
        tmp_path / "attempt",
        engine=engine,
    )
    assert result["status"] == "infrastructure-error"
    assert not result["stages"] and engine.options is None


def test_sealed_lock_comments_preserve_exact_dependency_roster(
    producer_context, tmp_path
):
    from dataclasses import replace
    import hashlib

    lock = b"# reviewed sealed closure\n" + producer_context.tools.lock
    value = producer_context.as_dict()
    value["tools"]["lock_sha256"] = hashlib.sha256(lock).hexdigest()
    context = replace(
        producer_context,
        serialized=canonical(value),
        tools=replace(producer_context.tools, lock=lock),
    )
    engine = FailedDocker()
    result = worker.produce_candidate(
        context,
        worker.SandboxPolicy("candidate-0-py3-none-any.whl"),
        tmp_path / "attempt",
        engine=engine,
    )
    assert len(result["stages"]) == 1 and engine.removed


def test_docker_private_pid_mode_uses_supported_engine_default(
    producer_context, tmp_path
):
    engine = FailedDocker()
    result = worker.produce_candidate(
        producer_context,
        worker.SandboxPolicy("candidate-0-py3-none-any.whl"),
        tmp_path / "attempt",
        engine=engine,
    )
    assert "--pid" not in engine.options  # Docker rejects literal `--pid private`.
    assert result["stages"][0]["execution"]["returncode"] == 1


def test_sealed_python_staging_allows_distinct_sandbox_uid_without_changing_file_bytes(
    producer_context, tmp_path
):
    (producer_context.tools.root / "python").chmod(0o700)
    (producer_context.tools.root / "python/bin").chmod(0o700)
    stage = tmp_path / "stage"
    stage.mkdir()
    worker._stage(
        producer_context, stage, worker.SandboxPolicy("candidate-0-py3-none-any.whl")
    )
    for path in [stage / "python", stage / "python/bin"]:
        assert path.stat().st_mode & 0o005 == 0o005
    assert (stage / "python/bin/python3").read_bytes() == b"no host execution"


def test_host_pid_namespace_is_rejected_before_candidate_start(
    producer_context, tmp_path
):
    class HostPidDocker(FailedDocker):
        def command(self, args):
            result = super().command(args)
            if args[:2] != ["container", "inspect"]:
                return result
            values = json.loads(result.stdout)
            values[0]["HostConfig"]["PidMode"] = "host"
            from dataclasses import replace

            return replace(result, stdout=json.dumps(values))

    engine = HostPidDocker()
    result = worker.produce_candidate(
        producer_context,
        worker.SandboxPolicy("candidate-0-py3-none-any.whl"),
        tmp_path / "attempt",
        engine=engine,
    )
    assert result["status"] == "infrastructure-error"
    assert "execution" not in result["stages"][0]
    assert engine.removed


def test_output_roster_rejects_unlisted_empty_directories(tmp_path):
    (tmp_path / "product").write_text("x")
    (tmp_path / "unlisted").mkdir()
    with pytest.raises(ValueError, match="roster"):
        evidence.read_products(tmp_path, ("product",), max_bytes=64)


def test_builder_config_drift_is_rejected_before_candidate_start(
    producer_context, tmp_path
):
    class ChangedConfigDocker(FailedDocker):
        def image(self, artifact):
            observed = super().image(artifact)
            observed["Config"]["Cmd"] = ["changed"]
            return observed

    engine = ChangedConfigDocker()
    result = worker.produce_candidate(
        producer_context,
        worker.SandboxPolicy("candidate-0-py3-none-any.whl"),
        tmp_path / "attempt",
        engine=engine,
    )
    assert result["status"] == "infrastructure-error" and not result["stages"]
    assert engine.options is None


def test_existing_supervision_preserves_binary_and_bounds_capture(tmp_path):
    import sys
    from p11lab.process import supervised_exec

    code = "import sys;sys.stdout.buffer.write(bytes([0,255,128,1,2,3]))"
    status, timed_out, owner, facts = supervised_exec(
        [sys.executable, "-I", "-B", "-c", code],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
        timeout=5,
        limit=5,
    )
    assert status == 0 and not timed_out
    assert bytes(owner.capture.buffers[0]) == b"\x00\xff\x80\x01\x02"
    assert facts["stdout_truncated"] and facts["drain_complete"]
    assert not facts["supervision_errors"] and not facts["stragglers_remaining"]


@pytest.mark.parametrize("kind", ["link", "traversal", "duplicate", "oversize"])
def test_bounded_volume_tar_is_validated_before_any_extraction(tmp_path, kind):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        info = tarfile.TarInfo("../escape" if kind == "traversal" else "product")
        info.mode = 0o644
        if kind == "link":
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
        else:
            info.size = 65 if kind == "oversize" else 1
        archive.addfile(info, None if kind == "link" else io.BytesIO(b"x" * info.size))
        if kind == "duplicate":
            archive.addfile(info, io.BytesIO(b"x"))
    destination = tmp_path / "products"
    destination.mkdir()
    with pytest.raises(ValueError):
        worker.readback_tar(data.getvalue(), destination, ("product",), max_bytes=64)
    assert not list(destination.iterdir())


def test_readback_directory_permissions_are_explicit_under_private_umask(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        directory = tarfile.TarInfo("site")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        file = tarfile.TarInfo("site/payload")
        file.size = 1
        file.mode = 0o644
        archive.addfile(file, io.BytesIO(b"x"))
    destination = tmp_path / "products"
    previous = os.umask(0o077)
    try:
        destination.mkdir()
        worker.readback_tar(
            data.getvalue(), destination, ("site/payload",), max_bytes=64
        )
    finally:
        os.umask(previous)
    assert destination.stat().st_mode & 0o777 == 0o755
    assert (destination / "site").stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize("axis", ["checker", "image", "proxy"])
def test_typed_producer_context_freezes_selected_source_and_local_authority(
    producer_context, axis
):
    from dataclasses import replace
    from pathlib import Path
    from p11lab.round_core.inputs import (
        LocalProducerEvent,
        ProtectedSelection,
        freeze_comparison_expectation,
        freeze_candidate_context,
        digest,
    )

    value = json.loads(
        (
            Path(__file__).parent / f"fixtures/authority/{axis}-authorized.json"
        ).read_bytes()
    )["protected_expected"]
    revision = value["protected"]["selected_candidate_source_sha"]
    source = replace(producer_context.source, revision=revision)
    context = freeze_candidate_context(
        ProtectedSelection(
            freeze_comparison_expectation(value),
            "sha256:" + "b" * 64,
            ("sha256:" + "c" * 64,),
            1,
            digest({"Env": ["PATH=/usr/bin:/bin"]}),
        ),
        LocalProducerEvent("https://github.com/p11lab/synthetic", revision, "fixture"),
        source,
        producer_context.tools,
    )
    actual = context.as_dict()
    assert actual["authority"] == {
        "scope": "local-controller",
        "repository": "https://github.com/p11lab/synthetic",
        "source_sha": revision,
        "attempt": "fixture",
    }
    assert actual["source"]["tree"] == producer_context.source.tree
    assert actual["expectation"]["operation"] == axis
    actual["authority"]["scope"] = "forged-ci"
    assert context.as_dict()["authority"]["scope"] == "local-controller"


def test_cancellation_before_creation_never_creates_a_container(
    producer_context, tmp_path
):
    import signal

    engine = FailedDocker()
    result = worker.produce_candidate(
        producer_context,
        worker.SandboxPolicy("candidate-0-py3-none-any.whl"),
        tmp_path / "attempt",
        engine=engine,
        interrupted=lambda: signal.SIGINT,
    )
    assert (
        result["status"] == "infrastructure-error"
        and result["interrupted_signal"] == signal.SIGINT
    )
    assert not result["stages"] and not engine.resources and not engine.volumes


def test_source_pax_bound_precedes_generic_tar_parser_and_metadata_expansion(
    tmp_path, monkeypatch
):
    import gzip

    path = tmp_path / "source.tar.gz"
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("backend.py")
        info.size = 1
        info.mode = 0o644
        info.pax_headers = {"comment": "x" * (128 * 1024)}
        archive.addfile(info, io.BytesIO(b"x"))
    requested = []
    original = gzip.GzipFile

    class CountedGzip:
        def __init__(self, *args, **kwargs):
            self.stream = original(*args, **kwargs)

        def read(self, size):
            requested.append(size)
            return self.stream.read(size)

        def close(self):
            self.stream.close()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def forbidden_parser(*args, **kwargs):
        pytest.fail("generic tar parser reached oversized extended metadata")

    monkeypatch.setattr(gzip, "GzipFile", CountedGzip)
    monkeypatch.setattr(tarfile, "open", forbidden_parser)
    with pytest.raises(ValueError, match="metadata"):
        worker.inspect_source_archive(path)
    assert sum(requested) <= 1024  # only the first fixed header was needed


def test_source_gzip_total_decompressed_stream_includes_padding(tmp_path):
    import gzip

    path = tmp_path / "source.tar.gz"
    original = io.BytesIO()
    with tarfile.open(fileobj=original, mode="w") as archive:
        info = tarfile.TarInfo("backend.py")
        info.size = 1
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(b"x"))
    with gzip.open(path, "wb") as stream:
        stream.write(original.getvalue())
        for _ in range(41):
            stream.write(b"\0" * (1024 * 1024))
    with pytest.raises(ValueError, match="stream"):
        worker.inspect_source_archive(path)


def test_source_compressed_input_is_bounded_before_reading_payload(
    tmp_path, monkeypatch
):
    path = tmp_path / "oversize.tar.gz"
    with path.open("wb") as stream:
        stream.truncate(41 * 1024 * 1024)

    def forbidden_parser(*args, **kwargs):
        pytest.fail("unbounded compressed source reached tar parser")

    monkeypatch.setattr(tarfile, "open", forbidden_parser)
    with pytest.raises(ValueError, match="archive"):
        worker.inspect_source_archive(path)


def test_reviewed_git_pax_comment_and_long_path_remain_supported(tmp_path):
    path = tmp_path / "source.tar.gz"
    name = "package/" + "a" * 140 + ".py"
    with tarfile.open(
        path, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": "a" * 40}
    ) as archive:
        info = tarfile.TarInfo(name)
        info.size = 1
        info.mode = 0o644
        info.mtime = 1.25
        archive.addfile(info, io.BytesIO(b"x"))
    rows = worker.inspect_source_archive(path)
    assert [json.loads(row)["path"] for row in rows] == [name]


def test_source_snapshot_survives_caller_archive_replacement_after_verified_tree(
    producer_context, tmp_path, monkeypatch
):
    old_tree = worker._source_tree_from_content
    original_snapshot = worker.read_source_archive
    reads = []

    def snapshot_once(path):
        reads.append(path)
        return original_snapshot(path)

    monkeypatch.setattr(worker, "read_source_archive", snapshot_once)
    original_backend = b'raise AssertionError("must never run on host")\n'
    replacement = io.BytesIO()
    with tarfile.open(fileobj=replacement, mode="w") as archive:
        for name, content in [
            ("backend.py", b"UNVERIFIED_REPLACEMENT_BYTES\n"),
            (
                "pyproject.toml",
                b'[build-system]\nrequires=[]\nbuild-backend="backend"\n',
            ),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))

    def replace_after_tree(path):
        tree = old_tree(path)
        producer_context.source.archive.write_bytes(replacement.getvalue())
        return tree

    monkeypatch.setattr(worker, "_source_tree_from_content", replace_after_tree)
    stage = tmp_path / "stage"
    stage.mkdir()
    worker._stage(
        producer_context, stage, worker.SandboxPolicy("candidate-0-py3-none-any.whl")
    )
    assert (stage / "source/backend.py").read_bytes() == original_backend
    assert producer_context.source.archive.read_bytes() == replacement.getvalue()
    assert reads == [producer_context.source.archive]


def test_native_pth_exception_is_a_failed_startup_even_with_zero_exit(tmp_path):
    import subprocess
    import sys

    (tmp_path / "failure.pth").write_text(
        "import sys; raise RuntimeError('M05_REVIEW_STARTUP_FAILURE')\n"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import site;site.addsitedir(" + repr(str(tmp_path)) + ")",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0 and "M05_REVIEW_STARTUP_FAILURE" in result.stderr
    with pytest.raises(ValueError, match="site processing"):
        worker.check_startup_diagnostics(result.stderr)


def test_source_payload_size_is_rejected_from_fixed_header_before_tar_parser(
    tmp_path, monkeypatch
):
    info = tarfile.TarInfo("backend.py")
    info.size = 32 * 1024 * 1024 + 1
    info.mode = 0o644
    path = tmp_path / "source.tar"
    path.write_bytes(info.tobuf() + b"\0" * 1024)

    def forbidden_parser(*args, **kwargs):
        pytest.fail("oversize declared payload reached generic parser")

    monkeypatch.setattr(tarfile, "open", forbidden_parser)
    with pytest.raises(ValueError, match="payload"):
        worker.inspect_source_archive(path)


def test_materialized_source_drift_fails_before_toml_metadata(
    producer_context, tmp_path, monkeypatch
):
    from pathlib import Path
    import tomllib

    stage = tmp_path / "stage"
    stage.mkdir()
    original = Path.write_bytes

    def corrupted_write(path, content):
        return original(
            path,
            b"UNVERIFIED_REPLACEMENT_BYTES\n"
            if path == stage / "source/backend.py"
            else content,
        )

    def forbidden_metadata(*args, **kwargs):
        pytest.fail("metadata parsed before final materialized source check")

    monkeypatch.setattr(Path, "write_bytes", corrupted_write)
    monkeypatch.setattr(tomllib, "loads", forbidden_metadata)
    with pytest.raises(ValueError, match="materialized source"):
        worker._stage(
            producer_context,
            stage,
            worker.SandboxPolicy("candidate-0-py3-none-any.whl"),
        )


def test_truncated_startup_diagnostics_fail_even_without_retained_exception_prefix():
    with pytest.raises(ValueError, match="site processing.*incomplete"):
        worker.check_startup_diagnostics("x" * 65536, stderr_truncated=True)


def test_benign_site_warning_is_retained_without_becoming_a_pth_exception():
    assert (
        worker.check_startup_diagnostics("UserWarning: harmless fixture warning\n")
        is None
    )


@pytest.mark.parametrize("fields", [{"GNU.sparse.map": "0,1"}, {"size": "1"}])
def test_source_metadata_cannot_redirect_unchecked_generic_parser_work(
    tmp_path, monkeypatch, fields
):
    path = tmp_path / "source.tar"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("backend.py")
        info.size = 2
        info.mode = 0o644
        info.pax_headers = fields
        archive.addfile(info, io.BytesIO(b"xx"))

    def forbidden_parser(*args, **kwargs):
        pytest.fail("unchecked metadata reached generic parser")

    monkeypatch.setattr(tarfile, "open", forbidden_parser)
    with pytest.raises(ValueError, match="metadata"):
        worker.inspect_source_archive(path)


def test_source_metadata_recursion_is_bounded_before_tar_parser(tmp_path, monkeypatch):
    path = tmp_path / "source.tar"
    content = io.BytesIO()
    for _ in range(9):
        header = tarfile.TarInfo("pax")
        header.type = tarfile.XHDTYPE
        header.size = 11
        header.mode = 0o644
        content.write(header.tobuf())
        content.write(b"11 mtime=1\n" + b"\0" * (512 - 11))
    path.write_bytes(content.getvalue() + b"\0" * 1024)

    def forbidden_parser(*args, **kwargs):
        pytest.fail("recursive metadata reached generic parser")

    monkeypatch.setattr(tarfile, "open", forbidden_parser)
    with pytest.raises(ValueError, match="metadata"):
        worker.inspect_source_archive(path)


def test_source_aggregate_metadata_is_bounded_before_tar_parser(tmp_path, monkeypatch):
    path = tmp_path / "source.tar"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for index in range(34):
            info = tarfile.TarInfo(str(index))
            info.size = 1
            info.mode = 0o644
            info.pax_headers = {"comment": "x" * (32 * 1024 - 32)}
            archive.addfile(info, io.BytesIO(b"x"))

    def forbidden_parser(*args, **kwargs):
        pytest.fail("aggregate metadata reached generic parser")

    monkeypatch.setattr(tarfile, "open", forbidden_parser)
    with pytest.raises(ValueError, match="metadata"):
        worker.inspect_source_archive(path)


def _pax_test_record(key, value):
    text = f" {key}={value}\n".encode()
    size = len(text) + 1
    while len(str(size)) + len(text) != size:
        size = len(str(size)) + len(text)
    return str(size).encode() + text


def _tar_test_record(name, content, kind=tarfile.REGTYPE):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = len(content)
    info.mode = 0o644
    return (
        info.tobuf(format=tarfile.USTAR_FORMAT)
        + content
        + b"\0" * (-len(content) % 512)
    )


@pytest.mark.parametrize("hidden", ["oversize-metadata", "sparse"])
def test_nested_pax_size_cannot_redirect_generic_parser_into_payload(
    tmp_path, monkeypatch, hidden
):
    metadata = (
        _pax_test_record("GNU.sparse.map", "0,1")
        if hidden == "sparse"
        else _pax_test_record("comment", "x" * (128 * 1024))
    )
    embedded = _tar_test_record(
        "hidden-pax", metadata, tarfile.XHDTYPE
    ) + _tar_test_record("hidden.py", b"x")
    raw = (
        _tar_test_record("outer-pax", _pax_test_record("size", "0"), tarfile.XHDTYPE)
        + _tar_test_record(
            "inner-pax", _pax_test_record("size", str(len(embedded))), tarfile.XHDTYPE
        )
        + _tar_test_record("backend.py", embedded)
        + b"\0" * 1024
    )
    path = tmp_path / "nested.tar"
    path.write_bytes(raw)

    def forbidden_parser(*args, **kwargs):
        pytest.fail("nested PAX precedence reached generic parsing")

    monkeypatch.setattr(tarfile, "open", forbidden_parser)
    with pytest.raises(ValueError, match="PAX size"):
        worker.inspect_source_archive(path)


@pytest.mark.parametrize("kind", [tarfile.XHDTYPE, tarfile.XGLTYPE])
@pytest.mark.parametrize("size", [0, 1])
def test_pax_size_is_rejected_even_when_it_matches_fixed_header(
    tmp_path, monkeypatch, kind, size
):
    path = tmp_path / "source.tar"
    path.write_bytes(
        _tar_test_record("pax", _pax_test_record("size", str(size)), kind)
        + _tar_test_record("backend.py", b"x" * size)
        + b"\0" * 1024
    )

    def forbidden_parser(*args, **kwargs):
        pytest.fail("PAX size reached generic parsing")

    monkeypatch.setattr(tarfile, "open", forbidden_parser)
    with pytest.raises(ValueError, match="PAX size"):
        worker.inspect_source_archive(path)


def test_nested_ordinary_pax_metadata_preserves_regular_payload(tmp_path):
    path = tmp_path / "source.tar"
    path.write_bytes(
        _tar_test_record(
            "global", _pax_test_record("comment", "a" * 40), tarfile.XGLTYPE
        )
        + _tar_test_record("outer", _pax_test_record("mtime", "1.25"), tarfile.XHDTYPE)
        + _tar_test_record(
            "inner", _pax_test_record("path", "ordinary.py"), tarfile.XHDTYPE
        )
        + _tar_test_record("backend.py", b"x")
        + b"\0" * 1024
    )
    rows = [json.loads(row) for row in worker.inspect_source_archive(path)]
    assert rows == [
        {
            "path": "ordinary.py",
            "mode": 420,
            "size": 1,
            "sha256": "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
        }
    ]
