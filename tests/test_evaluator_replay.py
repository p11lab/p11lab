"""Real same-interpreter planner observation; fixtures are not hosted authority."""

import json
import os
from pathlib import Path
import subprocess

import pytest


@pytest.fixture
def evaluator():
    path = os.environ.get("P11LAB_CUSTODY_TEST_EVALUATOR")
    if not path:
        pytest.skip("requires task-owned sealed evaluator")
    return Path(path)


def test_planner_wrapper_preserves_public_stdout_and_records_current_process(
    tmp_path, evaluator
):
    driver = (
        Path(__file__).resolve().parents[1]
        / "src/p11lab/data/ci/delivery/evaluator-replay-driver.py"
    )
    python = evaluator / "evaluator-install/bin/python"
    original = (
        evaluator
        / "evaluator-install/lib/python3.12/site-packages/pkcs11_check/testcases/test_interface.py"
    )
    view = tmp_path / "view"
    view.mkdir()
    (view / original.name).write_bytes(original.read_bytes())
    common = [
        "shard-units",
        "--shards",
        "1",
        "--testcases",
        str(view),
        "--format",
        "json",
    ]
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LD_LIBRARY_PATH": str(evaluator / "python/lib"),
    }
    direct = subprocess.run(
        [str(python), "-I", "-B", "-m", "pkcs11_check", *common],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=120,
    )
    journal = tmp_path / "runtime.json"
    wrapped = subprocess.run(
        [str(python), "-I", "-B", str(driver), "planner", str(journal), *common],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=120,
    )
    assert direct.returncode == wrapped.returncode == 0, wrapped.stderr.decode()
    assert wrapped.stdout == direct.stdout
    facts = json.loads(journal.read_bytes())
    assert facts["operation"] == "planner"
    assert facts["executable"]["sha256"]
    assert facts["loaded_elf"]
    assert all(row["sha256"] and row["size"] > 0 for row in facts["loaded_elf"])
    assert any(
        row["path"] == facts["executable"]["path"] for row in facts["loaded_elf"]
    )
    assert (
        facts["observation_scope"]
        == "resident ELF mappings immediately before process exit"
    )


def test_driver_requires_new_journal_before_public_operation(tmp_path, evaluator):
    driver = (
        Path(__file__).resolve().parents[1]
        / "src/p11lab/data/ci/delivery/evaluator-replay-driver.py"
    )
    python = evaluator / "evaluator-install/bin/python"
    journal = tmp_path / "runtime.json"
    journal.write_bytes(b"untouched")
    proc = subprocess.run(
        [str(python), "-I", "-B", str(driver), "planner", str(journal), "--help"],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        capture_output=True,
        timeout=120,
    )
    assert proc.returncode != 0
    assert journal.read_bytes() == b"untouched"
    assert not proc.stdout


def _runtime(operation, root):
    executable = {
        "path": str(root / "python/bin/python3.12"),
        "size": 10,
        "sha256": "a" * 64,
        "mount_id": 264,
        "mount_device": [0, 35],
        "stat_device": [0, 52],
        "inode": 123,
    }
    return {
        "schema_version": 1,
        "operation": operation,
        "executable": executable,
        "controller_root": "/controller/p11lab",
        "entrypoint": (
            {
                "name": "pkcs11_check.__main__",
                "path": str(
                    root
                    / "evaluator-install/lib/python3.12/site-packages/pkcs11_check/__main__.py"
                ),
                "size": 1,
                "sha256": "5" * 64,
            }
            if operation == "planner"
            else {
                "name": "image-evidence.py",
                "path": "/controller/p11lab/data/ci/delivery/image-evidence.py",
                "size": 1,
                "sha256": "6" * 64,
            }
        ),
        "checker_imports": [
            {
                "name": "pkcs11_check",
                "path": str(
                    root
                    / "evaluator-install/lib/python3.12/site-packages/pkcs11_check/__init__.py"
                ),
                "size": 1,
                "sha256": "4" * 64,
            }
        ],
        "loaded_elf": [
            executable,
            {
                "path": "/usr/lib/libc.so.6",
                "size": 20,
                "sha256": "b" * 64,
                "mount_id": 264,
                "mount_device": [0, 35],
                "stat_device": [0, 52],
                "inode": 124,
            },
        ],
        "machine": "x86_64",
        "platform": "fixture-platform",
        "libc": ["glibc", "2.41"],
        "observation_scope": "resident ELF mappings immediately before process exit",
    }


def test_runtime_comparison_preserves_roots_and_requires_exact_external_closure():
    from p11lab.round_core import evaluator_replay

    old, new = Path("/old/evaluator"), Path("/new/evaluator")
    producer = {op: _runtime(op, old) for op in ("planner", "admission")}
    receiver = {op: _runtime(op, new) for op in ("planner", "admission")}
    evaluator_replay.check_runtime_equivalence(
        producer, receiver, old_root=old, new_root=new
    )
    assert (
        producer["planner"]["executable"]["path"]
        != receiver["planner"]["executable"]["path"]
    )


@pytest.mark.parametrize(
    "damage", ["lib-hash", "lib-path", "executable", "missing", "operation", "abi"]
)
def test_runtime_comparison_refuses_changed_or_missing_native_facts(damage):
    from p11lab.round_core import evaluator_replay

    old, new = Path("/old/evaluator"), Path("/new/evaluator")
    producer = {op: _runtime(op, old) for op in ("planner", "admission")}
    receiver = {op: _runtime(op, new) for op in ("planner", "admission")}
    if damage == "lib-hash":
        receiver["admission"]["loaded_elf"][1]["sha256"] = "f" * 64
    if damage == "lib-path":
        receiver["admission"]["loaded_elf"][1]["path"] = "/other/libc.so.6"
    if damage == "executable":
        receiver["planner"]["executable"]["sha256"] = "f" * 64
    if damage == "missing":
        receiver["planner"]["loaded_elf"].pop()
    if damage == "operation":
        receiver.pop("admission")
    if damage == "abi":
        receiver["planner"]["libc"] = ["glibc", "2.40"]
    with pytest.raises(ValueError):
        evaluator_replay.check_runtime_equivalence(
            producer, receiver, old_root=old, new_root=new
        )


def _driver_module():
    import importlib.util

    path = (
        Path(__file__).resolve().parents[1]
        / "src/p11lab/data/ci/delivery/evaluator-replay-driver.py"
    )
    spec = importlib.util.spec_from_file_location("p11lab_replay_driver", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "damage", ["mount-id", "duplicate", "device", "inode", "changed"]
)
def test_mapped_file_binding_rejects_missing_or_changed_kernel_identity(damage):
    module = _driver_module()
    before = {
        "mount_id": 264,
        "fd_inode": 4892665,
        "mount_record": "264 65 0:35 /@agent-home /home/agent rw - btrfs /dev/test rw",
    }
    after = dict(before)
    stat_before = (52, 4892665, 100, 1)
    stat_after = stat_before
    records = [before["mount_record"]]
    if damage == "mount-id":
        after["mount_id"] = 265
    if damage == "duplicate":
        records.append(records[0])
    if damage == "device":
        before["mount_record"] = after["mount_record"] = records[0].replace(
            "0:35", "0:36"
        )
        records = [before["mount_record"]]
    if damage == "inode":
        after["fd_inode"] += 1
    if damage == "changed":
        stat_after = (52, 4892665, 100, 2)
    with pytest.raises(ValueError):
        module._check_map_binding(
            before,
            after,
            records,
            stat_before,
            stat_after,
            expected_device=(0, 35),
            expected_inode=4892665,
        )


def test_runtime_observation_rejects_changed_maps():
    module = _driver_module()
    with pytest.raises(ValueError, match="mappings changed"):
        module._check_maps_stable(["old mapping"], ["new mapping"])


def test_real_same_process_native_snapshots_match_across_roots(tmp_path, evaluator):
    from p11lab.round_core import evaluator_replay

    receiver = Path(os.environ["P11LAB_CUSTODY_TEST_RECEIVER"])
    if evaluator.resolve() == receiver.resolve():
        pytest.skip("requires distinct live evaluator roots")
    driver = (
        Path(__file__).resolve().parents[1]
        / "src/p11lab/data/ci/delivery/evaluator-replay-driver.py"
    )
    view = tmp_path / "view"
    view.mkdir()
    source = (
        evaluator
        / "evaluator-install/lib/python3.12/site-packages/pkcs11_check/testcases/test_interface.py"
    )
    (view / source.name).write_bytes(source.read_bytes())
    snapshots = []
    outputs = []
    for role, root in [("producer", evaluator), ("receiver", receiver)]:
        journal = tmp_path / (role + ".json")
        proc = subprocess.run(
            [
                str(root / "evaluator-install/bin/python"),
                "-I",
                "-B",
                str(driver),
                "planner",
                str(journal),
                "shard-units",
                "--shards",
                "1",
                "--testcases",
                str(view),
                "--format",
                "json",
            ],
            cwd=tmp_path,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(tmp_path),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "LD_LIBRARY_PATH": str(root / "python/lib"),
            },
            capture_output=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr.decode()
        snapshots.append(json.loads(journal.read_bytes()))
        outputs.append(proc.stdout)
    assert outputs[0] == outputs[1]
    assert evaluator_replay._runtime_projection(
        snapshots[0], "planner", evaluator
    ) == evaluator_replay._runtime_projection(snapshots[1], "planner", receiver)


def test_admission_wrapper_preserves_public_output_and_ledger(tmp_path, evaluator):
    raw = os.environ.get("P11LAB_CUSTODY_TEST_RAW")
    plan = os.environ.get("P11LAB_CUSTODY_TEST_PLAN")
    if not raw or not plan:
        pytest.skip("requires retained local checker originals")
    driver = (
        Path(__file__).resolve().parents[1]
        / "src/p11lab/data/ci/delivery/evaluator-replay-driver.py"
    )
    bridge = driver.with_name("image-evidence.py")
    python = evaluator / "evaluator-install/bin/python"
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LD_LIBRARY_PATH": str(evaluator / "python/lib"),
    }
    direct_ledger, wrapped_ledger = (
        tmp_path / "direct-ledger.jsonl",
        tmp_path / "wrapped-ledger.jsonl",
    )
    direct = subprocess.run(
        [str(python), "-I", "-B", str(bridge), raw, plan, str(direct_ledger)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=120,
    )
    journal = tmp_path / "admission-runtime.json"
    wrapped = subprocess.run(
        [
            str(python),
            "-I",
            "-B",
            str(driver),
            "admission",
            str(journal),
            raw,
            plan,
            str(wrapped_ledger),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=120,
    )
    assert direct.returncode == wrapped.returncode == 0, wrapped.stderr.decode()
    assert direct.stdout == wrapped.stdout
    assert direct_ledger.read_bytes() == wrapped_ledger.read_bytes()
    facts = json.loads(journal.read_bytes())
    assert facts["operation"] == "admission" and facts["loaded_elf"]


def test_planner_existing_adapter_option_observes_actual_execution(tmp_path, evaluator):
    import hashlib
    from p11lab.image_validation import plan_checker_shard

    receipt = evaluator / "evaluator-build-receipt.json"
    seal = hashlib.sha256(receipt.read_bytes()).hexdigest()
    journal = tmp_path / "planner-runtime.json"
    result = plan_checker_shard(
        evaluator,
        seal,
        {"test_interface.py"},
        tmp_path / "plan",
        runtime_journal=journal,
    )
    assert result["files"] == ["test_interface.py"]
    assert json.loads(journal.read_bytes())["operation"] == "planner"


def test_admission_existing_adapter_option_observes_actual_execution(
    tmp_path, evaluator
):
    import hashlib
    from p11lab.image_validation import admit_checker

    raw = os.environ.get("P11LAB_CUSTODY_TEST_RAW")
    plan = os.environ.get("P11LAB_CUSTODY_TEST_PLAN")
    if not raw or not plan:
        pytest.skip("requires retained local checker originals")
    checker = tmp_path / "checker-input"
    (checker / "checker").mkdir(parents=True)
    (checker / "checker/report.jsonl").write_bytes(Path(raw).read_bytes())
    seal = hashlib.sha256(
        (evaluator / "evaluator-build-receipt.json").read_bytes()
    ).hexdigest()
    journal = tmp_path / "admission-runtime.json"
    result = admit_checker(
        evaluator,
        seal,
        checker,
        Path(plan),
        tmp_path / "admission",
        runtime_journal=journal,
    )
    assert result["admission"]["admitted"] is True
    assert json.loads(journal.read_bytes())["operation"] == "admission"


@pytest.mark.parametrize(
    "kind",
    ["relative", "evaluator-overlap", "output-overlap", "existing", "symlink-parent"],
)
def test_runtime_journal_rejects_unsafe_destinations(tmp_path, kind):
    from p11lab.image_validation import _runtime_journal_path

    root, output = tmp_path / "evaluator", tmp_path / "output"
    root.mkdir()
    output.mkdir()
    path = tmp_path / "runtime.json"
    if kind == "relative":
        path = Path("relative.json")
    if kind == "evaluator-overlap":
        path = root / "runtime.json"
    if kind == "output-overlap":
        path = output / "runtime.json"
    if kind == "existing":
        path.write_bytes(b"existing")
    if kind == "symlink-parent":
        alias = tmp_path / "alias"
        alias.symlink_to(output, target_is_directory=True)
        path = alias / "runtime.json"
    with pytest.raises(ValueError):
        _runtime_journal_path(path, root, output)


def test_local_evaluator_observation_runs_real_planner_and_admission(
    tmp_path, evaluator
):
    import hashlib
    from p11lab.round_core import evaluator_replay

    raw = os.environ.get("P11LAB_CUSTODY_TEST_RAW")
    plan = os.environ.get("P11LAB_CUSTODY_TEST_PLAN")
    if not raw or not plan:
        pytest.skip("requires retained local checker originals")
    checker = tmp_path / "checker-input"
    (checker / "checker").mkdir(parents=True)
    (checker / "checker/report.jsonl").write_bytes(Path(raw).read_bytes())
    seal = hashlib.sha256(
        (evaluator / "evaluator-build-receipt.json").read_bytes()
    ).hexdigest()
    observation = evaluator_replay.observe_local_evaluator(
        evaluator,
        seal,
        {"test_interface.py"},
        checker,
        Path(plan),
        tmp_path / "observation",
    )
    value = observation.as_dict()
    assert value["receipt_sha256"] == seal
    assert value["runtime"]["planner"]["operation"] == "planner"
    assert value["runtime"]["admission"]["operation"] == "admission"
    assert value["admission"]["admission"]["admitted"] is True


def _observation_fixture(root):
    return {
        "schema_version": 1,
        "kind": "local-evaluator-observation",
        "root": str(root),
        "receipt_sha256": "a" * 64,
        "identity_sha256": "b" * 64,
        "driver": {"size": 123, "sha256": "9" * 64},
        "python": {
            "version": "3.12.14",
            "executable": "python/bin/python3",
            "sha256": "a" * 64,
            "archive_sha256": "d" * 64,
            "platform": "fixture-platform",
            "libc": ["glibc", "2.41"],
        },
        "native_dependencies": [{"path": "/usr/lib/libc.so.6", "sha256": "b" * 64}],
        "raw": {"size": 1, "sha256": "e" * 64},
        "plan": {"size": 1, "sha256": "f" * 64},
        "ledger": {"size": 1, "sha256": "1" * 64},
        "planner": {
            "files": ["test_interface.py"],
            "evaluator_source_sha256": {"test_interface.py": "2" * 64},
            "stdout_sha256": "3" * 64,
            "evaluator_receipt_sha256": "a" * 64,
        },
        "admission": {"admission": {"admitted": True}, "ledger_sha256": "1" * 64},
        "runtime": {op: _runtime(op, root) for op in ("planner", "admission")},
    }


def test_evaluator_observation_rejects_changed_receipt_or_missing_native_facts():
    from p11lab.round_core import evaluator_replay

    value = _observation_fixture(Path("/producer"))
    evaluator_replay.check_evaluator_observation(value)
    value["planner"]["evaluator_receipt_sha256"] = "f" * 64
    with pytest.raises(ValueError):
        evaluator_replay.check_evaluator_observation(value)


def test_evaluator_observation_refuses_external_library_outside_sealed_native_roster():
    from p11lab.round_core import evaluator_replay

    value = _observation_fixture(Path("/producer"))
    value["runtime"]["admission"]["loaded_elf"][1]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="unknown observed native dependency"):
        evaluator_replay.check_evaluator_observation(value)


def test_existing_local_observation_schema_requires_replay_driver_identity():
    from p11lab.round_core import evaluator_replay

    value = _observation_fixture(Path("/producer"))
    value["driver"] = {"size": 123, "sha256": "9" * 64}
    evaluator_replay.check_evaluator_observation(value)
    value.pop("driver")
    with pytest.raises(ValueError):
        evaluator_replay.check_evaluator_observation(value)


def test_replay_semantics_allow_distinct_receipts_without_rewriting_originals():
    from p11lab.round_core import evaluator_replay

    old = _observation_fixture(Path("/producer"))
    new = _observation_fixture(Path("/receiver"))
    new["receipt_sha256"] = "c" * 64
    new["planner"]["evaluator_receipt_sha256"] = "c" * 64
    new["planner"]["stdout_sha256"] = "4" * 64
    evaluator_replay.check_replay_equivalence(old, new)
    assert old["receipt_sha256"] != new["receipt_sha256"]
    new["ledger"]["sha256"] = "5" * 64
    with pytest.raises(ValueError):
        evaluator_replay.check_replay_equivalence(old, new)


def test_replay_binding_rejects_caller_asserted_authority(tmp_path):
    from p11lab.round_core import evaluator_replay

    with pytest.raises(TypeError, match="verified completed finalization"):
        evaluator_replay.bind_evaluator_replay(
            {"authenticated": True}, tmp_path / "old-receipt", {"equivalent": True}
        )


def test_replay_reports_exact_changed_sealed_native_dependency():
    from p11lab.round_core import evaluator_replay

    old = _observation_fixture(Path("/producer"))
    new = _observation_fixture(Path("/receiver"))
    new["receipt_sha256"] = "c" * 64
    new["planner"]["evaluator_receipt_sha256"] = "c" * 64
    new["native_dependencies"][0]["sha256"] = "f" * 64
    new["runtime"]["planner"]["loaded_elf"][1]["sha256"] = "f" * 64
    new["runtime"]["admission"]["loaded_elf"][1]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="/usr/lib/libc.so.6"):
        evaluator_replay.check_replay_equivalence(old, new)


def test_evaluator_observation_refuses_filesystem_root_as_identity_root():
    from p11lab.round_core import evaluator_replay

    value = _observation_fixture(Path("/"))
    with pytest.raises(ValueError, match="observation identity"):
        evaluator_replay.check_evaluator_observation(value)


def test_evidence_policy_refuses_untyped_replay_binding():
    from p11lab.image_validation import check_evidence_policy

    tools = {
        name: {
            "root": f"/tmp/{name}",
            "input_receipt": f"/tmp/{name}.json",
            "manifest_sha256": digit * 64,
        }
        for name, digit in [("checker", "1"), ("consumer", "2"), ("oracle", "3")]
    }
    policy = {
        "tools": tools,
        "evaluator": {"root": "/tmp/evaluator", "receipt_sha256": "4" * 64},
        "control_base_revision": "5" * 40,
    }
    value = {
        "tool_manifest_sha256": {
            name: row["manifest_sha256"] for name, row in tools.items()
        },
        "evaluator_receipt_sha256": "4" * 64,
        "control_base_revision_declared": "5" * 40,
        "scope": "local-only",
        "authority": "local-unauthenticated",
        "comparison": None,
        "promotable": False,
        "qualification_eligible": False,
    }
    with pytest.raises(TypeError, match="typed evaluator replay binding"):
        check_evidence_policy(value, policy, replay_binding={"approved": True})


def test_evidence_replay_refuses_caller_asserted_binding_before_io(tmp_path):
    from p11lab.image_validation import verify_evidence_package

    with pytest.raises(TypeError, match="typed evaluator replay binding"):
        verify_evidence_package(
            tmp_path / "missing", {}, {}, None, {}, replay_binding={"approved": True}
        )


def test_runtime_comparison_refuses_executing_foreign_interpreter_even_if_identical():
    from p11lab.round_core import evaluator_replay

    old = _observation_fixture(Path("/producer"))
    new = _observation_fixture(Path("/receiver"))
    new["receipt_sha256"] = "c" * 64
    new["planner"]["evaluator_receipt_sha256"] = "c" * 64
    for value in (old, new):
        value["native_dependencies"].insert(
            0, {"path": "/usr/bin/python3.12", "sha256": "a" * 64}
        )
        for operation in ("planner", "admission"):
            value["runtime"][operation]["executable"]["path"] = "/usr/bin/python3.12"
    with pytest.raises(ValueError, match="executable.*outside"):
        evaluator_replay.check_replay_equivalence(old, new)


def test_planner_wrapper_records_actual_checker_imports_within_selected_root(
    tmp_path, evaluator
):
    driver = (
        Path(__file__).resolve().parents[1]
        / "src/p11lab/data/ci/delivery/evaluator-replay-driver.py"
    )
    view = tmp_path / "view"
    view.mkdir()
    source = (
        evaluator
        / "evaluator-install/lib/python3.12/site-packages/pkcs11_check/testcases/test_interface.py"
    )
    (view / source.name).write_bytes(source.read_bytes())
    journal = tmp_path / "imports.json"
    proc = subprocess.run(
        [
            str(evaluator / "evaluator-install/bin/python"),
            "-I",
            "-B",
            str(driver),
            "planner",
            str(journal),
            "shard-units",
            "--shards",
            "1",
            "--testcases",
            str(view),
            "--format",
            "json",
        ],
        cwd=tmp_path,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            "LD_LIBRARY_PATH": str(evaluator / "python/lib"),
        },
        capture_output=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    imports = json.loads(journal.read_bytes())["checker_imports"]
    assert any(row["name"] == "pkcs11_check" for row in imports)
    assert all(
        Path(row["path"]).is_relative_to(evaluator) and row["sha256"] for row in imports
    )


def test_runtime_comparison_refuses_checker_import_outside_selected_root():
    from p11lab.round_core import evaluator_replay

    old = _observation_fixture(Path("/producer"))
    new = _observation_fixture(Path("/receiver"))
    new["receipt_sha256"] = "c" * 64
    new["planner"]["evaluator_receipt_sha256"] = "c" * 64
    for value in (old, new):
        for operation in ("planner", "admission"):
            value["runtime"][operation]["checker_imports"] = [
                {
                    "name": "pkcs11_check",
                    "path": "/foreign/__init__.py",
                    "size": 1,
                    "sha256": "4" * 64,
                }
            ]
    with pytest.raises(ValueError, match="checker import.*outside"):
        evaluator_replay.check_replay_equivalence(old, new)


def test_planner_records_executed_public_entrypoint_identity(tmp_path, evaluator):
    driver = (
        Path(__file__).resolve().parents[1]
        / "src/p11lab/data/ci/delivery/evaluator-replay-driver.py"
    )
    view = tmp_path / "view"
    view.mkdir()
    source = (
        evaluator
        / "evaluator-install/lib/python3.12/site-packages/pkcs11_check/testcases/test_interface.py"
    )
    (view / source.name).write_bytes(source.read_bytes())
    journal = tmp_path / "entrypoint.json"
    proc = subprocess.run(
        [
            str(evaluator / "evaluator-install/bin/python"),
            "-I",
            "-B",
            str(driver),
            "planner",
            str(journal),
            "shard-units",
            "--shards",
            "1",
            "--testcases",
            str(view),
            "--format",
            "json",
        ],
        cwd=tmp_path,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            "LD_LIBRARY_PATH": str(evaluator / "python/lib"),
        },
        capture_output=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    entry = json.loads(journal.read_bytes())["entrypoint"]
    assert entry["name"] == "pkcs11_check.__main__"
    assert Path(entry["path"]).is_relative_to(evaluator) and entry["sha256"]


def test_source_validation_replay_rejects_untyped_binding_before_input_io(tmp_path):
    from p11lab.delivery_authority import _verify_validation_package

    with pytest.raises(TypeError, match="typed evaluator replay binding"):
        _verify_validation_package(
            tmp_path / "missing",
            None,
            {},
            "",
            "",
            "",
            replay_binding={"approved": True},
        )


def test_source_facts_replay_refuses_untyped_binding_before_inspection(tmp_path):
    from p11lab.delivery_authority import _source_facts

    with pytest.raises(TypeError, match="typed evaluator replay binding"):
        _source_facts(
            environment="softhsm2",
            channel="release",
            artifact=None,
            evidence_dir=tmp_path,
            validation_dir=tmp_path,
            build_receipt=tmp_path / "build",
            sealed_dir=tmp_path,
            registry="x",
            seal_digest="a" * 64,
            content_digest="b" * 64,
            output_dir=tmp_path / "out",
            profile={},
            replay_binding={"approved": True},
        )


def test_replay_equivalence_accepts_same_path_string_with_distinct_receipts():
    """Different runner roots may use the same absolute spelling."""
    import copy
    from p11lab.round_core import evaluator_replay

    original = _observation_fixture(Path('/runner/evaluator'))
    receiver = _observation_fixture(Path('/runner/evaluator'))
    receiver['receipt_sha256'] = 'c' * 64
    receiver['planner']['evaluator_receipt_sha256'] = 'c' * 64
    receiver['planner']['stdout_sha256'] = '4' * 64
    retained = copy.deepcopy((original, receiver))
    evaluator_replay.check_replay_equivalence(original, receiver)
    assert (original, receiver) == retained
    receiver['native_dependencies'][0]['sha256'] = 'd' * 64
    with pytest.raises(ValueError):
        evaluator_replay.check_replay_equivalence(original, receiver)
