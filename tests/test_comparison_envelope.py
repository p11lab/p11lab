"""Provider-free byte bindings; fixture ledgers originate in the public raw pipeline."""

import json
import os
from functools import lru_cache
from pathlib import Path
import shutil

import pytest

from p11lab.round_core.inputs import freeze_comparison_expectation

FIXTURES = Path(__file__).parent / "fixtures/comparison"


def operation():
    from p11lab import comparison

    return comparison


def test_supported_guard_exists():
    assert callable(operation().validate_comparison_envelope)


@lru_cache
def tools():
    from p11lab.round_core.inputs import SealedToolInputs

    root = os.environ.get("P11LAB_W01_OUTPUT")
    return SealedToolInputs.from_evaluator(Path(root)) if root else None


def bundle(tmp_path, axis="checker-direct"):
    module = operation()
    shutil.copytree(FIXTURES / axis, tmp_path / "endpoints")
    source = FIXTURES / axis
    envelope = json.loads((source / "envelope.json").read_bytes())
    witness = module.LocalComparisonWitness(
        expectation=freeze_comparison_expectation(envelope),
        observations=(source / "witness.json").read_bytes(),
    )
    endpoints = {
        "authority": witness,
        "evaluator": tools(),
        **{role: tmp_path / "endpoints" / role for role in ("baseline", "candidate")},
    }
    return module, envelope, endpoints


@pytest.mark.parametrize("role", ["baseline", "candidate"])
def test_relative_endpoint_root_is_refused(tmp_path, monkeypatch, role):
    module, envelope, endpoints = bundle(tmp_path)
    monkeypatch.chdir(tmp_path)
    endpoints[role] = endpoints[role].relative_to(tmp_path)
    with pytest.raises(ValueError, match="unsafe/noncanonical endpoint root"):
        module.validate_comparison_envelope(envelope, endpoints)


@pytest.mark.parametrize("axis", ["checker-direct", "checker", "image", "proxy"])
def test_real_byte_backed_axis_and_explicit_direct_proxy(tmp_path, axis):
    module, envelope, endpoints = bundle(tmp_path, axis)
    if endpoints["evaluator"] is None:
        pytest.skip("set P11LAB_W01_OUTPUT to an explicitly verified sealed evaluator")
    result = module.validate_comparison_envelope(envelope, endpoints)
    assert result["scope"] == "local-controller"
    assert result["comparison"] is None
    assert result["image_promotable"] is False
    assert result["endpoints"]["baseline"]["selected"] == [
        "/executor/tests/test_a.py::test_one"
    ]
    assert result["endpoints"]["baseline"]["attempts"] == ["outer1"]


@pytest.mark.parametrize(
    "field",
    [
        "operation",
        "protected.control_sha",
        "protected.evaluator_sha",
        "protected.selected_candidate_source_sha",
        "frozen_controls.dataset",
        "endpoints.candidate.artifacts.provider.family",
        "endpoints.candidate.artifacts.provider.platform",
        "endpoints.candidate.artifacts.derivative.parent_manifest_digest",
        "endpoints.candidate.artifacts.proxy",
        "endpoints.candidate.catalog",
        "endpoints.candidate.selected",
        "endpoints.candidate.observed_selected",
        "catalog_union",
        "selected_union",
    ],
)
def test_candidate_cannot_replace_independent_expectations(tmp_path, field):
    module, envelope, endpoints = bundle(tmp_path)
    target = envelope
    parts = field.split(".")
    for part in parts[:-1]:
        target = target[part]
    key = parts[-1]
    current = target[key]
    target[key] = [] if isinstance(current, list) else "forged"
    with pytest.raises(ValueError):
        module.validate_comparison_envelope(envelope, endpoints)


@pytest.mark.parametrize(
    "name",
    [
        "raw/report.jsonl",
        "ledger.jsonl",
        "coverage.json",
        "header.json",
        "sidecar.json",
        "catalog.json",
        "selected.json",
        "obligations.json",
        "raw-manifest.json",
        "artifacts.json",
        "source.tar",
        "checker.whl",
        "build-manifest.json",
        "installed-manifest.json",
    ],
)
@pytest.mark.parametrize("mutation", ["change", "missing"])
def test_each_required_original_or_identity_is_byte_bound(tmp_path, name, mutation):
    module, envelope, endpoints = bundle(tmp_path)
    path = endpoints["candidate"] / name
    if mutation == "missing":
        path.unlink()
    else:
        path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        module.validate_comparison_envelope(envelope, endpoints)


@pytest.mark.parametrize(
    "kind",
    [
        "symlink",
        "hardlink",
        "fifo",
        "extra",
        "directory-symlink",
        "root-symlink",
        "oversize",
    ],
)
def test_unsafe_files_and_rosters_fail_before_public_boundary(
    tmp_path, kind, monkeypatch
):
    import os

    module, envelope, endpoints = bundle(tmp_path)
    root = endpoints["candidate"]
    path = root / "coverage.json"
    if kind in {"symlink", "hardlink", "fifo", "oversize"}:
        path.unlink()
    if kind == "symlink":
        path.symlink_to(root / "catalog.json")
    if kind == "hardlink":
        os.link(root / "catalog.json", path)
    if kind == "fifo":
        os.mkfifo(path)
    if kind == "extra":
        (root / "unexpected").write_text("data")
    if kind == "directory-symlink":
        (root / "alias").symlink_to(root / "raw", target_is_directory=True)
    if kind == "root-symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        endpoints["candidate"] = alias
    if kind == "oversize":
        with path.open("wb") as stream:
            stream.truncate(32 * 1024 * 1024 + 1)
    called = []
    monkeypatch.setattr(module, "_public_evidence", lambda *a: called.append(True))
    with pytest.raises(ValueError):
        module.validate_comparison_envelope(envelope, endpoints)
    assert called == []


def test_json_booleans_cannot_be_controller_authority(tmp_path):
    module, envelope, endpoints = bundle(tmp_path)
    endpoints["authority"] = {"authenticated": True, "expectation": envelope}
    with pytest.raises(TypeError):
        module.validate_comparison_envelope(envelope, endpoints)


def test_schema_is_generated_exact_canonical_mirror():
    from importlib.resources import files
    from p11lab.round_core.inputs import COMPARISON_ENVELOPE_V1

    value = json.loads(
        files("p11lab").joinpath("data/ci/comparison.schema.json").read_bytes()
    )
    assert value["definition"] == COMPARISON_ENVELOPE_V1
    assert value["generated_from"] == "p11lab.round_core.inputs.COMPARISON_ENVELOPE_V1"


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))


def reseal(envelope, endpoints):
    """Test controller seals a deliberately invalid producer result, not its roster."""
    import hashlib

    module = operation()
    observations = json.loads(endpoints["authority"].observations)
    for role in ("baseline", "candidate"):
        root = endpoints[role]
        observations["endpoints"][role]["files"] = sorted(
            [
                {
                    "path": path.relative_to(root).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for path in root.rglob("*")
                if path.is_file()
            ],
            key=lambda row: row["path"],
        )
    endpoints["authority"] = module.LocalComparisonWitness(
        freeze_comparison_expectation(envelope), json.dumps(observations).encode()
    )


@pytest.mark.parametrize(
    "mutation",
    ["missing", "duplicate", "overlap", "selection", "path", "attempt", "shard"],
)
def test_independent_expected_attempt_and_shard_manifest_cannot_shrink_or_overlap(
    tmp_path, mutation
):
    module, envelope, endpoints = bundle(tmp_path)
    witness = json.loads(endpoints["authority"].observations)
    streams = witness["endpoints"]["candidate"]["streams"]
    if mutation == "missing":
        streams.clear()
    elif mutation in {"duplicate", "overlap"}:
        streams.append(
            dict(
                streams[0],
                shard_id="other" if mutation == "overlap" else streams[0]["shard_id"],
            )
        )
    elif mutation == "selection":
        streams[0]["selected"] = []
    else:
        key = {"path": "path", "attempt": "attempt", "shard": "shard_id"}[mutation]
        streams[0][key] = "../escape" if mutation == "path" else "other"
    endpoints["authority"] = module.LocalComparisonWitness(
        endpoints["authority"].expectation, json.dumps(witness).encode()
    )
    with pytest.raises(ValueError):
        module.validate_comparison_envelope(envelope, endpoints)


@pytest.mark.parametrize(
    "name,raw",
    [
        ("obligations.json", b'{"catalog":{},"catalog":{},"profile":{}}'),
        (
            "raw/report.jsonl",
            b'{"$report_type":"SessionStart","$report_type":"SessionFinish"}\n',
        ),
        ("ledger.jsonl", b'{"record":"header","record":"case"}\n'),
        ("build-manifest.json", b'{"value":NaN}'),
        ("installed-manifest.json", b"[]"),
    ],
)
def test_even_producer_sealed_ambiguous_json_refuses_before_public_operations(
    tmp_path, name, raw, monkeypatch
):
    module, envelope, endpoints = bundle(tmp_path)
    (endpoints["candidate"] / name).write_bytes(raw)
    reseal(envelope, endpoints)
    called = []
    monkeypatch.setattr(module, "_public_evidence", lambda *args: called.append(True))
    with pytest.raises(ValueError):
        module.validate_comparison_envelope(envelope, endpoints)
    assert called == []


@pytest.mark.parametrize(
    "name",
    ["dataset", "profile", "config_policy", "consumer_policy", "obligation_policy"],
)
def test_real_control_bytes_are_bound_even_if_file_roster_is_resealed(
    tmp_path, name, monkeypatch
):
    module, envelope, endpoints = bundle(tmp_path)
    path = endpoints["candidate"] / "controls" / (name + ".json")
    path.parent.mkdir(exist_ok=True)
    path.write_text('{"forged":true}')
    reseal(envelope, endpoints)
    called = []
    monkeypatch.setattr(module, "_public_evidence", lambda *args: called.append(True))
    with pytest.raises(ValueError):
        module.validate_comparison_envelope(envelope, endpoints)
    assert called == []


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-header-role",
        "wrong-obligations",
        "wrong-catalog",
        "wrong-selection",
        "empty-ledger",
        "tool-role",
    ],
)
def test_resealed_endpoint_identity_still_needs_protected_cross_binding(
    tmp_path, mutation, monkeypatch
):
    module, envelope, endpoints = bundle(tmp_path)
    root = endpoints["candidate"]
    if mutation == "wrong-header-role":
        header = json.loads((root / "header.json").read_bytes())
        header["framework_sha"] = envelope["protected"]["evaluator_sha"]
        write_json(root / "header.json", header)
    if mutation == "wrong-obligations":
        write_json(root / "obligations.json", {"catalog": {}, "profile": {"cases": []}})
    if mutation == "wrong-catalog":
        write_json(
            root / "catalog.json",
            {
                "catalog": envelope["endpoints"]["candidate"]["catalog"]
                + ["/evaluator-only/test_other.py::test_extra"]
            },
        )
    if mutation == "wrong-selection":
        write_json(root / "selected.json", {"selected": []})
    if mutation == "empty-ledger":
        (root / "ledger.jsonl").write_bytes(b"")
    if mutation == "tool-role":
        write_json(
            root / "artifacts.json", envelope["endpoints"]["baseline"]["artifacts"]
        )
    reseal(envelope, endpoints)
    called = []
    monkeypatch.setattr(module, "_public_evidence", lambda *args: called.append(True))
    with pytest.raises(ValueError):
        module.validate_comparison_envelope(envelope, endpoints)
    assert called == []


@pytest.mark.parametrize("value", [True, 1.0])
def test_header_numeric_types_are_exact_before_public_operations(
    tmp_path, value, monkeypatch
):
    module, envelope, endpoints = bundle(tmp_path)
    path = endpoints["candidate"] / "header.json"
    header = json.loads(path.read_bytes())
    header["schema_v"] = value
    write_json(path, header)
    reseal(envelope, endpoints)
    called = []
    monkeypatch.setattr(module, "_public_evidence", lambda *args: called.append(True))
    with pytest.raises(ValueError):
        module.validate_comparison_envelope(envelope, endpoints)
    assert called == []


@pytest.mark.parametrize(
    "mutation",
    ["incomplete", "duplicate", "unselected", "changed-row", "malformed-record"],
)
def test_real_public_original_pipeline_refuses_invalid_producer_stream(
    tmp_path, mutation
):
    import hashlib

    module, envelope, endpoints = bundle(tmp_path)
    if endpoints["evaluator"] is None:
        pytest.skip("set P11LAB_W01_OUTPUT to an explicitly verified sealed evaluator")
    root = endpoints["candidate"]
    raw_path = root / "raw/report.jsonl"
    records = [json.loads(line) for line in raw_path.read_bytes().splitlines()]
    if mutation == "incomplete":
        records.pop()
    if mutation == "duplicate":
        records.insert(-1, records[-2])
    if mutation == "unselected":
        records[-2]["nodeid"] = "/executor/tests/test_b.py::test_two"
    if mutation == "malformed-record":
        records[-2]["user_properties"] = 123
    raw = b"\n".join(json.dumps(record).encode() for record in records) + b"\n"
    raw_path.write_bytes(raw)
    header = envelope["endpoints"]["candidate"]["header"]
    header["raw_stream_bytes"] = len(raw)
    header["raw_stream_sha256"] = hashlib.sha256(raw).hexdigest()
    write_json(root / "header.json", header)
    lines = (root / "ledger.jsonl").read_bytes().splitlines()
    if mutation == "changed-row":
        row = json.loads(lines[1])
        row["outcome"] = "passed"
        lines[1] = json.dumps(row).encode()
    (root / "ledger.jsonl").write_bytes(
        json.dumps(header).encode() + b"\n" + b"\n".join(lines[1:]) + b"\n"
    )
    envelope["endpoints"]["candidate"]["evidence"]["ledger_sha256"] = hashlib.sha256(
        (root / "ledger.jsonl").read_bytes()
    ).hexdigest()
    reseal(envelope, endpoints)
    with pytest.raises(ValueError, match="public raw export/load/admission refused"):
        module.validate_comparison_envelope(envelope, endpoints)


def test_actual_guard_routes_both_admissions_through_public_operations(
    tmp_path, monkeypatch
):
    module, envelope, endpoints = bundle(tmp_path, "image")
    if endpoints["evaluator"] is None:
        pytest.skip("set P11LAB_W01_OUTPUT to an explicitly verified sealed evaluator")
    actual = module._public_evidence
    calls = []

    def trace(snapshot, request, evaluator):
        calls.append((request["header"]["framework_sha"], evaluator.receipt_sha256))
        return actual(snapshot, request, evaluator)

    monkeypatch.setattr(module, "_public_evidence", trace)
    result = module.validate_comparison_envelope(envelope, endpoints)
    assert len(calls) == 2
    assert all(call[0] == "9df03bd8b811966fa7856394b19e3f57ffcd8a40" for call in calls)
    assert all(
        side["admission"]["header"]["counters"]["failed"] == 1
        for side in result["endpoints"].values()
    )
    assert all(
        side["admission"]["admitted"] is True for side in result["endpoints"].values()
    )
    assert result["comparison"] is None


def test_sealed_evaluator_cannot_replace_selected_executor_role(tmp_path):
    module, envelope, endpoints = bundle(tmp_path, "image")
    if endpoints["evaluator"] is None:
        pytest.skip("set P11LAB_W01_OUTPUT to an explicitly verified sealed evaluator")
    envelope["protected"]["evaluator_sha"] = "9df03bd8b811966fa7856394b19e3f57ffcd8a40"
    reseal(envelope, endpoints)
    with pytest.raises(ValueError, match="protected evaluator role mismatch"):
        module.validate_comparison_envelope(envelope, endpoints)


def test_adapter_consumption_stays_within_registered_public_api(tmp_path):
    from p11lab.round_core.bootstrap import audit_consumption

    module = operation()
    source = tmp_path / "public-adapter.py"
    source.write_text(module._PUBLIC_EVIDENCE)
    contract = json.loads(
        (
            Path(__file__).parents[1] / "src/p11lab/data/rounds/contract.json"
        ).read_bytes()
    )
    assert audit_consumption([source, Path(module.__file__)], contract) == []


def test_unsafe_coverage_field_type_refuses_before_public_operations(
    tmp_path, monkeypatch
):
    import hashlib

    module, envelope, endpoints = bundle(tmp_path)
    path = endpoints["candidate"] / "coverage.json"
    coverage = json.loads(path.read_bytes())
    coverage["mechanism_coverage"]["advertised_names"] = True
    write_json(path, coverage)
    envelope["endpoints"]["candidate"]["evidence"]["coverage_sha256"] = hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    reseal(envelope, endpoints)
    called = []
    monkeypatch.setattr(module, "_public_evidence", lambda *args: called.append(True))
    with pytest.raises(ValueError):
        module.validate_comparison_envelope(envelope, endpoints)
    assert called == []


def test_matched_but_unselected_proxy_cannot_appear_in_direct_endpoints(tmp_path):
    module, envelope, endpoints = bundle(tmp_path)
    proxy = json.loads((FIXTURES / "proxy/envelope.json").read_bytes())["endpoints"][
        "baseline"
    ]["artifacts"]["proxy"]
    envelope["endpoints"]["baseline"]["artifacts"]["proxy"] = proxy
    envelope["endpoints"]["candidate"]["artifacts"]["proxy"] = proxy
    with pytest.raises(ValueError, match="independent protected expectation"):
        module.validate_comparison_envelope(envelope, endpoints)


def test_controller_witness_requires_immutable_observation_bytes(tmp_path, monkeypatch):
    module, envelope, endpoints = bundle(tmp_path)
    authority = endpoints["authority"]
    endpoints["authority"] = module.LocalComparisonWitness(
        authority.expectation, bytearray(authority.observations)
    )
    called = []
    monkeypatch.setattr(module, "_public_evidence", lambda *args: called.append(True))
    with pytest.raises(TypeError, match="immutable"):
        module.validate_comparison_envelope(envelope, endpoints)
    assert called == []
