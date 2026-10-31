"""Protected image-qualification envelope and 3-run baseline index.

Slice P0-D authors the missing M03 qualification role: one N=1 fixed
smoke plus C/OpenSSL observation over exact custody bytes becomes one
ImageQualificationV1 record; exactly three such records become one
ImageBaselineIndexV1. The module reuses the existing custody acquire
path (`p11lab.image_custody.check_custody_manifest` over the
acquire-produced manifest) and the frozen smoke roster
(`p11lab.checker.load_profile`); it never forks custody, promotion, or
producer semantics. No ORAS publication, no auto-promotion, no
round-output consumption: `promotable` is always False and `comparison`
is always None.

Hermetic: constructed digests (`"ab" * 32` style, never real
identities), tmp_path payload dirs, and the installed frozen smoke-v1
roster. No network, no registry, no Docker, no gh.
"""

import hashlib
import inspect
import json
import re

import pytest

from p11lab import cli
from p11lab import image_qualification as qualification
from p11lab.checker import load_profile
from p11lab.models import canonical_json_bytes

FROZEN_ROSTER = load_profile()["nodes"]

# Refusal texts (each pinned by a test below).
L_NONDICT = "invalid qualification record envelope"
L_UNKNOWN = "invalid qualification record envelope: unknown field %r"
L_MISSING = "invalid qualification record envelope: missing field %r"
L_IDENTITY = "invalid qualification record identity"
L_CUSTODY = "invalid qualification custody identity"
L_IMAGE = "invalid qualification image identity"
L_ROSTER = "qualification roster is not the frozen smoke roster"
L_SMOKE = "invalid qualification smoke outcome"
L_OPENSSL = "invalid qualification openssl outcome"
L_COMPARISON = "qualification comparison must be null"
L_PROMOTABLE = "qualification promotable must be false"

I_COUNT = "baseline index requires exactly 3 records"
I_CUSTODY = "baseline index refuses altered custody"
I_LEG = "baseline index refuses missing leg"
I_ROSTER = "baseline index refuses roster change"
I_DRIFT = "baseline index refuses projection drift"

Q_STATEMENT = "invalid qualification custody statement"
Q_SELECTOR = "invalid qualification custody selector"
Q_SELECTOR_MISMATCH = "custody selector differs from verified finalization"
Q_MANIFEST_BIND = "custody manifest differs from verified finalization"
Q_SMOKE = "invalid smoke result outcome"
Q_OPENSSL = "invalid openssl result outcome"


def _custody(run_id=101, attempt=1, job_id=202, control_id=303,
             artifact="aa"):
    return {"environment": "softhsm2", "channel": "release",
            "run_id": run_id, "attempt": attempt, "job_id": job_id,
            "control_id": control_id,
            "artifact_digest": "sha256:" + artifact * 32}


def _image(engine="bb", config="cc", layers=("dd", "ee"), build="ff"):
    return {"engine_id": "sha256:" + engine * 32,
            "config_sha256": config * 32,
            "layers": ["sha256:" + item * 32 for item in layers],
            "build_key": build * 32}


def _leg(status="pass", digest="01"):
    return {"status": status, "result_sha256": digest * 32}


def _record(**overrides):
    kwargs = {"custody": _custody(), "image": _image(),
              "smoke": _leg(), "openssl": _leg(digest="02"),
              "roster": list(FROZEN_ROSTER)}
    kwargs.update(overrides)
    return qualification.build_qualification_record(**kwargs)


def _match(message):
    # Prefix-anchored like tests/test_provider_image_workflow.py: pytest
    # appends its own introspection after a custom assert message.
    return "^" + re.escape(message)


def test_build_accepts_single_run_observation():
    record = _record()
    assert set(record) == {"schema_version", "kind", "custody", "image",
                           "roster", "smoke", "openssl", "comparison",
                           "promotable"}
    assert record["schema_version"] == 1
    assert record["kind"] == "image-qualification"
    assert record["custody"] == _custody()
    assert record["image"] == _image()
    assert record["roster"] == FROZEN_ROSTER
    assert record["smoke"] == _leg()
    assert record["openssl"] == _leg(digest="02")
    assert record["comparison"] is None
    assert record["promotable"] is False


def test_build_snapshot_is_independent_of_caller_inputs():
    custody, image = _custody(), _image()
    record = _record(custody=custody, image=image)
    custody["run_id"] = 999
    image["layers"].append("sha256:" + "00" * 32)
    assert record["custody"]["run_id"] == 101
    assert record["image"]["layers"] == ["sha256:" + "dd" * 32,
                                         "sha256:" + "ee" * 32]


def test_build_signature_has_no_promotable_or_comparison_parameter():
    parameters = inspect.signature(
        qualification.build_qualification_record).parameters
    assert list(parameters) == ["custody", "image", "smoke", "openssl",
                                "roster"]
    assert all(item.kind is inspect.Parameter.KEYWORD_ONLY
               for item in parameters.values())
    assert "promotable" not in parameters
    assert "comparison" not in parameters


@pytest.mark.parametrize("field,value", [
    ("environment", ""), ("environment", "x" * 129),
    ("environment", None), ("channel", ""),
    ("run_id", 0), ("run_id", -1), ("run_id", True),
    ("run_id", "101"), ("attempt", 0), ("job_id", 0),
    ("control_id", 0), ("control_id", False),
    ("artifact_digest", "aa" * 32),
    ("artifact_digest", "sha256:" + "aa" * 31),
    ("artifact_digest", "sha256:" + "AA" * 32),
])
def test_build_refuses_invalid_custody_identity(field, value):
    custody = _custody()
    custody[field] = value
    with pytest.raises(ValueError, match=_match(L_CUSTODY)):
        _record(custody=custody)


@pytest.mark.parametrize("field,value", [
    ("engine_id", "bb" * 32),
    ("engine_id", "sha256:" + "bb" * 31),
    ("config_sha256", "cc" * 31),
    ("config_sha256", "sha256:" + "cc" * 32),
    ("layers", []), ("layers", ["dd" * 32]),
    ("layers", "sha256:" + "dd" * 32),
    ("build_key", "ff" * 31), ("build_key", None),
])
def test_build_refuses_invalid_image_identity(field, value):
    image = _image()
    image[field] = value
    with pytest.raises(ValueError, match=_match(L_IMAGE)):
        _record(image=image)


@pytest.mark.parametrize("leg", ["smoke", "openssl"])
@pytest.mark.parametrize("status", ["green", "", None, 0, "PASS"])
def test_build_refuses_non_closed_leg_status(leg, status):
    expected = L_SMOKE if leg == "smoke" else L_OPENSSL
    with pytest.raises(ValueError, match=_match(expected)):
        _record(**{leg: {"status": status, "result_sha256": "01" * 32}})


def test_build_refuses_non_frozen_roster():
    roster = list(FROZEN_ROSTER)
    roster[0] = "test_other.py::TestOther::test_other"
    with pytest.raises(ValueError, match=_match(L_ROSTER)):
        _record(roster=roster)


def test_build_refuses_reordered_frozen_roster():
    roster = list(reversed(FROZEN_ROSTER))
    assert roster != FROZEN_ROSTER
    with pytest.raises(ValueError, match=_match(L_ROSTER)):
        _record(roster=roster)


def test_load_accepts_built_record():
    record = _record()
    assert qualification.load_qualification_record(record) == record


def test_load_accepts_canonical_json_round_trip():
    record = _record()
    raw = canonical_json_bytes(record)
    from p11lab.jsonutil import loads
    assert qualification.load_qualification_record(loads(raw)) == record


def test_load_refuses_non_dict():
    with pytest.raises(ValueError, match=_match(L_NONDICT)):
        qualification.load_qualification_record([])


def test_load_refuses_unknown_field():
    record = _record()
    record["round_positive"] = True
    with pytest.raises(ValueError, match=_match(L_UNKNOWN % "round_positive")):
        qualification.load_qualification_record(record)


def test_load_refuses_missing_field():
    record = _record()
    del record["openssl"]
    with pytest.raises(ValueError, match=_match(L_MISSING % "openssl")):
        qualification.load_qualification_record(record)


@pytest.mark.parametrize("schema,kind", [
    (0, "image-qualification"), ("1", "image-qualification"),
    (True, "image-qualification"),
    (1, "image-baseline-index"), (1, "image-qualification-custody"),
])
def test_load_refuses_non_record_identity(schema, kind):
    record = _record()
    record["schema_version"] = schema
    record["kind"] = kind
    with pytest.raises(ValueError, match=_match(L_IDENTITY)):
        qualification.load_qualification_record(record)


def test_load_refuses_invalid_custody_section():
    record = _record()
    record["custody"] = dict(_custody(), attempt=True)
    with pytest.raises(ValueError, match=_match(L_CUSTODY)):
        qualification.load_qualification_record(record)


def test_load_refuses_invalid_image_section():
    record = _record()
    record["image"] = dict(_image(), layers=[])
    with pytest.raises(ValueError, match=_match(L_IMAGE)):
        qualification.load_qualification_record(record)


def test_load_refuses_non_frozen_roster():
    record = _record()
    record["roster"] = ["test_other.py::TestOther::test_other"]
    with pytest.raises(ValueError, match=_match(L_ROSTER)):
        qualification.load_qualification_record(record)


@pytest.mark.parametrize("leg,expected", [
    ("smoke", L_SMOKE), ("openssl", L_OPENSSL)])
@pytest.mark.parametrize("value", [
    {"status": "pass"}, {"status": "pass", "result_sha256": "01" * 32,
                         "extra": 1},
    {"status": "fail", "result_sha256": "zz" * 32},
    {"status": "fail", "result_sha256": "01" * 31}, "pass", [],
])
def test_load_refuses_malformed_leg(leg, expected, value):
    record = _record()
    record[leg] = value
    with pytest.raises(ValueError, match=_match(expected)):
        qualification.load_qualification_record(record)


@pytest.mark.parametrize("leg", ["smoke", "openssl"])
def test_load_accepts_recorded_absent_leg(leg):
    record = _record(**{leg: None})
    assert qualification.load_qualification_record(record)[leg] is None


def test_load_refuses_non_null_comparison():
    record = _record()
    record["comparison"] = {"verdict": "same"}
    with pytest.raises(ValueError, match=_match(L_COMPARISON)):
        qualification.load_qualification_record(record)


def test_load_refuses_promotable_true():
    record = _record()
    record["promotable"] = True
    with pytest.raises(ValueError, match=_match(L_PROMOTABLE)):
        qualification.load_qualification_record(record)


def test_load_refuses_promotable_zero_alias():
    record = _record()
    record["promotable"] = 0
    with pytest.raises(ValueError, match=_match(L_PROMOTABLE)):
        qualification.load_qualification_record(record)


def _run_triple():
    first = _record(custody=_custody(run_id=30, job_id=32, control_id=33),
                    smoke=_leg(digest="11"), openssl=_leg(digest="12"))
    second = _record(custody=_custody(run_id=10, job_id=12, control_id=13),
                     smoke=_leg(digest="13"), openssl=_leg(digest="14"))
    third = _record(custody=_custody(run_id=20, job_id=22, control_id=23),
                    smoke=_leg(digest="15"), openssl=_leg(digest="16"))
    return [first, second, third]


def test_index_accepts_three_equal_projection_runs():
    records = _run_triple()
    index = qualification.build_baseline_index(records)
    assert set(index) == {"schema_version", "kind", "representative",
                          "records", "projection"}
    assert index["schema_version"] == 1
    assert index["kind"] == "image-baseline-index"
    assert index["representative"] is records[1]
    assert index["representative"]["custody"]["run_id"] == 10
    assert len(index["records"]) == 3
    assert all(item is original
               for item, original in zip(index["records"], records))
    assert index["projection"] == {
        "image": records[1]["image"], "roster": FROZEN_ROSTER,
        "smoke": "pass", "openssl": "pass"}


def test_index_representative_is_earliest_run_id():
    records = _run_triple()
    order = [records[2], records[0], records[1]]
    index = qualification.build_baseline_index(order)
    assert index["representative"] is records[1]


@pytest.mark.parametrize("count", [0, 1, 2, 4])
def test_index_refuses_any_count_other_than_three(count):
    records = _run_triple()[:count] if count <= 3 else _run_triple() + [
        _record(custody=_custody(run_id=40))]
    with pytest.raises(ValueError, match=_match(I_COUNT)):
        qualification.build_baseline_index(records)


@pytest.mark.parametrize("value", ["records", {"records": []}, None])
def test_index_refuses_non_list_container(value):
    with pytest.raises(ValueError, match=_match(I_COUNT)):
        qualification.build_baseline_index(value)


def test_index_refuses_altered_custody():
    records = _run_triple()
    records[2]["custody"]["artifact_digest"] = "sha256:" + "ab" * 32
    with pytest.raises(ValueError, match=_match(I_CUSTODY)):
        qualification.build_baseline_index(records)


@pytest.mark.parametrize("leg", ["smoke", "openssl"])
def test_index_refuses_missing_leg(leg):
    records = _run_triple()
    records[1][leg] = None
    with pytest.raises(ValueError, match=_match(I_LEG)):
        qualification.build_baseline_index(records)


def test_index_refuses_roster_change():
    records = _run_triple()
    roster = list(FROZEN_ROSTER)
    roster[-1] = "test_other.py::TestOther::test_other"
    records[0]["roster"] = roster
    with pytest.raises(ValueError, match=_match(I_ROSTER)):
        qualification.build_baseline_index(records)


@pytest.mark.parametrize("field,value", [
    ("build_key", "ab" * 32), ("config_sha256", "ab" * 32),
    ("engine_id", "sha256:" + "ab" * 32),
])
def test_index_refuses_image_projection_drift(field, value):
    records = _run_triple()
    records[2]["image"][field] = value
    with pytest.raises(ValueError, match=_match(I_DRIFT)):
        qualification.build_baseline_index(records)


def test_index_refuses_layer_projection_drift():
    records = _run_triple()
    records[2]["image"]["layers"] = ["sha256:" + "ab" * 32]
    with pytest.raises(ValueError, match=_match(I_DRIFT)):
        qualification.build_baseline_index(records)


@pytest.mark.parametrize("leg", ["smoke", "openssl"])
def test_index_refuses_status_projection_drift(leg):
    records = _run_triple()
    records[2][leg]["status"] = "fail"
    with pytest.raises(ValueError, match=_match(I_DRIFT)):
        qualification.build_baseline_index(records)


def test_index_propagates_strict_load_refusal():
    records = _run_triple()
    records[1]["promotable"] = True
    with pytest.raises(ValueError, match=_match(L_PROMOTABLE)):
        qualification.build_baseline_index(records)


def test_three_runs_never_form_one_qualification():
    index = qualification.build_baseline_index(_run_triple())
    with pytest.raises(ValueError,
                       match=_match(L_UNKNOWN % "projection")):
        qualification.load_qualification_record(index)


@pytest.mark.parametrize("leg", ["smoke", "openssl"])
def test_concatenated_observations_never_form_one_leg(leg):
    with pytest.raises(ValueError):
        _record(**{leg: [_leg(), _leg(), _leg()]})
    with pytest.raises(ValueError):
        _record(**{leg: "pass"})


def test_concatenated_custody_never_forms_one_record():
    with pytest.raises(ValueError, match=_match(L_CUSTODY)):
        _record(custody=[_custody(), _custody(), _custody()])


def _manifest(artifact="aa", run_id=101, attempt=1, job_id=202,
              build="ff", config="cc", layers=("dd", "ee")):
    from p11lab.image_custody import COMPONENTS, SEGMENT_FILES, SEGMENT_ROLES
    files = {}
    tag = 0
    for role in SEGMENT_ROLES:
        part_files = {}
        for name in SEGMENT_FILES[role]:
            tag += 1
            part_files[name] = {"size": 16 + tag,
                                "sha256": "%02x" % tag * 32}
        files[role] = [{"part": 1, "files": part_files}]
    evaluator_receipt = files["evaluator-original"][0][
        "files"]["evaluator-build-receipt.json"]["sha256"]
    components = []
    for index, name in enumerate(sorted(COMPONENTS)):
        digest = evaluator_receipt if name == "evaluator-original" else (
            "b%01x" % (index % 16)) * 32
        components.append({
            "name": name,
            "artifact": {"kind": COMPONENTS[name],
                         "reference": "sha256:" + digest,
                         "sha256": digest, "platform": "linux/amd64"},
            "review_sha256": ("c%01x" % (index % 16)) * 32,
            "source": {
                "reference": "ghcr.io/p11lab/" + name + "@sha256:" + (
                    "d%01x" % (index % 16)) * 32,
                "manifest_sha256": ("d%01x" % (index % 16)) * 32,
                "file_sha256": ("e%01x" % (index % 16)) * 32,
                "receipt_sha256": ("f%01x" % (index % 16)) * 32,
                "spdx_sha256": ("0%01x" % (index % 16)) * 32,
                "inventory_sha256": ("1%01x" % (index % 16)) * 32,
                "source_archive_size": 100 + index}})
    records = files["source-records"][0]["files"]
    validation_files = files["validation"][0]["files"]
    artifact_ref = {"kind": "docker-local",
                    "reference": "sha256:" + artifact * 32,
                    "sha256": artifact * 32, "platform": "linux/amd64"}
    layer_rows = [{"diff_id": "sha256:" + item * 32} for item in layers]
    return {
        "schema_version": 1, "kind": "image-qualification-custody",
        "qualification_only": True, "image_promotable": False,
        "retention_days": 14, "artifact": artifact_ref,
        "engine_id": artifact_ref["reference"],
        "config_sha256": config * 32, "layers": layer_rows,
        "build_key": build * 32,
        "facts": {
            "artifact": artifact_ref, "build_key": build * 32,
            "build_receipt_sha256": records["build-receipt.json"]["sha256"],
            "source": {
                "sealed": {
                    "reference": "ghcr.io/p11lab/softhsm2@sha256:" + "61" * 32,
                    "manifest_sha256": "61" * 32, "archive_sha256": "62" * 32,
                    "receipt_sha256": records["sealed-source.json"]["sha256"]},
                "content": {
                    "reference": "ghcr.io/p11lab/softhsm2@sha256:" + "63" * 32,
                    "manifest_sha256": "63" * 32, "file_sha256": "64" * 32,
                    "receipt_sha256": records[
                        "source-companion.json"]["sha256"],
                    "spdx_sha256": records["sbom.spdx.json"]["sha256"],
                    "inventory_sha256": "65" * 32}},
            "validation": {
                "validation_sha256": validation_files[
                    "validation.json"]["sha256"],
                "package_sha256": validation_files[
                    "package.tar.gz"]["sha256"],
                "body_sha256": "66" * 32, "config_sha256": config * 32,
                "layers": layer_rows}},
        "image_archive": files["image"][0]["files"]["image.tar"],
        "files": files,
        "source_archives": {
            "sealed": {"size": 512, "sha256": "62" * 32,
                       "media_type": "application/gzip"},
            "content": {"size": 1024, "sha256": "64" * 32,
                        "media_type": "application/gzip"}},
        "producer": {"repository": "p11lab/p11lab", "repository_id": 1,
                     "owner_id": 2, "workflow_id": 3,
                     "workflow_path": ".github/workflows/provider-delivery.yml",
                     "source_sha": "07" * 20, "source_ref": "refs/heads/main",
                     "signer_sha": "08" * 20, "graph_sha256": "09" * 32},
        "run": {"run_id": run_id, "attempt": attempt,
                "job": "trusted-producer", "job_id": job_id},
        "profile_sha256": "6a" * 32, "controller_sha256": "6b" * 32,
        "evaluator_receipt_sha256": evaluator_receipt,
        "evaluator_identity_sha256": "6c" * 32, "components": components,
        "component_rights_tree_sha256": "6d" * 32}


def _statement(manifest_raw, run_id=101, attempt=1, job_id=202):
    return {"schema_version": 1, "kind": "image-custody-finalization",
            "role": "image-custody-producer", "environment": "softhsm2",
            "channel": "release",
            "run": {"run_id": run_id, "attempt": attempt,
                    "job": "trusted-producer", "job_id": job_id},
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}


def _payload_dir(root, manifest=None, statement=None, control_id=303):
    manifest = _manifest() if manifest is None else manifest
    manifest_raw = canonical_json_bytes(manifest)
    statement = (_statement(manifest_raw) if statement is None
                 else statement)
    authority = root / "authority"
    image_part = root / "acquisition/payload/image-part1"
    image_part.mkdir(parents=True)
    authority.mkdir(parents=True, exist_ok=True)
    (authority / "custody-finalization.json").write_bytes(
        canonical_json_bytes(statement))
    (image_part / "custody-manifest.json").write_bytes(manifest_raw)
    run = statement["run"] if isinstance(
        statement.get("run"), dict) else {}
    (root / "custody-selector.json").write_text(json.dumps(
        {"run_id": run.get("run_id", 101),
         "attempt": run.get("attempt", 1),
         "job_id": run.get("job_id", 202), "control_id": control_id},
        sort_keys=True) + "\n")
    return root


def _result_file(path, status="pass"):
    path.write_text(json.dumps({"status": status}) + "\n")
    return path


def test_qualify_projects_exact_custody_and_image_identities(tmp_path):
    payload = _payload_dir(tmp_path / "payload")
    smoke = _result_file(tmp_path / "smoke.json")
    openssl = _result_file(tmp_path / "openssl.json", status="fail")
    output = tmp_path / "qualification"
    record = qualification.qualify_payload(
        payload_dir=payload, smoke_result=smoke,
        openssl_result=openssl, output_dir=output)
    assert record["custody"] == _custody()
    assert record["image"] == _image(engine="aa")
    assert record["roster"] == FROZEN_ROSTER
    assert record["smoke"] == {"status": "pass",
                               "result_sha256": hashlib.sha256(
                                   smoke.read_bytes()).hexdigest()}
    assert record["openssl"] == {"status": "fail",
                                 "result_sha256": hashlib.sha256(
                                     openssl.read_bytes()).hexdigest()}
    assert record["comparison"] is None
    assert record["promotable"] is False
    stored = output / "qualification-record.json"
    assert stored.read_bytes() == canonical_json_bytes(record)
    from p11lab.jsonutil import loads
    assert qualification.load_qualification_record(
        loads(stored.read_bytes())) == record


def test_qualify_tolerates_statement_evidence_beyond_its_projection(tmp_path):
    manifest_raw = canonical_json_bytes(_manifest())
    statement = _statement(manifest_raw)
    statement["evaluator"] = {"receipt_sha256": "ab" * 32}
    statement["components"] = []
    payload = _payload_dir(tmp_path / "payload", statement=statement)
    record = qualification.qualify_payload(
        payload_dir=payload, smoke_result=_result_file(tmp_path / "s.json"),
        openssl_result=_result_file(tmp_path / "o.json"),
        output_dir=tmp_path / "out")
    assert record["custody"]["run_id"] == 101


def test_qualify_refuses_manifest_digest_mismatch(tmp_path):
    payload = _payload_dir(tmp_path / "payload")
    manifest_path = payload / "acquisition/payload/image-part1" / \
        "custody-manifest.json"
    manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
    with pytest.raises(ValueError, match=_match(Q_MANIFEST_BIND)):
        qualification.qualify_payload(
            payload_dir=payload,
            smoke_result=_result_file(tmp_path / "s.json"),
            openssl_result=_result_file(tmp_path / "o.json"),
            output_dir=tmp_path / "out")


def test_qualify_refuses_manifest_run_mismatch(tmp_path):
    manifest = _manifest(run_id=404)
    manifest_raw = canonical_json_bytes(manifest)
    statement = _statement(manifest_raw)
    payload = _payload_dir(tmp_path / "payload", manifest=manifest,
                           statement=statement)
    with pytest.raises(ValueError, match=_match(Q_MANIFEST_BIND)):
        qualification.qualify_payload(
            payload_dir=payload,
            smoke_result=_result_file(tmp_path / "s.json"),
            openssl_result=_result_file(tmp_path / "o.json"),
            output_dir=tmp_path / "out")


def test_qualify_refuses_manifest_rejected_by_custody_gate(tmp_path):
    manifest = _manifest()
    manifest["layers"] = []
    manifest_raw = canonical_json_bytes(manifest)
    statement = _statement(manifest_raw)
    payload = _payload_dir(tmp_path / "payload", manifest=manifest,
                           statement=statement)
    with pytest.raises(ValueError, match=_match("invalid custody layer")):
        qualification.qualify_payload(
            payload_dir=payload,
            smoke_result=_result_file(tmp_path / "s.json"),
            openssl_result=_result_file(tmp_path / "o.json"),
            output_dir=tmp_path / "out")


def test_qualify_refuses_selector_mismatch(tmp_path):
    payload = _payload_dir(tmp_path / "payload")
    (payload / "custody-selector.json").write_text(json.dumps(
        {"run_id": 999, "attempt": 1, "job_id": 202,
         "control_id": 303}) + "\n")
    with pytest.raises(ValueError, match=_match(Q_SELECTOR_MISMATCH)):
        qualification.qualify_payload(
            payload_dir=payload,
            smoke_result=_result_file(tmp_path / "s.json"),
            openssl_result=_result_file(tmp_path / "o.json"),
            output_dir=tmp_path / "out")


def test_qualify_refuses_malformed_selector(tmp_path):
    payload = _payload_dir(tmp_path / "payload")
    (payload / "custody-selector.json").write_text(json.dumps(
        {"run_id": 101, "attempt": 1, "job_id": 202}) + "\n")
    with pytest.raises(ValueError, match=_match(Q_SELECTOR)):
        qualification.qualify_payload(
            payload_dir=payload,
            smoke_result=_result_file(tmp_path / "s.json"),
            openssl_result=_result_file(tmp_path / "o.json"),
            output_dir=tmp_path / "out")


def test_qualify_refuses_malformed_statement(tmp_path):
    manifest_raw = canonical_json_bytes(_manifest())
    statement = _statement(manifest_raw)
    statement["run"] = {"run_id": 101}
    payload = _payload_dir(tmp_path / "payload", statement=statement)
    with pytest.raises(ValueError, match=_match(Q_STATEMENT)):
        qualification.qualify_payload(
            payload_dir=payload,
            smoke_result=_result_file(tmp_path / "s.json"),
            openssl_result=_result_file(tmp_path / "o.json"),
            output_dir=tmp_path / "out")


@pytest.mark.parametrize("name,expected", [
    ("smoke", Q_SMOKE), ("openssl", Q_OPENSSL)])
@pytest.mark.parametrize("body", [
    '{"status": "green"}\n', '{"status": "pass", "extra": 1}\n',
    '"pass"\n', '{}\n',
])
def test_qualify_refuses_invalid_result_outcome(tmp_path, name, expected,
                                                body):
    payload = _payload_dir(tmp_path / "payload")
    smoke = tmp_path / "s.json"
    openssl = tmp_path / "o.json"
    smoke.write_text('{"status": "pass"}\n')
    openssl.write_text('{"status": "pass"}\n')
    (smoke if name == "smoke" else openssl).write_text(body)
    with pytest.raises(ValueError, match=_match(expected)):
        qualification.qualify_payload(
            payload_dir=payload, smoke_result=smoke,
            openssl_result=openssl, output_dir=tmp_path / "out")


def test_qualify_requires_fresh_output_dir(tmp_path):
    payload = _payload_dir(tmp_path / "payload")
    output = tmp_path / "out"
    output.mkdir()
    with pytest.raises(OSError):
        qualification.qualify_payload(
            payload_dir=payload,
            smoke_result=_result_file(tmp_path / "s.json"),
            openssl_result=_result_file(tmp_path / "o.json"),
            output_dir=output)


def test_qualify_requires_acquire_produced_payload(tmp_path):
    with pytest.raises(OSError):
        qualification.qualify_payload(
            payload_dir=tmp_path / "missing",
            smoke_result=_result_file(tmp_path / "s.json"),
            openssl_result=_result_file(tmp_path / "o.json"),
            output_dir=tmp_path / "out")


def test_cli_qualify_emits_one_record(tmp_path, capsys):
    payload = _payload_dir(tmp_path / "payload")
    smoke = _result_file(tmp_path / "s.json")
    openssl = _result_file(tmp_path / "o.json")
    output = tmp_path / "out"
    assert cli.main(["custody", "qualify", "--payload-dir", str(payload),
                     "--smoke-result", str(smoke),
                     "--openssl-result", str(openssl),
                     "--output-dir", str(output)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["kind"] == "image-qualification"
    assert printed["promotable"] is False
    from p11lab.jsonutil import loads
    assert qualification.load_qualification_record(loads(
        (output / "qualification-record.json").read_bytes())) == printed


def test_cli_qualify_reports_usage_error_without_traceback(tmp_path, capsys):
    assert cli.main(["custody", "qualify", "--payload-dir",
                     str(tmp_path / "missing"),
                     "--smoke-result", str(_result_file(tmp_path / "s.json")),
                     "--openssl-result", str(_result_file(tmp_path / "o.json")),
                     "--output-dir", str(tmp_path / "out")]) == 2
    assert "p11lab: " in capsys.readouterr().err


def test_cli_baseline_index_emits_three_run_index(tmp_path, capsys):
    paths = []
    for position, record in enumerate(_run_triple()):
        path = tmp_path / ("record-%d.json" % position)
        path.write_bytes(canonical_json_bytes(record))
        paths.append(path)
    output = tmp_path / "index"
    argv = ["custody", "baseline-index", "--output-dir", str(output)]
    for path in paths:
        argv += ["--record", str(path)]
    assert cli.main(argv) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["kind"] == "image-baseline-index"
    assert printed["representative"]["custody"]["run_id"] == 10
    from p11lab.jsonutil import loads
    stored = loads((output / "baseline-index.json").read_bytes())
    assert stored == printed
    assert [item["custody"]["run_id"] for item in stored["records"]] == [
        30, 10, 20]


def test_cli_baseline_index_refuses_two_records(tmp_path, capsys):
    paths = []
    for position, record in enumerate(_run_triple()[:2]):
        path = tmp_path / ("record-%d.json" % position)
        path.write_bytes(canonical_json_bytes(record))
        paths.append(path)
    argv = ["custody", "baseline-index", "--output-dir",
           str(tmp_path / "index")]
    for path in paths:
        argv += ["--record", str(path)]
    assert cli.main(argv) == 2
    assert I_COUNT in capsys.readouterr().err
    assert not (tmp_path / "index").exists()


def test_cli_exposes_qualification_verbs(capsys):
    for operation in ("qualify", "baseline-index"):
        with pytest.raises(SystemExit) as exit_result:
            cli.main(["custody", operation, "--help"])
        assert exit_result.value.code == 0
        capsys.readouterr()


