"""Protected image-qualification records and 3-run baseline index.

One N=1 fixed smoke plus C/OpenSSL observation over exact custody bytes
becomes one ImageQualificationV1 record (`build_qualification_record`,
`load_qualification_record`); exactly three single-run records become
one ImageBaselineIndexV1 (`build_baseline_index`). `qualify_payload`
projects one `p11lab custody acquire` on-disk output plus two leg
outcomes into one record.

Reuse, never fork:

- `p11lab.image_custody.check_custody_manifest` validates the
  acquire-produced custody manifest.
- `p11lab.checker.load_profile` supplies the frozen smoke-v1 roster.
- `p11lab.models.canonical_json_bytes` serializes record artifacts.
- `p11lab.jsonutil.loads` decodes every JSON input.
- `p11lab.delivery_authority._read_bounded_file` bounds every read.

No ORAS publication, no auto-promotion, no round-output consumption:
`promotable` is always False, `comparison` is always None, and result
files carry exactly one `status` key so no round output can feed a leg.
"""

import hashlib
from pathlib import Path
import re

RECORD_SCHEMA = 1
RECORD_KIND = "image-qualification"
INDEX_KIND = "image-baseline-index"
RECORD_FIELDS = ("schema_version", "kind", "custody", "image", "roster",
                 "smoke", "openssl", "comparison", "promotable")
CUSTODY_FIELDS = ("environment", "channel", "run_id", "attempt", "job_id",
                  "control_id", "artifact_digest")
IMAGE_FIELDS = ("engine_id", "config_sha256", "layers", "build_key")
LEG_STATUSES = ("pass", "fail")

STATEMENT_LIMIT = 4 * 1024 * 1024
MANIFEST_LIMIT = 2 * 1024 * 1024
SELECTOR_LIMIT = 64 * 1024
RESULT_LIMIT = 1024 * 1024


def _is_sha(value):
    return (type(value) is str
            and re.fullmatch(r"[0-9a-f]{64}", value) is not None)


def _is_digest(value):
    return (type(value) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)


def _is_name(value):
    return type(value) is str and 1 <= len(value) <= 128


def _frozen_roster():
    from .checker import load_profile
    return load_profile()["nodes"]


def _check_custody(value):
    if type(value) is not dict or set(value) != set(CUSTODY_FIELDS):
        raise ValueError("invalid qualification custody identity")
    if (not _is_name(value["environment"])
            or not _is_name(value["channel"])
            or any(type(value[key]) is not int or value[key] <= 0
                   for key in ("run_id", "attempt", "job_id", "control_id"))
            or not _is_digest(value["artifact_digest"])):
        raise ValueError("invalid qualification custody identity")


def _check_image(value):
    if type(value) is not dict or set(value) != set(IMAGE_FIELDS):
        raise ValueError("invalid qualification image identity")
    layers = value["layers"]
    if (not _is_digest(value["engine_id"])
            or not _is_sha(value["config_sha256"])
            or type(layers) is not list or not layers
            or any(not _is_digest(row) for row in layers)
            or not _is_sha(value["build_key"])):
        raise ValueError("invalid qualification image identity")


def _check_leg(value, name):
    if value is None:
        return
    if (type(value) is not dict
            or set(value) != {"status", "result_sha256"}
            or value["status"] not in LEG_STATUSES
            or not _is_sha(value["result_sha256"])):
        raise ValueError("invalid qualification %s outcome" % name)


def load_qualification_record(data):
    """Strictly validate one ImageQualificationV1 record dict."""
    if type(data) is not dict:
        raise ValueError("invalid qualification record envelope")
    unknown = [key for key in data if key not in RECORD_FIELDS]
    if unknown:
        raise ValueError(
            "invalid qualification record envelope: unknown field %r"
            % sorted(unknown, key=repr)[0])
    missing = [name for name in RECORD_FIELDS if name not in data]
    if missing:
        raise ValueError(
            "invalid qualification record envelope: missing field %r"
            % missing[0])
    if (type(data["schema_version"]) is not int
            or data["schema_version"] != RECORD_SCHEMA
            or data["kind"] != RECORD_KIND):
        raise ValueError("invalid qualification record identity")
    _check_custody(data["custody"])
    _check_image(data["image"])
    if data["roster"] != _frozen_roster():
        raise ValueError("qualification roster is not the frozen smoke roster")
    _check_leg(data["smoke"], "smoke")
    _check_leg(data["openssl"], "openssl")
    if data["comparison"] is not None:
        raise ValueError("qualification comparison must be null")
    if data["promotable"] is not False:
        raise ValueError("qualification promotable must be false")
    return data


def build_qualification_record(*, custody, image, smoke, openssl, roster):
    """Assemble one ImageQualificationV1 record from a single run.

    The observation covers exactly one custody selector, one image
    load, one smoke outcome, and one OpenSSL outcome; lists of
    observations never concatenate here. The returned record is an
    independent snapshot: later caller mutation cannot change it.
    """
    from .jsonutil import loads
    from .models import canonical_json_bytes
    record = {"schema_version": RECORD_SCHEMA, "kind": RECORD_KIND,
              "custody": custody, "image": image, "roster": roster,
              "smoke": smoke, "openssl": openssl, "comparison": None,
              "promotable": False}
    load_qualification_record(record)
    return loads(canonical_json_bytes(record))


def _semantic_projection(record):
    from .models import canonical_json_bytes
    return canonical_json_bytes(
        {"image": record["image"], "roster": record["roster"],
         "smoke": record["smoke"]["status"],
         "openssl": record["openssl"]["status"]})


def build_baseline_index(records):
    """Combine exactly 3 single-run records into one ImageBaselineIndexV1.

    The three records must agree on custody artifact, legs present,
    roster, and canonical semantic projection; the representative is
    the earliest run id (ties keep input order) and every original is
    retained by reference. Any other count, altered custody, missing
    leg, roster change, or projection drift is refused.
    """
    if type(records) is not list or len(records) != 3:
        raise ValueError("baseline index requires exactly 3 records")
    if all(type(item) is dict and "roster" in item for item in records):
        first = records[0]["roster"]
        if any(item["roster"] != first for item in records[1:]):
            raise ValueError("baseline index refuses roster change")
    for item in records:
        load_qualification_record(item)
    digests = [item["custody"]["artifact_digest"] for item in records]
    if any(digest != digests[0] for digest in digests[1:]):
        raise ValueError("baseline index refuses altered custody")
    if any(item["smoke"] is None or item["openssl"] is None
           for item in records):
        raise ValueError("baseline index refuses missing leg")
    projections = [_semantic_projection(item) for item in records]
    if any(item != projections[0] for item in projections[1:]):
        raise ValueError("baseline index refuses projection drift")
    representative = min(records, key=lambda item: item["custody"]["run_id"])
    return {"schema_version": RECORD_SCHEMA, "kind": INDEX_KIND,
            "representative": representative, "records": list(records),
            "projection": {"image": representative["image"],
                           "roster": representative["roster"],
                           "smoke": representative["smoke"]["status"],
                           "openssl": representative["openssl"]["status"]}}


def _read_json(path, limit):
    from .delivery_authority import _read_bounded_file
    from .jsonutil import loads
    raw = _read_bounded_file(path, limit)
    return raw, loads(raw.decode("utf-8"))


def _check_statement(value):
    if (type(value) is not dict
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != RECORD_SCHEMA
            or value.get("kind") != "image-custody-finalization"
            or value.get("role") != "image-custody-producer"
            or not _is_name(value.get("environment"))
            or not _is_name(value.get("channel"))
            or not _is_sha(value.get("manifest_sha256"))):
        raise ValueError("invalid qualification custody statement")
    run = value.get("run")
    if (type(run) is not dict
            or set(run) != {"run_id", "attempt", "job", "job_id"}
            or any(type(run[key]) is not int or run[key] <= 0
                   for key in ("run_id", "attempt", "job_id"))
            or not _is_name(run["job"])):
        raise ValueError("invalid qualification custody statement")


def _check_selector(value):
    if (type(value) is not dict
            or set(value) != {"run_id", "attempt", "job_id", "control_id"}
            or any(type(value[key]) is not int or value[key] <= 0
                   for key in ("run_id", "attempt", "job_id", "control_id"))):
        raise ValueError("invalid qualification custody selector")


def _leg_from_result(raw, parsed, name):
    if (type(parsed) is not dict or set(parsed) != {"status"}
            or parsed["status"] not in LEG_STATUSES):
        raise ValueError("invalid %s result outcome" % name)
    return {"status": parsed["status"],
            "result_sha256": hashlib.sha256(raw).hexdigest()}


def qualify_payload(*, payload_dir, smoke_result, openssl_result, output_dir):
    """Project one acquire output plus two leg outcomes into one record.

    Reads (all bounded) the verified finalization statement, the
    custody manifest (validated by the reused custody gate and bound to
    the statement by digest and run), the caller-recorded selector echo
    (run, attempt, and job cross-checked against the verified
    statement), and the two single-status result files. Writes canonical
    `qualification-record.json` into a fresh output directory.
    """
    from .image_custody import check_custody_manifest
    from .models import canonical_json_bytes
    root = Path(payload_dir)
    _, statement = _read_json(
        root / "authority/custody-finalization.json", STATEMENT_LIMIT)
    _check_statement(statement)
    manifest_raw, manifest = _read_json(
        root / "acquisition/payload/image-part1/custody-manifest.json",
        MANIFEST_LIMIT)
    if hashlib.sha256(manifest_raw).hexdigest() != statement["manifest_sha256"]:
        raise ValueError("custody manifest differs from verified finalization")
    check_custody_manifest(manifest)
    if manifest["run"] != statement["run"]:
        raise ValueError("custody manifest differs from verified finalization")
    _, selector = _read_json(root / "custody-selector.json", SELECTOR_LIMIT)
    _check_selector(selector)
    run = statement["run"]
    if any(selector[key] != run[key] for key in ("run_id", "attempt", "job_id")):
        raise ValueError("custody selector differs from verified finalization")
    smoke_raw, smoke = _read_json(Path(smoke_result), RESULT_LIMIT)
    openssl_raw, openssl = _read_json(Path(openssl_result), RESULT_LIMIT)
    record = build_qualification_record(
        custody={"environment": statement["environment"],
                 "channel": statement["channel"], "run_id": run["run_id"],
                 "attempt": run["attempt"], "job_id": run["job_id"],
                 "control_id": selector["control_id"],
                 "artifact_digest": manifest["artifact"]["reference"]},
        image={"engine_id": manifest["engine_id"],
               "config_sha256": manifest["config_sha256"],
               "layers": [row["diff_id"] for row in manifest["layers"]],
               "build_key": manifest["build_key"]},
        smoke=_leg_from_result(smoke_raw, smoke, "smoke"),
        openssl=_leg_from_result(openssl_raw, openssl, "openssl"),
        roster=list(_frozen_roster()))
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    (output / "qualification-record.json").write_bytes(
        canonical_json_bytes(record))
    return record
