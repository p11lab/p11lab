"""Protected local-controller endpoint binding, before public comparison.

The caller owns witness provenance. A Python object is an interface boundary, not
GitHub authentication: never construct this witness from candidate output. This
operation supports exactly one outer attempt / raw stream per endpoint (N=1).
It admits evidence through the sealed public evaluator but never compares it.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib.resources import files
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any, cast

from .round_core.inputs import (
    COMPARISON_ENVELOPE_V1,
    FrozenComparisonExpectation,
    SealedToolInputs,
    canonical,
    digest,
    freeze_comparison_expectation,
    load_json,
    safe_path,
    validate_shape,
)

_ENDPOINT_SCHEMA = cast(dict[str, Any], COMPARISON_ENVELOPE_V1)["endpoints"]["baseline"]

_MAX_BYTES = 32 * 1024 * 1024
_MAX_FILES = 128
_REQUIRED = {
    "artifacts.json",
    "header.json",
    "sidecar.json",
    "ledger.jsonl",
    "coverage.json",
    "catalog.json",
    "selected.json",
    "obligations.json",
    "raw-manifest.json",
    "build-manifest.json",
    "installed-manifest.json",
    "source.tar",
    "checker.whl",
}
_REQUIRED |= {
    "controls/" + name + ".json" for name in COMPARISON_ENVELOPE_V1["frozen_controls"]
}
_COVERAGE = (
    "advertised",
    "accepted",
    "attempted",
    "rejected_cleanly",
    "skipped_by_capability",
    "crashed",
    "timeout",
    "selected",
    "selection_rejected",
    "invoked",
)


@dataclass(frozen=True)
class LocalComparisonWitness:
    """Producer-owned frozen observation, supplied over a trusted Python boundary.

    ``observations`` is immutable canonical JSON: schema_version=1,
    scope=local-controller, endpoints={baseline,candidate}. Each side has ``files``
    (sorted path/size/sha256 rows), and ``streams`` (exactly one path/attempt/
    shard_id/selected row). Freeze scheduled names/selection before execution;
    seal measured sizes/digests afterwards using stopped, controller-owned state.
    Do not derive scheduled membership from surviving outputs.
    """

    expectation: FrozenComparisonExpectation
    observations: bytes


_PUBLIC_EVIDENCE = r"""
import dataclasses, io, json, sys
from pathlib import Path
from pkcs11_check.core.report_log import iter_report_log_records, SessionCompletionTracker
from pkcs11_check.core.evidence import (export_ledger, load_ledger, compile_obligations,
    ShardExpectation, PredeclaredRoster, admit_lane, shard_digest)
root=Path(sys.argv[1])
request=json.loads((root/'request.json').read_bytes())
raw=root/request['stream']['path']
identity={key:str(value) for key,value in request['header'].items()}
identity['shard_id']=request['stream']['shard_id']
tracker=SessionCompletionTracker()
invalid=[]
def bad():
    invalid.append(True)
    tracker.invalidate()
def records():
    for record in iter_report_log_records(raw,on_invalid=bad):
        tracker.observe(record)
        yield record
sink=io.StringIO()
export_ledger(records(),identity,sink,reader_invalid_lines=lambda:len(invalid))
if not tracker.complete or tracker.single_exitstatus is None:
    raise ValueError('raw stream is not one complete original session')
(root/'reexport.jsonl').write_text(sink.getvalue())
original=load_ledger(root/'ledger.jsonl')
regenerated=load_ledger(root/'reexport.jsonl')
if original != regenerated:
    raise ValueError('ledger does not reproduce from actual raw original')
header,rows=original
ob=json.loads((root/'obligations.json').read_bytes())
obligations=compile_obligations(ob['catalog'],ob['profile'])
# Names and selected membership came from the independent frozen controller plan;
# only the outcome-dependent row count/seal is measured here.
shard=request['stream']['shard_id']
roster=PredeclaredRoster(request['header']['lane'],{shard:ShardExpectation(len(rows),shard_digest(rows))})
verdict=admit_lane(header,rows,roster,obligations)
if not verdict.admitted:
    raise ValueError('public admission refused: '+repr(verdict.failures))
print(json.dumps({'header':dict(dataclasses.asdict(header),record='header'),
    'nodes':sorted(set(row.node_id for row in rows)),
    'shards':sorted(set(row.shard_id for row in rows)),
    'selected':sorted(obligations.members), 'unselected':sorted(obligations.unselected),
    'exitstatus':tracker.single_exitstatus,'warnings':verdict.warnings,'admitted':verdict.admitted}))
"""


def _snapshot(root: Path) -> dict[str, bytes]:
    """Snapshot bounded files via directory descriptors; never follow aliases."""
    if (
        not isinstance(root, Path)
        or not root.is_absolute()
        or root.absolute() != root.resolve()
    ):
        raise ValueError("unsafe/noncanonical endpoint root")
    result: dict[str, bytes] = {}
    directories: set[str] = set()
    counts = {"bytes": 0}

    def visit(fd: int, prefix: str, depth: int) -> None:
        if depth > 16:
            raise ValueError("endpoint directory depth bound")
        names = os.listdir(fd)
        if len(names) + len(result) + len(directories) > _MAX_FILES:
            raise ValueError("endpoint file roster bound")
        for name in names:
            relative = safe_path(prefix + name)
            details = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(details.st_mode):
                directories.add(relative)
                child = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
                try:
                    visit(child, relative + "/", depth + 1)
                finally:
                    os.close(child)
                continue
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or details.st_mode & 0o7000
                or details.st_size > _MAX_BYTES
            ):
                raise ValueError("unsafe endpoint file type/link/mode/size")
            child = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
            )
            with os.fdopen(child, "rb") as stream:
                before = os.fstat(stream.fileno())
                raw = stream.read(_MAX_BYTES + 1)
                after = os.fstat(stream.fileno())

            def identity(info: os.stat_result) -> tuple:
                return (
                    info.st_dev,
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                    info.st_mode,
                    info.st_nlink,
                )

            if (
                identity(details) != identity(before)
                or identity(before) != identity(after)
                or len(raw) != details.st_size
            ):
                raise ValueError("endpoint changed during snapshot")
            counts["bytes"] += len(raw)
            if counts["bytes"] > _MAX_BYTES:
                raise ValueError("endpoint byte bound")
            result[relative] = raw

    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            visit(fd, "", 0)
        finally:
            os.close(fd)
    except OSError as error:
        raise ValueError("unsafe/unavailable endpoint") from error
    expected_dirs = {
        str(parent)
        for name in result
        for parent in Path(name).parents
        if str(parent) != "."
    }
    if directories != expected_dirs:
        raise ValueError("unexpected empty endpoint directory")
    return result


def _rows(snapshot: dict[str, bytes]) -> list[dict]:
    return [
        {"path": path, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        for path, raw in sorted(snapshot.items())
    ]


def _public_evidence(
    snapshot: dict[str, bytes], request: dict, tools: SealedToolInputs
) -> dict:
    """Use only registered APIs in an isolated, fully verified tool installation."""
    with tempfile.TemporaryDirectory(prefix="p11lab-comparison-") as directory:
        root = Path(directory)
        for name, raw in snapshot.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        (root / "request.json").write_bytes(canonical(request))
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": directory,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "LD_LIBRARY_PATH": str(tools.root / "python/lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        with (
            (root / "stdout").open("wb") as stdout,
            (root / "stderr").open("wb") as stderr,
        ):
            try:
                process = subprocess.run(
                    [
                        str(tools.root / "evaluator-install/bin/python3"),
                        "-I",
                        "-B",
                        "-c",
                        _PUBLIC_EVIDENCE,
                        directory,
                    ],
                    cwd=directory,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=60,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ValueError("public evaluator unavailable/timed out") from error
        if process.returncode or (root / "stdout").stat().st_size > 2 * 1024 * 1024:
            raise ValueError("public raw export/load/admission refused endpoint")
        return load_json((root / "stdout").read_bytes())


def _bind(
    snapshot: dict[str, bytes], expected: dict, observation: dict, envelope: dict
) -> dict:
    validate_shape(
        observation,
        {
            "files": [{"path": "text", "size": "int", "sha256": "hash"}],
            "streams": [
                {
                    "path": "text",
                    "attempt": "text",
                    "shard_id": "text",
                    "selected": ["text"],
                }
            ],
        },
    )
    if _rows(snapshot) != observation["files"]:
        raise ValueError("protected endpoint file roster/length/hash mismatch")
    streams = observation["streams"]
    if len(streams) != 1:
        raise ValueError(
            "N=1 requires exactly one predeclared attempt/shard/raw stream"
        )
    stream = streams[0]
    safe_path(stream["path"])
    if stream["path"] in _REQUIRED or set(snapshot) != _REQUIRED | {stream["path"]}:
        raise ValueError("required endpoint original roster mismatch")
    if stream["selected"] != expected["selected"]:
        raise ValueError("predeclared stream selection mismatch")
    for name, raw in snapshot.items():
        if name.endswith(".json"):
            load_json(raw)
    for name in ("ledger.jsonl", stream["path"]):
        lines = snapshot[name].splitlines()
        if not lines or len(lines) > 100000:
            raise ValueError("empty/oversized endpoint JSONL roster")
        for line in lines:
            load_json(line)
    for name, expected_hash in envelope["frozen_controls"].items():
        if (
            hashlib.sha256(snapshot["controls/" + name + ".json"]).hexdigest()
            != expected_hash
        ):
            raise ValueError("actual frozen control bytes mismatch: " + name)
    for name in (stream["attempt"], stream["shard_id"]):
        safe_path(name)
    for key in ("artifacts", "header", "sidecar"):
        observed = load_json(snapshot[key + ".json"])
        validate_shape(observed, _ENDPOINT_SCHEMA[key], "$.endpoints.baseline." + key)
        if observed != expected[key]:
            raise ValueError("actual endpoint " + key + " mismatch")
    header = expected["header"]
    ledger_header = load_json(snapshot["ledger.jsonl"].splitlines()[0])
    validate_shape(ledger_header, _ENDPOINT_SCHEMA["header"])
    if ledger_header != header:
        raise ValueError("actual ledger header mismatch")
    if (
        header["lane"] != envelope["lane"]
        or header["lane_os"] != "linux"
        or header["lane_arch"] != "amd64"
        or header["framework_sha"] != expected["artifacts"]["checker"]["source_sha"]
        or header["p11lab_sha"] != envelope["protected"]["control_sha"]
        or header["image_digest"]
        != expected["artifacts"]["derivative"]["manifest_digest"]
        or header["corpus_hash"] != envelope["frozen_controls"]["dataset"]
        or header["planned_count"] != len(expected["selected"])
        or header["planned_collection_hash"] != expected["evidence"]["selected_sha256"]
        or header["raw_stream_bytes"] != len(snapshot[stream["path"]])
        or header["raw_stream_sha256"]
        != hashlib.sha256(snapshot[stream["path"]]).hexdigest()
    ):
        raise ValueError("header tool/control/source/selection/raw identity mismatch")
    for name in ("ledger", "coverage", "raw_manifest", "obligations"):
        path = name.replace("_", "-") + (".jsonl" if name == "ledger" else ".json")
        if (
            hashlib.sha256(snapshot[path]).hexdigest()
            != expected["evidence"][name + "_sha256"]
        ):
            raise ValueError("actual evidence hash mismatch: " + name)
    for name in ("catalog", "selected"):
        value = load_json(snapshot[name + ".json"])
        if (
            value != {name: expected[name]}
            or digest(expected[name]) != expected["evidence"][name + "_sha256"]
        ):
            raise ValueError("actual membership mismatch: " + name)
    obligations = load_json(snapshot["obligations.json"])
    if (
        set(obligations) != {"catalog", "profile"}
        or type(obligations["catalog"]) is not dict
        or set(obligations["catalog"]) != set(expected["catalog"])
        or obligations["profile"] != {"cases": expected["selected"]}
    ):
        raise ValueError("per-side catalog/obligations mismatch")
    if load_json(snapshot["raw-manifest.json"]) != {"streams": streams}:
        raise ValueError("actual raw attempt/shard/selection manifest mismatch")
    for key, path in (
        ("build_manifest_sha256", "build-manifest.json"),
        ("installed_manifest_sha256", "installed-manifest.json"),
        ("source_archive_sha256", "source.tar"),
    ):
        if hashlib.sha256(snapshot[path]).hexdigest() != expected["sidecar"][key]:
            raise ValueError("actual sidecar input bytes mismatch")
    if (
        expected["sidecar"]["installed_manifest_sha256"]
        != expected["artifacts"]["checker"]["installed_manifest_sha256"]
        or hashlib.sha256(snapshot["checker.whl"]).hexdigest()
        != expected["artifacts"]["checker"]["wheel_sha256"]
    ):
        raise ValueError("actual checker role/artifact bytes mismatch")
    # Presence/shape only: coverage interpretation and comparison remain public CLI operations.
    coverage = load_json(snapshot["coverage.json"])
    if type(coverage.get("mechanism_coverage")) is not dict or any(
        name + "_names" not in coverage["mechanism_coverage"] for name in _COVERAGE
    ):
        raise ValueError("missing public coverage field")
    for name in _COVERAGE:
        validate_shape(coverage["mechanism_coverage"][name + "_names"], ["text"])
    return {"header": header, "stream": stream}


def validate_comparison_envelope(envelope: dict, endpoints: dict) -> dict:
    """Authenticate bytes/controls with a trusted local witness; never promote.

    endpoints has exactly authority: LocalComparisonWitness, evaluator:
    SealedToolInputs, baseline: Path, candidate: Path. The evaluator is an explicit
    trusted tool input; no development workspace path or caller executable is used.
    Rejected inert inputs cannot reach public operations. The future image facade
    must call this operation before its public comparison and coverage operations.
    """
    if type(endpoints) is not dict or set(endpoints) != {
        "authority",
        "evaluator",
        "baseline",
        "candidate",
    }:
        raise TypeError("explicit authority/evaluator/two endpoint paths required")
    authority = endpoints["authority"]
    if (
        type(authority) is not LocalComparisonWitness
        or type(authority.expectation) is not FrozenComparisonExpectation
    ):
        raise TypeError(
            "typed protected local-controller witness required; JSON is not authority"
        )
    if (
        type(authority.observations) is not bytes
        or type(authority.expectation.serialized) is not bytes
    ):
        raise TypeError("immutable protected expectation/observation bytes required")
    expected = freeze_comparison_expectation(authority.expectation.as_dict()).as_dict()
    actual = freeze_comparison_expectation(envelope).as_dict()
    if actual != expected:
        raise ValueError("envelope differs from independent protected expectation")
    schema = load_json(
        files("p11lab").joinpath("data/ci/comparison.schema.json").read_bytes()
    )
    if schema != {
        "generated_from": "p11lab.round_core.inputs.COMPARISON_ENVELOPE_V1",
        "definition": COMPARISON_ENVELOPE_V1,
    }:
        raise ValueError("packaged comparison schema drift")
    observations = load_json(authority.observations)
    if (
        set(observations) != {"schema_version", "scope", "endpoints"}
        or type(observations["schema_version"]) is not int
        or observations["schema_version"] != 1
        or observations["scope"] != "local-controller"
        or type(observations["endpoints"]) is not dict
        or set(observations["endpoints"]) != {"baseline", "candidate"}
    ):
        raise ValueError("local controller observation contract mismatch")
    snapshots, requests = {}, {}
    for role in ("baseline", "candidate"):
        snapshots[role] = _snapshot(endpoints[role])
        requests[role] = _bind(
            snapshots[role],
            expected["endpoints"][role],
            observations["endpoints"][role],
            expected,
        )
    tools = endpoints["evaluator"]
    if type(tools) is not SealedToolInputs:
        raise TypeError("explicit sealed evaluator input required")
    verified = SealedToolInputs.from_evaluator(tools.root)
    if tools != verified:
        raise ValueError("sealed evaluator input drift")
    receipt = load_json(
        (tools.root / "evaluator-build-receipt.json").read_bytes(),
        max_bytes=16 * 1024 * 1024,
    )
    if receipt["source"]["commit"] != expected["protected"]["evaluator_sha"]:
        raise ValueError("protected evaluator role mismatch")
    result = {}
    for role in ("baseline", "candidate"):
        public = _public_evidence(snapshots[role], requests[role], tools)
        endpoint = expected["endpoints"][role]
        if (
            public["header"] != endpoint["header"]
            or public["selected"] != endpoint["selected"]
            or public["nodes"] != endpoint["observed_selected"]
            or public["shards"] != [requests[role]["stream"]["shard_id"]]
            or public["unselected"] != sorted(endpoint["unselected"])
        ):
            raise ValueError(
                "public observed header/membership/shard differs from protected plan"
            )
        result[role] = {
            "files": _rows(snapshots[role]),
            "selected": public["selected"],
            "attempts": [requests[role]["stream"]["attempt"]],
            "shards": public["shards"],
            "admission": public,
        }
    return {
        "schema_version": 1,
        "scope": "local-controller",
        "operation": expected["operation"],
        "expectation_sha256": digest(expected),
        "observations_sha256": hashlib.sha256(authority.observations).hexdigest(),
        "evaluator_receipt_sha256": tools.receipt_sha256,
        "endpoints": result,
        "comparison": None,
        "image_promotable": False,
    }
