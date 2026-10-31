"""Round execution over fixture and github transports: prepare to capsule.

One `execute_round` call chains the existing round primitives end to end for a
single policy lane: opaque input preparation, sealed candidate production,
verify-only sealed-evaluator binding, comparison-envelope binding, sealed
semantic/coverage verdicts, and round-native capsule plus receipt assembly with
typed causes. Fixture callers stage the builder identity explicitly; github
binds builder and sandbox from the enrolled producer profile, and refuses
without staged owner-proven material or a verified owner proof.

The chain runs bootstrap before produce: freezing the candidate context needs
the sealed tool inputs, so the evaluator binds first even though the phase
names list produce first. Callers stage comparison material explicitly
(builder identity, typed witness, endpoint directories); without it the chain
refuses instead of inventing evidence. Dependency seams (prepare, engine,
binders, verdict runners) default to the real primitives; tests inject fakes.
Only public library operations are used.
"""
from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
import hashlib
import json
import subprocess
from typing import Any, Callable

from . import JsonObject
from .causes import CAUSE_EXIT, CAUSE_STATUS, ExecuteCause
from .inputs import (
    DIGEST,
    SHA,
    LocalProducerEvent,
    ProtectedSelection,
    SealedToolInputs,
    VerifiedSource,
    canonical,
    digest,
    freeze_candidate_context,
    load_json,
    read_source_archive,
    safe_path,
)
from .policy import load_policy
from .worker import SandboxPolicy, inspect_source_archive, produce_candidate, source_tree
from ..comparison import LocalComparisonWitness, validate_comparison_envelope
from ..results import ResultError, validate_result

_ROUND_CAPSULE_SCHEMA = "p11lab-round-execution-v1"
_ROUND_RECEIPT_SCHEMA = "p11lab-round-receipt-v1"
_FIXTURE_REPOSITORY_PREFIX = "https://github.com/"
_VERDICT_TIMEOUT_SECONDS = 300
_VERDICT_STDOUT_LIMIT = 2 * 1024 * 1024
_FIXTURE_LIMITATION = (
    "Fixture transport is local-only and non-authoritative; no caller, "
    "producer, or publication authority is established.")
_GITHUB_LIMITATION = (
    "GitHub transport: producer authority established by round owner proof "
    "over the prepared dist; comparison evidence staged by caller; builder "
    "source epoch bound from the enrolled profile runtime.")


@dataclass(frozen=True)
class BuilderIdentity:
    """Sealed builder image; caller-staged for fixture, profile-bound for github."""

    image: str
    layers: tuple[str, ...]
    config_sha256: str
    source_date_epoch: int


@dataclass(frozen=True)
class CompareOutcome:
    """Parsed `evidence-compare` verdict; positivity is computed here, not claimed."""

    regressions: tuple[dict[str, Any], ...]
    improvements: tuple[dict[str, Any], ...]
    unstable: tuple[str, ...]
    counts: dict[str, int]
    positive: bool
    provider_failure: bool
    provider_failure_detail: str | None


@dataclass(frozen=True)
class CoverageOutcome:
    """Parsed `compare-coverage` verdict."""

    positive: bool
    has_loss: bool
    states_compared: tuple[str, ...]
    lost_by_state: dict[str, list[str]]


def _require_text(value: Any, path: str) -> str:
    if type(value) is not str or not value or len(value) > 8192 or "\x00" in value:
        raise ValueError(path + ": invalid string")
    return value


def _require_fingerprint(value: Any, path: str) -> str | list[str]:
    if type(value) is str:
        return _require_text(value, path)
    if type(value) is list and value and len(value) <= 1000:
        return [_require_text(item, path + "[]") for item in value]
    raise ValueError(path + ": invalid outcome fingerprint")


def parse_compare_output(raw: bytes) -> CompareOutcome:
    """Parse `evidence-compare --output json` into a comparison verdict.

    The verdict core must match the registered ComparisonVerdict shape
    (regressions/improvements/unstable/counts); command path echoes are
    ignored. Positive means no regressions and nothing quorum-unstable.
    provider_failure stays False with detail None for every structurally
    valid verdict: False means no supported provider attribution, not
    proof the provider succeeded. Regression phase/axis are plain str
    with no causal semantics (data/rounds/contract.json ComparisonVerdict
    :65-89, Regression :427-455); a merely provider-named row, an
    unstable entry, or an improvement never flips this flag. Reopen only
    after an owner-documented causal signal or an exact versioned
    axis/phase map at a reviewed evaluator pin, demonstrated through the
    real parser. Injected runners exercise the provider-failure path.
    """
    value = load_json(raw, max_bytes=_VERDICT_STDOUT_LIMIT)
    for key in ("regressions", "improvements", "unstable", "counts"):
        if key not in value:
            raise ValueError("compare verdict is missing: " + key)

    def rows(entries: Any, path: str) -> tuple[dict[str, Any], ...]:
        if type(entries) is not list or len(entries) > 100000:
            raise ValueError(path + ": invalid verdict roster")
        parsed = []
        for entry in entries:
            if type(entry) is not dict or set(entry) != {
                    "node_id", "phase", "old", "new", "axis"}:
                raise ValueError(path + "[]: invalid verdict row")
            parsed.append({
                "node_id": _require_text(entry["node_id"], path + "[].node_id"),
                "phase": _require_text(entry["phase"], path + "[].phase"),
                "old": _require_fingerprint(entry["old"], path + "[].old"),
                "new": _require_fingerprint(entry["new"], path + "[].new"),
                "axis": _require_text(entry["axis"], path + "[].axis")})
        return tuple(parsed)

    regressions = rows(value["regressions"], "$.regressions")
    improvements = rows(value["improvements"], "$.improvements")
    unstable = value["unstable"]
    if type(unstable) is not list or len(unstable) > 100000:
        raise ValueError("$.unstable: invalid verdict roster")
    unstable_rows = tuple(_require_text(item, "$.unstable[]") for item in unstable)
    counts = value["counts"]
    if (type(counts) is not dict or len(counts) > 100
            or any(type(name) is not str or type(total) is not int or total < 0
                   for name, total in counts.items())):
        raise ValueError("$.counts: invalid verdict counts")
    return CompareOutcome(
        regressions, improvements, unstable_rows, dict(counts),
        positive=not regressions and not unstable_rows,
        provider_failure=False, provider_failure_detail=None)


def parse_coverage_output(raw: bytes) -> CoverageOutcome:
    """Parse `compare-coverage --output json` into a coverage verdict."""
    value = load_json(raw, max_bytes=_VERDICT_STDOUT_LIMIT)
    for key in ("has_loss", "states_compared", "lost_by_state"):
        if key not in value:
            raise ValueError("coverage verdict is missing: " + key)
    has_loss = value["has_loss"]
    if type(has_loss) is not bool:
        raise ValueError("$.has_loss: invalid coverage flag")
    states = value["states_compared"]
    if type(states) is not list or len(states) > 100:
        raise ValueError("$.states_compared: invalid coverage roster")
    lost = value["lost_by_state"]
    if type(lost) is not dict or len(lost) > 100:
        raise ValueError("$.lost_by_state: invalid coverage loss")
    parsed_lost = {}
    for state, names in lost.items():
        _require_text(state, "$.lost_by_state")
        if type(names) is not list or len(names) > 100000:
            raise ValueError("$.lost_by_state[]: invalid coverage names")
        parsed_lost[state] = [_require_text(name, "$.lost_by_state[]") for name in names]
    return CoverageOutcome(
        positive=not has_loss, has_loss=has_loss,
        states_compared=tuple(_require_text(name, "$.states_compared[]") for name in states),
        lost_by_state=parsed_lost)


class _Refused(Exception):
    """Chain halt with an observable row; usage errors propagate instead."""

    def __init__(self, phase: str, cause: ExecuteCause, detail: str | None) -> None:
        super().__init__(f"{phase}/{cause.value}: {detail}")
        self.phase = phase
        self.cause = cause
        self.detail = detail


def _contract_coverage_states() -> tuple[str, ...]:
    raw = files("p11lab").joinpath("data/rounds/contract.json").read_bytes()
    contract = load_json(raw, max_bytes=16 * 1024 * 1024)
    states = contract["coverage_fields"]
    if type(states) is not list or not states or len(states) > 100:
        raise ValueError("evaluator contract has no coverage fields")
    return tuple(_require_text(name, "$.coverage_fields[]") for name in states)


def _run_sealed_cli(tools: SealedToolInputs, command: str, baseline: Path,
                    candidate: Path, workdir: Path) -> bytes:
    """Run one registered sealed CLI; the JSON verdict is authoritative."""
    launcher = tools.root / "evaluator-install/bin/pkcs11-check"
    if not launcher.is_file() or launcher.is_symlink():
        raise ValueError("sealed pkcs11-check launcher is missing")
    argv = [str(launcher), command, str(baseline), str(candidate),
           "--output", "json"]
    env = {"PATH": "/usr/bin:/bin", "HOME": str(workdir), "LANG": "C.UTF-8",
           "LC_ALL": "C.UTF-8", "LD_LIBRARY_PATH": str(tools.root / "python/lib"),
           "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        completed = subprocess.run(
            argv, cwd=workdir, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=_VERDICT_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"sealed {command} is unavailable/timed out") from error
    if completed.returncode not in (0, 1):
        raise ValueError(f"sealed {command} failed with exit {completed.returncode}")
    if len(completed.stdout) > _VERDICT_STDOUT_LIMIT:
        raise ValueError(f"sealed {command} output exceeds bounds")
    return completed.stdout


def _run_sealed_compare(tools: SealedToolInputs, baseline: Path, candidate: Path,
                        binding: JsonObject, workdir: Path) -> CompareOutcome:
    raw = _run_sealed_cli(tools, "evidence-compare", baseline / "ledger.jsonl",
                           candidate / "ledger.jsonl", workdir)
    (workdir / "verdict-compare.json").write_bytes(raw)
    return parse_compare_output(raw)


def _run_sealed_coverage(tools: SealedToolInputs, baseline: Path, candidate: Path,
                         binding: JsonObject, workdir: Path) -> CoverageOutcome:
    raw = _run_sealed_cli(tools, "compare-coverage", baseline, candidate, workdir)
    (workdir / "verdict-coverage.json").write_bytes(raw)
    return parse_coverage_output(raw)


def _bound_hashes(binding: JsonObject) -> dict[str, dict[str, str]]:
    """Index bound endpoint file digests by role and path."""
    indexed = {}
    endpoints = binding["endpoints"]
    if type(endpoints) is not dict or set(endpoints) != {"baseline", "candidate"}:
        raise ValueError("binding has no baseline/candidate endpoints")
    for role, endpoint in endpoints.items():
        rows = endpoint["files"]
        if type(rows) is not list:
            raise ValueError("binding endpoint has no file rows")
        indexed[role] = {row["path"]: row["sha256"] for row in rows}
    return indexed


def _read_bounded(path: Path, limit: int = 32 * 1024 * 1024 + 1) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(limit)
    if len(raw) >= limit:
        raise ValueError("endpoint file exceeds bounds: " + path.name)
    return raw


def _assert_inputs_stable(binding: JsonObject, authority: LocalComparisonWitness,
                           baseline: Path, candidate: Path, phase: str) -> None:
    """Re-hash verdict inputs against the binding; the facade keeps compared bytes identical."""
    try:
        observations = load_json(authority.observations)
        streams = {role: observations["endpoints"][role]["streams"][0]["path"]
                   for role in ("baseline", "candidate")}
        for stream in streams.values():
            safe_path(stream)
        expected = _bound_hashes(binding)
        for role, root in (("baseline", baseline), ("candidate", candidate)):
            for name in ("coverage.json", "ledger.jsonl", streams[role]):
                actual = hashlib.sha256(_read_bounded(root / name)).hexdigest()
                if expected[role].get(name) != actual:
                    raise ValueError("compared bytes differ from binding: " + name)
    except (KeyError, TypeError, IndexError, OSError) as error:
        raise _Refused(phase, ExecuteCause.EXECUTE_ENDPOINT_DRIFT,
                       f"{type(error).__name__}: {error}") from error
    except ValueError as error:
        raise _Refused(phase, ExecuteCause.EXECUTE_ENDPOINT_DRIFT, str(error)) from error


def _map_result_record(row: JsonObject, lane_provider: JsonObject) -> JsonObject:
    """Map genuine round facts into an experiment-result record for the oracle.

    Unmapped identities stay honestly unperformed; no provider artifact, shard
    roster, or distribution fact is invented. The oracle validates a positive
    copy, so its first refusal names the true acceptance blocker.
    """
    def identity(status: str, reason: str | None) -> JsonObject:
        return {"status": status, "sha256": None, "source_revision": None,
                "artifact": None, "reason": reason}

    return {
        "schema_version": 1, "kind": "experiment-result", "experiment_kind": "checker",
        "stage": "runtime-diagnostic",
        "caller": {"kind": "local", "repository": None, "run_id": None,
                   "run_attempt": None, "job": "round-execute",
                   "local_run_id": "local-1"},
        "identities": {
            "control": identity("unperformed", "No control revision is bound in C1a."),
            "candidate": identity("unperformed", "No candidate identity receipt is bound in C1a."),
            "evaluator": identity("unperformed", "No evaluator identity receipt is bound in C1a."),
            "policy": identity("unperformed", "No policy identity receipt is bound in C1a."),
            "inputs": identity("unperformed", "No inputs identity receipt is bound in C1a."),
            "derivative": identity("not-applicable", "Checker experiments have no derivative."),
            "client": identity("not-applicable", "Checker experiments have no proxy client."),
            "source": identity("unperformed", "No source identity receipt is bound in C1a.")},
        "policy_revision": "round-execute-c1a",
        "provider": {"environment": lane_provider["family"], "channel": "release",
                     "platform": lane_provider["platform"], "artifact": None,
                     "registry_status": "unperformed",
                     "registry_reason": "No provider image was built or admitted in C1a.",
                     "root": None, "platform_manifest_digest": None, "config_digest": None,
                     "local_engine_id": None, "build_receipt": None,
                     "provider_build_key": None, "experiment_key": None},
        "execution": {"profile": None, "roster_sha256": None, "expected_shards": [],
                      "observed_shards": [],
                      "raw_status": {"process_returncode": None,
                                     "findings": len(row["regressions"]), "skips": 0}},
        "axes": {"image_usable": False, "lifecycle_complete": False,
                 "evidence_complete": row["evidence_complete"],
                 "evidence_admitted": row["evidence_admitted"],
                 "comparison_positive": row["comparison_positive"],
                 "within_budget": None, "distribution_eligible": False},
        "policy": {"qualification_only": True, "promotable": False,
                   "comparison_required": True, "comparison_performed": True,
                   "coverage_positive": row["coverage_positive"],
                   "budget_required": False, "budget_performed": False,
                   "distribution_required": False, "image_semantics_reviewed": None,
                   "proxy": None},
        "reproduction": ["p11lab", "round", "execute"],
        "evidence": [],
        "limitations": [_GITHUB_LIMITATION if row["transport"] == "github"
                        else _FIXTURE_LIMITATION],
    }


def _acceptance_oracle(mapped: JsonObject) -> tuple[bool, str]:
    """Ask results.py acceptance predicates whether this round could accept."""
    candidate = dict(mapped)
    candidate["stage"] = "accepted"
    try:
        validate_result(candidate)
    except ResultError as error:
        return True, str(error)
    except Exception as error:  # Our mapping bug must stay observable, never fatal.
        return True, f"oracle unavailable: {type(error).__name__}: {error}"
    return False, "acceptance predicates hold; round_positive remains false"


def _manifest(output_dir: Path, exclude: str) -> list[JsonObject]:
    entries = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_file() and path.name != exclude:
            raw = path.read_bytes()
            entries.append({"path": path.relative_to(output_dir).as_posix(),
                            "size": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest()})
    return entries


def _coverage_map(candidate_dir: Path, states: tuple[str, ...]) -> dict[str, list[str]]:
    payload = load_json((candidate_dir / "coverage.json").read_bytes())
    mechanisms = payload.get("mechanism_coverage")
    if type(mechanisms) is not dict:
        raise ValueError("candidate coverage has no mechanism map")
    result = {}
    for state in states:
        names = mechanisms.get(state + "_names")
        if type(names) is not list or len(names) > 100000:
            raise ValueError("candidate coverage is missing: " + state)
        result[state + "_names"] = [_require_text(name, "$.coverage[]")
                                    for name in names[:10]]
    return result


def _freeze_producer_inputs(prepared: JsonObject, context: JsonObject,
                            prepare_dir: Path, builder: BuilderIdentity,
                            authority: LocalComparisonWitness,
                            tools: SealedToolInputs):
    """Build the typed frozen candidate context from prepared fixture outputs."""
    identity = prepared["identity"]
    repository = context["repository"]
    if not repository.startswith(_FIXTURE_REPOSITORY_PREFIX):
        repository = _FIXTURE_REPOSITORY_PREFIX + repository
    event = LocalProducerEvent(repository, identity["candidate_sha"],
                               str(identity["attempt"]))
    role = prepared["dist"]["roles"]["sdist"]
    archive = prepare_dir / "dist" / role["path"]
    source = VerifiedSource(archive, role["sha256"], identity["candidate_sha"],
                            source_tree(archive), inspect_source_archive(archive))
    selection = ProtectedSelection(
        authority.expectation, builder.image, tuple(builder.layers),
        builder.source_date_epoch, builder.config_sha256)
    return freeze_candidate_context(selection, event, source, tools)


def github_producer_profile(repository: str, workflow_id: int) -> JsonObject:
    """Select the enrolled producer profile; mirrors prepare's selection."""
    raw = files("p11lab").joinpath("data/rounds/producer-profiles.json").read_bytes()
    profiles = load_json(raw)
    if (set(profiles) != {"schema_version", "profiles"}
            or type(profiles["schema_version"]) is not int
            or profiles["schema_version"] != 1
            or type(profiles["profiles"]) is not list
            or any(type(entry) is not dict for entry in profiles["profiles"])):
        raise ValueError("invalid protected producer profiles")
    selected = [entry for entry in profiles["profiles"]
                if entry.get("repository") == repository
                and entry.get("workflow_id") == workflow_id]
    if len(selected) != 1:
        raise ValueError("protected producer profile unavailable or ambiguous")
    return selected[0]


def bind_github_produce_inputs(
        profile: JsonObject, prepared: JsonObject, *,
        source_date_epoch: int | None,
        build_reports: tuple[str, ...] | None,
        startup_reports: tuple[str, ...] | None,
        timeout_seconds: int | None) -> tuple[BuilderIdentity, SandboxPolicy]:
    """Bind github produce inputs from enrolled profile material.

    The builder image, layers, config, and source epoch come from the
    profile `runtime` block after its digest is cross-checked against the
    prepared pin; the sandbox takes `max_output_bytes` from the same block
    and the wheel name from the prepared candidate dist, with
    reports/timeout explicit or the fixture-tested defaults. An explicitly
    staged epoch is rejected: github binds it from profile material, not
    caller staging. Wrongly typed inputs raise `TypeError`; binding
    failures raise `ValueError` for the chain to refuse.
    """
    if type(profile) is not dict or type(prepared) is not dict:
        raise TypeError("typed github profile and prepared inputs required")
    if digest(profile) != prepared.get("protected_profile_sha256"):
        raise ValueError("github producer profile does not match prepared inputs")
    runtime = profile.get("runtime")
    if type(runtime) is not dict:
        raise ValueError("github producer runtime is not sealed")
    image = runtime.get("image")
    layers = runtime.get("layers")
    config = runtime.get("config_sha256")
    max_output = runtime.get("max_output_bytes")
    if type(image) is not str or not DIGEST.fullmatch(image):
        raise ValueError("github producer runtime image is not a sealed digest")
    if (type(layers) is not list or not layers
            or any(type(entry) is not str or not DIGEST.fullmatch(entry)
                   for entry in layers)):
        raise ValueError("github producer runtime layers are not sealed digests")
    if type(config) is not str or not SHA.fullmatch(config):
        raise ValueError("github producer runtime config is not sealed")
    if (type(max_output) is not int
            or not 1024 <= max_output <= 128 * 1024 * 1024):
        raise ValueError("github producer runtime max_output_bytes is out of bounds")
    if source_date_epoch is not None:
        raise TypeError("github builder binding takes source epoch "
                        "from profile material, not caller staging")
    epoch = runtime.get("source_date_epoch")
    if epoch is None:
        raise ValueError("github producer runtime source_date_epoch "
                         "is missing from the profile")
    if type(epoch) is not int:
        raise TypeError("typed github source epoch required")
    if not 0 <= epoch <= 2 ** 31 - 1:
        raise ValueError(
            "github builder binding has an invalid profile source_date_epoch")
    if build_reports is None:
        build_reports = ()
    if startup_reports is None:
        startup_reports = ("startup.json",)
    if timeout_seconds is None:
        timeout_seconds = 60
    if type(build_reports) is not tuple or type(startup_reports) is not tuple:
        raise TypeError("typed github sandbox reports required")
    if type(timeout_seconds) is not int:
        raise TypeError("typed github sandbox timeout required")
    try:
        wheel_path = prepared["dist"]["roles"]["primary_wheel"]["path"]
    except (KeyError, TypeError) as error:
        raise ValueError(
            "github sandbox wheel is not bound to the prepared dist") from error
    if type(wheel_path) is not str or not Path(wheel_path).name.endswith(".whl"):
        raise ValueError("github sandbox wheel is not bound to the prepared dist")
    builder = BuilderIdentity(
        image=image, layers=tuple(layers), config_sha256=config,
        source_date_epoch=epoch)
    sandbox = SandboxPolicy(
        Path(wheel_path).name, build_reports=build_reports,
        startup_reports=startup_reports, timeout_seconds=timeout_seconds,
        max_output_bytes=max_output)
    sandbox.validate()
    return builder, sandbox


def execute_round(
        context_path: Path, policy_root: Path | None, evaluator_root: Path,
        output_dir: Path, output_json: Path, tier: str | None = None, *,
        lane: str | None = None, builder: BuilderIdentity | None = None,
        authority: LocalComparisonWitness | None = None,
        sandbox: SandboxPolicy | None = None,
        baseline: Path | None = None, candidate: Path | None = None,
        source_date_epoch: int | None = None,
        sandbox_build_reports: tuple[str, ...] | None = None,
        sandbox_startup_reports: tuple[str, ...] | None = None,
        sandbox_timeout_seconds: int | None = None,
        engine: Any = None,
        run_prepare: Callable[[JsonObject, Path | None, Path], JsonObject] | None = None,
        bind_produce_inputs: Callable[..., tuple[BuilderIdentity, SandboxPolicy]] | None = None,
        bind_evaluator: Callable[[Path], SealedToolInputs] | None = None,
        bind_envelope: Callable[[JsonObject, JsonObject], JsonObject] | None = None,
        run_compare: Callable[[SealedToolInputs, Path, Path, JsonObject, Path],
                              CompareOutcome] | None = None,
        run_coverage: Callable[[SealedToolInputs, Path, Path, JsonObject, Path],
                               CoverageOutcome] | None = None) -> dict[str, Any]:
    """Execute one fixture- or github-transport round lane; return its verdict row.

    Usage errors (unreadable context, tier mismatch, unknown lane, stale
    output directory) raise and the CLI reports exit 2. Every chain halt
    instead returns a verdict row with a typed cause and exit 0 or 3, and
    writes the row, receipt, and capsule. Comparison material and seams are
    explicit caller inputs; the CLI passes none and refuses past bootstrap
    (fixture) or before prepare (github, which needs staged material).
    """
    from ..tool_downloads import safe_directory
    from .inputs import prepare as prepare_inputs

    if builder is not None and type(builder) is not BuilderIdentity:
        raise TypeError("typed builder identity required")
    if authority is not None and type(authority) is not LocalComparisonWitness:
        raise TypeError("typed comparison witness required")
    if sandbox is not None and type(sandbox) is not SandboxPolicy:
        raise TypeError("typed sandbox policy required")
    for name, value in (("baseline", baseline), ("candidate", candidate)):
        if value is not None and not isinstance(value, Path):
            raise TypeError(f"typed {name} endpoint path required")
    context_path = context_path.absolute()
    context = load_json(read_source_archive(context_path))
    for field in ("artifact_path", "fixture_metadata_path", "data_root", "cache_file"):
        if field in context:
            if type(context[field]) is not str or not context[field]:
                raise ValueError("invalid preparation context path")
            path = Path(context[field])
            context[field] = str(path if path.is_absolute() else context_path.parent / path)
    context_tier = context.get("tier")
    if type(context_tier) is not str or not context_tier:
        raise ValueError("invalid execution context: tier is missing")
    if tier is not None and tier != context_tier:
        raise ValueError("tier flag does not match preparation context")
    resolved_tier = context_tier
    policy = load_policy(policy_root, resolved_tier)
    lanes = {entry["id"]: entry for entry in policy.active_lanes}
    if lane is None:
        lane_id = policy.active_lanes[0]["id"]
    elif lane in lanes:
        lane_id = lane
    else:
        raise ValueError(f"unknown lane for tier {resolved_tier}: {lane!r}")
    lane_entry = lanes[lane_id]
    provider = {"family": lane_entry["provider"], "channel": lane_entry["channel"],
                "platform": lane_entry["platform"]}
    states = _contract_coverage_states()
    if not evaluator_root.is_dir():
        raise ValueError("invalid evaluator root")
    safe_directory(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    if not output_json.parent.exists():
        raise ValueError("invalid output JSON path")
    context_sha = hashlib.sha256(canonical(context)).hexdigest()
    transport = context.get("transport")
    if transport not in ("fixture", "github"):
        raise ValueError("unknown transport")

    seen: dict[str, Any] = {"prepared": None, "producer": None, "tools": None,
                            "binding": None, "compare": None, "coverage": None,
                            "coverage_map": {}, "missing": [],
                            "selected_count": 0, "observed_count": 0,
                            "attempt_roster": [], "shard_roster": [],
                            "provider_failure": None}
    history: list[JsonObject] = []

    def note(phase: str, cause: ExecuteCause, detail: str | None) -> None:
        history.append({"phase": phase, "cause": cause.value, "cause_detail": detail})

    def finish(phase: str, cause: ExecuteCause, detail: str | None) -> dict[str, Any]:
        note(phase, cause, detail)
        return _deliver(
            output_dir, output_json, context, context_sha, transport, resolved_tier,
            lane_id, provider, policy, authority, seen, history,
            phase, cause, detail)

    try:
        if transport == "github":
            if builder is not None or sandbox is not None:
                raise TypeError("github transport binds builder and sandbox "
                                "from profile material, not caller staging")
            if source_date_epoch is not None:
                raise TypeError("github transport binds source epoch "
                                "from profile material, not caller staging")
            if authority is None and baseline is None and candidate is None:
                raise _Refused("prepare", ExecuteCause.EXECUTE_TRANSPORT_REFUSED,
                               "github transport requires staged owner-proven material")
        else:
            for staged_name, staged_value in (
                    ("source_date_epoch", source_date_epoch),
                    ("sandbox_build_reports", sandbox_build_reports),
                    ("sandbox_startup_reports", sandbox_startup_reports),
                    ("sandbox_timeout_seconds", sandbox_timeout_seconds)):
                if staged_value is not None:
                    raise TypeError(f"{staged_name} is github-only")
        prepare_dir = output_dir / "prepare"
        prepare_runner = run_prepare or prepare_inputs
        seen["prepared"] = prepare_runner(context, policy_root, prepare_dir)
        if transport == "github":
            owner_authority = seen["prepared"].get("authority")
            if (owner_authority != "round-owner-proof-verified"
                    or "owner_proof" not in seen["prepared"]):
                raise _Refused(
                    "prepare", ExecuteCause.EXECUTE_TRANSPORT_REFUSED,
                    "github transport requires round owner proof "
                    f"(authority: {owner_authority})")
        note("prepare", ExecuteCause.EXECUTE_OK, None)
        binder = bind_evaluator or SealedToolInputs.from_evaluator
        try:
            seen["tools"] = binder(evaluator_root)
        except ValueError as error:
            raise _Refused("bootstrap", ExecuteCause.EXECUTE_EVALUATOR_REFUSED,
                           str(error)) from error
        except Exception as error:
            raise _Refused("bootstrap", ExecuteCause.EXECUTE_EVALUATOR_FAILED,
                           f"{type(error).__name__}: {error}") from error
        if type(seen["tools"]) is not SealedToolInputs:
            raise _Refused("bootstrap", ExecuteCause.EXECUTE_EVALUATOR_FAILED,
                           "evaluator binder returned untyped tools")
        note("bootstrap", ExecuteCause.EXECUTE_OK, None)
        if transport == "github":
            if authority is None:
                raise _Refused("produce", ExecuteCause.EXECUTE_PRODUCE_INPUTS_MISSING,
                               "missing produce inputs: authority")
            try:
                profile = github_producer_profile(
                    context["repository"], context["workflow_id"])
            except (TypeError, ValueError, KeyError) as error:
                raise _Refused("produce", ExecuteCause.EXECUTE_PRODUCE_INPUTS_MISSING,
                               str(error)) from error
            produce_binder = bind_produce_inputs or bind_github_produce_inputs
            try:
                bound_builder, bound_sandbox = produce_binder(
                    profile, seen["prepared"], source_date_epoch=source_date_epoch,
                    build_reports=sandbox_build_reports,
                    startup_reports=sandbox_startup_reports,
                    timeout_seconds=sandbox_timeout_seconds)
            except ValueError as error:
                raise _Refused("produce", ExecuteCause.EXECUTE_PRODUCE_INPUTS_MISSING,
                               str(error)) from error
            if (type(bound_builder) is not BuilderIdentity
                    or type(bound_sandbox) is not SandboxPolicy):
                raise _Refused("produce", ExecuteCause.EXECUTE_PRODUCER_FAILED,
                               "produce binder returned untyped inputs")
            builder, sandbox = bound_builder, bound_sandbox
        else:
            missing_produce = [name for name, value in
                               (("builder", builder), ("authority", authority),
                                ("sandbox", sandbox)) if value is None]
            if missing_produce:
                raise _Refused("produce", ExecuteCause.EXECUTE_PRODUCE_INPUTS_MISSING,
                               "missing produce inputs: " + ", ".join(missing_produce))
            assert builder is not None and authority is not None and sandbox is not None
        try:
            frozen = _freeze_producer_inputs(
                seen["prepared"], context, prepare_dir, builder, authority,
                seen["tools"])
            seen["producer"] = produce_candidate(
                frozen, sandbox, output_dir / "produce", engine=engine)
        except (TypeError, ValueError, KeyError) as error:
            raise _Refused("produce", ExecuteCause.EXECUTE_PRODUCER_FAILED,
                           f"{type(error).__name__}: {error}") from error
        if seen["producer"].get("status") != "produced":
            raise _Refused("produce", ExecuteCause.EXECUTE_PRODUCER_FAILED,
                           seen["producer"].get("error") or "candidate was not produced")
        note("produce", ExecuteCause.EXECUTE_OK, None)
        missing_bind = [name for name, value in
                        (("baseline", baseline), ("candidate", candidate))
                        if value is None]
        if missing_bind:
            raise _Refused("bind", ExecuteCause.EXECUTE_BIND_INPUTS_MISSING,
                           "missing bind inputs: " + ", ".join(missing_bind))
        assert baseline is not None and candidate is not None
        envelope_binder = bind_envelope or validate_comparison_envelope
        envelope = authority.expectation.as_dict()
        try:
            seen["binding"] = envelope_binder(
                envelope, {"authority": authority, "evaluator": seen["tools"],
                           "baseline": baseline, "candidate": candidate})
        except (TypeError, ValueError) as error:
            raise _Refused("bind", ExecuteCause.EXECUTE_BIND_REFUSED,
                           str(error)) from error
        except Exception as error:
            raise _Refused("bind", ExecuteCause.EXECUTE_BIND_FAILED,
                           f"{type(error).__name__}: {error}") from error
        bind_dir = output_dir / "bind"
        bind_dir.mkdir()
        (bind_dir / "binding.json").write_bytes(canonical(seen["binding"]) + b"\n")
        try:
            endpoints = seen["binding"]["endpoints"]
            missing: set[str] = set()
            for role in ("baseline", "candidate"):
                selected = endpoints[role]["selected"]
                observed = endpoints[role]["admission"]["nodes"]
                missing.update(set(selected) - set(observed))
            seen["missing"] = sorted(missing)
            seen["selected_count"] = len(endpoints["candidate"]["selected"])
            seen["observed_count"] = len(endpoints["candidate"]["admission"]["nodes"])
            seen["attempt_roster"] = list(endpoints["candidate"]["attempts"])
            seen["shard_roster"] = list(endpoints["candidate"]["shards"])
        except (KeyError, TypeError) as error:
            raise _Refused("bind", ExecuteCause.EXECUTE_BIND_FAILED,
                           f"binding is malformed: {error}") from error
        if seen["missing"]:
            raise _Refused("bind", ExecuteCause.EXECUTE_MISSING_SELECTED,
                           "missing selected obligations: "
                           + ", ".join(seen["missing"][:10]))
        note("bind", ExecuteCause.EXECUTE_OK, None)
        compare_dir = output_dir / "compare"
        compare_dir.mkdir()
        _assert_inputs_stable(seen["binding"], authority, baseline, candidate, "compare")
        compare_runner = run_compare or _run_sealed_compare
        try:
            seen["compare"] = compare_runner(seen["tools"], baseline, candidate,
                                             seen["binding"], compare_dir)
        except Exception as error:
            raise _Refused("compare", ExecuteCause.EXECUTE_COMPARE_FAILED,
                           f"{type(error).__name__}: {error}") from error
        if type(seen["compare"]) is not CompareOutcome:
            raise _Refused("compare", ExecuteCause.EXECUTE_COMPARE_FAILED,
                           "compare runner returned an untyped verdict")
        _assert_inputs_stable(seen["binding"], authority, baseline, candidate, "compare")
        if seen["compare"].provider_failure:
            seen["provider_failure"] = (
                seen["compare"].provider_failure_detail or "provider failure observed")
        note("compare", ExecuteCause.EXECUTE_OK, None)
        coverage_dir = output_dir / "coverage"
        coverage_dir.mkdir()
        _assert_inputs_stable(seen["binding"], authority, baseline, candidate, "coverage")
        coverage_runner = run_coverage or _run_sealed_coverage
        try:
            seen["coverage"] = coverage_runner(seen["tools"], baseline, candidate,
                                               seen["binding"], coverage_dir)
        except Exception as error:
            raise _Refused("coverage", ExecuteCause.EXECUTE_COVERAGE_FAILED,
                           f"{type(error).__name__}: {error}") from error
        if type(seen["coverage"]) is not CoverageOutcome:
            raise _Refused("coverage", ExecuteCause.EXECUTE_COVERAGE_FAILED,
                           "coverage runner returned an untyped verdict")
        _assert_inputs_stable(seen["binding"], authority, baseline, candidate, "coverage")
        try:
            seen["coverage_map"] = _coverage_map(candidate, states)
        except (ValueError, OSError) as error:
            raise _Refused("coverage", ExecuteCause.EXECUTE_COVERAGE_FAILED,
                           f"candidate coverage is unusable: {error}") from error
        note("coverage", ExecuteCause.EXECUTE_OK, None)
        if seen["provider_failure"] is not None:
            return finish("done", ExecuteCause.EXECUTE_PROVIDER_FAILED,
                          seen["provider_failure"])
        return finish("done", ExecuteCause.EXECUTE_OK, None)
    except _Refused as refused:
        return finish(refused.phase, refused.cause, refused.detail)


def _deliver(output_dir: Path, output_json: Path, context: JsonObject,
             context_sha: str, transport: Any, tier: str, lane_id: str,
             provider: JsonObject, policy: Any,
             authority: LocalComparisonWitness | None,
             seen: dict[str, Any], history: list[JsonObject],
             phase: str, cause: ExecuteCause, detail: str | None) -> dict[str, Any]:
    """Assemble the verdict row, receipt, and capsule; this never refuses."""
    status = CAUSE_STATUS[cause]
    exit_code = CAUSE_EXIT[cause]
    prepared = seen["prepared"]
    identity = prepared["identity"] if prepared else context.get("identity")
    if type(identity) is not dict:
        identity = {}
    attempt = identity.get("attempt")
    if type(attempt) is not int:
        attempt = None
    compare = seen["compare"]
    coverage = seen["coverage"]
    admitted = any(entry["phase"] == "bind" and entry["cause"] == ExecuteCause.EXECUTE_OK.value
                   for entry in history)
    row: dict[str, Any] = {
        "lane": lane_id, "provider": dict(provider), "transport": transport,
        "tier": tier, "attempt": attempt, "phase": phase, "status": status,
        "cause": cause.value, "cause_detail": detail, "exit_code": exit_code,
        "comparison_positive": compare.positive if compare else None,
        "coverage_positive": coverage.positive if coverage else False,
        "regressions": [dict(entry) for entry in compare.regressions] if compare else [],
        "improvements": [dict(entry) for entry in compare.improvements] if compare else [],
        "selected_count": seen["selected_count"],
        "observed_count": seen["observed_count"],
        "missing_selected": list(seen["missing"]),
        "image_usable": False,
        "evidence_complete": status in ("executed", "provider-failure"),
        "evidence_admitted": admitted,
        "producer_status": seen["producer"].get("status") if seen["producer"] else None,
        "evaluator_receipt_sha256": seen["tools"].receipt_sha256 if seen["tools"] else None,
        "expectation_sha256": digest(authority.expectation.as_dict()) if authority else None,
        "policy_digest": policy.policy_digest,
        "attempt_roster": list(seen["attempt_roster"]),
        "shard_roster": list(seen["shard_roster"]),
        "coverage": {name: list(names) for name, names in seen["coverage_map"].items()},
    }
    output_json.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    if compare is not None and coverage is not None:
        blocked, reason = _acceptance_oracle(_map_result_record(row, provider))
    else:
        blocked, reason = True, f"no completed verdict ({phase}/{cause.value})"
    acceptance = {"blocked": blocked, "reason": reason}
    receipt: dict[str, Any] = {
        "schema": _ROUND_RECEIPT_SCHEMA, "kind": "round-execution-receipt",
        "inputs": {"context_sha256": context_sha, "tier": tier, "lane": lane_id,
                   "transport": transport, "policy_digest": policy.policy_digest,
                   "evaluator_receipt_sha256": row["evaluator_receipt_sha256"],
                   "expectation_sha256": row["expectation_sha256"]},
        "phases": [dict(entry) for entry in history],
        "artifacts": _manifest(output_dir, "round-receipt.json"),
        "acceptance": acceptance,
        "verdict_sha256": hashlib.sha256(canonical(row)).hexdigest(),
    }
    (output_dir / "round-receipt.json").write_bytes(canonical(receipt) + b"\n")
    transport_limitation = (_GITHUB_LIMITATION if transport == "github"
                            else _FIXTURE_LIMITATION)
    limitations = [transport_limitation,
                   f"Acceptance blocked: {reason}" if blocked else reason]
    capsule: dict[str, Any] = {
        "schema": _ROUND_CAPSULE_SCHEMA, "diagnostic_only": True, "tier": tier,
        "framework_sha": prepared["identity"]["candidate_sha"] if prepared else None,
        "p11lab_ref": None, "round_positive": False,
        "policy": policy.to_record(),
        "expectation_sha256": row["expectation_sha256"],
        "observations_sha256": hashlib.sha256(authority.observations).hexdigest()
        if authority else None,
        "evaluator_receipt_sha256": row["evaluator_receipt_sha256"],
        "endpoints": seen["binding"]["endpoints"] if seen["binding"] else None,
        "verdict_row": row, "image_promotable": False,
        "receipt_artifact": "round-receipt.json",
        "capsule_artifact": "round-capsule.json", "capsule_sha256": None,
        "raw_artifacts_manifest": _manifest(output_dir, "round-capsule.json"),
        "image_usable": row["image_usable"],
        "evidence_complete": row["evidence_complete"],
        "evidence_admitted": row["evidence_admitted"],
        "comparison_positive": row["comparison_positive"],
        "limitations": limitations,
    }
    capsule["capsule_sha256"] = hashlib.sha256(
        canonical({**capsule, "capsule_sha256": None})).hexdigest()
    assert capsule["round_positive"] is False
    (output_dir / "round-capsule.json").write_bytes(canonical(capsule) + b"\n")
    return row
