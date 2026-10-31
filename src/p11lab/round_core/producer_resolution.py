"""Event-lineage producer-run resolution and real context staging (P0-G).

The consumer reusable inherits ``event.workflow_run`` from the enrolled
wrapper in the producer repository; the reusable sees the wrapper's event
payload, so no fourth input and no run listing are needed. Resolution
selects exactly ``event.workflow_run.{id,run_attempt}``, verifies the
producer metadata through the existing bounded transport fetch, binds the
producer head to the reviewed profile graph, and stages the REAL producer
context. Selection grants no authority: roster, attestation, and digest
checks stay mandatory downstream.

Every resolution failure raises :class:`ProducerResolutionRefused` with a
frozen text under the existing ``EXECUTE_TRANSPORT_REFUSED`` cause (phase
``prepare``, exit 3). No new cause enum exists. Caller input problems
(bad paths, malformed SHAs, unknown tiers) raise plain ``ValueError``
usage errors instead. This module performs no network I/O itself; it only
calls the injected transport's existing ``_metadata``/``download``/
``source_file`` operations.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import time
import zipfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote

from . import JsonObject
from .artifacts import (
    GitHubTransport,
    TransientTransportError,
    _classify_transport_error,
    _validate_transport_status,
    verify_artifact_digest,
    verify_profile_graph,
)
from .causes import ExecuteCause
from .inputs import (
    REV,
    SHA,
    SOURCE_ARCHIVE_LIMIT,
    canonical,
    digest,
    load_json,
    read_source_archive,
    safe_path,
    select_run_artifact,
)

RESOLUTION_BUDGET_SECONDS = 60
METADATA_BYTE_BOUND = 2 * 1024 * 1024
TIERS = ("pr-smoke", "nightly", "release")
# Internal producer artifact uploaded by the produce job under this exact
# 0D-pilot name; it carries dependency-lock.json plus the run-identity,
# numeric-identity, and policy-digest files the context job consumes.
INPUTS_ARTIFACT_TEMPLATE = "producer-context-inputs-{run_id}-{attempt}"
INPUTS_ARCHIVE_ROSTER = (
    "dependency-lock.json",
    "identity.json",
    "numeric.json",
    "policy_digest.txt",
)
_BRANCH = re.compile(r"[A-Za-z0-9._/-]+")
_HTTP_FAILURE = re.compile(r"GitHub request failed with HTTP (\d+)")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")

_NO_MATCH = "refused: producer run resolution: no match"
_AMBIGUOUS_MATCH = "refused: producer run resolution: ambiguous match"
_ASSOCIATION_UNAVAILABLE = (
    "refused: producer run resolution: producer association unavailable"
)
_IDENTITY_MISMATCH = "refused: producer run resolution: identity mismatch"
_NOT_SUCCESSFUL = "refused: producer run resolution: producer run not successful"
_SUPERSEDED = "refused: producer run resolution: producer attempt superseded"
_METADATA_CHANGED = "refused: producer run resolution: metadata changed"
_MALFORMED_METADATA = "refused: producer run resolution: malformed metadata"
_BOUND_EXCEEDED = "refused: producer run resolution: metadata bound exceeded"
_TRANSPORT_FAILURE = "refused: producer run resolution: API transport failure"
_REQUEST_FAILED = "refused: producer run resolution: API request failed"
_RERUN = "refused: rerun requires producer"


class ProducerResolutionRefused(ValueError):
    """A typed P0-G resolution refusal (frozen cause, phase, exit code).

    Native signals are retained separately on ``error_category``,
    ``http_status``, and ``diagnostics``; the message is always one of the
    frozen refusal texts.
    """

    def __init__(
        self,
        text: str,
        *,
        error_category: str | None = None,
        http_status: int | None = None,
        diagnostics: dict | None = None,
    ) -> None:
        super().__init__(text)
        self.cause = ExecuteCause.EXECUTE_TRANSPORT_REFUSED.value
        self.phase = "prepare"
        self.exit_code = 3
        self.error_category = error_category
        self.http_status = http_status
        self.diagnostics = dict(diagnostics or {})


def _refuse_for_transport(error: BaseException) -> ProducerResolutionRefused:
    """Translate a transport signal into a frozen refusal text.

    API failures never become no-match: transport breakdowns refuse as API
    transport failure, non-success HTTP as API request failed, byte/time
    bounds as metadata bound exceeded, and anything else from the wire as
    malformed metadata.
    """
    if isinstance(error, TransientTransportError):
        return ProducerResolutionRefused(
            _TRANSPORT_FAILURE,
            error_category=getattr(error, "error_category", None),
            http_status=getattr(error, "http_status", None),
            diagnostics={
                "record": getattr(error, "failure_record", None),
                "message": str(error)[:500],
            },
        )
    if isinstance(error, HTTPError):
        status = _validate_transport_status(error.code)
        category, _ = _classify_transport_error(error)
        return ProducerResolutionRefused(
            _REQUEST_FAILED,
            error_category=category,
            http_status=status,
            diagnostics={"message": f"HTTP {status}" if status else "HTTP unknown"},
        )
    if isinstance(error, (URLError, TimeoutError, ConnectionError, OSError)):
        category, status = _classify_transport_error(error)
        return ProducerResolutionRefused(
            _TRANSPORT_FAILURE,
            error_category=category,
            http_status=status,
            diagnostics={"native": type(error).__name__},
        )
    if isinstance(error, ValueError):
        message = str(error)
        match = _HTTP_FAILURE.search(message)
        if match is not None:
            status = _validate_transport_status(int(match.group(1)))
            return ProducerResolutionRefused(
                _REQUEST_FAILED,
                http_status=status,
                diagnostics={"native": "ValueError", "message": message[:500]},
            )
        if "redirect" in message:
            return ProducerResolutionRefused(
                _REQUEST_FAILED,
                diagnostics={"native": "ValueError", "message": message[:500]},
            )
        if "bound" in message:
            return ProducerResolutionRefused(
                _BOUND_EXCEEDED,
                diagnostics={"native": "ValueError", "message": message[:500]},
            )
        return ProducerResolutionRefused(
            _MALFORMED_METADATA,
            diagnostics={"native": "ValueError", "message": message[:500]},
        )
    raise error


def _guarded(operation: object, *args: object, **kwargs: object) -> object:
    """Call a transport operation, translating its failures to refusals."""
    assert callable(operation)
    try:
        return operation(*args, **kwargs)
    except ProducerResolutionRefused:
        raise
    except (
        TransientTransportError,
        HTTPError,
        URLError,
        TimeoutError,
        ConnectionError,
        OSError,
        ValueError,
    ) as error:
        raise _refuse_for_transport(error) from error


def _require_transport(transport: object) -> None:
    for method in ("_metadata", "download", "source_file"):
        if not callable(getattr(transport, method, None)):
            raise ValueError("invalid resolution transport")


def _require_first_attempt() -> None:
    """Refuse consumer-only reruns from the runner-attested attempt."""
    raw = os.environ.get("GITHUB_RUN_ATTEMPT")
    if raw is None or not raw.strip():
        raise ProducerResolutionRefused(
            _ASSOCIATION_UNAVAILABLE,
            diagnostics={"reason": "consumer attempt unavailable"},
        )
    try:
        attempt = int(raw.strip(), 10)
    except ValueError:
        raise ProducerResolutionRefused(
            _ASSOCIATION_UNAVAILABLE,
            diagnostics={"reason": "consumer attempt malformed"},
        ) from None
    if attempt < 1:
        raise ProducerResolutionRefused(
            _ASSOCIATION_UNAVAILABLE,
            diagnostics={"reason": "consumer attempt malformed"},
        )
    if attempt > 1:
        raise ProducerResolutionRefused(_RERUN)


def _require_lineage(event: JsonObject) -> tuple[int, int]:
    """Extract the exact event coordinates; absent lineage is unavailable."""
    if type(event) is not dict or type(event.get("workflow_run")) is not dict:
        raise ProducerResolutionRefused(_ASSOCIATION_UNAVAILABLE)
    lineage = event["workflow_run"]
    run_id, attempt_nr = lineage.get("id"), lineage.get("run_attempt")
    if (
        type(run_id) is not int
        or type(attempt_nr) is not int
        or run_id <= 0
        or attempt_nr <= 0
    ):
        raise ProducerResolutionRefused(_MALFORMED_METADATA)
    return run_id, attempt_nr


def _require_profile(profile: JsonObject) -> None:
    """Check the enrolled profile shape; unusable enrollment refuses."""
    if type(profile) is not dict:
        raise ProducerResolutionRefused(_ASSOCIATION_UNAVAILABLE)
    try:
        repository = profile["repository"]
        repository_id = profile["repository_id"]
        owner_id = profile["owner_id"]
        workflow_id = profile["workflow_id"]
        workflow_path = profile["workflow_path"]
        producer_job = profile["producer_job"]
        control_sha = profile["control_sha"]
        graph = profile["graph"]
        data_sources = profile["data_sources"]
    except KeyError as error:
        raise ProducerResolutionRefused(
            _ASSOCIATION_UNAVAILABLE, diagnostics={"missing": str(error)}
        ) from error
    if (
        type(repository) is not str
        or not _REPO.fullmatch(repository)
        or type(repository_id) is not int
        or repository_id <= 0
        or type(owner_id) is not int
        or owner_id <= 0
        or type(workflow_id) is not int
        or workflow_id <= 0
        or type(workflow_path) is not str
        or not workflow_path
        or type(producer_job) is not str
        or not producer_job
        or type(control_sha) is not str
        or not REV.fullmatch(control_sha)
        or type(graph) is not list
        or type(data_sources) is not list
    ):
        raise ProducerResolutionRefused(_ASSOCIATION_UNAVAILABLE)


def _load_pilot_target() -> JsonObject:
    """Load the enrolled v1 pilot target through the control data file."""
    from importlib.resources import files

    raw = files("p11lab").joinpath("data/rounds/pilot-target.json").read_bytes()
    return load_json(raw)


def _require_enrollment(profile: JsonObject, tier: str) -> str:
    """Check enrolled pins against control's own loaders (fail fast).

    Returns the control policy digest the producer claim is bound to.
    """
    from .policy import load_policy

    policy_digest = load_policy(None, tier).policy_digest
    if profile.get("policy_sha256") != policy_digest:
        raise ProducerResolutionRefused(
            _ASSOCIATION_UNAVAILABLE,
            diagnostics={"reason": "policy pin incoherence"},
        )
    if digest(_load_pilot_target()) != profile.get("target_sha256"):
        raise ProducerResolutionRefused(
            _ASSOCIATION_UNAVAILABLE,
            diagnostics={"reason": "target pin incoherence"},
        )
    if digest(profile["data_sources"]) != profile.get("data_sources_sha256"):
        raise ProducerResolutionRefused(
            _ASSOCIATION_UNAVAILABLE,
            diagnostics={"reason": "data sources pin incoherence"},
        )
    return policy_digest


def _fetch_bundle(
    transport: object, run_id: int, attempt_nr: int, deadline: float
) -> JsonObject:
    """Fetch one bounded metadata bundle through the existing transport."""
    if time.monotonic() > deadline:
        raise ProducerResolutionRefused(
            _TRANSPORT_FAILURE,
            diagnostics={"reason": "resolution budget exceeded"},
        )
    metadata = getattr(transport, "_metadata")
    name = quote(
        INPUTS_ARTIFACT_TEMPLATE.format(run_id=run_id, attempt=attempt_nr),
        safe="",
    )
    run = _guarded(metadata, f"/actions/runs/{run_id}", deadline)
    attempt = _guarded(
        metadata, f"/actions/runs/{run_id}/attempts/{attempt_nr}", deadline
    )
    jobs = _guarded(
        metadata,
        f"/actions/runs/{run_id}/attempts/{attempt_nr}/jobs?per_page=100",
        deadline,
    )
    listing = _guarded(
        metadata,
        f"/actions/runs/{run_id}/artifacts?per_page=100&name={name}",
        deadline,
    )
    return {"run": run, "attempt": attempt, "jobs": jobs, "listing": listing}


def _malformed(field: str) -> ProducerResolutionRefused:
    return ProducerResolutionRefused(
        _MALFORMED_METADATA, diagnostics={"field": field}
    )


def _select_inputs_artifact(
    identity: JsonObject,
    attempt: JsonObject,
    jobs: JsonObject,
    listing: JsonObject,
    name: str,
) -> JsonObject:
    """Reuse the run-artifact consistency boundary for the inputs artifact."""
    try:
        return select_run_artifact(identity, attempt, jobs, listing, name=name)
    except ProducerResolutionRefused:
        raise
    except ValueError as error:
        message = str(error)
        if message.startswith("incomplete") or message.startswith("malformed"):
            raise ProducerResolutionRefused(
                _MALFORMED_METADATA, diagnostics={"message": message}
            ) from error
        raise ProducerResolutionRefused(
            _IDENTITY_MISMATCH, diagnostics={"message": message}
        ) from error


def _bind_graph(graph: list, fetch: object) -> None:
    """Bind the producer head to the enrolled graph bytes (wrong head fails)."""
    assert callable(fetch)
    try:
        verify_profile_graph(graph, fetch)  # type: ignore[arg-type]
    except ProducerResolutionRefused:
        raise
    except ValueError as error:
        message = str(error)
        if "mismatch" in message:
            raise ProducerResolutionRefused(
                _IDENTITY_MISMATCH, diagnostics={"message": message}
            ) from error
        raise ProducerResolutionRefused(
            _ASSOCIATION_UNAVAILABLE, diagnostics={"message": message}
        ) from error


def _verify_bundle(
    bundle: JsonObject,
    run_id: int,
    attempt_nr: int,
    profile: JsonObject,
    framework_sha: str,
    transport: object,
) -> tuple[JsonObject, str, str, str]:
    """Verify one metadata bundle; returns (artifact, head, branch, title)."""
    run, attempt, jobs, listing = (
        bundle.get("run"),
        bundle.get("attempt"),
        bundle.get("jobs"),
        bundle.get("listing"),
    )
    for name, payload in (
        ("run", run),
        ("attempt", attempt),
        ("jobs", jobs),
        ("listing", listing),
    ):
        if type(payload) is not dict:
            raise _malformed(name)
    assert type(run) is dict and type(attempt) is dict
    assert type(jobs) is dict and type(listing) is dict
    if run.get("id") != run_id:
        raise _malformed("run.id")
    current = run.get("run_attempt")
    if type(current) is not int:
        raise _malformed("run.run_attempt")
    if current != attempt_nr:
        raise ProducerResolutionRefused(_SUPERSEDED)
    if attempt.get("id") != run_id or attempt.get("run_attempt") != attempt_nr:
        raise _malformed("attempt.echo")
    repository = attempt.get("repository")
    if (
        type(repository) is not dict
        or type(repository.get("id")) is not int
        or repository["id"] <= 0
        or type(repository.get("full_name")) is not str
        or not repository["full_name"]
        or type(repository.get("owner")) is not dict
        or type(repository["owner"].get("id")) is not int
        or repository["owner"]["id"] <= 0
    ):
        raise _malformed("attempt.repository")
    if (
        repository["id"] != profile["repository_id"]
        or repository["full_name"] != profile["repository"]
        or repository["owner"]["id"] != profile["owner_id"]
    ):
        raise ProducerResolutionRefused(_IDENTITY_MISMATCH)
    workflow_id = attempt.get("workflow_id")
    if type(workflow_id) is not int or workflow_id <= 0:
        raise _malformed("attempt.workflow_id")
    if workflow_id != profile["workflow_id"]:
        raise ProducerResolutionRefused(_IDENTITY_MISMATCH)
    path = attempt.get("path")
    if type(path) is not str or not path:
        raise _malformed("attempt.path")
    if path != profile["workflow_path"]:
        raise ProducerResolutionRefused(_IDENTITY_MISMATCH)
    event_name = attempt.get("event")
    if type(event_name) is not str or not event_name:
        raise _malformed("attempt.event")
    if event_name != "workflow_dispatch":
        raise ProducerResolutionRefused(_IDENTITY_MISMATCH)
    status, conclusion = attempt.get("status"), attempt.get("conclusion")
    if type(status) is not str or (
        conclusion is not None and type(conclusion) is not str
    ):
        raise _malformed("attempt.status")
    if status != "completed" or conclusion != "success":
        raise ProducerResolutionRefused(_NOT_SUCCESSFUL)
    title = attempt.get("display_title")
    if type(title) is not str or not title:
        raise _malformed("attempt.display_title")
    if title != "produce-framework-dist-" + framework_sha:
        raise ProducerResolutionRefused(_IDENTITY_MISMATCH)
    head = attempt.get("head_sha")
    if type(head) is not str or not REV.fullmatch(head):
        raise _malformed("attempt.head_sha")
    branch = attempt.get("head_branch")
    # Branch charset mirrors the owner-proof overlay's source-ref rule; the
    # value binds through metadata stability and downstream overlay use.
    if type(branch) is not str or not _BRANCH.fullmatch(branch):
        raise _malformed("attempt.head_branch")

    def fetch(path: str) -> bytes:
        return _guarded(getattr(transport, "source_file"), head, path)  # type: ignore[return-value]

    _bind_graph(profile["graph"], fetch)
    rows = listing.get("artifacts")
    if type(rows) is not list:
        raise _malformed("listing.artifacts")
    inputs_name = INPUTS_ARTIFACT_TEMPLATE.format(
        run_id=run_id, attempt=attempt_nr
    )
    if any(type(row) is not dict or row.get("name") != inputs_name for row in rows):
        raise _malformed("listing.artifacts")
    total = listing.get("total_count")
    if type(total) is not int or total != len(rows) or len(rows) > 100:
        raise _malformed("listing.total_count")
    matched = [
        row for row in rows if type(row) is dict and row.get("name") == inputs_name
    ]
    if not matched:
        raise ProducerResolutionRefused(_NO_MATCH)
    if len(matched) > 1:
        raise ProducerResolutionRefused(_AMBIGUOUS_MATCH)
    identity = {
        "run_id": run_id,
        "attempt": attempt_nr,
        "workflow_id": profile["workflow_id"],
        "repository_id": profile["repository_id"],
        "run_head_sha": head,
        "candidate_sha": framework_sha,
        "producer_job": profile["producer_job"],
    }
    artifact = _select_inputs_artifact(identity, attempt, jobs, listing, inputs_name)
    return artifact, head, branch, title


def resolve_producer_run(
    *,
    event: JsonObject,
    profile: JsonObject,
    framework_sha: str,
    tier: str,
    transport: object,
) -> JsonObject:
    """Resolve and verify the event-selected producer run coordinates.

    Returns the verified coordinates plus the stabilized metadata snapshot
    the staging recheck compares against. Raises frozen refusals; caller
    input problems raise plain ``ValueError`` usage errors.
    """
    if type(framework_sha) is not str or not REV.fullmatch(framework_sha):
        raise ValueError("invalid framework_sha: 40-hex required")
    if type(tier) is not str or tier not in TIERS:
        raise ValueError(f"unknown tier: {tier!r}")
    _require_transport(transport)
    _require_first_attempt()
    run_id, attempt_nr = _require_lineage(event)
    _require_profile(profile)
    policy_digest = _require_enrollment(profile, tier)
    deadline = time.monotonic() + RESOLUTION_BUDGET_SECONDS
    bundle = _fetch_bundle(transport, run_id, attempt_nr, deadline)
    artifact, head, branch, title = _verify_bundle(
        bundle, run_id, attempt_nr, profile, framework_sha, transport
    )
    second = _fetch_bundle(transport, run_id, attempt_nr, deadline)
    if canonical(second) != canonical(bundle):
        raise ProducerResolutionRefused(_METADATA_CHANGED)
    return {
        "producer": {
            "run_id": run_id,
            "attempt": attempt_nr,
            "repository": profile["repository"],
            "repository_id": profile["repository_id"],
            "owner_id": profile["owner_id"],
            "workflow_id": profile["workflow_id"],
            "workflow_path": profile["workflow_path"],
            "producer_job": profile["producer_job"],
            "run_head_sha": head,
            "head_branch": branch,
            "display_title": title,
            "candidate_sha": framework_sha,
        },
        "artifact": artifact,
        "verified_metadata": bundle,
        "policy_sha256": policy_digest,
        "profile_sha256": digest(profile),
        "_deadline": deadline,
    }


def _decode_inputs_archive(raw: bytes) -> dict[str, bytes]:
    """Decode the closed 4-file context-inputs archive (strict roster)."""
    if type(raw) is not bytes:
        raise ValueError("invalid context-inputs artifact bytes")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) != len(INPUTS_ARCHIVE_ROSTER) or {
                item.filename for item in members
            } != set(INPUTS_ARCHIVE_ROSTER):
                raise ValueError("invalid context-inputs archive roster")
            result: dict[str, bytes] = {}
            for member in members:
                if (
                    member.orig_filename != member.filename
                    or member.is_dir()
                    or member.flag_bits & 1
                    or stat.S_IFMT(member.external_attr >> 16)
                    not in (0, stat.S_IFREG)
                    or (member.create_system == 0 and member.external_attr & 0x10)
                    or member.file_size > METADATA_BYTE_BOUND
                ):
                    raise ValueError("invalid context-inputs archive member")
                result[member.filename] = archive.read(member)
            return result
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ValueError("invalid context-inputs archive") from error


def _load_member(members: dict[str, bytes], name: str) -> JsonObject:
    try:
        value = load_json(members[name])
    except (KeyError, ValueError) as error:
        raise ProducerResolutionRefused(
            _MALFORMED_METADATA, diagnostics={"member": name}
        ) from error
    if type(value) is not dict:
        raise ProducerResolutionRefused(
            _MALFORMED_METADATA, diagnostics={"member": name}
        )
    return value


def _require_roster_entry(profile: JsonObject) -> tuple[str, int, str]:
    """Select the single v1 corpus roster entry (refuses 0 or 2+)."""
    sources = profile["data_sources"]
    if len(sources) == 0:
        raise ProducerResolutionRefused(_NO_MATCH)
    if len(sources) > 1:
        raise ProducerResolutionRefused(_AMBIGUOUS_MATCH)
    entry = sources[0]
    if (
        type(entry) is not dict
        or set(entry) != {"path", "url", "size", "sha256", "redirect_origin"}
        or type(entry["size"]) is not int
        or not 0 <= entry["size"] <= SOURCE_ARCHIVE_LIMIT
        or type(entry["sha256"]) is not str
        or not SHA.fullmatch(entry["sha256"])
        or type(entry["url"]) is not str
        or not entry["url"]
        or type(entry["redirect_origin"]) is not str
        or not entry["redirect_origin"]
    ):
        raise ProducerResolutionRefused(_ASSOCIATION_UNAVAILABLE)
    try:
        name = safe_path(entry["path"])
    except ValueError as error:
        raise ProducerResolutionRefused(_ASSOCIATION_UNAVAILABLE) from error
    return name, entry["size"], entry["sha256"]


def stage_producer_context(
    *,
    resolution: JsonObject,
    profile: JsonObject,
    framework_sha: str,
    tier: str,
    transport: object,
    output_dir: str | Path,
    consumer_run_id: int,
    consumer_attempt: int,
) -> JsonObject:
    """Download the producer lock and atomically stage the real context.

    The staged file is published (temp + rename) only after full
    validation, including the post-acquisition metadata recheck. Nothing
    is minted: missing enrollment or data refuses.
    """
    from ..receipts import write_receipt

    if type(framework_sha) is not str or not REV.fullmatch(framework_sha):
        raise ValueError("invalid framework_sha: 40-hex required")
    if type(tier) is not str or tier not in TIERS:
        raise ValueError(f"unknown tier: {tier!r}")
    _require_transport(transport)
    if (
        type(resolution) is not dict
        or type(resolution.get("producer")) is not dict
        or type(resolution.get("artifact")) is not dict
        or type(resolution.get("verified_metadata")) is not dict
        or type(resolution.get("_deadline")) is not float
    ):
        raise ValueError("invalid producer resolution")
    producer = resolution["producer"]
    if (
        producer.get("candidate_sha") != framework_sha
        or type(producer.get("run_id")) is not int
        or type(producer.get("attempt")) is not int
        or type(resolution["artifact"].get("id")) is not int
    ):
        raise ValueError("invalid producer resolution")
    if (
        type(consumer_run_id) is not int
        or type(consumer_attempt) is not int
        or consumer_run_id <= 0
        or consumer_attempt <= 0
    ):
        raise ValueError("invalid consumer run coordinates")
    run_id, attempt_nr = producer["run_id"], producer["attempt"]
    _require_profile(profile)
    policy_digest = _require_enrollment(profile, tier)
    data_name, data_size, data_sha = _require_roster_entry(profile)
    target = _load_pilot_target()
    output = Path(output_dir).absolute()
    try:
        output.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ValueError(f"invalid staging output directory: {error}") from error
    staged_path = output / "round-github-context.json"
    evidence_path = (
        output / f"producer-resolution-{consumer_run_id}-{consumer_attempt}.json"
    )
    for path in (staged_path, evidence_path):
        if path.exists() or path.is_symlink():
            raise ValueError("staging outputs already exist; refusing to overwrite")
    raw = _guarded(getattr(transport, "download"), resolution["artifact"]["id"])
    if type(raw) is not bytes:
        raise ValueError("invalid context-inputs artifact bytes")
    if len(raw) > METADATA_BYTE_BOUND:
        raise ProducerResolutionRefused(_BOUND_EXCEEDED)
    try:
        verify_artifact_digest(raw, resolution["artifact"])
    except ValueError as error:
        raise ProducerResolutionRefused(
            _IDENTITY_MISMATCH, diagnostics={"message": str(error)}
        ) from error
    recheck = _fetch_bundle(transport, run_id, attempt_nr, resolution["_deadline"])
    if canonical(recheck) != canonical(resolution["verified_metadata"]):
        raise ProducerResolutionRefused(_METADATA_CHANGED)
    try:
        members = _decode_inputs_archive(raw)
    except ValueError as error:
        raise ProducerResolutionRefused(
            _MALFORMED_METADATA, diagnostics={"message": str(error)[:200]}
        ) from error
    identity_doc = _load_member(members, "identity.json")
    if set(identity_doc) != {
        "repository_id",
        "run_id",
        "attempt",
        "candidate_sha",
        "target_sha",
        "merge_base_sha",
    }:
        raise ProducerResolutionRefused(
            _MALFORMED_METADATA, diagnostics={"member": "identity.json"}
        )
    for field in ("candidate_sha", "target_sha", "merge_base_sha"):
        if type(identity_doc[field]) is not str or not REV.fullmatch(
            identity_doc[field]
        ):
            raise ProducerResolutionRefused(
                _MALFORMED_METADATA, diagnostics={"member": "identity.json"}
            )
    if (
        identity_doc["repository_id"] != profile["repository_id"]
        or identity_doc["run_id"] != run_id
        or identity_doc["attempt"] != attempt_nr
        or identity_doc["candidate_sha"] != framework_sha
    ):
        raise ProducerResolutionRefused(_IDENTITY_MISMATCH)
    # v1 H-C rule, enforced identically on the producer side: distinct
    # targets are post-v1.
    if (
        identity_doc["target_sha"] != framework_sha
        or identity_doc["merge_base_sha"] != framework_sha
    ):
        raise ProducerResolutionRefused(_IDENTITY_MISMATCH)
    numeric = _load_member(members, "numeric.json")
    if set(numeric) != {"repository_id", "workflow_id"}:
        raise ProducerResolutionRefused(
            _MALFORMED_METADATA, diagnostics={"member": "numeric.json"}
        )
    if (
        numeric["repository_id"] != profile["repository_id"]
        or numeric["workflow_id"] != profile["workflow_id"]
    ):
        raise ProducerResolutionRefused(_IDENTITY_MISMATCH)
    try:
        policy_text = members["policy_digest.txt"].decode("ascii").strip()
    except (KeyError, UnicodeDecodeError) as error:
        raise ProducerResolutionRefused(
            _MALFORMED_METADATA, diagnostics={"member": "policy_digest.txt"}
        ) from error
    if not SHA.fullmatch(policy_text):
        raise ProducerResolutionRefused(
            _MALFORMED_METADATA, diagnostics={"member": "policy_digest.txt"}
        )
    if policy_text != policy_digest:
        raise ProducerResolutionRefused(_IDENTITY_MISMATCH)
    lock_raw = members["dependency-lock.json"]
    _load_member(members, "dependency-lock.json")
    lock_sha = hashlib.sha256(lock_raw).hexdigest()
    context = {
        "transport": "github",
        "tier": tier,
        "identity": {
            "repository_id": profile["repository_id"],
            "run_id": run_id,
            "attempt": attempt_nr,
            "candidate_sha": framework_sha,
            "target_sha": framework_sha,
            "merge_base_sha": framework_sha,
        },
        "repository": profile["repository"],
        "run_head_sha": producer["run_head_sha"],
        "workflow_id": profile["workflow_id"],
        "producer_job": profile["producer_job"],
        "dependency_lock_sha256": lock_sha,
        "data_root": str(output / "round-data"),
        "data_files": [{"path": data_name, "size": data_size, "sha256": data_sha}],
        "disabled_path": data_name,
        "target": target,
        "control_sha": profile["control_sha"],
    }
    evidence = {
        "status": "resolved",
        "framework_sha": framework_sha,
        "tier": tier,
        "consumer": {"run_id": consumer_run_id, "run_attempt": consumer_attempt},
        "producer": {
            "run_id": run_id,
            "attempt": attempt_nr,
            "repository": profile["repository"],
            "repository_id": profile["repository_id"],
            "workflow_id": profile["workflow_id"],
            "workflow_path": profile["workflow_path"],
            "producer_job": profile["producer_job"],
            "run_head_sha": producer["run_head_sha"],
            "head_branch": producer["head_branch"],
            "display_title": producer["display_title"],
        },
        "dependency_lock_sha256": lock_sha,
        "policy_sha256": policy_digest,
        "profile_sha256": digest(profile),
        "staged": "round-github-context.json",
    }
    write_receipt(staged_path, context)
    write_receipt(evidence_path, evidence)
    return evidence


def _select_profile(event: JsonObject, profiles_doc: JsonObject) -> JsonObject:
    """Select the enrolled profile for the event association (no fallback)."""
    lineage = event.get("workflow_run") if type(event) is dict else None
    if type(lineage) is not dict:
        raise ProducerResolutionRefused(_ASSOCIATION_UNAVAILABLE)
    repository = lineage.get("repository")
    workflow_id = lineage.get("workflow_id")
    if (
        type(repository) is not dict
        or type(repository.get("full_name")) is not str
        or not repository["full_name"]
        or type(workflow_id) is not int
    ):
        raise ProducerResolutionRefused(_MALFORMED_METADATA)
    matched = [
        entry
        for entry in profiles_doc["profiles"]
        if entry.get("repository") == repository["full_name"]
        and entry.get("workflow_id") == workflow_id
    ]
    if not matched:
        raise ProducerResolutionRefused(_NO_MATCH)
    if len(matched) > 1:
        raise ProducerResolutionRefused(_AMBIGUOUS_MATCH)
    return matched[0]


def run_resolve_producer(
    *,
    event_path: str | Path,
    profile_path: str | Path,
    framework_sha: str,
    tier: str,
    consumer_run_id: int,
    consumer_attempt: int,
    output_dir: str | Path,
    transport: object | None = None,
) -> JsonObject:
    """Resolve the producer run and stage its real context (CLI flow).

    On refusal the typed refusal evidence is written and the refusal
    re-raised for the CLI to report with exit 3; no staged context and
    no capsule are fabricated.
    """
    from ..receipts import write_receipt

    if type(framework_sha) is not str or not REV.fullmatch(framework_sha):
        raise ValueError("invalid framework_sha: 40-hex required")
    if type(tier) is not str or tier not in TIERS:
        raise ValueError(f"unknown tier: {tier!r}")
    if (
        type(consumer_run_id) is not int
        or type(consumer_attempt) is not int
        or consumer_run_id <= 0
        or consumer_attempt <= 0
    ):
        raise ValueError("invalid consumer run coordinates")
    output = Path(output_dir).absolute()
    event: JsonObject | None = None
    try:
        if consumer_attempt > 1:
            raise ProducerResolutionRefused(_RERUN)
        try:
            event = load_json(read_source_archive(Path(event_path)))
        except (OSError, ValueError) as error:
            raise ValueError(f"invalid event payload: {error}") from error
        try:
            profiles_doc = load_json(read_source_archive(Path(profile_path)))
        except (OSError, ValueError) as error:
            raise ValueError(f"invalid producer profiles: {error}") from error
        if (
            type(profiles_doc) is not dict
            or profiles_doc.get("schema_version") != 1
            or type(profiles_doc.get("profiles")) is not list
            or any(type(entry) is not dict for entry in profiles_doc["profiles"])
        ):
            raise ValueError("invalid producer profiles document")
        profile = _select_profile(event, profiles_doc)
        _require_profile(profile)
        if transport is None:
            transport = GitHubTransport(
                profile["repository"], os.environ.get("GITHUB_TOKEN", "")
            )
        resolution = resolve_producer_run(
            event=event,
            profile=profile,
            framework_sha=framework_sha,
            tier=tier,
            transport=transport,
        )
        return stage_producer_context(
            resolution=resolution,
            profile=profile,
            framework_sha=framework_sha,
            tier=tier,
            transport=transport,
            output_dir=output,
            consumer_run_id=consumer_run_id,
            consumer_attempt=consumer_attempt,
        )
    except ProducerResolutionRefused as error:
        lineage = event.get("workflow_run") if type(event) is dict else None
        record = {
            "status": "refused",
            "cause": error.cause,
            "phase": error.phase,
            "exit_code": error.exit_code,
            "text": str(error),
            "error_category": error.error_category,
            "http_status": error.http_status,
            "diagnostics": error.diagnostics,
            "framework_sha": framework_sha,
            "tier": tier,
            "consumer": {
                "run_id": consumer_run_id,
                "run_attempt": consumer_attempt,
            },
            "producer": {
                "run_id": lineage.get("id") if type(lineage) is dict else None,
                "attempt": lineage.get("run_attempt")
                if type(lineage) is dict
                else None,
            },
        }
        try:
            output.mkdir(parents=True, exist_ok=True)
            write_receipt(
                output
                / f"producer-resolution-{consumer_run_id}-{consumer_attempt}.json",
                record,
            )
        except OSError as write_error:
            raise OSError(
                f"{error} (refusal evidence unwritable: {write_error})"
            ) from write_error
        raise
