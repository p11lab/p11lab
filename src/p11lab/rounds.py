"""Public round policy operation, shared by local and future CI callers."""
from pathlib import Path
import json
from typing import Any, TYPE_CHECKING

from .round_core.policy import load_policy

if TYPE_CHECKING:
    from .comparison import LocalComparisonWitness


def validate_policy(policy_root: Path | None, tier: str, output_json: Path) -> dict[str, Any]:
    """Write a diagnostic proposal only after strict policy validation succeeds."""
    result = load_policy(policy_root, tier).to_record()
    output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return result


def prepare(context_path: Path, policy_root: Path | None, output_dir: Path,
            output_json: Path) -> dict[str, Any]:
    """Prepare opaque round inputs using an explicit caller context."""
    from .round_core.inputs import load_json, prepare as prepare_inputs, read_source_archive

    context_path = context_path.absolute()
    context = load_json(read_source_archive(context_path))
    for field in ('artifact_path', 'fixture_metadata_path', 'data_root', 'cache_file'):
        if field in context:
            if type(context[field]) is not str or not context[field]:
                raise ValueError('invalid preparation context path')
            path = Path(context[field])
            context[field] = str(path if path.is_absolute() else context_path.parent / path)
    result = prepare_inputs(context, policy_root, output_dir)
    output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return result


def load_staged_comparison(
        authority: Path | None, baseline: Path | None,
        candidate: Path | None) -> tuple["LocalComparisonWitness", Path, Path] | None:
    """Validate staged bridge entries and build the typed comparison witness.

    All three entries are required together; all-absent preserves the
    legacy unstaged call. Every staging problem raises before dispatch
    (usage; the executor is untouched). The witness is an interface
    boundary type, never authority: parsing JSON never confers producer
    authority, and the executor's binder re-verifies the envelope plus
    the sealed evaluator before any verdict.
    """
    from .comparison import LocalComparisonWitness
    from .jsonutil import loads
    from .round_core.inputs import canonical, freeze_comparison_expectation

    if authority is None and baseline is None and candidate is None:
        return None
    if authority is None or baseline is None or candidate is None:
        raise ValueError("staged bridge requires --authority, --baseline "
                         "and --candidate together")
    for name, value in (("authority", authority), ("baseline", baseline),
                        ("candidate", candidate)):
        if not isinstance(value, Path):
            raise TypeError(f"typed staged bridge paths required: {name}")
    assert isinstance(authority, Path)
    assert isinstance(baseline, Path)
    assert isinstance(candidate, Path)
    endpoints: dict[str, Path] = {}
    for name, value in (("baseline", baseline), ("candidate", candidate)):
        if value.absolute() != value.resolve():
            raise ValueError(f"staged bridge {name} endpoint root is "
                             "unsafe/noncanonical")
        if not value.is_dir() or value.is_symlink():
            raise ValueError(f"staged bridge {name} endpoint is missing or "
                             "not a directory")
        endpoints[name] = value.resolve()
    if not authority.is_file() or authority.is_symlink():
        raise ValueError("staged bridge authority is missing or not a "
                         "regular file")
    staged_authority = authority.resolve()
    for name in ("baseline", "candidate"):
        if staged_authority == endpoints[name] or endpoints[name] in staged_authority.parents:
            raise ValueError("staged bridge authority is candidate-controlled: "
                             "it must be independently staged controller material")
    try:
        with authority.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
    except OSError as error:
        raise ValueError(f"staged bridge authority is missing: {error}") from error
    if len(raw) > 1024 * 1024:
        raise ValueError("staged bridge authority exceeds 1 MiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"staged bridge authority is not valid JSON: {error}") from error
    try:
        document = loads(text)
    except ValueError as error:
        raise ValueError(f"staged bridge authority is not valid JSON: {error}") from error
    except RecursionError:
        raise ValueError("staged bridge authority is not valid JSON: excessive nesting")
    if type(document) is not dict or set(document) != {"expectation", "observations"}:
        raise ValueError("staged bridge authority has no expectation/observations pair")
    expectation = freeze_comparison_expectation(document["expectation"])
    observations = document["observations"]
    if type(observations) is not dict:
        raise ValueError("staged bridge authority observations are not an object")
    if observations.get("scope") != "local-controller":
        raise ValueError("unsupported staged witness provenance: "
                         f"{observations.get('scope')!r}")
    witness = LocalComparisonWitness(expectation, canonical(observations))
    return witness, endpoints["baseline"], endpoints["candidate"]


def execute(context_path: Path, policy_root: Path | None, evaluator_root: Path,
            output_dir: Path, output_json: Path, tier: str | None = None, *,
            authority: Path | None = None, baseline: Path | None = None,
            candidate: Path | None = None) -> dict[str, Any]:
    """Execute one fixture- or github-transport round lane and return its verdict row."""
    from .round_core.execute import execute_round

    staged = load_staged_comparison(authority, baseline, candidate)
    if staged is None:
        return execute_round(context_path, policy_root, evaluator_root, output_dir,
                             output_json, tier=tier)
    witness, baseline_path, candidate_path = staged
    return execute_round(context_path, policy_root, evaluator_root, output_dir,
                         output_json, tier=tier, authority=witness,
                         baseline=baseline_path, candidate=candidate_path)
