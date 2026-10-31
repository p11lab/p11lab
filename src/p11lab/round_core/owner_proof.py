"""Round-mode job-binding owner proof.

Owned custody-style extension over delivery_authority: the per-run overlay
carries grounded pins only (run head, branch-derived ref, policy backstop),
never a synthesized profile. Sealed verifier semantics are imported, never
copied: run_round_verifier delegates to _run_verifier with round_artifact=True
and check_round_signature delegates to _check_verified with the round
predicate, subject, job-naming predicate content, and job window.

DEFEAT argument (same-run malicious job): the adversary cannot mint ANY
attestation for the round predicate without id-token:write, which human
review grants only to the producer job in the exact workflow bytes pinned
by the profile graph. C3 defeats predicate confusion, C2 byte substitution,
C1 cross-run replay, and the code-enforced 2-job roster proves no extra
job ran. Predicate-naming alone would not suffice; token exclusivity is
the load-bearing layer.
"""
import re
from datetime import datetime, timedelta, timezone

from ..delivery_authority import ROUND_PREDICATE_TYPE, _check_verified, _run_verifier
from .inputs import REV, SHA, load_json

ROUND_SUBJECT_NAME = 'round-artifact.json'
ROUND_MAX_AGE_SECONDS = 86400
_UNENROLLED_ROOT = '0' * 64


def _require_enrolled_root(profile):
    root = profile.get('root_sha256') if type(profile) is dict else None
    if type(root) is not str or not SHA.fullmatch(root) or root == _UNENROLLED_ROOT:
        raise ValueError('round owner proof is not enrolled')


def round_verifier_overlay(profile, context, attempt):
    """Build the per-run verifier overlay from grounded pins only.

    source_sha and signer_sha are the caller run head (cross-checked here
    against the stabilized attempt; selection and the graph fetch pin the
    job and workflow bytes to the same revision). source_ref derives from
    the attempt's live head_branch; a missing or invalid branch refuses,
    never crashes. max_age_seconds is a policy backstop, inert under the
    always-passed job timestamp window.
    """
    _require_enrolled_root(profile)
    run_head_sha = context.get('run_head_sha') if type(context) is dict else None
    if type(run_head_sha) is not str or not REV.fullmatch(run_head_sha):
        raise ValueError('invalid round run head')
    if type(attempt) is not dict or attempt.get('head_sha') != run_head_sha:
        raise ValueError('round run head mismatch')
    head_branch = attempt.get('head_branch')
    if type(head_branch) is not str or not head_branch:
        raise ValueError('round attestation source ref unavailable')
    source_ref = 'refs/heads/' + head_branch
    if not re.fullmatch(r'refs/heads/[A-Za-z0-9._/-]+', source_ref):
        raise ValueError('round attestation source ref unavailable')
    overlaid = dict(profile)
    overlaid['source_sha'] = run_head_sha
    overlaid['signer_sha'] = run_head_sha
    overlaid['source_ref'] = source_ref
    overlaid['max_age_seconds'] = ROUND_MAX_AGE_SECONDS
    return overlaid


def check_round_roster(jobs, profile):
    """Enforce the closed 2-job round roster in code.

    Exactly the producer and context jobs, nothing else: total_count==2
    with exact names. The roster proves no extra job ran; selection alone
    cannot show that.
    """
    try:
        rows = jobs['jobs']
        if (type(rows) is not list or jobs['total_count'] != 2 or len(rows) != 2
                or {row.get('name') for row in rows} != {profile['producer_job'], profile['context_job']}):
            raise ValueError('round job roster mismatch')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed round job roster') from error


def check_round_subject(subject_raw, dist_digest, identity):
    """Bind the attested subject to the independently acquired dist bytes."""
    try:
        subject = load_json(subject_raw)
    except ValueError as error:
        raise ValueError('malformed round attestation subject') from error
    try:
        if (set(subject) != {'schema_version', 'dist_digest', 'run_id', 'attempt'}
                or type(subject['schema_version']) is not int or subject['schema_version'] != 1
                or type(subject['dist_digest']) is not str
                or type(subject['run_id']) is not int or type(subject['attempt']) is not int):
            raise ValueError('malformed round attestation subject')
        if (subject['dist_digest'] != dist_digest or subject['run_id'] != identity['run_id']
                or subject['attempt'] != identity['attempt']):
            raise ValueError('round attestation subject mismatch')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed round attestation subject') from error


def check_round_signature(result, profile, identity, raw, job, now):
    """Check pinned verifier output against an independently resolved job.

    Callers must resolve the job and run the verifier separately. C1 binds
    bytes to the run, C2 to the subject bytes, C3 names the producing job,
    C4 bounds the signature to the authenticated job window.
    """
    _require_enrolled_root(profile)
    try:
        if now.tzinfo is None:
            raise ValueError('verification clock requires timezone')

        def stamp(value):
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                raise ValueError('round job timestamp requires timezone')
            return parsed.astimezone(timezone.utc)

        start, end = stamp(job['started_at']), stamp(job['completed_at'])
        if start > end:
            raise ValueError('invalid round job timing')
        skew = timedelta(minutes=5)
        lower = max(start - skew, now - timedelta(days=14))
        upper = min(end + skew, now + skew)
        if lower > upper:
            raise ValueError('round attestation expired or premature')
        _check_verified(result, profile, identity, raw, now, predicate_type=ROUND_PREDICATE_TYPE,
                        subject_name=ROUND_SUBJECT_NAME, timestamp_window=(lower, upper),
                        predicate={'schema_version': 1, 'producer_job': profile['producer_job']})
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        raise ValueError('malformed round job timing') from error


def run_round_verifier(executable, subject, bundle, root, root_sha256, profile, output):
    """Run the existing pinned verifier on the distinct round predicate."""
    _require_enrolled_root(profile)
    if type(root_sha256) is not str or not SHA.fullmatch(root_sha256) or root_sha256 == _UNENROLLED_ROOT:
        raise ValueError('round owner proof is not enrolled')
    return _run_verifier(executable, subject, bundle, root, root_sha256, profile, output,
                         round_artifact=True)


def check_token_exclusivity_premise(profile):
    """Record the review-rooted token-exclusivity premise.

    The premise — id-token:write granted only to the producer job — is
    established by human review of the exact workflow bytes hashed in the
    profile graph. The standard library has no YAML parser, so this hook
    asserts the premise's structural precondition (the producer workflow
    is among the pinned reviewed bytes) and returns the auditable record.
    It cannot and does not re-derive token scoping from bytes.
    """
    try:
        graph = profile['graph']
        workflow_path = profile['workflow_path']
        rows = [row for row in graph if row['path'] == workflow_path]
        if len(rows) != 1:
            raise ValueError('round token premise lacks pinned workflow')
        return {'premise': 'human-review-of-pinned-bytes',
                'note': ('id-token:write is granted only to the producer job by human review of '
                         'these exact bytes; the standard library has no YAML parser, so token '
                         'scoping is stated, not code-derived.'),
                'workflow_path': workflow_path, 'workflow_sha256': rows[0]['sha256'],
                'producer_job': profile['producer_job']}
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed round token premise') from error
