"""Thin local derivative over the selected unchanged provider image.

Parent selection comes from the protected images.json entry plus the DiffID
roster; verification is exact ordered DiffID prefix plus manifest/config
binding into the F28 naming fields. Only build_proxy_derivative touches
Docker; every other entry here is pure and hermetic. Labels, RepoTags, and
child RepoDigests are never evidence.
"""
from pathlib import Path
import hashlib
import json
import re
import uuid

from .catalog import package_data
from .docker import Docker
from .models import ArtifactRef

_SHA = re.compile(r'[0-9a-f]{64}\Z')
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')

DERIVATIVE_PRODUCTS = ('pkcs11-proxy-ng', 'pkcs11-proxy-ng-cli', 'proxy-entrypoint.sh')

# Pinned-source license bytes feeding proxy-notices/. Authority: the
# retained real-a348 source tree checked by native.py packaging
# (M07-candidate-preparation report: Apache 0ce791dd..., MIT 3aa121fc...).
DERIVATIVE_NOTICES = {
    'LICENSE-APACHE': '0ce791dda40abbd4d2864eed831cd6d1149adbe4cf194c64bc795be6e576e785',
    'LICENSE-MIT': '3aa121fcdb31dbf67f6db829710bfd37daed8ed0de3b32913673dec378377402',
}

# src/p11lab/data/runtime/proxy.Dockerfile is byte-stable (not owned); the
# build refuses any other Dockerfile bytes before touching Docker.
PROXY_DOCKERFILE_SHA256 = 'baf70929d39b589c7dbebffe42e0ef05bfdc11ee3963e05a4408e6bf9d8b0f41'

_ROSTER_FILENAME = 'softhsm2-release-amd64.diffids.json'
_BUILD_ARGS = ('PROXY_BINS_MANIFEST_SHA256', 'PROXY_SOURCE_REVISION', 'PROXY_CARGO_LOCK_SHA256')


def _invalid(detail):
    return ValueError('proxy derivative parent invalid: %s' % detail)


def _mismatch(path):
    return ValueError('proxy derivative parent mismatch: %s' % path)


def _layers(value, *, where):
    if type(value) is not list or not value or not all(
            isinstance(entry, str) and _DIGEST.fullmatch(entry) for entry in value):
        raise _invalid('%s requires a non-empty list of sha256 DiffIDs' % where)
    return list(value)


def _read_images_entry(*, family, channel, platform):
    """Return the images.json pin entry for one family/channel/platform."""
    try:
        pinned = json.loads(package_data('ci/images.json').read_bytes())
    except (OSError, ValueError) as error:
        raise ValueError('derivative parent selection invalid: images.json unreadable') from error
    if type(pinned) is not dict or type(pinned.get('images')) is not list:
        raise ValueError('derivative parent selection invalid: images.json shape changed')
    for entry in pinned['images']:
        if not isinstance(entry, dict):
            continue
        if (entry.get('environment') == family and entry.get('channel') == channel
                and entry.get('platform') == platform):
            return entry
    raise ValueError('derivative parent selection unavailable: %s/%s/%s'
                     % (family, channel, platform))


def _read_roster_selection():
    """Return the selection-shaped roster for the bound parent image."""
    try:
        roster = json.loads(package_data('ci/' + _ROSTER_FILENAME).read_bytes())
    except (OSError, ValueError) as error:
        raise ValueError('derivative parent selection invalid: DiffID roster unreadable') from error
    if type(roster) is not dict or roster.get('schema') != 'p11lab.ci-parent-diffids.v1':
        raise ValueError('derivative parent selection invalid: DiffID roster schema changed')
    for key in ('family', 'channel', 'platform', 'repository', 'manifest_digest',
                'config_digest', 'local_engine_id'):
        if not isinstance(roster.get(key), str) or not roster[key]:
            raise ValueError('derivative parent selection invalid: roster requires %s' % key)
    for key in ('manifest_digest', 'config_digest', 'local_engine_id'):
        if _DIGEST.fullmatch(roster[key]) is None:
            raise ValueError('derivative parent selection invalid: roster %s malformed' % key)
    layers = roster.get('layers')
    if type(layers) is not list or len(layers) != 6 or not all(
            isinstance(entry, str) and _DIGEST.fullmatch(entry) for entry in layers):
        raise ValueError('derivative parent selection invalid: roster requires six DiffIDs')
    return {'family': roster['family'], 'channel': roster['channel'],
            'platform': roster['platform'], 'repository': roster['repository'],
            'manifest_digest': roster['manifest_digest'], 'config_digest': roster['config_digest'],
            'local_engine_id': roster['local_engine_id'], 'layers': list(layers)}


def load_parent_selection(*, family='softhsm2', channel='release',
                          platform='linux/amd64'):
    """Load the verified parent selection for one family/channel/platform.

    Cross-checks the images.json entry against the protected DiffID roster
    and refuses any pin divergence. Only the roster-bound parent is
    selectable in this slice; anything else fails closed.
    """
    roster = _read_roster_selection()
    if (family, channel, platform) != (roster['family'], roster['channel'], roster['platform']):
        raise ValueError('derivative parent selection unavailable: %s/%s/%s'
                         % (family, channel, platform))
    entry = _read_images_entry(family=family, channel=channel, platform=platform)
    root = entry.get('root') if isinstance(entry.get('root'), dict) else {}
    expected = {'repository': entry.get('repository'),
                'manifest_digest': root.get('digest') or entry.get('platform_manifest_digest'),
                'config_digest': entry.get('config_digest'),
                'local_engine_id': entry.get('local_engine_id')}
    for key, value in expected.items():
        if roster[key] != value:
            raise ValueError('derivative parent selection invalid: roster pin mismatch: %s' % key)
    return roster


def _require_selection(selection):
    if type(selection) is not dict:
        raise _invalid('parent_selection must be a dict')
    for key in ('family', 'platform', 'manifest_digest', 'config_digest', 'layers'):
        if key not in selection:
            raise _invalid('parent_selection requires %s' % key)
    if set(selection) - {'family', 'channel', 'platform', 'repository', 'manifest_digest',
                         'config_digest', 'local_engine_id', 'layers'}:
        raise _invalid('parent_selection carries unknown fields')
    if not isinstance(selection['family'], str) or not selection['family']:
        raise _invalid('parent_selection requires a family name')
    if not isinstance(selection['platform'], str) or not selection['platform']:
        raise _invalid('parent_selection requires a platform')
    for key in ('manifest_digest', 'config_digest'):
        if _DIGEST.fullmatch(selection[key] or '') is None:
            raise _invalid('parent_selection %s must be a sha256 digest' % key)
    return {'family': selection['family'], 'platform': selection['platform'],
            'manifest_digest': selection['manifest_digest'],
            'config_digest': selection['config_digest'],
            'repository': selection.get('repository'),
            'local_engine_id': selection.get('local_engine_id'),
            'layers': _layers(selection['layers'], where='parent_selection.layers')}


def _check_parent_inspection(parent, selection):
    """Corroborate one parent inspection against the verified selection."""
    if type(parent) is not dict:
        raise _invalid('parent_inspection must be a dict')
    try:
        observed_layers = parent['RootFS']['Layers']
    except (KeyError, TypeError):
        raise _invalid('parent_inspection requires RootFS.Layers') from None
    if (type(observed_layers) is not list
            or [entry for entry in observed_layers] != selection['layers']):
        raise _mismatch('parent.RootFS.Layers')
    if selection['local_engine_id'] is None or parent.get('Id') != selection['local_engine_id']:
        raise _mismatch('parent.Id')
    if selection['repository'] is None:
        raise _invalid('parent_selection requires a repository for RepoDigest corroboration')
    expected = selection['repository'] + '@' + selection['manifest_digest']
    if not isinstance(parent.get('RepoDigests'), list) or expected not in parent['RepoDigests']:
        raise _mismatch('parent.RepoDigests')


def verify_derivative_parent(child_inspection, parent_selection, *, parent_inspection=None):
    """Verify a derivative child inspection against the parent selection.

    Requires the exact ordered DiffID prefix (child layers start with the
    parent roster). With parent_inspection, additionally corroborates the
    parent engine Id, exact parent layers, and the retained RepoDigest for
    the manifest (offline manifest corroboration; no manifest is fetched).
    Labels, tags, and child RepoDigests are never consulted. Returns the
    validated binding populating the F28 naming fields plus the layer
    evidence. First mismatch raises ValueError naming the field path.
    """
    selection = _require_selection(parent_selection)
    if type(child_inspection) is not dict:
        raise _invalid('child_inspection must be a dict')
    try:
        child_layers = child_inspection['RootFS']['Layers']
    except (KeyError, TypeError):
        raise _invalid('child_inspection requires RootFS.Layers') from None
    child_layers = _layers(child_layers, where='child_inspection.RootFS.Layers')
    if child_layers[:len(selection['layers'])] != selection['layers']:
        raise _mismatch('child.RootFS.Layers')
    if parent_inspection is not None:
        _check_parent_inspection(parent_inspection, selection)
    return {'family': selection['family'], 'platform': selection['platform'],
            'manifest_digest': selection['manifest_digest'],
            'config_digest': selection['config_digest'],
            'parent_layers': list(selection['layers']), 'child_layers': child_layers,
            'child_layers_prefix_ok': True}


def verify_derivative_notices(notices):
    """Require byte-exact pinned-source license texts (fail closed)."""
    if type(notices) is not dict or set(notices) != set(DERIVATIVE_NOTICES):
        raise ValueError('proxy derivative notices invalid: requires exactly %s'
                         % sorted(DERIVATIVE_NOTICES))
    digests = {}
    for name in sorted(notices):
        data = notices[name]
        if type(data) is not bytes or not data:
            raise ValueError('proxy derivative notices invalid: %s must be nonempty bytes' % name)
        digest = hashlib.sha256(data).hexdigest()
        if digest != DERIVATIVE_NOTICES[name]:
            raise ValueError('proxy derivative notices mismatch: %s' % name)
        digests[name] = digest
    return digests


def _checked_product(entry):
    if type(entry) is not dict or set(entry) != {'name', 'sha256', 'size', 'path'}:
        raise ValueError('proxy derivative context invalid: products require {name, sha256, size, path}')
    if entry['name'] not in DERIVATIVE_PRODUCTS:
        raise ValueError('proxy derivative context invalid: unexpected product %r' % (entry['name'],))
    if _SHA.fullmatch(entry['sha256'] or '') is None:
        raise ValueError('proxy derivative context invalid: products.%s sha256 malformed'
                         % entry['name'])
    if type(entry['size']) is not int or entry['size'] <= 0:
        raise ValueError('proxy derivative context invalid: products.%s size invalid'
                         % entry['name'])
    try:
        data = Path(entry['path']).read_bytes()
    except OSError as error:
        raise ValueError('proxy derivative context invalid: products.%s unreadable'
                         % entry['name']) from error
    if len(data) != entry['size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise ValueError('proxy derivative context mismatch: products.%s' % entry['name'])
    return entry['name'], data


def render_derivative_build_context(*, products, notices, dest, dockerfile=None):
    """Render the sealed offline build context (proxy-bins + notices).

    Verifies every product's bytes against its recorded digest, writes the
    sha256sum-compatible proxy-bins.sha256 manifest the Dockerfile gate
    checks, and stages the notice bytes verbatim. Returns
    {proxy_bins_sha256, staged_files[], dockerfile_sha256}.
    """
    if type(products) is not list or [entry.get('name') for entry in products
                                      if isinstance(entry, dict)] == []:
        raise ValueError('proxy derivative context invalid: products must be a nonempty list')
    staged_products = {}
    for entry in products:
        name, data = _checked_product(entry)
        if name in staged_products:
            raise ValueError('proxy derivative context invalid: duplicate product %s' % name)
        staged_products[name] = data
    if set(staged_products) != set(DERIVATIVE_PRODUCTS):
        raise ValueError('proxy derivative context invalid: products must be exactly %s'
                         % list(DERIVATIVE_PRODUCTS))
    if type(notices) is not dict or set(notices) != set(DERIVATIVE_NOTICES):
        raise ValueError('proxy derivative context invalid: notices must be exactly %s'
                         % sorted(DERIVATIVE_NOTICES))
    for name, data in notices.items():
        if type(data) is not bytes or not data:
            raise ValueError('proxy derivative context invalid: notice %s must be nonempty bytes'
                             % name)
    if dockerfile is not None and (type(dockerfile) is not bytes or not dockerfile):
        raise ValueError('proxy derivative context invalid: dockerfile must be nonempty bytes')
    target = Path(dest)
    try:
        target.mkdir(parents=True, exist_ok=False)
        bins = target / 'proxy-bins'
        notes = target / 'proxy-notices'
        bins.mkdir(exist_ok=False)
        notes.mkdir(exist_ok=False)
        for name in sorted(staged_products):
            (bins / name).write_bytes(staged_products[name])
            (bins / name).chmod(0o644)
        manifest = ''.join('%s  %s\n' % (hashlib.sha256(staged_products[name]).hexdigest(), name)
                           for name in sorted(staged_products))
        (target / 'proxy-bins.sha256').write_text(manifest)
        (target / 'proxy-bins.sha256').chmod(0o644)
        for name in sorted(notices):
            (notes / name).write_bytes(notices[name])
            (notes / name).chmod(0o644)
        dockerfile_sha256 = None
        if dockerfile is not None:
            (target / 'Dockerfile').write_bytes(dockerfile)
            (target / 'Dockerfile').chmod(0o644)
            dockerfile_sha256 = hashlib.sha256(dockerfile).hexdigest()
    except FileExistsError as error:
        raise ValueError('proxy derivative context invalid: destination must be fresh') from error
    staged = sorted(path.relative_to(target).as_posix() for path in target.rglob('*')
                    if path.is_file())
    return {'proxy_bins_sha256': hashlib.sha256(manifest.encode()).hexdigest(),
            'staged_files': staged, 'dockerfile_sha256': dockerfile_sha256}


def verify_derivative_build_context(dest, *, proxy_bins_sha256, staged_files):
    """Re-verify a rendered context: exact roster plus manifest seal."""
    target = Path(dest)
    try:
        found = sorted(path.relative_to(target).as_posix() for path in target.rglob('*')
                       if path.is_file())
    except OSError as error:
        raise ValueError('proxy derivative context invalid: context unreadable') from error
    if type(staged_files) is not list or found != sorted(staged_files):
        raise ValueError('proxy derivative context mismatch: staged_files')
    try:
        manifest = (target / 'proxy-bins.sha256').read_bytes()
    except OSError as error:
        raise ValueError('proxy derivative context invalid: manifest unreadable') from error
    if hashlib.sha256(manifest).hexdigest() != proxy_bins_sha256:
        raise ValueError('proxy derivative context mismatch: proxy-bins.sha256')
    pinned = {}
    for line in manifest.decode().splitlines():
        digest, _, name = line.partition('  ')
        if _SHA.fullmatch(digest) is None or not name or name in pinned:
            raise ValueError('proxy derivative context mismatch: proxy-bins.sha256')
        pinned[name] = digest
    if set(pinned) != set(DERIVATIVE_PRODUCTS):
        raise ValueError('proxy derivative context mismatch: proxy-bins.sha256')
    for name, digest in pinned.items():
        try:
            data = (target / 'proxy-bins' / name).read_bytes()
        except OSError as error:
            raise ValueError('proxy derivative context mismatch: staged_files') from error
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('proxy derivative context mismatch: proxy-bins.%s' % name)
    return {'proxy_bins_sha256': proxy_bins_sha256, 'staged_files': sorted(staged_files),
            'verified': True}


def _checked_build_args(build_args, proxy_bins_sha256):
    if type(build_args) is not dict or set(build_args) != set(_BUILD_ARGS):
        raise ValueError('proxy derivative build invalid: build_args must be exactly %s'
                         % list(_BUILD_ARGS))
    for key in _BUILD_ARGS:
        if not isinstance(build_args[key], str) or not build_args[key]:
            raise ValueError('proxy derivative build invalid: %s must be nonempty' % key)
    if build_args['PROXY_BINS_MANIFEST_SHA256'] != proxy_bins_sha256:
        raise ValueError('proxy derivative build mismatch: PROXY_BINS_MANIFEST_SHA256')


def _result_summary(result):
    """Compact one-line summary of an engine result for retained errors."""
    return 'returncode=%s timed_out=%s stdout=%r stderr=%r' % (
        result.returncode, result.timed_out, (result.stdout or '')[:200],
        (result.stderr or '')[:200])


# Complete recognized per-stream absence envelopes for `image inspect`
# of a missing child. The CLI's default JSON inspector writes `[]` to
# stdout when no objects are returned while the daemon sentence goes to
# stderr, so the absence gate accepts ONLY these exact per-stream shapes:
# stdout empty or exactly the empty-array envelope `[]`, stderr exactly
# one of the recognized daemon absence responses naming the complete
# requested reference (surrounding whitespace ignored for the CLI's
# trailing newline). Any other probe text — a different or extended
# reference, an embedded diagnostic, altered casing, extra lines, or a
# nonempty stdout object — leaves the gate incomplete (fail closed).
_ABSENCE_RESPONSE_TEMPLATES = ('Error response from daemon: No such image: %s',)
_ABSENCE_STDOUT_SHAPES = ('', '[]')


def _probe_confirms_absence(probe, child_ref):
    """Positive complete-response absence confirmation only; never a substring.

    A nonzero return code alone proves nothing (daemon errors and timeouts
    are nonzero too), and neither does the marker text appearing anywhere:
    absence of the requested child is verified only when stderr IS one of
    the recognized complete daemon absence responses naming exactly that
    child (see _ABSENCE_RESPONSE_TEMPLATES) and stdout is empty or exactly
    the CLI's empty-array envelope `[]` (see _ABSENCE_STDOUT_SHAPES). A
    different or extended reference (`<child_ref>-other`), the phrase
    embedded in a longer diagnostic, altered casing, or a nonempty stdout
    object never confirms. Timed-out, truncated, or present-image (rc 0)
    probes never confirm — truncated output cannot confirm.
    """
    if probe.timed_out or probe.returncode == 0:
        return False
    if probe.stdout_truncated or probe.stderr_truncated:
        return False
    if (probe.stdout or '').strip() not in _ABSENCE_STDOUT_SHAPES:
        return False
    stderr = (probe.stderr or '').strip()
    return any(stderr == template % child_ref for template in _ABSENCE_RESPONSE_TEMPLATES)


def _remove_child_image(worker, child_ref, cleanup):
    """Remove exactly the owned child image and verify absence (never masks).

    Best-effort for engine errors so failure-path cleanup never hides the
    root error: every outcome lands in `cleanup` and the caller gates on
    `child_absence_verified`. Absence is verified ONLY on positive ref-bound
    no-such-image probe evidence for exactly this child; any other probe
    outcome leaves the gate incomplete with the probe error retained. A
    removal failure diagnostic is retained even when absence later verifies
    (absence-verified plus removal-error are compatible facts).
    """
    removal_note = None
    try:
        removed = worker.command(['image', 'rm', child_ref], timeout=120, check=False)
    except (ValueError, OSError) as error:
        cleanup['child_image_removed'] = False
        removal_note = 'image rm raised %s: %s' % (type(error).__name__, error)
    else:
        cleanup['child_image_removed'] = (
            removed.returncode == 0 and not removed.timed_out)
        if not cleanup['child_image_removed']:
            removal_note = 'image rm ' + _result_summary(removed)
    try:
        probe = worker.command(['image', 'inspect', child_ref], timeout=30, check=False)
    except (ValueError, OSError) as error:
        cleanup['child_absence_verified'] = False
        note = 'absence probe raised %s: %s' % (type(error).__name__, error)
    else:
        if _probe_confirms_absence(probe, child_ref):
            cleanup['child_absence_verified'] = True
            cleanup['child_absence_error'] = removal_note
            return
        cleanup['child_absence_verified'] = False
        note = 'absence probe ' + _result_summary(probe)
    cleanup['child_absence_error'] = note if removal_note is None else removal_note + '; ' + note


def _remove_recovered_container(worker, error, labels, cleanup):
    """Remove a create-recovered owned container before image removal (never masks).

    Docker.create raises DockerError(resource=('container', identity)) when a
    failed creation still left a confirmed owned container behind; that
    container can pin the child image, so it goes first. Only an exact
    ('container', identity) resource is consumed, through the same
    ownership-verifying worker.remove the success path uses (exact identity
    plus labels re-verified there). Uncertain resources and any other shape
    are left untouched — an unverified name must never select a deletion.
    The outcome lands in `cleanup`; engine errors never mask the root error
    (worker.remove parses inspection responses, so the same parsing-error
    tuple as the encompassing catch applies here).
    """
    resource = getattr(error, 'resource', None)
    if (type(resource) is not tuple or len(resource) != 2 or resource[0] != 'container'
            or not isinstance(resource[1], str) or not resource[1]):
        return
    try:
        worker.remove('container', resource[1], labels)
    except (ValueError, OSError, IndexError, KeyError, TypeError) as removal_error:
        cleanup['build_container_error'] = 'recovered container rm raised %s: %s' % (
            type(removal_error).__name__, removal_error)
    else:
        cleanup['build_container_removed'] = True


def _record_cleanup(out, cleanup, error):
    """Write the failure-path cleanup outcome beside build.log (never masks).

    Every post-build failure raise leaves the populated `cleanup` outcome
    (verified flags plus retained errors) in out/build-cleanup.json, so a
    caller catching the failure can read exactly what cleanup did. The same
    outcome payload is also attached to the propagated exception as
    `error.proxy_derivative_cleanup` (a `{'error': '<Type>: <message>',
    'cleanup': {...}}` dict identical to the file content), so the outcome
    stays readable even when the record writes themselves fail (ENOSPC,
    unwritable directory). Best effort: a record-write failure never masks
    the root error.
    """
    outcome = {'error': '%s: %s' % (type(error).__name__, error),
               'cleanup': dict(cleanup)}
    try:
        error.proxy_derivative_cleanup = outcome
    except (AttributeError, TypeError):
        pass
    try:
        (out / 'build-cleanup.json').write_text(
            json.dumps(outcome, sort_keys=True, indent=2) + '\n')
    except (OSError, ValueError):
        pass


def build_proxy_derivative(*, parent_ref, products, notices, build_args, output, engine=None):
    """Build the thin derivative once over the verified parent (Docker only).

    Seals the offline context, runs exactly one bounded `docker build` (no
    push, tag, cache export, or network), verifies the child against the
    parent selection, reads the build.json claim, and removes exactly the
    owned container and child image with absence re-verified. Every input
    refusal happens before Docker is touched. Returns {parent_inspection,
    child_inspection, base_ref, config_digest, manifest_digest_or_absence,
    diff_ids, build_json_bytes, cleanup}.
    """
    selection = load_parent_selection()
    if parent_ref != selection['local_engine_id']:
        raise ValueError('proxy derivative build mismatch: parent_ref')
    verify_derivative_notices(notices)
    try:
        dockerfile = package_data('runtime/proxy.Dockerfile').read_bytes()
    except OSError as error:
        raise ValueError('proxy derivative build invalid: Dockerfile unreadable') from error
    if hashlib.sha256(dockerfile).hexdigest() != PROXY_DOCKERFILE_SHA256:
        raise ValueError('proxy derivative build mismatch: Dockerfile bytes changed')
    out = Path(output)
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError as error:
        raise ValueError('proxy derivative build invalid: output must be fresh') from error
    context = out / 'context'
    rendered = render_derivative_build_context(products=products, notices=notices,
                                               dest=context, dockerfile=dockerfile)
    verify_derivative_build_context(context, proxy_bins_sha256=rendered['proxy_bins_sha256'],
                                    staged_files=rendered['staged_files'])
    _checked_build_args(build_args, rendered['proxy_bins_sha256'])
    worker = Docker() if engine is None else engine
    parent = ArtifactRef('docker-local', parent_ref, parent_ref.removeprefix('sha256:'),
                         selection['platform'])
    parent_inspection = worker.image(parent)
    _check_parent_inspection(parent_inspection, _require_selection(selection))
    iidfile = out / 'child.iid'
    # FROM takes the pinned repository@manifest reference (a bare engine ID
    # is not a valid build base reference); it is derived from the verified
    # selection, never from caller input, and the child is re-verified after.
    from_ref = selection['repository'] + '@' + selection['manifest_digest']
    argv = ['build', '--network=none', '--pull=false', '--progress=plain',
           '--iidfile', str(iidfile),
           '--build-arg', 'PROVIDER_IMAGE=' + from_ref,
           '--build-arg', 'PROXY_BINS_MANIFEST_SHA256=' + build_args['PROXY_BINS_MANIFEST_SHA256'],
           '--build-arg', 'PROXY_SOURCE_REVISION=' + build_args['PROXY_SOURCE_REVISION'],
           '--build-arg', 'PROXY_CARGO_LOCK_SHA256=' + build_args['PROXY_CARGO_LOCK_SHA256'],
           '--file', str(context / 'Dockerfile'), str(context)]
    # Fresh attempt identity, unique per build call: the container name and
    # ownership label must never derive from out.name alone — two attempts
    # sharing an output basename would otherwise collide, letting
    # create-failure recovery select (and delete) another attempt's
    # container. Bound here, before any recovered resource can be consumed.
    attempt = uuid.uuid4().hex
    labels = {'org.p11lab.derivative-build': attempt}
    cleanup = {'build_container_removed': False, 'build_container_error': None,
               'child_image_removed': False, 'child_absence_verified': False,
               'child_absence_error': None}
    child_ref = ''
    try:
        # The effectful build runs under the guard: it may already have
        # created the child (valid iidfile) when it raises.
        built_image = worker.command(argv, timeout=600, check=False, limit=8 * 1024 * 1024)
        (out / 'build.log').write_text(
            'argv: %s\nreturncode: %s timed_out: %s\nstdout:\n%s\nstderr:\n%s\n' % (
                argv, built_image.returncode, built_image.timed_out, built_image.stdout,
                built_image.stderr))
        if built_image.returncode or built_image.timed_out or built_image.stdout_truncated:
            raw = ''
            if iidfile.exists():
                try:
                    raw = iidfile.read_text().strip()
                except (OSError, ValueError):
                    raw = ''
            if _DIGEST.fullmatch(raw) is not None:
                child_ref = raw
            elif raw:
                try:
                    worker.command(['image', 'rm', raw], timeout=120, check=False)
                except (ValueError, OSError):
                    pass
            raise ValueError('derivative build failed (see build.log)')
        child_ref = iidfile.read_text().strip()
        if _DIGEST.fullmatch(child_ref) is None:
            raise ValueError('proxy derivative build invalid: unexpected child image identity')
        child = ArtifactRef('docker-local', child_ref, child_ref.removeprefix('sha256:'),
                            selection['platform'])
        child_inspection = worker.image(child)
        verify_derivative_parent(child_inspection, selection, parent_inspection=parent_inspection)
        options = ['--network', 'none', '--read-only', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev']
        container = worker.create(child_ref, ('proxy-build',), options, labels,
                                  'p11lab-derivative-' + attempt)
        try:
            built = worker.execute(container, 120, lambda: None)
        finally:
            worker.remove('container', container, labels)
            cleanup['build_container_removed'] = True
        if built.returncode or built.timed_out:
            raise ValueError('derivative proxy-build claim unavailable')
        try:
            claim = json.loads(built.stdout)
        except ValueError as error:
            raise ValueError('derivative proxy-build claim invalid') from error
        if type(claim) is not dict:
            raise ValueError('derivative proxy-build claim invalid')
    except (ValueError, OSError, IndexError, KeyError, TypeError) as error:
        _remove_recovered_container(worker, error, labels, cleanup)
        ref = child_ref if _DIGEST.fullmatch(child_ref) is not None else ''
        if not ref:
            try:
                candidate = iidfile.read_text().strip()
            except (OSError, ValueError):
                candidate = ''
            if _DIGEST.fullmatch(candidate) is not None:
                ref = candidate
        if ref:
            _remove_child_image(worker, ref, cleanup)
        _record_cleanup(out, cleanup, error)
        raise
    build_json_bytes = built.stdout.encode()
    _remove_child_image(worker, child_ref, cleanup)
    if not cleanup['child_absence_verified']:
        failure = ValueError('derivative child image cleanup incomplete')
        _record_cleanup(out, cleanup, failure)
        raise failure
    try:
        expected_repo = selection['repository'] + '@' + selection['manifest_digest']
        observation = {
            'parent_inspection': parent_inspection, 'child_inspection': child_inspection,
            'base_ref': parent_ref, 'config_digest': selection['config_digest'],
            'manifest_digest_or_absence': {'digest': selection['manifest_digest'],
                                           'repo_digest': expected_repo,
                                           'corroborated': True,
                                           'fetch': 'not-performed-offline'},
            'diff_ids': list(child_inspection['RootFS']['Layers']),
            'build_json_bytes': build_json_bytes, 'cleanup': cleanup}
        (out / 'build-observation.json').write_text(json.dumps(
            {'base_ref': parent_ref, 'config_digest': selection['config_digest'],
             'manifest_digest_or_absence': observation['manifest_digest_or_absence'],
             'diff_ids': observation['diff_ids'],
             'build_json_sha256': hashlib.sha256(build_json_bytes).hexdigest(),
             'build_json_text': built.stdout, 'cleanup': cleanup,
             'build_argv': argv, 'staged_files': rendered['staged_files'],
             'proxy_bins_sha256': rendered['proxy_bins_sha256']},
            sort_keys=True, indent=2) + '\n')
        (out / 'build.json').write_bytes(build_json_bytes)
    except (ValueError, OSError, IndexError, KeyError, TypeError) as error:
        _record_cleanup(out, cleanup, error)
        raise
    return observation
