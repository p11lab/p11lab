"""Packaged immutable image policy, independent of the caller's working directory.

This validates declarations. It neither resolves tags nor authenticates OCI bytes;
registry/build/run receipts must supply those observations independently.
"""

from datetime import datetime
import hashlib
import json
import re
from urllib.parse import urlsplit

from .catalog import package_data


class CIInputError(ValueError):
    """A packaged image policy is ambiguous, malformed or contradictory."""


def _require(condition, message):
    if not condition:
        raise CIInputError(message)


def _detached(value):
    """Accept JSON values only; do not coerce tuples, non-string keys or NaN."""
    def walk(item):
        if type(item) is dict:
            _require(all(type(key) is str for key in item), 'JSON object keys must be strings')
            for child in item.values():
                walk(child)
        elif type(item) is list:
            for child in item:
                walk(child)
        else:
            _require(item is None or type(item) in (str, bool, int, float), 'record requires JSON values')
    try:
        walk(value)
    except RecursionError as error:
        raise CIInputError('record requires acyclic JSON with bounded nesting') from error
    try:
        return json.loads(json.dumps(value, allow_nan=False))
    except (ValueError, TypeError, OverflowError) as error:
        raise CIInputError('record requires finite JSON values') from error


def _schema(value, rule, document, path='$'):
    """Validate the small JSON Schema vocabulary used by our bundled contracts.

    Not a general JSON Schema implementation. Schemas carry structural rules;
    the public validators also enforce their documented cross-field invariants.
    """
    if '$ref' in rule:
        target = document
        for part in rule['$ref'].removeprefix('#/').split('/'):
            target = target[part]
        _schema(value, target, document, path)
    if 'anyOf' in rule:
        failures = []
        for alternative in rule['anyOf']:
            try:
                _schema(value, alternative, document, path)
                break
            except CIInputError as error:
                failures.append(str(error))
        else:
            raise CIInputError(f'{path}: no valid alternative: ' + '; '.join(failures))
    kind = rule.get('type')
    types = {'object': dict, 'array': list, 'string': str, 'integer': int,
             'boolean': bool, 'null': type(None)}
    if kind:
        _require(type(value) is types[kind], f'{path}: requires {kind}')
    if 'const' in rule:
        expected = rule['const']
        _require(type(value) is type(expected) and value == expected, f'{path}: requires {expected!r}')
    if 'enum' in rule:
        _require(any(type(value) is type(item) and value == item for item in rule['enum']), f'{path}: unsupported value')
    if type(value) is dict:
        required = set(rule.get('required', []))
        _require(required <= value.keys(), f'{path}: missing required fields: ' + ', '.join(sorted(required - value.keys())))
        properties = rule.get('properties', {})
        if rule.get('additionalProperties') is False:
            _require(value.keys() <= properties.keys(), f'{path}: unknown fields: ' + ', '.join(sorted(value.keys() - properties.keys())))
        for key, child_rule in properties.items():
            if key in value:
                _schema(value[key], child_rule, document, f'{path}.{key}')
    elif type(value) is list:
        _require(len(value) >= rule.get('minItems', 0), f'{path}: too few members')
        _require('maxItems' not in rule or len(value) <= rule['maxItems'], f'{path}: too many members')
        if rule.get('uniqueItems'):
            members = [json.dumps(item, sort_keys=True, separators=(',', ':')) for item in value]
            _require(len(members) == len(set(members)), f'{path}: duplicate members')
        if 'items' in rule:
            for index, item in enumerate(value):
                _schema(item, rule['items'], document, f'{path}[{index}]')
    elif type(value) is str:
        _require(len(value) >= rule.get('minLength', 0), f'{path}: requires nonempty text')
        if 'pattern' in rule:
            _require(re.search(rule['pattern'], value) is not None, f'{path}: invalid format')
        if rule.get('format') == 'date-time':
            try:
                observed = datetime.fromisoformat(value.replace('Z', '+00:00'))
                _require(observed.utcoffset() is not None, f'{path}: requires UTC timestamp')
            except ValueError as error:
                raise CIInputError(f'{path}: invalid timestamp') from error
    elif type(value) is int and 'minimum' in rule:
        _require(value >= rule['minimum'], f'{path}: below minimum')
    for conjunction in rule.get('allOf', []):
        _schema(value, conjunction, document, path)
    if 'if' in rule:
        try:
            _schema(value, rule['if'], document, path)
        except CIInputError:
            branch = rule.get('else', {})
        else:
            branch = rule.get('then', {})
        try:
            _schema(value, branch, document, path)
        except CIInputError as error:
            condition = json.dumps(rule['if'], sort_keys=True, separators=(',', ':'))
            raise CIInputError(f'{error} (conditional rule: {condition})') from error


def _validate_document(value, schema_name):
    detached = _detached(value)
    document = json.loads(package_data('ci/' + schema_name).read_text(encoding='utf-8'))
    _schema(detached, document, document)
    return detached


def _validate_root(root, platform_manifest_digest, path='root'):
    if root['kind'] == 'index':
        _require(root['index_digest'] == root['digest'], f'{path}.index_digest must equal the observed root digest')
    else:
        _require(root['digest'] == platform_manifest_digest, f'{path} manifest digest must equal platform_manifest_digest')


def _validate_evidence(artifact, path='evidence'):
    # URLs are public locators, not credentials or expiring signed download links.
    if artifact['url'] is not None:
        parsed = urlsplit(artifact['url'])
        _require(parsed.hostname is not None and parsed.username is None and parsed.password is None
                 and not parsed.query and not parsed.fragment, f'{path}.url must be public HTTPS without credentials/query/fragment')
    parts = artifact['path'].split('/')
    _require(all(part not in ('', '.', '..') for part in parts), f'{path}.path must be a canonical relative artifact path')


def validate_image_pins(policy: dict) -> dict:
    """Return a detached validated ImagePinsV1; unresolved pins remain inactive."""
    result = _validate_document(policy, 'images.schema.json')
    seen = set()
    for pin in result['images']:
        key = (pin['environment'], pin['channel'], pin['platform'])
        _require(key not in seen, 'duplicate environment/channel/platform image pin')
        seen.add(key)
        _validate_root(pin['root'], pin['platform_manifest_digest'])
        provenance, eligibility = pin['provenance'], pin['eligibility']
        if provenance['patches']:
            _require(pin['semantics']['modified'] is True,
                     'nonempty ordered patches require semantics.modified=true')
        for name in ('source_seal', 'content_companion', 'handoff'):
            source = provenance[name]
            if source is not None:
                _require(source['reference'] == pin['repository'] + '@sha256:' + source['manifest_sha256'],
                         f'provenance.{name} must bind matching same-repository manifest_sha256')
        for observation in pin['observations'].values():
            if observation is not None:
                for artifact in observation['evidence']:
                    _validate_evidence(artifact)
        if eligibility['distribution_eligible']:
            _require(all(patch['license_status'] == 'reviewed' for patch in provenance['patches']),
                     'distribution eligibility requires reviewed ordered patch provenance')
        else:
            _require(eligibility['blockers'], 'ineligible image requires explicit eligibility blockers')
        if eligibility['acquisition_eligible']:
            _require(eligibility['distribution_eligible'], 'acquisition eligibility requires distribution eligibility')
    return result


def image_pins_sha256() -> str:
    """Hash the exact packaged policy bytes for a separately frozen round input."""
    return hashlib.sha256(package_data('ci/images.json').read_bytes()).hexdigest()


def load_image_pins() -> dict:
    """Load the complete packaged policy; never use a caller-cwd fallback."""
    return validate_image_pins(json.loads(package_data('ci/images.json').read_text(encoding='utf-8')))


def load_image_pin(environment: str, channel: str, platform: str) -> dict:
    """Resolve one exact pin, including explicit unresolved/ineligible fields."""
    for pin in load_image_pins()['images']:
        if (pin['environment'], pin['channel'], pin['platform']) == (environment, channel, platform):
            return pin
    raise CIInputError(f'no image pin for {environment!r}/{channel!r}/{platform!r}')
