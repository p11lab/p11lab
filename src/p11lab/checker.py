"""Optional installed-checker adapter; ordinary application runs need no checker.

execute_checker is the host execution boundary for native adapters. It assumes a
ready provider, a translated token-present slot index and explicit child PINs.
Neither it nor run_checker provisions native installations or retries operations.
"""
from dataclasses import replace
from importlib.resources import files
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from .models import RunResult, RunSpec
from .process import supervised_exec, write_process_logs
from .proxy_finalize import HOOK_DIRNAME, install_hook, reconcile_evidence
from .receipts import write_receipt
from .tls import (
    CLIENT_ENV_VARS,
    CONNECT_TIMEOUT_VAR,
    ENDPOINT_VAR,
    TRANSPORT_ENV_VARS,
    build_consumer_env,
)

SOURCE = 'de4db3d2ee738a9f99d0654e4baf568cdbd4774a'
WHEEL = '812c57e94fb967bc5ba939f0519bba67c58d5e755705b84c8442bbc2774d96f9'
LOCK = 'fe8bce22bb409a005977449cadb64f70ea19dd0a0ce9d685d78ac11447926372'


def load_profile(profile: str = 'smoke-v1') -> dict:
    frozen = json.loads(files('p11lab').joinpath('data/profiles/smoke-v1.json').read_text())
    if profile in {'smoke-v1', 'p11lab-smoke-v1'}:
        return frozen
    selected = json.loads(Path(profile).read_text())
    if any(selected.get(k) != frozen[k] for k in ('source_revision', 'wheel_sha256', 'runtime_lock_sha256', 'sources')):
        raise ValueError('profile checker/source identity mismatch')
    nodes = selected.get('nodes', [])
    if not isinstance(nodes, list) or any(not isinstance(n, str) for n in nodes) or not nodes or len(nodes) != len(set(nodes)) or not set(nodes) <= set(frozen['nodes']):
        raise ValueError('profile requires unique frozen smoke nodes')
    return frozen | {'nodes': nodes}


def source_inventory(root: Path, roster: list[str]) -> dict:
    root = root.resolve(strict=True)
    known = load_profile()
    if not roster or len(roster) != len(set(roster)) or not set(roster) <= set(known['nodes']):
        raise ValueError('selection must contain unique frozen nodes')
    inventory = {}
    for name in sorted({n.split('::', 1)[0] for n in roster}):
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root) or path.relative_to(root).as_posix() != name:
            raise ValueError('installed source identity escapes or aliases the root')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != known['sources'][name]:
            raise ValueError('installed source hash mismatch')
        inventory[name] = {'path': str(path), 'sha256': digest}
    return inventory


def canonical_node(node: str, root: Path) -> str:
    """Restore collection/report path identity while preserving the exact suffix.

    pytest may report paths relative to its installed root, cwd, or filesystem
    root. Accept only candidates resolving to one known installed source; never
    use basename matching or alter parameter/class/function spelling.
    """
    head, sep, tail = node.partition('::')
    if not sep:
        raise ValueError('expected exact node ID')
    head = head.replace('\\', '/')
    candidates = {Path(head).resolve(), (root / head).resolve()}
    if not Path(head).is_absolute():
        candidates.add(Path('/' + head).resolve())
    known = source_inventory(root, load_profile()['nodes'])
    identities = {str(p) for p in candidates if str(p) in {v['path'] for v in known.values()}}
    if len(identities) != 1:
        raise ValueError('unknown or ambiguous installed source path')
    return identities.pop() + '::' + tail


def select_token_slot(slots, label: str) -> tuple[int, int]:
    """Select the single token-present slot matching label; fail loud.

    The caller supplies the expected token label (P11LAB_LABEL, default
    'P11Lab'); providers with a fixed different label (haskoki:
    'haskoki-demo') need the explicit input. A mismatch or ambiguity
    reports the tried label and every observed token-present label so
    both sides are named.
    """
    observed = [(index, slot.slot_id, slot.get_token().label) for index, slot in enumerate(slots)]
    selected = [(index, native) for index, native, name in observed if name == label]
    if len(selected) != 1:
        raise ValueError('token identity must select exactly one token-present slot '
                         f"(label={label!r} among {[name for _, _, name in observed]!r})")
    return selected[0]


def installed_identity() -> dict:
    import pkcs11_check.testcases as tests
    root = Path(tests.__file__).resolve().parent
    if not root.is_relative_to(Path(sys.prefix).resolve()):
        raise ValueError('checker test root is outside the installed environment')
    version = importlib.metadata.version('pkcs11-check')
    if version != '0.2.2':
        raise ValueError('unsupported installed checker version')
    # Build seal is supplied only after offline hash-locked wheel installation.
    seal = json.loads(Path('/usr/share/p11lab/checker-install.json').read_text())
    if seal.get('source_revision') != SOURCE or seal.get('wheel_sha256') != WHEEL or seal.get('runtime_lock_sha256') != LOCK:
        raise ValueError('installed wheel seal mismatch')
    return seal | {'version': version, 'installed_root': str(root),
                   'python': sys.executable,
                   'dependencies': dict(sorted((d.metadata['Name'], d.version) for d in importlib.metadata.distributions()))}


PROVIDER_DESCRIPTOR_PATH = Path('/usr/share/p11lab/provider.json')


def _declared_fixed_env(provider_descriptor) -> dict:
    """Provider-declared non-secret env for checker grandchildren (names+values).

    The declaration is the only allowlist extension source; undeclared names
    stay scrubbed. Fail closed and loud: a present-but-invalid declaration
    raises instead of silently scrubbing. Only a missing file (host callers
    outside a provider image) or an absent key (providers without getenv-only
    controls) means no extension.
    """
    from .catalog import validate_runtime_env
    if provider_descriptor is None:
        try:
            raw = PROVIDER_DESCRIPTOR_PATH.read_text(encoding='utf-8')
        except FileNotFoundError:
            return {}
        except OSError as error:
            raise ValueError('provider declaration is unreadable') from error
        try:
            provider_descriptor = json.loads(raw)
        except ValueError as error:
            raise ValueError('provider declaration is not valid JSON') from error
    if not isinstance(provider_descriptor, dict):
        raise ValueError('provider declaration must be an object')
    if 'runtime_env' not in provider_descriptor:
        return {}
    validate_runtime_env(provider_descriptor['runtime_env'],
                         token_stores=provider_descriptor.get('runtime_env_token_stores'))
    return {entry['name']: entry['value'] for entry in provider_descriptor['runtime_env']}


def proxy_transport_from_environ(environ=None) -> dict | None:
    """Collect explicitly passed proxy transport; partial ambient fails loud.

    Direct runs carry no transport names and get None. Proxy runs must
    carry exactly the five shim variables; anything in between is a broken
    producer, never a defaultable state.
    """
    source = os.environ if environ is None else environ
    present = {name: source[name] for name in TRANSPORT_ENV_VARS if name in source}
    if present and set(present) != set(TRANSPORT_ENV_VARS):
        raise ValueError('partial proxy transport in environment: %s' % sorted(present))
    return present or None


def _validated_proxy_transport(mapping: dict) -> dict:
    """Validate exactly the five shim variables; no partial set is admitted."""
    if set(mapping) != set(TRANSPORT_ENV_VARS):
        raise ValueError('proxy transport requires exactly the five shim variables')
    validated = build_consumer_env(
        endpoint=mapping[ENDPOINT_VAR],
        ca_cert=mapping[CLIENT_ENV_VARS[0]],
        client_cert=mapping[CLIENT_ENV_VARS[1]],
        client_key=mapping[CLIENT_ENV_VARS[2]],
    )
    timeout = mapping[CONNECT_TIMEOUT_VAR]
    if not isinstance(timeout, str) or not timeout or any(c in timeout for c in '\0\n\r'):
        raise ValueError('proxy transport requires a clean connect timeout')
    validated[CONNECT_TIMEOUT_VAR] = timeout
    return validated


def _install_proxy_transport(action: str) -> dict | None:
    """Install validated transport for the proxy action; direct stays ambient.

    Only 'execute-proxy' collects the environment: the five collected
    values re-validate, every other PKCS11_PROXY_* name is scrubbed (an
    image-baked extra such as a TLS hostname override must not reach
    shim discovery), and the validated five are installed. Ordinary
    'execute' returns None with the ambient environment untouched, so
    direct runs keep their exact pre-proxy scrubbing behavior.
    """
    if action != 'execute-proxy':
        return None
    validated = _validated_proxy_transport(proxy_transport_from_environ() or {})
    for name in tuple(os.environ):
        if name.startswith('PKCS11_PROXY_'):
            del os.environ[name]
    os.environ.update(validated)
    return validated


def checker_environment(output: Path, pin: str, so_pin: str, *, provider_descriptor=None,
                        proxy_env=None, module_path=None) -> dict:
    # Inherited P11TEST_*, pytest options, TOML search locations and plugins must
    # not change selection. Keep only provider configuration and OS essentials.
    allowed = {'PATH', 'LD_LIBRARY_PATH', 'SYSTEMROOT', 'WINDIR', 'SOFTHSM2_CONF'}
    env = {k: v for k, v in os.environ.items() if k in allowed}
    # Declared fixed values are authoritative for grandchildren; ambient values
    # for the same names are ignored so adapter/descriptor drift cannot silently
    # change the checked configuration.
    env.update(_declared_fixed_env(provider_descriptor))
    hook_identity = None
    if proxy_env is not None:
        # Transport names are declaration-ineligible (reserved PKCS11_
        # prefix), so this explicit mapping is their only channel; values
        # re-validate exactly as the runner emitted them (no partials).
        # Transport validates before the hook installs anything.
        validated = _validated_proxy_transport(proxy_env)
        if not module_path:
            raise ValueError('proxy finalize requires the module path')
        installed = install_hook(output.resolve() / HOOK_DIRNAME)
        hook_dir = installed['dir']
        env.update(validated)
        # Separate explicit channel alongside (never inside) the five
        # transport vars: the exit-finalize hook for proxy checker
        # children, incl. the Popen'd preflight helper. The checker CLI
        # takes --module and never reads P11LAB_MODULE, so this addition
        # cannot change checked behavior; direct runs stay scrubbed.
        env.update(PYTHONPATH=hook_dir, PYTHONDONTWRITEBYTECODE='1',
                   P11LAB_MODULE=str(module_path),
                   P11LAB_PROXY_FINALIZE_DIR=hook_dir)
        hook_identity = {'version': installed['version'], 'sha256': installed['sha256'],
                         'scope': 'preflight', 'module': str(module_path)}
    provenance_file = output.resolve() / 'build-provenance.json'
    provenance_extra = {'checker': {'source_revision': SOURCE, 'wheel_sha256': WHEEL,
                                    'runtime_lock_sha256': LOCK}}
    if hook_identity is not None:
        provenance_extra['proxy_finalize'] = hook_identity
    with os.fdopen(os.open(provenance_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump({'extra': provenance_extra}, stream, indent=2)
    env.update(HOME=str(output), XDG_CONFIG_HOME=str(output), PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',
               PYTEST_ADDOPTS='-v',
               P11TEST_PIN=pin, P11TEST_SO_PIN=so_pin,
               PKCS11_CHECK_FRAMEWORK_VERSION='0.2.2',
               PKCS11_CHECK_BUILD_PROVENANCE=str(provenance_file))
    if os.name == 'nt':
        # ntpath.expanduser ignores HOME: without USERPROFILE the checker's
        # import-time Path.home() (testcases.data) aborts every CLI call.
        # Redirect to the output dir (hermetic), never inherit the caller.
        env['USERPROFILE'] = str(output)
    # The pin expects the source tree's -v default when parsing -qq collection.
    # Reproduce only output verbosity in the installed environment; no filters.
    # The checker explicitly loads required plugins in its child command.
    return env


def execute_checker(*, installed_root: Path, module: Path, slot: int,
                    nodes: list[str], output_dir: Path, pin: str, so_pin: str,
                    identity: dict, proxy_env: dict | None = None) -> dict:
    """Run the public installed CLI with controlled settings; retain all findings.

    This library boundary also serves host/native execution. The caller supplies
    verified installation identity and readiness, and owns provider lifecycle.
    output_dir must be a new directory; credentials never enter argv/receipts.
    proxy_env carries the exact five shim transport variables for proxy runs
    (direct runs pass None); the controlled environment admits no partial set.
    """
    if type(slot) is not int or slot < 0:
        raise ValueError('slot must be a translated token-present index')
    if any(identity.get(k) != v for k, v in {'source_revision': SOURCE, 'wheel_sha256': WHEEL, 'runtime_lock_sha256': LOCK}.items()):
        raise ValueError('checker installation identity mismatch')
    import pkcs11_check.testcases as tests
    if installed_root.resolve() != Path(tests.__file__).resolve().parent:
        raise ValueError('execution requires this interpreter installed test root')
    sources = source_inventory(installed_root, nodes)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    output_dir.chmod(0o700)
    targets = [str(installed_root.resolve() / node) for node in nodes]
    env = checker_environment(output_dir, pin, so_pin, proxy_env=proxy_env,
                             module_path=str(module))
    prefix = [sys.executable, '-m', 'pkcs11_check']
    collect = subprocess.run([*prefix, 'list-tests', '--include-disabled', *targets],
                             cwd=output_dir, env=env, capture_output=True, text=True, timeout=180)
    (output_dir / 'collection.stdout.log').write_text(collect.stdout)
    (output_dir / 'collection.stderr.log').write_text(collect.stderr)
    collected = [canonical_node(n, installed_root) for n in collect.stdout.splitlines()]
    # Collection uses canonical installed source paths (parameter suffix literal).
    if collect.returncode or len(collected) != len(targets) or set(collected) != set(targets):
        raise ValueError('installed collection differs from frozen selection')
    (output_dir / 'collection.json').write_text(json.dumps({'nodes': nodes, 'installed_nodes': collected, 'returncode': collect.returncode}, indent=2))
    argv = [*prefix, 'test', '--module', str(module), '--slot', str(slot), '--interface', 'auto',
            '--isolation', 'file', '--timeout', '180', '--ignore-disabled-tests', '--no-collection-cache',
            '--key-inject', 'off', '--recover-mode', 'off', '--output', 'json',
            '--output-file', str(output_dir / 'results.json'), '--state-file', str(output_dir / 'state.json'),
            '--policy-file', str(output_dir / 'policy.json'), *targets]
    status, timed_out, owner, supervision = supervised_exec(
        argv, cwd=output_dir, env=env, timeout=900)
    log_evidence = write_process_logs(owner, output_dir, 'checker', (pin, so_pin), marker=True)
    logs = {'checker.' + name + '.log': log_evidence[name + '_truncated'] for name in ('stdout', 'stderr')}
    supervision.update(log_evidence)
    record = {'schema_version': 1, 'attempt_id': uuid4().hex, 'nodes': nodes, 'sources': sources,
              'checker': identity, 'slot_index': slot, 'returncode': status, 'timeout': timed_out, 'logs_truncated': logs, 'supervision': supervision,
              'settings': {'interface': 'auto', 'isolation': 'file', 'timeout': 180,
                           'key_inject': 'off', 'recover_mode': 'off', 'ignore_disabled_tests': True,
                           'pytest_addopts': '-v'}}
    write_receipt(output_dir / 'checker-receipt.json', record)
    assessment = validate_results(output_dir, nodes, installed_root)
    if not supervision['drain_complete'] or supervision['stragglers_remaining'] or supervision['supervision_errors']:
        assessment['complete'] = False
        assessment['errors'] = [*assessment.get('errors', []), 'checker supervision incomplete']
    record['evidence'] = assessment
    write_receipt(output_dir / 'checker-receipt.json', record)
    return record


def _lifecycle(entry: dict) -> bool:
    return entry.get('nodeid') == 'C_Finalize::teardown' and entry.get('lifecycle') == 'session-teardown'


def _grouped_classifications(units: list[dict], root: Path):
    from collections import Counter
    from pkcs11_check.core.run_metrics import RESULT_OUTCOME_KEYS
    def test_identity(test):
        node = test['nodeid'] if _lifecycle(test) else canonical_node(test['nodeid'], root)
        return (node, test.get('outcome'), test.get('lifecycle'))
    return Counter((canonical_node(u['target'] + '::__owner__', root).split('::', 1)[0],
                    u['status'], u['returncode'],
                    tuple(u.get('counts', {}).get(k, 0) for k in RESULT_OUTCOME_KEYS),
                    tuple(sorted(Counter(test_identity(t) for t in u.get('tests', [])).items())))
                   for u in units)


def _checker_private_api() -> dict:
    """Import the checker's private validation internals behind one gate.

    validate_results reconstructs grouped classifications with the pinned
    checker's own parser/assembler, whose entry points are underscore-
    private in the owning repo. Every such import lives in this adapter:
    a checker refactor breaks here (and in the version-gated import test)
    instead of scattering ImportErrors through validation. Negotiating a
    public validation entry point stays an owning-repo follow-up.
    """
    if importlib.metadata.version('pkcs11-check') != '0.2.2':
        raise ValueError('checker validation adapter requires pkcs11-check 0.2.2')
    from pkcs11_check.core.file_runner import _completion_verified_for_attempt
    from pkcs11_check.core._report_records import _build_detail_from_report_records
    from pkcs11_check.core._report_writers import _build_isolated_json_payload
    from pkcs11_check.core._run_units import FileRunResult, FileRunState
    return {'completion_verified_for_attempt': _completion_verified_for_attempt,
            'build_detail_from_report_records': _build_detail_from_report_records,
            'build_isolated_json_payload': _build_isolated_json_payload,
            'FileRunResult': FileRunResult, 'FileRunState': FileRunState}


def durable_finalize_errors(directory):
    """Proxy finalize verification for durable (re)validation.

    Pure provenance + evidence reads (no checker import), so execute_checker
    and shard merges share one verdict. [] when inapplicable: direct runs,
    grandfathered runs without the hook record, and foreign directories.
    """
    try:
        provenance = json.loads((Path(directory) / 'build-provenance.json').read_text())
    except (OSError, ValueError):
        return []
    if not isinstance(provenance, dict):
        return []
    extra = provenance.get('extra')
    if not isinstance(extra, dict):
        return []
    if 'proxy_finalize' not in extra:
        return []
    expected = extra['proxy_finalize']
    if not isinstance(expected, dict) or not expected:
        return ['proxy finalize provenance malformed']
    return reconcile_evidence(
        Path(directory) / HOOK_DIRNAME,
        module_path=expected.get('module'),
        hook_version=expected.get('version'),
        hook_sha256=expected.get('sha256'),
    )


def validate_results(directory: Path, nodes: list[str], installed_root: Path) -> dict:
    """Reconcile native state, grouped JSON and raw isolated attempt evidence.

    Uses the optional checker's own validated bookends/completion rules. Grouped
    tests contain notable failures, not every passed case; process executions and
    raw per-attempt records account for the complete frozen roster.
    """
    from collections import Counter
    from pkcs11_check.core.report_log import SessionCompletionTracker
    from pkcs11_check.core.run_metrics import RESULT_OUTCOME_KEYS, run_is_incomplete
    private = _checker_private_api()
    errors = []
    root = installed_root.resolve()
    expected = {str(root / n) for n in nodes}
    def phase(entry):
        return (canonical_node(entry['nodeid'], root), entry.get('when'), entry.get('outcome'))
    try:
        errors.extend(durable_finalize_errors(directory))
        source_inventory(root, nodes)
        payload = json.loads((directory / 'results.json').read_text())
        state = json.loads((directory / 'state.json').read_text())
        raw = [json.loads(line) for line in (directory / 'report.jsonl').read_text().splitlines() if line.strip()]
        results = state['results']
        if set(state['units']) != expected or len(state['units']) != len(expected):
            errors.append('state roster mismatch')
        if {r['target'] for r in results} != expected or len(results) != len(expected):
            errors.append('isolated result roster mismatch')
        units = payload['units']
        if payload['summary'].get('incomplete') is not False or run_is_incomplete(payload['summary'], units):
            errors.append('checker marked incomplete')
        grouped = {canonical_node(t['nodeid'], root) for u in units for t in u.get('tests', []) if not _lifecycle(t)}
        if not grouped <= expected:
            errors.append('unknown grouped test case')
        observations = state['process_observations']
        raw_observations = [r['observation'] for r in raw if r.get('$report_type') == 'ProcessReport']
        grouped_observations = [o for u in units for o in u.get('executions', [])]
        for label, entries in (('state', observations), ('raw', raw_observations), ('grouped', grouped_observations)):
            if Counter(o['target'] for o in entries if o.get('role') == 'unit') != Counter(expected):
                errors.append(f'{label} supervisor roster mismatch')
        if state.get('process_observations_complete') is not True:
            errors.append('supervisor observations incomplete')
        cache_phases = Counter()
        expected_phases = Counter()
        cache_finalize = Counter()
        details = {}
        for result in results:
            target = result['target']
            cache = directory / '.state.json.report-records' / (hashlib.sha256(target.encode()).hexdigest() + '.jsonl')
            status, rc = result['status'], result['returncode']
            if cache.exists():
                records = [json.loads(line) for line in cache.read_text().splitlines() if line.strip()]
            elif status in {'crashed', 'timeout'}:
                # A process can die before its first pytest record. Public raw
                # report/state/grouped supervisor evidence is still required.
                records = []
            else:
                raise ValueError('missing normal pytest attempt cache')
            tracker = SessionCompletionTracker()
            for entry in records:
                tracker.observe(entry)
            cache_finalize.update(json.dumps(r, sort_keys=True) for r in records if r.get('$report_type') == 'TeardownFinalize')
            detail = private['build_detail_from_report_records'](records)
            if detail is not None:
                details[target] = detail
            if result.get('completion_verified') is not True:
                errors.append('unverified isolated completion')
            if not private['completion_verified_for_attempt'](cache, status, rc, tracker.single_exitstatus):
                errors.append('missing or contradictory session evidence')
            own = [o for o in observations if o.get('target') == target and o.get('role') == 'unit']
            valid_observation = len(own) == 1 and type(own[0].get('attempt')) is int and own[0]['attempt'] >= 0
            if valid_observation:
                termination = own[0].get('termination', {})
                raw_code = termination.get('raw_code')
                valid_observation = type(raw_code) is int and (raw_code == rc or
                    (status == 'timeout' and rc == 124 and termination.get('kind') == 'timeout'))
            if not valid_observation:
                errors.append('missing or contradictory supervisor attempt')
            else:
                markers = [r for r in records if r.get('$report_type') == 'IsolatedUnitReport']
                if records and (len(markers) != 1 or markers[0].get('target') != target or markers[0].get('attempt') != own[0]['attempt']):
                    errors.append('raw unit/attempt marker mismatch')
                raw_own = [r['observation'] for r in raw if r.get('$report_type') == 'ProcessReport' and r.get('observation', {}).get('target') == target and r['observation'].get('role') == 'unit']
                grouped_own = [o for u in units for o in u.get('executions', []) if o.get('target') == target and o.get('role') == 'unit']
                if raw_own != own or grouped_own != own:
                    errors.append('raw/grouped supervisor attempt mismatch')
                if status in {'crashed', 'timeout'}:
                    kind = own[0]['termination'].get('kind')
                    if (status == 'timeout' and kind != 'timeout') or (status == 'crashed' and kind not in {'signal', 'exception', 'abrupt_exit'}):
                        errors.append('unsupported supervisor failure evidence')
                    if not any(t.get('outcome') == status and canonical_node(t['nodeid'], root) == target for u in units for t in u.get('tests', []) if not _lifecycle(t)):
                        errors.append('missing synthetic supervisor failure entry')
            tests = [r for r in records if r.get('$report_type') == 'TestReport' and not _lifecycle(r)]
            seen = {phase(r)[0] for r in tests}
            if not seen <= {target} or (status not in {'crashed', 'timeout'} and seen != {target}):
                errors.append('raw attempt membership mismatch')
            # A selected node/attempt can emit each pytest phase only once,
            # even when both retained copies contain the same extra report.
            phases = [phase(r) for r in tests]
            if (any(p[1] not in {'setup', 'call', 'teardown'} or p[2] not in {'passed', 'failed', 'skipped'} for p in phases)
                    or len({p[:2] for p in phases}) != len(phases)):
                errors.append('duplicate or invalid per-attempt test phase')
            expected_phases.update(set(phases))
            cache_phases.update(phase(r) for r in tests)
        raw_phases = Counter(phase(r) for r in raw if r.get('$report_type') == 'TestReport' and not _lifecycle(r) and r.get('outcome') in {'passed', 'failed', 'skipped'})
        if raw_phases != expected_phases or cache_phases != expected_phases:
            errors.append('aggregate raw attempt evidence mismatch')
        if not {phase(r)[0] for r in raw if r.get('$report_type') == 'TestReport' and not _lifecycle(r)} <= expected:
            errors.append('unknown raw test case')
        raw_finalize = Counter(json.dumps(r, sort_keys=True) for r in raw if r.get('$report_type') == 'TeardownFinalize')
        if raw_finalize != cache_finalize:
            errors.append('aggregate raw finalize evidence mismatch')
        # Reconstruct classifications with the pin's own parser and assembler.
        # This retains its finalize priority, synthetic deaths and grouped RCs.
        native_results = [private['FileRunResult'](**{k: r[k] for k in private['FileRunResult'].__dataclass_fields__ if k in r}
                                       | {'duration_s': r.get('duration_s', 0.0)}) for r in results]
        reconstructed = private['build_isolated_json_payload'](private['FileRunState'](
            units=list(expected), fingerprint='', results=native_results,
            process_observations=observations), per_unit_details=details)
        if _grouped_classifications(units, root) != _grouped_classifications(reconstructed['units'], root):
            errors.append('grouped classifications differ from raw attempts')
        if any(payload['summary'].get(k, 0) != reconstructed['summary'].get(k, 0)
               for k in (*RESULT_OUTCOME_KEYS, 'total')):
            errors.append('aggregate counts differ from raw attempts')
        if run_is_incomplete(reconstructed['summary'], reconstructed['units']):
            errors.append('checker marked incomplete')
        executed = [o['target'] for u in units for o in u.get('executions', []) if o.get('role') == 'unit']
        if set(executed) != expected or len(executed) != len(expected):
            errors.append('grouped execution roster mismatch')
    except (OSError, ValueError, KeyError, TypeError):
        errors.append('missing or malformed durable evidence')
        payload = {}
    return {'complete': not errors,
            'observations_complete': not (set(errors) - {'checker marked incomplete'}),
            'errors': sorted(set(errors)), 'summary': payload.get('summary', {}),
            'provider_statuses': [u.get('status') for u in payload.get('units', [])]}


def run_checker(spec: RunSpec, profile: str) -> RunResult:
    """Execute an optional Docker derivative through the accepted runner.

    spec.argv is reserved and must be empty. For a shard, profile is a JSON
    selection under spec.cwd containing frozen nodes and the same build identity.
    Token selection reads P11LAB_LABEL from spec.inputs with a 'P11Lab'
    default; providers with a fixed different label (haskoki: 'haskoki-demo')
    need the explicit input or selection fails loud. Proxy runs execute the
    'execute-proxy' action (ambient shim transport is validated before
    discovery); every other mode executes 'execute' with direct scrubbing.
    """
    from .run import run_application
    if spec.argv:
        raise ValueError('run_checker builds argv; provide an empty argv')
    selected = load_profile(profile)
    argv = ('/opt/p11lab-checker/bin/python', '-m', 'p11lab.checker',
            'execute-proxy' if spec.mode == 'proxy' else 'execute',
            json.dumps(selected['nodes'], separators=(',', ':')))
    result = run_application(replace(spec, argv=argv))
    try:
        receipt = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        complete = receipt['evidence']['complete'] is True
        observations_complete = receipt['evidence']['observations_complete'] is True
    except (OSError, ValueError, KeyError, TypeError):
        complete = observations_complete = False
    outer = json.loads(result.receipt_path.read_text())
    outer['checker'] = {'profile': selected['name'], 'nodes': selected['nodes'], 'evidence_complete': complete,
                        'observations_complete': observations_complete}
    if not observations_complete:
        outer['lifecycle_errors'].append('checker observation evidence incomplete or unavailable')
    if not complete:
        outer['exit_code'] = result.exit_code or 1
    write_receipt(result.receipt_path, outer)
    return replace(result, lifecycle_errors=tuple(outer['lifecycle_errors']), exit_code=outer['exit_code'])


def _main():
    if sys.argv[1] not in ('execute', 'execute-proxy'):
        raise ValueError('expected execute')
    proxy_env = _install_proxy_transport(sys.argv[1])
    from pkcs11_check.core.loader import load_module
    module = Path(os.environ['P11LAB_MODULE'])
    p11 = load_module(module, interface='auto')
    slots = p11.get_slots(token_present=True)
    label = os.environ.get('P11LAB_LABEL', 'P11Lab')
    slot, native_id = select_token_slot(slots, label)
    from pkcs11_check.raw.rv import expect_rv
    from pkcs11_check.raw.types_std import CKR_OK
    expect_rv(p11.raw.C_Finalize(None), CKR_OK)
    def secret(name):
        return Path(os.environ[name + '_FILE']).read_text().rstrip('\n') if name + '_FILE' in os.environ else os.environ[name]
    identity = installed_identity()
    record = execute_checker(installed_root=Path(identity['installed_root']), module=module, slot=slot,
                             nodes=json.loads(sys.argv[2]), output_dir=Path('/p11lab-output/checker'),
                             pin=secret('P11LAB_PIN'), so_pin=secret('P11LAB_SO_PIN'), identity=identity,
                             proxy_env=proxy_env)
    record['token'] = {'label': label, 'native_slot_id': native_id, 'token_present_index': slot}
    write_receipt(Path('/p11lab-output/checker/checker-receipt.json'), record)
    sys.exit(record['returncode'] or (0 if record['evidence']['complete'] else 1))


if __name__ == '__main__':
    _main()
