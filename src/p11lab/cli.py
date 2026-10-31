"""Installed catalogue, verified source acquisition and runtime builds."""

import argparse
from dataclasses import asdict
from pathlib import Path
import json
import sys

from .catalog import CatalogError, list_environments, load_environment, package_data, validate_tools


# Flags each publish operation reads; anything else on the command line is a
# misrouted flag or typo and is rejected instead of silently ignored. (Full
# per-operation subparsers stay a follow-up.)
_PUBLISH_OP_FLAGS = {
    "controller-identity": set(),
    "check-producer": {"--channel"},
    "materialize-inventory": {"--artifact", "--build-receipt", "--output-dir"},
    "prepare-source": {"--validation-policy", "--channel", "--artifact", "--inventory", "--validation-dir", "--build-receipt", "--sealed-dir", "--output-dir"},
    "source-context": {"--validation-policy", "--channel", "--artifact", "--evidence-dir", "--validation-dir", "--build-receipt", "--sealed-dir", "--registry", "--source-manifest-digest", "--content-manifest-digest", "--output-dir"},
    "admit-source": {"--validation-policy", "--channel", "--artifact", "--evidence-dir", "--validation-dir", "--build-receipt", "--sealed-dir", "--registry", "--source-manifest-digest", "--content-manifest-digest", "--output-dir", "--attestation-context", "--bundle", "--gh", "--trusted-root"},
    "seal-sources": {"--channel", "--resolved-dir", "--output-dir"},
    "seal-native": {"--channel", "--target", "--output-dir"},
    "verify-readback": {"--sealed-receipt", "--pulled-dir", "--transcript", "--extract-dir",
                        "--source-manifest", "--source-manifest-digest", "--registry"},
    "verify-content-readback": {"--content-receipt", "--pulled-dir", "--transcript", "--extract-dir",
                               "--source-manifest", "--source-manifest-digest", "--registry", "--artifact"},
    "check-inputs": {"--channel", "--sealed-manifest", "--build-receipt", "--manifest"},
    "admit": {"--channel", "--target", "--sealed-receipt", "--sealed-manifest", "--readback-proof",
              "--build-receipt", "--manifest", "--artifact-kind", "--artifact-reference", "--artifact-digest",
              "--platform", "--registry", "--evidence-dir", "--output-dir", "--producer-wheel-sha256",
              "--source-manifest-digest", "--source-manifest", "--content-receipt", "--content-manifest",
              "--content-manifest-digest", "--content-readback-proof", "--content-pulled-dir", "--content-transcript"},
    "expose": {"--admission", "--pushed-digest", "--pushed-tag", "--pushed-size", "--registry",
               "--output-dir", "--local-inspect", "--pulled-inspect", "--pulled-bundle"},
    "show-handoff": {"--handoff"},
}


def _load_proxy_build_manifest(path: Path):
    """Load and strictly validate an explicit expected proxy-build identity.

    Pre-workflow authored JSON under review (explicitly unprotected,
    test-only): every manifest failure is a usage error (exit 2).
    """
    from .models import ProxyBuildIdentityV1
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(1024 * 1024 + 1)
    except OSError as error:
        raise ValueError('proxy build manifest is missing: %s' % error) from error
    if len(raw) > 1024 * 1024:
        raise ValueError('proxy build manifest exceeds 1 MiB')
    try:
        from .jsonutil import loads
        data = loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError('proxy build manifest is not valid JSON: %s' % error) from error
    except RecursionError as error:
        raise ValueError('proxy build manifest is not valid JSON: excessive nesting') from error
    try:
        return ProxyBuildIdentityV1.from_dict(data)
    except ValueError as error:
        raise ValueError('proxy build manifest is not a valid identity record: %s' % error) from error
    except RecursionError as error:
        raise ValueError('proxy build manifest is not a valid identity record: excessive nesting') from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="p11lab", description="PKCS#11 provider environment catalogue")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="list candidate environments and channel dispositions")
    listing.add_argument("--json", action="store_true")
    describe = commands.add_parser("describe", help="describe a selected environment/channel")
    describe.add_argument("id")
    describe.add_argument("--channel", required=True)
    commands.add_parser("validate", help="validate installed catalogue and declared assets")
    for name in ("resolve", "build"):
        command = commands.add_parser(name, help="acquire locked sources" if name == "resolve" else "build a locked runtime")
        command.add_argument("id")
        command.add_argument("--channel", required=True)
        command.add_argument("--output-dir", required=True, type=Path)
        if name == "build":
            command.add_argument("--role", default="runtime", choices=("runtime", "native"))
            command.add_argument("--debug-output-dir", type=Path, help="export a separate matched binary debug companion")
    round_command = commands.add_parser("round", help="validate protected round policy; diagnostic only")
    round_operations = round_command.add_subparsers(dest="round_operation", required=True)
    policy_check = round_operations.add_parser("validate-policy", help="validate policy without executing a round")
    policy_check.add_argument("--policy-root", type=Path, help="policy resource directory; defaults to installed policy")
    policy_check.add_argument("--tier", required=True, choices=("pr-smoke", "nightly", "release"))
    policy_check.add_argument("--output-json", type=Path, required=True)
    round_prepare = round_operations.add_parser("prepare", help="freeze opaque round inputs")
    round_prepare.add_argument("--context", type=Path, required=True)
    round_prepare.add_argument("--policy-root", type=Path)
    round_prepare.add_argument("--output-dir", type=Path, required=True)
    round_prepare.add_argument("--output-json", type=Path, required=True)
    round_execute = round_operations.add_parser("execute", help="execute one round lane")
    round_execute.add_argument("--context", type=Path, required=True)
    round_execute.add_argument("--policy-root", type=Path)
    round_execute.add_argument("--evaluator-root", type=Path, required=True)
    round_execute.add_argument("--output-dir", type=Path, required=True)
    round_execute.add_argument("--output-json", type=Path, required=True)
    round_execute.add_argument("--tier", choices=("pr-smoke", "nightly", "release"))
    round_execute.add_argument("--authority", type=Path)
    round_execute.add_argument("--baseline", type=Path)
    round_execute.add_argument("--candidate", type=Path)
    round_resolve = round_operations.add_parser("resolve-producer", help="resolve the producer run and stage the real github context")
    round_resolve.add_argument("--event-path", type=Path, required=True)
    round_resolve.add_argument("--profile", type=Path, required=True)
    round_resolve.add_argument("--framework-sha", required=True)
    round_resolve.add_argument("--tier", required=True, choices=("pr-smoke", "nightly", "release"))
    round_resolve.add_argument("--run-id", type=int, required=True)
    round_resolve.add_argument("--attempt", type=int, required=True)
    round_resolve.add_argument("--output-dir", type=Path, required=True)
    proxy_command = commands.add_parser("proxy", help="proxy round operations; gates, cells, aggregate")
    proxy_operations = proxy_command.add_subparsers(dest="proxy_operation", required=True)
    proxy_execute = proxy_operations.add_parser("execute", help="gate one caller-built proxy artifact")
    proxy_execute.add_argument("--artifact", required=True, type=Path)
    proxy_execute.add_argument("--run-id", required=True, type=int)
    proxy_execute.add_argument("--attempt", required=True, type=int)
    proxy_execute.add_argument("--output-dir", required=True, type=Path)
    proxy_execute.add_argument("--output-json", required=True, type=Path)
    proxy_execute_cell = proxy_operations.add_parser("execute-cell", help="run one named proxy cell from a staged payload")
    proxy_execute_cell.add_argument("--cell", required=True, choices=("direct", "accepted-proxy", "candidate-proxy"))
    proxy_execute_cell.add_argument("--artifact", required=True, type=Path)
    proxy_execute_cell.add_argument("--run-id", required=True, type=int)
    proxy_execute_cell.add_argument("--attempt", required=True, type=int)
    proxy_execute_cell.add_argument("--cell-payload", required=True, type=Path)
    proxy_execute_cell.add_argument("--output-dir", required=True, type=Path)
    proxy_execute_cell.add_argument("--output-json", required=True, type=Path)
    proxy_aggregate = proxy_operations.add_parser("aggregate", help="merge staged cell observations into the experiment verdict")
    proxy_aggregate.add_argument("--cells-dir", required=True, type=Path)
    proxy_aggregate.add_argument("--run-id", required=True, type=int)
    proxy_aggregate.add_argument("--attempt", required=True, type=int)
    proxy_aggregate.add_argument("--comparison", required=True, type=Path)
    proxy_aggregate.add_argument("--budgets", required=True, type=Path)
    proxy_aggregate.add_argument("--output-dir", required=True, type=Path)
    proxy_aggregate.add_argument("--output-json", required=True, type=Path)
    proxy_aggregate.add_argument("--cancelled", action="store_true")
    proxy_aggregate.add_argument("--uploads-incomplete", action="store_true")
    tools = commands.add_parser("tools", help="acquire fixed test-tool inputs; no build or admission")
    operations = tools.add_subparsers(dest="tool_operation", required=True)
    tool_resolve = operations.add_parser("resolve", help="acquire curated opaque consumer/checker/oracle input rosters")
    tool_resolve.add_argument("toolset", choices=("consumer", "checker", "oracle", "proxy"))
    tool_resolve.add_argument("--target", required=True)
    tool_resolve.add_argument("--output-dir", required=True, type=Path)
    install = commands.add_parser("install", help="install a verified local native candidate")
    install.add_argument("id")
    install.add_argument("--channel", required=True)
    install.add_argument("--artifact", required=True, type=Path)
    install.add_argument("--sha256", required=True)
    install.add_argument("--platform", required=True, choices=("linux/amd64", "windows/amd64"))
    install.add_argument("--prefix", required=True, type=Path)
    command = commands.add_parser("run", help="run an application in an owned provider instance")
    command.add_argument("id")
    command.add_argument("--channel", required=True)
    command.add_argument("--mode", choices=("direct", "proxy", "native"), default="direct")
    command.add_argument("--where", choices=("provider", "container", "host"))
    artifact_choice = command.add_mutually_exclusive_group(required=True)
    artifact_choice.add_argument("--artifact", help="exact local engine image ID or native archive")
    artifact_choice.add_argument("--installed-prefix", type=Path)
    command.add_argument("--sha256", help="required SHA256 for native archive input")
    command.add_argument("--control-dir", type=Path, help="native private control directory")
    command.add_argument("--consumer-image")
    command.add_argument("--client-artifact")
    command.add_argument("--client-sha256", help="required SHA256 for proxy native-client bundle input")
    command.add_argument("--proxy-build-manifest", type=Path, default=None,
                         help="explicit expected proxy-build identity JSON (proxy mode only)")
    command.add_argument("--platform", default="linux/amd64", choices=("linux/amd64", "windows/amd64"))
    command.add_argument("--input", action="append", default=[], metavar="NAME=VALUE")
    command.add_argument("--state-dir", type=Path, help="existing caller-owned persistent state directory")
    command.add_argument("--output-dir", required=True, type=Path)
    command.add_argument("--cwd", type=Path, default=Path.cwd())
    command.add_argument("--timeout", type=int, default=300,
                         help="lifecycle attempt budget in seconds, 1..86400 (24h ceiling)")
    image = commands.add_parser("image", help="local image validation")
    image.add_argument("operation", choices=("prepare-tools", "validate-local"))
    image.add_argument("--artifact", type=Path)
    image.add_argument("--policy", type=Path)
    image.add_argument("--output-dir", required=True, type=Path)
    custody = commands.add_parser("custody", help="prepare and replay exact qualification-only image custody")
    custody_operations = custody.add_subparsers(dest="custody_operation", required=True)
    for operation in ("component-sources", "prepare", "finalize"):
        selected = custody_operations.add_parser(operation)
        for option in ("environment", "channel", "registry", "source-manifest-digest", "content-manifest-digest"):
            selected.add_argument("--" + option, required=True)
        for option in ("artifact", "evidence-dir", "validation-dir", "validation-policy", "build-receipt", "sealed-dir",
                       "attestation-context", "bundle", "gh", "trusted-root", "output-dir"):
            selected.add_argument("--" + option, type=Path, required=True)
        if operation in ("prepare", "finalize"):
            selected.add_argument("--component-sources", type=Path, required=True)
        if operation == "finalize":
            selected.add_argument("--payload-dir", type=Path, required=True)
            selected.add_argument("--uploads", type=Path, required=True)
    acquire = custody_operations.add_parser("acquire")
    for option in ("environment", "channel"):
        acquire.add_argument("--" + option, required=True)
    for option in ("run-id", "attempt", "job-id", "control-id"):
        acquire.add_argument("--" + option, type=int, required=True)
    for option in ("gh", "trusted-root", "evaluator-root", "output-dir"):
        acquire.add_argument("--" + option, type=Path, required=True)
    evaluator = custody_operations.add_parser("prepare-evaluator")
    evaluator.add_argument("--output-dir", type=Path, required=True)
    qualify = custody_operations.add_parser("qualify")
    for option in ("payload-dir", "smoke-result", "openssl-result", "output-dir"):
        qualify.add_argument("--" + option, type=Path, required=True)
    baseline = custody_operations.add_parser("baseline-index")
    baseline.add_argument("--record", type=Path, required=True, action="append")
    baseline.add_argument("--output-dir", type=Path, required=True)
    # Delivery gates never publish; source-context/admit-source read public source bytes.
    publish = commands.add_parser("publish", help="source-first delivery gates")
    publish.add_argument("operation", choices=("controller-identity", "check-producer", "materialize-inventory", "prepare-source", "source-context", "admit-source", "seal-sources", "seal-native", "verify-readback", "verify-content-readback", "check-inputs", "admit", "expose", "show-handoff"))
    publish.add_argument("id", nargs="?")
    publish.add_argument("--channel")
    publish.add_argument("--target", default="debian13-amd64")
    publish.add_argument("--resolved-dir", type=Path)
    publish.add_argument("--sealed-receipt", type=Path)
    publish.add_argument("--sealed-manifest", type=Path)
    publish.add_argument("--pulled-dir", type=Path)
    publish.add_argument("--transcript", type=Path)
    publish.add_argument("--extract-dir", type=Path)
    publish.add_argument("--build-receipt", type=Path)
    publish.add_argument("--manifest", type=Path)
    publish.add_argument("--readback-proof", type=Path)
    publish.add_argument("--artifact-kind", choices=("docker-local", "bundle"))
    publish.add_argument("--artifact-reference")
    publish.add_argument("--artifact-digest")
    publish.add_argument("--platform", default="linux/amd64")
    publish.add_argument("--registry")
    publish.add_argument("--evidence-dir", type=Path)
    publish.add_argument("--handoff", type=Path)
    publish.add_argument("--output-dir", type=Path)
    publish.add_argument("--producer-wheel-sha256")
    publish.add_argument("--admission", type=Path)
    publish.add_argument("--pushed-digest")
    publish.add_argument("--pushed-tag")
    publish.add_argument("--pushed-size", type=int)
    publish.add_argument("--local-inspect", type=Path)
    publish.add_argument("--pulled-inspect", type=Path)
    publish.add_argument("--pulled-bundle", type=Path)
    publish.add_argument("--source-manifest-digest")
    publish.add_argument("--source-manifest", type=Path)
    publish.add_argument("--artifact", type=Path)
    publish.add_argument("--content-receipt", type=Path)
    publish.add_argument("--content-manifest", type=Path)
    publish.add_argument("--content-manifest-digest")
    publish.add_argument("--content-readback-proof", type=Path)
    publish.add_argument("--content-pulled-dir", type=Path)
    publish.add_argument("--content-transcript", type=Path)
    publish.add_argument("--inventory", type=Path)
    publish.add_argument("--validation-dir", type=Path)
    publish.add_argument("--validation-policy", type=Path)
    publish.add_argument("--sealed-dir", type=Path)
    publish.add_argument("--attestation-context", type=Path)
    publish.add_argument("--bundle", type=Path)
    publish.add_argument("--gh", type=Path)
    publish.add_argument("--trusted-root", type=Path)
    arguments = list(sys.argv[1:] if argv is None else argv)
    application_argv = []
    if arguments and arguments[0] == "run" and "--" in arguments:
        boundary = arguments.index("--")
        application_argv = arguments[boundary + 1:]
        arguments = arguments[:boundary]
    args = parser.parse_args(arguments)
    try:
        if args.command == "publish":
            from . import publish as delivery
            operation = args.operation
            allowed = _PUBLISH_OP_FLAGS[operation]
            for token in arguments:
                if token.startswith("--"):
                    flag = token.split("=", 1)[0]
                    if not any(option == flag or option.startswith(flag) for option in allowed):
                        raise ValueError(f"{flag} is not a publish {operation} option")
            if operation == 'controller-identity':
                from .delivery_authority import controller_identity
                print(json.dumps(controller_identity(), indent=2, sort_keys=True))
            elif operation == 'check-producer':
                import os
                from .delivery_authority import load_profile, _authenticate_live_run
                if not args.id or not args.channel:
                    raise ValueError('check-producer requires ID and channel')
                profile = load_profile(args.id, args.channel)
                _authenticate_live_run(profile, int(os.environ.get('GITHUB_RUN_ID', '0')),
                                       int(os.environ.get('GITHUB_RUN_ATTEMPT', '0')),
                                       os.environ.get('GH_TOKEN', ''))
                print(json.dumps({'status': 'active-producer-verified', 'source_admission': 'not-yet-verified'}))
            elif operation == 'materialize-inventory':
                from .delivery_authority import materialize_inventory
                from .jsonutil import loads
                from .models import ArtifactRef
                if not all((args.artifact, args.build_receipt, args.output_dir)):
                    raise ValueError('materialize-inventory requires artifact, build receipt and output')
                data = loads(args.artifact.read_bytes())
                result = materialize_inventory(artifact=ArtifactRef(**data.get('artifact', data)),
                                               build_receipt=args.build_receipt, output_dir=args.output_dir)
                print(json.dumps(result, indent=2, sort_keys=True))
            elif operation in {"prepare-source", "source-context", "admit-source"}:
                import os
                from .delivery_authority import prepare_source, prepare_context, admit_source, _read_bounded_file
                from .jsonutil import loads
                from .models import ArtifactRef
                if not all((args.id, args.channel, args.artifact, args.validation_dir, args.build_receipt,
                            args.sealed_dir, args.output_dir, args.validation_policy)):
                    raise ValueError("source delivery requires ID/channel, artifact, validation, build receipt, seal and output")
                data = loads(args.artifact.read_bytes())
                artifact = ArtifactRef(**data.get('artifact', data))
                identity = {'run_id': int(os.environ.get('GITHUB_RUN_ID', '0')),
                            'attempt': int(os.environ.get('GITHUB_RUN_ATTEMPT', '0')),
                            'token': os.environ.get('GH_TOKEN', '')}
                common = {'environment': args.id, 'channel': args.channel, 'artifact': artifact,
                          'validation_dir': args.validation_dir, 'build_receipt': args.build_receipt,
                          'sealed_dir': args.sealed_dir, 'output_dir': args.output_dir,
                          'validation_policy': loads(_read_bounded_file(args.validation_policy, 1024 * 1024)), **identity}
                if operation == 'prepare-source':
                    if not args.inventory:
                        raise ValueError('prepare-source requires --inventory')
                    result = prepare_source(inventory_path=args.inventory, **common)
                else:
                    if not all((args.evidence_dir, args.registry, args.source_manifest_digest, args.content_manifest_digest)):
                        raise ValueError('source context/admission requires evidence, repository and both source digests')
                    common.update(evidence_dir=args.evidence_dir, registry=args.registry,
                                  seal_digest=args.source_manifest_digest, content_digest=args.content_manifest_digest)
                    if operation == 'source-context':
                        result = prepare_context(**common)
                    else:
                        if not all((args.attestation_context, args.bundle, args.gh, args.trusted_root)):
                            raise ValueError('admit-source requires attested context, bundle, verifier and trusted root')
                        result = admit_source(context_path=args.attestation_context, bundle_path=args.bundle,
                                              executable=args.gh, trusted_root=args.trusted_root, **common)
                print(json.dumps(result, indent=2, sort_keys=True))
            elif operation == "seal-sources":
                if not args.id or not args.channel or not args.resolved_dir or not args.output_dir:
                    raise ValueError("seal-sources requires an ID, --channel, --resolved-dir and --output-dir")
                spec = load_environment(args.id, args.channel)
                resolved = json.loads((args.resolved_dir / "resolved-sources.json").read_text())
                print(json.dumps(delivery.seal_sources(spec, resolved, args.output_dir), indent=2, sort_keys=True))
            elif operation == "seal-native":
                if not args.id or not args.channel or not args.output_dir:
                    raise ValueError("seal-native requires an ID, --channel and --output-dir")
                from .catalog import load_native_target
                spec = load_native_target(args.id, args.channel, args.target)
                print(json.dumps(delivery.seal_native_source(spec, args.output_dir), indent=2, sort_keys=True))
            elif operation == "verify-readback":
                if not args.sealed_receipt or not args.pulled_dir or not args.transcript or not args.extract_dir:
                    raise ValueError("verify-readback requires --sealed-receipt, --pulled-dir, --transcript and --extract-dir")
                print(json.dumps(delivery.verify_readback(args.sealed_receipt, args.pulled_dir,
                    transcript_path=args.transcript, extract_dir=args.extract_dir,
                    source_manifest_path=args.source_manifest, source_manifest_digest=args.source_manifest_digest,
                    registry=args.registry), indent=2, sort_keys=True))
            elif operation == "verify-content-readback":
                if not all((args.content_receipt, args.pulled_dir, args.transcript, args.extract_dir,
                            args.source_manifest, args.source_manifest_digest, args.registry, args.artifact)):
                    raise ValueError("verify-content-readback requires --content-receipt, --pulled-dir, --transcript,"
                                     " --extract-dir, --source-manifest, --source-manifest-digest, --registry and --artifact")
                from .models import ArtifactRef
                value = json.loads(args.artifact.read_text())
                artifact = ArtifactRef(**value.get("artifact", value))
                print(json.dumps(delivery.verify_content_readback(args.content_receipt, args.pulled_dir,
                    transcript_path=args.transcript, extract_dir=args.extract_dir, artifact=artifact,
                    source_manifest_path=args.source_manifest, source_manifest_digest=args.source_manifest_digest,
                    registry=args.registry), indent=2, sort_keys=True))
            elif operation == "check-inputs":
                if not args.id or not args.channel or not args.sealed_manifest or not args.build_receipt:
                    raise ValueError("check-inputs requires an ID, --channel, --sealed-manifest and --build-receipt")
                sealed = json.loads(args.sealed_manifest.read_text())
                spec = load_environment(args.id, args.channel)
                manifest = json.loads(args.manifest.read_text()) if args.manifest else None
                print(json.dumps(delivery.check_input_match(sealed, args.build_receipt, spec, manifest=manifest),
                                 indent=2, sort_keys=True))
            elif operation == "admit":
                required = (args.id, args.channel, args.sealed_receipt, args.sealed_manifest, args.readback_proof,
                            args.build_receipt, args.artifact_kind, args.artifact_reference, args.artifact_digest,
                            args.registry, args.output_dir, args.producer_wheel_sha256,
                            args.source_manifest_digest, args.source_manifest)
                if not all(required):
                    raise ValueError("admit requires ID/channel, sealed receipt+manifest, readback proof, build receipt,"
                                     " artifact kind/reference/digest, registry, output dir, producer wheel identity"
                                     " and pushed source manifest digest+bytes")
                sealed = json.loads(args.sealed_manifest.read_text())
                if sealed.get("runtime_role") == "native":
                    from .catalog import load_native_target
                    spec = load_native_target(args.id, args.channel, sealed.get("target", args.target))
                else:
                    spec = load_environment(args.id, args.channel)
                manifest = json.loads(args.manifest.read_text()) if args.manifest else None
                result = delivery.admit(artifact_kind=args.artifact_kind, artifact_reference=args.artifact_reference,
                    artifact_digest=args.artifact_digest, platform=args.platform, sealed_receipt_path=args.sealed_receipt,
                    sealed_manifest=sealed, readback_proof=json.loads(args.readback_proof.read_text()),
                    build_receipt_path=args.build_receipt, spec=spec, registry=args.registry,
                    evidence_dir=args.evidence_dir, out_dir=args.output_dir,
                    producer={"p11lab_wheel_sha256": args.producer_wheel_sha256}, manifest=manifest,
                    source_manifest_digest=args.source_manifest_digest, source_manifest_path=args.source_manifest,
                    content_receipt_path=args.content_receipt, content_manifest_path=args.content_manifest,
                    content_manifest_digest=args.content_manifest_digest, content_readback_proof_path=args.content_readback_proof,
                    content_pulled_dir=args.content_pulled_dir, content_transcript_path=args.content_transcript)
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0 if result["status"] == "eligible" else 3
            elif operation == "expose":
                required = (args.admission, args.pushed_digest, args.pushed_tag, args.pushed_size,
                            args.registry, args.output_dir)
                if not all(required):
                    raise ValueError("expose requires --admission, --pushed-digest, --pushed-tag, --pushed-size,"
                                     " --registry and --output-dir, plus readback identity")
                result = delivery.expose(admission_path=args.admission, pushed_digest=args.pushed_digest,
                    pushed_tag=args.pushed_tag, pushed_size=args.pushed_size, local_inspect_path=args.local_inspect,
                    pulled_inspect_path=args.pulled_inspect, pulled_bundle_path=args.pulled_bundle,
                    registry=args.registry, out_dir=args.output_dir)
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0 if result["status"] == "eligible" else 3
            elif operation == "show-handoff":
                if not args.handoff:
                    raise ValueError("show-handoff requires --handoff")
                print(json.dumps(delivery.show_handoff(args.handoff), indent=2, sort_keys=True))
        elif args.command == "custody":
            import os
            from . import image_custody
            from .delivery_authority import _read_bounded_file
            from .jsonutil import loads
            from .models import ArtifactRef
            if args.custody_operation == 'prepare-evaluator':
                from .round_core import bootstrap
                from .round_core.tool_identity import verified_evaluator_identity
                lock_root = Path(bootstrap.__file__).parent.parent / 'data/rounds/evaluator'
                source = loads(_read_bounded_file(lock_root / 'source.json', 4 * 1024 * 1024))
                receipt = bootstrap.acquire_evaluator(source, lock_root, args.output_dir)
                bootstrap.verify_receipt(receipt, args.output_dir, lock_root)
                identity = verified_evaluator_identity(args.output_dir)
                result = {'status': 'strict-local-evaluator', 'root': str(args.output_dir.absolute()),
                          'receipt_sha256': identity['receipt_sha256'], 'identity_sha256': identity['identity_sha256'],
                          'qualification_status': 'not-performed'}
            elif args.custody_operation == 'acquire':
                from .custody_authority import verify_completed_finalization
                token = os.environ.get('GH_TOKEN', '')
                root = args.output_dir
                authority = verify_completed_finalization(environment=args.environment, channel=args.channel,
                    run_id=args.run_id, attempt=args.attempt, job_id=args.job_id, control_id=args.control_id,
                    token=token, executable=args.gh, trusted_root=args.trusted_root, output_dir=root / 'authority')
                payload = image_custody.acquire_custody_payload(authority, token=token, executable=args.gh,
                    trusted_root=args.trusted_root, output_dir=root / 'acquisition')
                loaded = image_custody.load_custody_image(authority, payload, token=token, executable=args.gh,
                    trusted_root=args.trusted_root, output_dir=root / 'load')
                result = image_custody.replay_custody_source(authority, payload, loaded, evaluator_root=args.evaluator_root,
                    token=token, executable=args.gh, trusted_root=args.trusted_root, output_dir=root / 'source-replay').as_dict()
            elif args.custody_operation == 'qualify':
                from .image_qualification import qualify_payload
                result = qualify_payload(payload_dir=args.payload_dir, smoke_result=args.smoke_result,
                    openssl_result=args.openssl_result, output_dir=args.output_dir)
            elif args.custody_operation == 'baseline-index':
                from .image_qualification import build_baseline_index, load_qualification_record
                from .models import canonical_json_bytes
                records = [load_qualification_record(loads(_read_bounded_file(path, 1024 * 1024)))
                           for path in args.record]
                result = build_baseline_index(records)
                args.output_dir.mkdir(parents=True, exist_ok=False)
                (args.output_dir / 'baseline-index.json').write_bytes(canonical_json_bytes(result))
            else:
                artifact_value = loads(_read_bounded_file(args.artifact, 4 * 1024 * 1024))
                artifact = ArtifactRef(**artifact_value.get('artifact', artifact_value))
                common = {'environment': args.environment, 'channel': args.channel, 'artifact': artifact,
                    'evidence_dir': args.evidence_dir, 'validation_dir': args.validation_dir, 'build_receipt': args.build_receipt,
                    'sealed_dir': args.sealed_dir, 'registry': args.registry, 'seal_digest': args.source_manifest_digest,
                    'content_digest': args.content_manifest_digest, 'context_path': args.attestation_context,
                    'bundle_path': args.bundle, 'executable': args.gh, 'trusted_root': args.trusted_root,
                    'run_id': int(os.environ.get('GITHUB_RUN_ID', '0')), 'attempt': int(os.environ.get('GITHUB_RUN_ATTEMPT', '0')),
                    'token': os.environ.get('GH_TOKEN', ''),
                    'validation_policy': loads(_read_bounded_file(args.validation_policy, 1024 * 1024))}
                if args.custody_operation == 'component-sources':
                    result = image_custody.materialize_custody_components(output_dir=args.output_dir, **common)
                else:
                    common['component_sources'] = loads(_read_bounded_file(args.component_sources, 2 * 1024 * 1024))
                    if args.custody_operation == 'prepare':
                        result = image_custody.prepare_custody_payload(output_dir=args.output_dir, **common).as_dict()
                    else:
                        uploads = loads(_read_bounded_file(args.uploads, 2 * 1024 * 1024))
                        result = image_custody.finalize_custody_payload(payload_dir=args.payload_dir,
                            uploads=uploads, output_dir=args.output_dir, **common)
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command == "image":
            if args.operation == 'prepare-tools':
                from .delivery_authority import prepare_validation_tools
                if args.artifact or args.policy:
                    raise ValueError('prepare-tools does not accept artifact or policy')
                print(json.dumps(prepare_validation_tools(args.output_dir), indent=2, sort_keys=True))
                return 0
            from .image_validation import validate_image
            from .jsonutil import loads
            from .models import ArtifactRef
            if not args.artifact or not args.policy:
                raise ValueError('validate-local requires artifact and policy')
            data = loads(args.artifact.read_bytes())
            result = validate_image(ArtifactRef(**data.get('artifact', data)), loads(args.policy.read_bytes()), args.output_dir)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result['status'] == 'observations-complete' else 3
        elif args.command == "install":
            from .native import NATIVE_CONFIGURATION, native_lifecycle
            from .models import ArtifactRef
            install_native, _, _ = native_lifecycle(args.id)
            artifact = ArtifactRef('bundle', str(args.artifact.resolve()), args.sha256, args.platform)
            installed = install_native(artifact, args.prefix, environment=args.id, channel=args.channel)
            print(json.dumps({'artifact': asdict(installed.artifact), 'prefix': str(installed.prefix),
                              'module': str(installed.prefix / 'payload' / installed.manifest['module']),
                              'configuration': NATIVE_CONFIGURATION[args.id],
                              'receipt_path': str(installed.receipt_path)}, indent=2))
        elif args.command == "run":
            from .models import ArtifactRef, RunSpec
            from .run import run_application
            def artifact(reference):
                return ArtifactRef("docker-local", reference, reference.removeprefix("sha256:"), args.platform) if reference else None
            if args.installed_prefix is not None:
                if args.mode != 'native' or args.sha256:
                    raise ValueError('installed-prefix requires native mode without archive SHA256')
                from .bundle import read_installation
                selected_artifact = read_installation(args.installed_prefix, environment=args.id,
                    channel=args.channel, platform=args.platform).artifact
            elif args.mode == 'native':
                if not args.sha256:
                    raise ValueError('native archive input requires --sha256')
                selected_artifact = ArtifactRef('bundle', str(Path(args.artifact).resolve()), args.sha256, args.platform)
            else:
                if args.sha256 or args.control_dir:
                    raise ValueError('native archive/control options require native mode')
                selected_artifact = artifact(args.artifact)
            if args.client_sha256 and (args.mode != 'proxy' or not args.client_artifact):
                raise ValueError('--client-sha256 requires proxy mode with --client-artifact')
            if args.mode == 'proxy' and args.client_artifact:
                if not args.client_sha256:
                    raise ValueError('proxy client bundle requires --client-sha256')
                selected_client = ArtifactRef('bundle', str(Path(args.client_artifact).resolve()),
                                              args.client_sha256, args.platform)
            else:
                selected_client = artifact(args.client_artifact)
            inputs = {}
            for item in args.input:
                if "=" not in item:
                    raise ValueError("input requires NAME=VALUE")
                key, value = item.split("=", 1)
                if key in inputs:
                    raise ValueError("duplicate input name")
                inputs[key] = value
            if args.state_dir is not None:
                if "P11LAB_STATE_DIR" in inputs:
                    raise ValueError("duplicate state directory input")
                inputs["P11LAB_STATE_DIR"] = str(args.state_dir)
            if args.control_dir is not None:
                if 'P11LAB_CONTROL_DIR' in inputs:
                    raise ValueError('duplicate control directory input')
                inputs['P11LAB_CONTROL_DIR'] = str(args.control_dir)
            if not 1 <= args.timeout <= 86400:
                raise ValueError('--timeout must be 1..86400 seconds')
            expected_proxy_identity = None
            if args.proxy_build_manifest is not None:
                if args.mode != 'proxy':
                    raise ValueError('--proxy-build-manifest requires proxy mode')
                expected_proxy_identity = _load_proxy_build_manifest(args.proxy_build_manifest)
            result = run_application(RunSpec(args.id, args.channel, args.mode, selected_artifact,
                args.where or {"direct": "provider", "proxy": "host", "native": "host"}[args.mode],
                artifact(args.consumer_image), selected_client, tuple(application_argv), inputs,
                args.output_dir, args.cwd, args.timeout, args.installed_prefix,
                expected_proxy_identity=expected_proxy_identity))
            record = asdict(result)
            if args.mode == 'native':
                execution = json.loads(result.receipt_path.read_text())['execution']
                record.update(module=execution['module'])
                if 'configuration' in execution:
                    record.update(configuration=execution['configuration'])
            print(json.dumps(record, default=str, indent=2, sort_keys=True))
            return result.exit_code
        elif args.command == "round":
            if args.round_operation == "validate-policy":
                from .rounds import validate_policy
                result = validate_policy(args.policy_root, args.tier, args.output_json)
                print(json.dumps(result, indent=2, sort_keys=True))
            elif args.round_operation == "prepare":
                from .rounds import prepare
                result = prepare(args.context, args.policy_root, args.output_dir, args.output_json)
                print(json.dumps(result, indent=2, sort_keys=True))
            elif args.round_operation == "resolve-producer":
                from .round_core.producer_resolution import ProducerResolutionRefused, run_resolve_producer
                try:
                    result = run_resolve_producer(event_path=args.event_path, profile_path=args.profile,
                                                  framework_sha=args.framework_sha, tier=args.tier,
                                                  consumer_run_id=args.run_id, consumer_attempt=args.attempt,
                                                  output_dir=args.output_dir)
                except ProducerResolutionRefused as error:
                    print(str(error), file=sys.stderr)
                    return 3
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                from .rounds import execute
                result = execute(args.context, args.policy_root, args.evaluator_root,
                                 args.output_dir, args.output_json, args.tier,
                                 authority=args.authority, baseline=args.baseline,
                                 candidate=args.candidate)
                print(json.dumps(result, indent=2, sort_keys=True))
                return result["exit_code"]
        elif args.command == "proxy":
            if args.proxy_operation == "execute":
                from .round_core.proxy_execute import execute_proxy
                result = execute_proxy(args.artifact, run_id=args.run_id,
                                       run_attempt=args.attempt,
                                       output_dir=args.output_dir,
                                       output_json=args.output_json)
            elif args.proxy_operation == "execute-cell":
                from .round_core.proxy_execute import execute_proxy_cell_staged
                result = execute_proxy_cell_staged(
                    args.artifact, cell=args.cell, run_id=args.run_id,
                    run_attempt=args.attempt,
                    cell_payload_path=args.cell_payload,
                    output_dir=args.output_dir, output_json=args.output_json)
            else:
                from .round_core.proxy_execute import (
                    aggregate_proxy_experiment_staged)
                result = aggregate_proxy_experiment_staged(
                    args.cells_dir, run_id=args.run_id,
                    run_attempt=args.attempt,
                    comparison_path=args.comparison,
                    budgets_path=args.budgets,
                    uploads_complete=not args.uploads_incomplete,
                    cancelled=args.cancelled, output_dir=args.output_dir,
                    output_json=args.output_json)
            print(json.dumps(result, indent=2, sort_keys=True))
            return result["exit_code"]
        elif args.command == "tools":
            from .tool_inputs import resolve_tool_inputs
            result = resolve_tool_inputs(args.toolset, target=args.target, output_dir=args.output_dir)
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command in {"resolve", "build"}:
            spec = load_environment(args.id, args.channel)
            if args.command == "resolve":
                from .sources import resolve_sources
                result = resolve_sources(spec, output_dir=args.output_dir)
            else:
                from .build import build_artifact
                if args.role == 'native' and args.debug_output_dir is not None:
                    raise ValueError('native build does not export container debug companions')
                artifact = build_artifact(spec, args.role, args.output_dir)
                result = asdict(artifact)
                if args.debug_output_dir is not None:
                    from .debug import export_debug_companion
                    export_debug_companion(spec, artifact, args.output_dir, args.debug_output_dir)
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command == "describe":
            spec = load_environment(args.id, args.channel)
            spec['delivery_formats'] = {
                'container': spec['channel_spec']['status'],
                'native': spec.get('native_targets', {'status': 'not-packaged', 'reason': 'No native packaging target is declared.'}),
            }
            print(json.dumps(spec, indent=2, sort_keys=True))
        else:
            environments = list_environments()
            if args.command == "validate":
                from .tool_inputs import load_tool_input_lock
                validate_tools(json.loads(package_data("tools.json").read_text(encoding="utf-8")))
                load_tool_input_lock("consumer", target="debian13-amd64")
                print(f"Validated {len(environments)} candidate environments; distribution remains evidence-gated.")
            elif args.json:
                print(json.dumps(environments, indent=2, sort_keys=True))
            else:
                for spec in environments:
                    channels = ", ".join(f"{name}={value['status']}" for name, value in spec["channels"].items())
                    print(f"{spec['id']}: {channels}; distribution={spec['distribution']['status']}")
    except (CatalogError, OSError, ValueError) as error:
        print(f"p11lab: {error}", file=sys.stderr)
        return 2
    return 0
