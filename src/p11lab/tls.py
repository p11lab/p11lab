"""Per-run mTLS material for the pinned proxy transport.

create_test_tls generates a disposable evaluation CA, server leaf and client
leaf with OpenSSL Ed25519 keys following the public transport contract, then
verifies SAN/EKU/chain before returning paths. Only server leaf/key+CA reach
the daemon and only client leaf/key+CA reach the consumer; the CA private key
never enters either mount set.
"""
from pathlib import Path
import copy
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess

from .models import ProxyBuildIdentityV1

CLIENT_ENV_VARS = ('PKCS11_PROXY_TLS_CA_CERT', 'PKCS11_PROXY_TLS_CLIENT_CERT',
                   'PKCS11_PROXY_TLS_CLIENT_KEY')
ENDPOINT_VAR = 'PKCS11_PROXY_ENDPOINT'
CONNECT_TIMEOUT_VAR = 'PKCS11_PROXY_CONNECT_TIMEOUT'
# Exact per-run shim transport set the runner emits and checker grandchildren
# accept; no partial set is ever valid. Single source so producer (run) and
# consumer (checker) cannot drift apart.
TRANSPORT_ENV_VARS = (ENDPOINT_VAR, *CLIENT_ENV_VARS, CONNECT_TIMEOUT_VAR)

# Pinned public proxy inputs. Derivative build.json and native-client manifests
# record these component identities; a proxy component change requires new
# derivative/client identities and refuses to run against old ones.
PROXY_SOURCE_REVISION = 'a348a5f59b535b1ca309ea9f0a722e3bec692f72'
PROXY_CARGO_LOCK_SHA256 = '39ae3c64cff6fddd4f2d621f8e26139005936b22e6d7652b2ed14e4921fa5979'

_DNS = re.compile(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\Z')


def _openssl(*args, **kwargs):
    try:
        return subprocess.run(['openssl', *args], capture_output=True, text=True,
                              timeout=60, **kwargs)
    except OSError as error:
        raise ValueError('openssl execution failed') from error


def openssl_version() -> str:
    executable = shutil.which('openssl')
    if executable is None:
        raise ValueError('openssl is required for proxy test TLS')
    result = _openssl('version')
    if result.returncode:
        raise ValueError('openssl version query failed')
    return result.stdout.strip()


def _check_name(name):
    if not isinstance(name, str) or not name or len(name) > 253 or any(c in name for c in '\0\n\r'):
        raise ValueError('server name must be a single-line DNS name or IP literal')
    try:
        ipaddress.ip_address(name)
        return 'IP:' + name
    except ValueError:
        pass
    if not _DNS.fullmatch(name):
        raise ValueError('server name is not a DNS name or IP literal: ' + name)
    return 'DNS:' + name


def _extensions(path):
    result = _openssl('x509', '-in', str(path), '-noout',
                      '-ext', 'subjectAltName,extendedKeyUsage,basicConstraints,keyUsage')
    if result.returncode:
        raise ValueError('certificate extension inspection failed: ' + path.name)
    return result.stdout


def verify_server_identity(*, server_cert: Path, ca_cert: Path, expected_names: tuple[str, ...]) -> dict:
    """Verify chain plus SAN/EKU/keyUsage against the names the consumer verifies."""
    if not expected_names:
        raise ValueError('server identity requires expected names')
    for name in expected_names:
        _check_name(name)
    result = _openssl('verify', '-CAfile', str(ca_cert), str(server_cert))
    if result.returncode or not result.stdout.strip().endswith('OK'):
        raise ValueError('server certificate chain verification failed')
    text = _extensions(server_cert)
    if 'CA:FALSE' not in text or 'Digital Signature' not in text or 'TLS Web Server Authentication' not in text:
        raise ValueError('server leaf requires CA:FALSE, digitalSignature and serverAuth')
    sans = set(re.findall(r'(?:DNS|IP Address):([^,\s]+)', text))
    missing = [name for name in expected_names if name not in sans]
    if missing:
        raise ValueError('server certificate SAN does not cover: ' + ', '.join(missing))
    return {'chain': result.stdout.strip(), 'sans': sorted(sans)}


def verify_client_identity(*, client_cert: Path, ca_cert: Path) -> dict:
    result = _openssl('verify', '-CAfile', str(ca_cert), str(client_cert))
    if result.returncode or not result.stdout.strip().endswith('OK'):
        raise ValueError('client certificate chain verification failed')
    subject = _openssl('x509', '-in', str(client_cert), '-noout', '-subject')
    if subject.returncode or subject.stdout.strip() in {'subject=', 'subject= '}:
        raise ValueError('client certificate requires a nonempty subject')
    text = _extensions(client_cert)
    if 'CA:FALSE' not in text or 'Digital Signature' not in text or 'TLS Web Client Authentication' not in text:
        raise ValueError('client leaf requires CA:FALSE, digitalSignature and clientAuth')
    return {'chain': result.stdout.strip(), 'subject': subject.stdout.strip()}


def create_test_tls(output_dir: Path, server_names: tuple[str, ...]) -> dict:
    """Generate and verify per-run proxy TLS material in a fresh directory."""
    if not isinstance(server_names, tuple) or not server_names:
        raise ValueError('server identity requires a nonempty tuple of names')
    sans = [_check_name(name) for name in server_names]
    output = Path(output_dir)
    if output.exists():
        raise ValueError('TLS output directory must be fresh')
    version = openssl_version()
    output.mkdir(parents=True, mode=0o700)
    ca_key, ca_crt = output / 'ca.key', output / 'ca.crt'
    server_key, server_csr, server_crt = output / 'server.key', output / 'server.csr', output / 'server.crt'
    client_key, client_csr, client_crt = output / 'client.key', output / 'client.csr', output / 'client.crt'
    steps = [
        ('req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '30',
         '-keyout', str(ca_key), '-out', str(ca_crt), '-subj', '/CN=P11Lab evaluation CA',
         '-addext', 'basicConstraints=critical,CA:TRUE',
         '-addext', 'keyUsage=critical,keyCertSign,cRLSign'),
        ('req', '-newkey', 'ed25519', '-nodes', '-keyout', str(server_key), '-out', str(server_csr),
         '-subj', '/CN=' + server_names[0],
         '-addext', 'subjectAltName=' + ','.join(sans),
         '-addext', 'basicConstraints=critical,CA:FALSE',
         '-addext', 'keyUsage=critical,digitalSignature',
         '-addext', 'extendedKeyUsage=serverAuth'),
        ('x509', '-req', '-in', str(server_csr), '-CA', str(ca_crt), '-CAkey', str(ca_key),
         '-CAcreateserial', '-days', '30', '-copy_extensions', 'copy', '-out', str(server_crt)),
        ('req', '-newkey', 'ed25519', '-nodes', '-keyout', str(client_key), '-out', str(client_csr),
         '-subj', '/CN=p11lab-client',
         '-addext', 'basicConstraints=critical,CA:FALSE',
         '-addext', 'keyUsage=critical,digitalSignature',
         '-addext', 'extendedKeyUsage=clientAuth'),
        ('x509', '-req', '-in', str(client_csr), '-CA', str(ca_crt), '-CAkey', str(ca_key),
         '-CAcreateserial', '-days', '30', '-copy_extensions', 'copy', '-out', str(client_crt)),
    ]
    try:
        for args in steps:
            result = _openssl(*args)
            if result.returncode:
                raise ValueError('openssl certificate generation failed: ' + args[0])
        for key in (ca_key, server_key, client_key):
            key.chmod(0o600)
        # Certificates carry no secrets but get explicit modes so acceptance
        # never depends on the ambient umask.
        for cert in (ca_crt, server_crt, client_crt):
            cert.chmod(0o644)
        (output / 'ca.srl').unlink(missing_ok=True)
        server_csr.unlink()
        client_csr.unlink()
        server_evidence = verify_server_identity(server_cert=server_crt, ca_cert=ca_crt,
                                                 expected_names=server_names)
        client_evidence = verify_client_identity(client_cert=client_crt, ca_cert=ca_crt)
    except (ValueError, OSError):
        shutil.rmtree(output, ignore_errors=True)
        raise
    material = {'dir': str(output), 'openssl_version': version,
                'server_names': list(server_names),
                'ca_cert': str(ca_crt), 'ca_key': str(ca_key),
                'server_cert': str(server_crt), 'server_key': str(server_key),
                'client_cert': str(client_crt), 'client_key': str(client_key),
                'evidence': {'server': server_evidence, 'client': client_evidence}}
    check_tls_file_permissions({'ca_cert': ca_crt, 'server_cert': server_crt,
                                'server_key': server_key, 'client_cert': client_crt,
                                'client_key': client_key}, owner_uid=os.geteuid())
    return material


def daemon_mount_files(material: dict) -> dict:
    """Only server leaf/key+CA reach the daemon; never the CA private key."""
    return {'ca_cert': material['ca_cert'], 'server_cert': material['server_cert'],
            'server_key': material['server_key']}


def consumer_mount_files(material: dict) -> dict:
    """Only client leaf/key+CA reach the consumer; never the CA private key."""
    return {'ca_cert': material['ca_cert'], 'client_cert': material['client_cert'],
            'client_key': material['client_key']}


def check_tls_file_permissions(paths: dict[str, Path], *, owner_uid: int) -> None:
    """Reject missing, unowned or unsafely permissioned TLS files before mounting."""
    if not isinstance(owner_uid, int) or owner_uid < 0:
        raise ValueError('TLS ownership check requires an owner UID')
    for role, path in paths.items():
        candidate = Path(path)
        try:
            info = candidate.stat()
        except OSError:
            raise ValueError('TLS file is missing: ' + role) from None
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError('TLS file must be a regular file: ' + role)
        if info.st_uid != owner_uid:
            raise ValueError('TLS file ownership mismatch: ' + role)
        mode = info.st_mode & 0o777
        if role.endswith('_key'):
            if mode & 0o077:
                raise ValueError('TLS private key must have no group/other permissions: ' + role)
        elif mode & 0o002:
            raise ValueError('TLS certificate must not be world-writable: ' + role)


def split_tls_env(mapping: dict[str, str]) -> dict[str, str]:
    """Extract a complete client TLS triple; partial configuration fails."""
    present = {name: mapping[name] for name in CLIENT_ENV_VARS if mapping.get(name)}
    if present and set(present) != set(CLIENT_ENV_VARS):
        missing = [name for name in CLIENT_ENV_VARS if name not in present]
        raise ValueError('partial TLS configuration is refused; missing: ' + ', '.join(missing))
    return present


def build_consumer_env(*, endpoint: str, ca_cert: str, client_cert: str, client_key: str) -> dict[str, str]:
    """Assemble the exact shim/CLI TLS environment; no partial triple is emitted."""
    values = {ENDPOINT_VAR: endpoint, CLIENT_ENV_VARS[0]: ca_cert,
              CLIENT_ENV_VARS[1]: client_cert, CLIENT_ENV_VARS[2]: client_key}
    if (not endpoint.startswith('https://') or
            any(not isinstance(value, str) or not value or any(c in value for c in '\0\n\r')
                for value in values.values())):
        raise ValueError('proxy consumer requires an https endpoint and complete TLS paths')
    return values


def cert_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# Pinned default proxy-build identity (plan M07.2). Values below describe the
# live real-a348 producer observation and are embedded with provenance; the
# constructor returns a fresh validated record per call so nested containers
# are never shared mutable state.
# Provenance:
# - source/lock/products/ABI: D/M07-proxy-producer-artifacts/live-proof-4.json
#   sha256 adaafdd7e436f0e04fd18f4d8c88ed40b1f02207207c48fdfa73b959447d5348
# - selection/toolchain/staging/spec/caller: retained real-a348
#   proxy-producer-observation.json
#   sha256 8620dfe42c393bde7b9968de912fc2661cb6a0a3add3fcee160b6e1d5b0cd58b
# - version_requirements/symbol_versions: parsed from the retained real
#   products (hashes verified first) with the current producer ELF parser
#   (22/21/21 requirements, 115/106/97 associations)
# - build-selection/target/features/profile/flags/args:
#   src/p11lab/data/tool-inputs/proxy/build-selection-v1.json
#   sha256 9667b71f83b65061f5b5edb5d68d42c724df7c70daf691bac697222e873e1932
# - F18 digests: src/p11lab/data/rounds/proxy-producer-v1.json
#   sha256 522b8a04812040c5d83aa7f94176afac75f14a13a43a294c33a1948389dc4f17
# - F11 record digests: tool-inputs rust/protoc/crates v1 JSON bytes
#   (cd0da947.../2b99d40e.../7e236993...); version strings are the observed
#   toolchain-canary strings from M07-identity-brief.md
# - F23: sha256(render_proxy_toml(module_path='<provider-module>'))
# - F24: src/p11lab/data/runtime/proxy-entrypoint.sh bytes (byte-stable slice)
# - F26: digest-of-digests over observation build_view/staging/spec digests
#   plus the toolchain manifest; F27 verbatim local caller; F28 unselected
#   (naming binds at selection time, receipt chain is a later slice).
_PINNED_DEFAULT_IDENTITY = {
    'schema': 'p11lab.proxy-build-identity.v1',
    'schema_version': 1,
    'origin': 'installed-default',
    'source_commit': 'a348a5f59b535b1ca309ea9f0a722e3bec692f72',
    'source_tree': '436915ad13986c6770de4d190684276bb71de0c8',
    'source_archive': {'sha256': '4446dfd31ada97c7249cf0044e43ae2b77fb69960c9bee265f9acb6ea77194cc', 'size': 2124074, 'prefix': 'pkcs11-proxy-ng-a348a5f59b535b1ca309ea9f0a722e3bec692f72'},
    'source_members': {'count': 689, 'canonical_roster_sha256': 'f2965bf8a12881f8ca6433b5c42b7339aafd19fb27851e7a625904c615f8c6d2'},
    'content_seal': None,
    'cargo_lock_sha256': '39ae3c64cff6fddd4f2d621f8e26139005936b22e6d7652b2ed14e4921fa5979',
    'vendor_packages': [
        {'identity': 'adler2-2.0.1', 'sha256': '320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa'},
        {'identity': 'aho-corasick-1.1.4', 'sha256': 'ddd31a130427c27518df266943a5308ed92d4b226cc639f5a8f1002816174301'},
        {'identity': 'alloca-0.4.0', 'sha256': 'e5a7d05ea6aea7e9e64d25b9156ba2fee3fdd659e34e41063cd2fc7cd020d7f4'},
        {'identity': 'anes-0.1.6', 'sha256': '4b46cbb362ab8752921c97e041f5e366ee6297bd428a31275b9fcf1e380f7299'},
        {'identity': 'anstream-1.0.0', 'sha256': '824a212faf96e9acacdbd09febd34438f8f711fb84e09a8916013cd7815ca28d'},
        {'identity': 'anstyle-1.0.13', 'sha256': '5192cca8006f1fd4f7237516f40fa183bb07f8fbdfedaa0036de5ea9b0b45e78'},
        {'identity': 'anstyle-parse-1.0.0', 'sha256': '52ce7f38b242319f7cabaa6813055467063ecdc9d355bbb4ce0c68908cd8130e'},
        {'identity': 'anstyle-query-1.1.5', 'sha256': '40c48f72fd53cd289104fc64099abca73db4166ad86ea0b4341abe65af83dadc'},
        {'identity': 'anstyle-wincon-3.0.11', 'sha256': '291e6a250ff86cd4a820112fb8898808a366d8f9f58ce16d1f538353ad55747d'},
        {'identity': 'anyhow-1.0.103', 'sha256': '2a4385e2e34eb35d6b3efe798b9eb88096925d87726c0798709bf56d9ed84af3'},
        {'identity': 'asn1-rs-0.7.1', 'sha256': '56624a96882bb8c26d61312ae18cb45868e5a9992ea73c58e45c3101e56a1e60'},
        {'identity': 'asn1-rs-derive-0.6.0', 'sha256': '3109e49b1e4909e9db6515a30c633684d68cdeaa252f215214cb4fa1a5bfee2c'},
        {'identity': 'asn1-rs-impl-0.2.0', 'sha256': '7b18050c2cd6fe86c3a76584ef5e0baf286d038cda203eb6223df2cc413565f7'},
        {'identity': 'async-trait-0.1.89', 'sha256': '9035ad2d096bed7955a320ee7e2230574d28fd3c3a0f186cbea1ff3c7eed5dbb'},
        {'identity': 'atomic-waker-1.1.2', 'sha256': '1505bd5d3d116872e7271a6d4e16d81d0c8570876c8de68093a09ac269d8aac0'},
        {'identity': 'autocfg-1.5.0', 'sha256': 'c08606f8c3cbf4ce6ec8e28fb0014a2c086708fe954eaa885384a6165172e7e8'},
        {'identity': 'axum-0.8.9', 'sha256': '31b698c5f9a010f6573133b09e0de5408834d0c82f8d7475a89fc1867a71cd90'},
        {'identity': 'axum-core-0.5.6', 'sha256': '08c78f31d7b1291f7ee735c1c6780ccde7785daae9a9206026862dab7d8792d1'},
        {'identity': 'base64-0.21.7', 'sha256': '9d297deb1925b89f2ccc13d7635fa0714f12c87adce1c75356b39ca9b7178567'},
        {'identity': 'base64-0.22.1', 'sha256': '72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6'},
        {'identity': 'base64ct-1.8.3', 'sha256': '2af50177e190e07a26ab74f8b1efbfe2ef87da2116221318cb1c2e82baf7de06'},
        {'identity': 'bitflags-2.11.0', 'sha256': '843867be96c8daad0d758b57df9392b6d8d271134fce549de6ce169ff98a92af'},
        {'identity': 'block-buffer-0.10.4', 'sha256': '3078c7629b62d3f0439517fa394996acacc5cbc91c5a20d8c658e77abd503a71'},
        {'identity': 'bumpalo-3.20.2', 'sha256': '5d20789868f4b01b2f2caec9f5c4e0213b41e3e5702a50157d699ae31ced2fcb'},
        {'identity': 'byteorder-1.5.0', 'sha256': '1fd0f2584146f6f2ef48085050886acf353beff7305ebd1ae69500e27c67f64b'},
        {'identity': 'bytes-1.11.1', 'sha256': '1e748733b7cbc798e1434b6ac524f0c1ff2ab456fe201501e6497c8417a4fc33'},
        {'identity': 'cast-0.3.0', 'sha256': '37b2a672a2cb129a2e41c10b1224bb368f9f37a2b16b612598138befd7b37eb5'},
        {'identity': 'cc-1.2.56', 'sha256': 'aebf35691d1bfb0ac386a69bac2fde4dd276fb618cf8bf4f5318fe285e821bb2'},
        {'identity': 'cfg-if-1.0.4', 'sha256': '9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801'},
        {'identity': 'cfg_aliases-0.2.1', 'sha256': '613afe47fcd5fac7ccf1db93babcb082c5994d996f20b8b159f2ad1658eb5724'},
        {'identity': 'ciborium-0.2.2', 'sha256': '42e69ffd6f0917f5c029256a24d0161db17cea3997d185db0d35926308770f0e'},
        {'identity': 'ciborium-io-0.2.2', 'sha256': '05afea1e0a06c9be33d539b876f1ce3692f4afea2cb41f740e7743225ed1c757'},
        {'identity': 'ciborium-ll-0.2.2', 'sha256': '57663b653d948a338bfb3eeba9bb2fd5fcfaecb9e199e87e1eda4d9e8b240fd9'},
        {'identity': 'clap-4.6.0', 'sha256': 'b193af5b67834b676abd72466a96c1024e6a6ad978a1f484bd90b85c94041351'},
        {'identity': 'clap_builder-4.6.0', 'sha256': '714a53001bf66416adb0e2ef5ac857140e7dc3a0c48fb28b2f10762fc4b5069f'},
        {'identity': 'clap_derive-4.6.0', 'sha256': '1110bd8a634a1ab8cb04345d8d878267d57c3cf1b38d91b71af6686408bbca6a'},
        {'identity': 'clap_lex-1.1.0', 'sha256': 'c8d4a3bb8b1e0c1050499d1815f5ab16d04f0959b233085fb31653fbfc9d98f9'},
        {'identity': 'colorchoice-1.0.4', 'sha256': 'b05b61dc5112cbb17e4b6cd61790d9845d13888356391624cbe7e41efeac1e75'},
        {'identity': 'const-oid-0.9.6', 'sha256': 'c2459377285ad874054d797f3ccebf984978aa39129f6eafde5cdc8315b612f8'},
        {'identity': 'cpufeatures-0.2.17', 'sha256': '59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280'},
        {'identity': 'crc32fast-1.5.0', 'sha256': '9481c1c90cbf2ac953f07c8d4a58aa3945c425b7185c9154d67a65e4230da511'},
        {'identity': 'criterion-0.8.2', 'sha256': '950046b2aa2492f9a536f5f4f9a3de7b9e2476e575e05bd6c333371add4d98f3'},
        {'identity': 'criterion-plot-0.8.2', 'sha256': 'd8d80a2f4f5b554395e47b5d8305bc3d27813bacb73493eb1001e8f76dae29ea'},
        {'identity': 'crossbeam-channel-0.5.15', 'sha256': '82b8f8f868b36967f9606790d1903570de9ceaf870a7bf9fbbd3016d636a2cb2'},
        {'identity': 'crossbeam-deque-0.8.6', 'sha256': '9dd111b7b7f7d55b72c0a6ae361660ee5853c9af73f70c3c2ef6858b950e2e51'},
        {'identity': 'crossbeam-epoch-0.9.20', 'sha256': '2d6914041f254d6e9176c01941b21115dcfb7089e55135a35411081bd106ef3f'},
        {'identity': 'crossbeam-utils-0.8.22', 'sha256': '61803da095bee82a81bb1a452ecc25d3b2f1416d1897eb86430c6159ef717c17'},
        {'identity': 'crunchy-0.2.4', 'sha256': '460fbee9c2c2f33933d720630a6a0bac33ba7053db5344fac858d4b8952d77d5'},
        {'identity': 'crypto-common-0.1.7', 'sha256': '78c8292055d1c1df0cce5d180393dc8cce0abec0a7102adb6c7b1eef6016d60a'},
        {'identity': 'cryptoki-sys-0.5.0', 'sha256': 'f1fd850498411e4057f1cba79e6e2bc7cbe960544c1046ab46d4685c403a1121'},
        {'identity': 'curve25519-dalek-4.1.3', 'sha256': '97fb8b7c4503de7d6ae7b42ab72a5a59857b4c937ec27a3d4539dba95b5ab2be'},
        {'identity': 'curve25519-dalek-derive-0.1.1', 'sha256': 'f46882e17999c6cc590af592290432be3bce0428cb0d5f8b6715e4dc7b383eb3'},
        {'identity': 'dashmap-6.1.0', 'sha256': '5041cc499144891f3790297212f32a74fb938e5136a14943f338ef9e0ae276cf'},
        {'identity': 'data-encoding-2.10.0', 'sha256': 'd7a1e2f27636f116493b8b860f5546edb47c8d8f8ea73e1d2a20be88e28d1fea'},
        {'identity': 'der-0.7.10', 'sha256': 'e7c1832837b905bbfb5101e07cc24c8deddf52f93225eee6ead5f4d63d53ddcb'},
        {'identity': 'der-parser-10.0.0', 'sha256': '07da5016415d5a3c4dd39b11ed26f915f52fc4e0dc197d87908bc916e51bc1a6'},
        {'identity': 'deranged-0.5.8', 'sha256': '7cd812cc2bc1d69d4764bd80df88b4317eaef9e773c75226407d9bc0876b211c'},
        {'identity': 'digest-0.10.7', 'sha256': '9ed9a281f7bc9b7576e61468ba615a66a5c8cfdff42420a70aa82701a3b1e292'},
        {'identity': 'displaydoc-0.2.5', 'sha256': '97369cbbc041bc366949bc74d34658d6cda5621039731c6310521892a3a20ae0'},
        {'identity': 'ed25519-2.2.3', 'sha256': '115531babc129696a58c64a4fef0a8bf9e9698629fb97e9e40767d235cfbcd53'},
        {'identity': 'ed25519-dalek-2.2.0', 'sha256': '70e796c081cee67dc755e1a36a0a172b897fab85fc3f6bc48307991f64e4eca9'},
        {'identity': 'either-1.15.0', 'sha256': '48c757948c5ede0e46177b7add2e67155f70e33c07fea8284df6576da70b3719'},
        {'identity': 'equivalent-1.0.2', 'sha256': '877a4ace8713b0bcf2a4e7eec82529c029f1d0619886d18145fea96c3ffe5c0f'},
        {'identity': 'errno-0.3.14', 'sha256': '39cab71617ae0d63f51a36d69f866391735b51691dbda63cf6f96d042b63efeb'},
        {'identity': 'fastrand-2.3.0', 'sha256': '37909eebbb50d72f9059c3b6d82c0463f2ff062c9e95845c43a6c9c0355411be'},
        {'identity': 'fiat-crypto-0.2.9', 'sha256': '28dea519a9695b9977216879a3ebfddf92f1c08c05d984f8996aecd6ecdc811d'},
        {'identity': 'find-msvc-tools-0.1.9', 'sha256': '5baebc0774151f905a1a2cc41989300b1e6fbb29aff0ceffa1064fdd3088d582'},
        {'identity': 'fixedbitset-0.5.7', 'sha256': '1d674e81391d1e1ab681a28d99df07927c6d4aa5b027d7da16ba32d1d21ecd99'},
        {'identity': 'flate2-1.1.9', 'sha256': '843fba2746e448b37e26a819579957415c8cef339bf08564fe8b7ddbd959573c'},
        {'identity': 'fnv-1.0.7', 'sha256': '3f9eec918d3f24069decb9af1554cad7c880e2da24a9afd88aca000531ab82c1'},
        {'identity': 'foldhash-0.1.5', 'sha256': 'd9c4f5dac5e15c24eb999c26181a6ca40b39fe946cbe4c263c7209467bc83af2'},
        {'identity': 'futures-0.3.32', 'sha256': '8b147ee9d1f6d097cef9ce628cd2ee62288d963e16fb287bd9286455b241382d'},
        {'identity': 'futures-channel-0.3.32', 'sha256': '07bbe89c50d7a535e539b8c17bc0b49bdb77747034daa8087407d655f3f7cc1d'},
        {'identity': 'futures-core-0.3.32', 'sha256': '7e3450815272ef58cec6d564423f6e755e25379b217b0bc688e295ba24df6b1d'},
        {'identity': 'futures-executor-0.3.32', 'sha256': 'baf29c38818342a3b26b5b923639e7b1f4a61fc5e76102d4b1981c6dc7a7579d'},
        {'identity': 'futures-io-0.3.32', 'sha256': 'cecba35d7ad927e23624b22ad55235f2239cfa44fd10428eecbeba6d6a717718'},
        {'identity': 'futures-macro-0.3.32', 'sha256': 'e835b70203e41293343137df5c0664546da5745f82ec9b84d40be8336958447b'},
        {'identity': 'futures-sink-0.3.32', 'sha256': 'c39754e157331b013978ec91992bde1ac089843443c49cbc7f46150b0fad0893'},
        {'identity': 'futures-task-0.3.32', 'sha256': '037711b3d59c33004d3856fbdc83b99d4ff37a24768fa1be9ce3538a1cde4393'},
        {'identity': 'futures-util-0.3.32', 'sha256': '389ca41296e6190b48053de0321d02a77f32f8a5d2461dd38762c0593805c6d6'},
        {'identity': 'generic-array-0.14.7', 'sha256': '85649ca51fd72272d7821adaf274ad91c288277713d9c18820d8499a7ff69e9a'},
        {'identity': 'getrandom-0.2.17', 'sha256': 'ff2abc00be7fca6ebc474524697ae276ad847ad0a6b3faa4bcb027e9a4614ad0'},
        {'identity': 'getrandom-0.4.2', 'sha256': '0de51e6874e94e7bf76d726fc5d13ba782deca734ff60d5bb2fb2607c7406555'},
        {'identity': 'h2-0.4.16', 'sha256': 'a9f37a958b41b3b19ee2707c06439c0e9e547e847223eb791ecb0cb821c65e27'},
        {'identity': 'half-2.7.1', 'sha256': '6ea2d84b969582b4b1864a92dc5d27cd2b77b622a8d79306834f1be5ba20d84b'},
        {'identity': 'hashbrown-0.14.5', 'sha256': 'e5274423e17b7c9fc20b6e7e208532f9b19825d82dfd615708b70edd83df41f1'},
        {'identity': 'hashbrown-0.15.5', 'sha256': '9229cfe53dfd69f0609a49f65461bd93001ea1ef889cd5529dd176593f5338a1'},
        {'identity': 'hashbrown-0.16.1', 'sha256': '841d1cc9bed7f9236f321df977030373f4a4163ae1a7dbfe1a51a2c1a51d9100'},
        {'identity': 'hdrhistogram-7.5.4', 'sha256': '765c9198f173dd59ce26ff9f95ef0aafd0a0fe01fb9d72841bc5066a4c06511d'},
        {'identity': 'heck-0.5.0', 'sha256': '2304e00983f87ffb38b55b444b5e3b60a884b5d30c0fca7d82fe33449bbe55ea'},
        {'identity': 'hex-0.4.3', 'sha256': '7f24254aa9a54b5c858eaee2f5bccdb46aaf0e486a595ed5fd8f86ba55232a70'},
        {'identity': 'http-1.4.0', 'sha256': 'e3ba2a386d7f85a81f119ad7498ebe444d2e22c2af0b86b069416ace48b3311a'},
        {'identity': 'http-body-1.0.1', 'sha256': '1efedce1fb8e6913f23e0c92de8e62cd5b772a67e7b3946df930a62566c93184'},
        {'identity': 'http-body-util-0.1.3', 'sha256': 'b021d93e26becf5dc7e1b75b1bed1fd93124b374ceb73f43d4d4eafec896a64a'},
        {'identity': 'httparse-1.10.1', 'sha256': '6dbf3de79e51f3d586ab4cb9d5c3e2c14aa28ed23d180cf89b4df0454a69cc87'},
        {'identity': 'httpdate-1.0.3', 'sha256': 'df3b46402a9d5adb4c86a0cf463f42e19994e3ee891101b1841f30a545cb49a9'},
        {'identity': 'hyper-1.8.1', 'sha256': '2ab2d4f250c3d7b1c9fcdff1cece94ea4e2dfbec68614f7b87cb205f24ca9d11'},
        {'identity': 'hyper-timeout-0.5.2', 'sha256': '2b90d566bffbce6a75bd8b09a05aa8c2cb1fabb6cb348f8840c9e4c90a0d83b0'},
        {'identity': 'hyper-util-0.1.20', 'sha256': '96547c2556ec9d12fb1578c4eaf448b04993e7fb79cbaad930a656880a6bdfa0'},
        {'identity': 'id-arena-2.3.0', 'sha256': '3d3067d79b975e8844ca9eb072e16b31c3c1c36928edf9c6789548c524d0d954'},
        {'identity': 'indexmap-2.13.0', 'sha256': '7714e70437a7dc3ac8eb7e6f8df75fd8eb422675fc7678aff7364301092b1017'},
        {'identity': 'is_terminal_polyfill-1.70.2', 'sha256': 'a6cb138bb79a146c1bd460005623e142ef0181e3d0219cb493e02f7d08a35695'},
        {'identity': 'itertools-0.13.0', 'sha256': '413ee7dfc52ee1a4949ceeb7dbc8a33f2d6c088194d9f922fb8318faf1f01186'},
        {'identity': 'itertools-0.14.0', 'sha256': '2b192c782037fadd9cfa75548310488aabdbf3d2da73885b31bd0abd03351285'},
        {'identity': 'itoa-1.0.17', 'sha256': '92ecc6618181def0457392ccd0ee51198e065e016d1d527a7ac1b6dc7c1f09d2'},
        {'identity': 'js-sys-0.3.91', 'sha256': 'b49715b7073f385ba4bc528e5747d02e66cb39c6146efb66b781f131f0fb399c'},
        {'identity': 'lazy_static-1.5.0', 'sha256': 'bbd2bcb4c963f2ddae06a2efc7e9f3591312473c50c6685e1f298068316e66fe'},
        {'identity': 'leb128fmt-0.1.0', 'sha256': '09edd9e8b54e49e587e4f6295a7d29c3ea94d469cb40ab8ca70b288248a81db2'},
        {'identity': 'libc-0.2.183', 'sha256': 'b5b646652bf6661599e1da8901b3b9522896f01e736bad5f723fe7a3a27f899d'},
        {'identity': 'libloading-0.8.9', 'sha256': 'd7c4b02199fee7c5d21a5ae7d8cfa79a6ef5bb2fc834d6e9058e89c825efdc55'},
        {'identity': 'linux-raw-sys-0.12.1', 'sha256': '32a66949e030da00e8c7d4434b251670a91556f4144941d37452769c25d58a53'},
        {'identity': 'lock_api-0.4.14', 'sha256': '224399e74b87b5f3557511d98dff8b14089b3dadafcab6bb93eab67d3aace965'},
        {'identity': 'log-0.4.29', 'sha256': '5e5032e24019045c762d3c0f28f5b6b8bbf38563a65908389bf7978758920897'},
        {'identity': 'matchers-0.2.0', 'sha256': 'd1525a2a28c7f4fa0fc98bb91ae755d1e2d1505079e05539e35bc876b5d65ae9'},
        {'identity': 'matchit-0.8.4', 'sha256': '47e1ffaa40ddd1f3ed91f717a33c8c0ee23fff369e3aa8772b9605cc1d22f4c3'},
        {'identity': 'memchr-2.8.0', 'sha256': 'f8ca58f447f06ed17d5fc4043ce1b10dd205e060fb3ce5b979b8ed8e59ff3f79'},
        {'identity': 'memoffset-0.9.1', 'sha256': '488016bfae457b036d996092f6cb448677611ce4449e970ceaf42695203f218a'},
        {'identity': 'mime-0.3.17', 'sha256': '6877bb514081ee2a7ff5ef9de3281f14a4dd4bceac4c09388074a6b5df8a139a'},
        {'identity': 'minimal-lexical-0.2.1', 'sha256': '68354c5c6bd36d73ff3feceb05efa59b6acb7626617f4962be322a825e61f79a'},
        {'identity': 'miniz_oxide-0.8.9', 'sha256': '1fa76a2c86f704bdb222d66965fb3d63269ce38518b83cb0575fca855ebb6316'},
        {'identity': 'mio-1.1.1', 'sha256': 'a69bcab0ad47271a0234d9422b131806bf3968021e5dc9328caf2d4cd58557fc'},
        {'identity': 'multimap-0.10.1', 'sha256': '1d87ecb2933e8aeadb3e3a02b828fed80a7528047e68b4f424523a0981a3a084'},
        {'identity': 'nix-0.31.2', 'sha256': '5d6d0705320c1e6ba1d912b5e37cf18071b6c2e9b7fa8215a1e8a7651966f5d3'},
        {'identity': 'nom-7.1.3', 'sha256': 'd273983c5a657a70a3e8f2a01329822f3b8c8172b73826411a55751e404a0a4a'},
        {'identity': 'nu-ansi-term-0.50.3', 'sha256': '7957b9740744892f114936ab4a57b3f487491bbeafaf8083688b16841a4240e5'},
        {'identity': 'num-bigint-0.4.6', 'sha256': 'a5e44f723f1133c9deac646763579fdb3ac745e418f2a7af9cd0c431da1f20b9'},
        {'identity': 'num-conv-0.2.0', 'sha256': 'cf97ec579c3c42f953ef76dbf8d55ac91fb219dde70e49aa4a6b7d74e9919050'},
        {'identity': 'num-integer-0.1.46', 'sha256': '7969661fd2958a5cb096e56c8e1ad0444ac2bbcd0061bd28660485a44879858f'},
        {'identity': 'num-traits-0.2.19', 'sha256': '071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841'},
        {'identity': 'oid-registry-0.8.1', 'sha256': '12f40cff3dde1b6087cc5d5f5d4d65712f34016a03ed60e9c08dcc392736b5b7'},
        {'identity': 'once_cell-1.21.4', 'sha256': '9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50'},
        {'identity': 'once_cell_polyfill-1.70.2', 'sha256': '384b8ab6d37215f3c5301a95a4accb5d64aa607f1fcb26a11b5303878451b4fe'},
        {'identity': 'oorandom-11.1.5', 'sha256': 'd6790f58c7ff633d8771f42965289203411a5e5c68388703c06e14f24770b41e'},
        {'identity': 'page_size-0.6.0', 'sha256': '30d5b2194ed13191c1999ae0704b7839fb18384fa22e49b57eeaa97d79ce40da'},
        {'identity': 'parking_lot_core-0.9.12', 'sha256': '2621685985a2ebf1c516881c026032ac7deafcda1a2c9b7850dc81e3dfcb64c1'},
        {'identity': 'pem-3.0.6', 'sha256': '1d30c53c26bc5b31a98cd02d20f25a7c8567146caf63ed593a9d87b2775291be'},
        {'identity': 'percent-encoding-2.3.2', 'sha256': '9b4f627cb1b25917193a259e49bdad08f671f8d9708acfd5fe0a8c1455d87220'},
        {'identity': 'petgraph-0.8.3', 'sha256': '8701b58ea97060d5e5b155d383a69952a60943f0e6dfe30b04c287beb0b27455'},
        {'identity': 'pin-project-1.1.11', 'sha256': 'f1749c7ed4bcaf4c3d0a3efc28538844fb29bcdd7d2b67b2be7e20ba861ff517'},
        {'identity': 'pin-project-internal-1.1.11', 'sha256': 'd9b20ed30f105399776b9c883e68e536ef602a16ae6f596d2c473591d6ad64c6'},
        {'identity': 'pin-project-lite-0.2.17', 'sha256': 'a89322df9ebe1c1578d689c92318e070967d1042b512afbe49518723f4e6d5cd'},
        {'identity': 'pin-utils-0.1.0', 'sha256': '8b870d8c151b6f2fb93e84a13146138f05d02ed11c7e7c54f8826aaaf7c9f184'},
        {'identity': 'pkcs11-abi-0.2.0', 'sha256': '9cba42280f784d54873423f6d60f3154941c244cc3ba6ace11d39ed38e5919fa'},
        {'identity': 'pkcs11-module-0.2.0', 'sha256': '406e34951fb5062884cdc140dbdfb18a2b5a26c73a104a5c1d09cb6acf0062e8'},
        {'identity': 'pkcs8-0.10.2', 'sha256': 'f950b2377845cebe5cf8b5165cb3cc1a5e0fa5cfa3e1f7f55707d8fd82e0a7b7'},
        {'identity': 'plotters-0.3.7', 'sha256': '5aeb6f403d7a4911efb1e33402027fc44f29b5bf6def3effcc22d7bb75f2b747'},
        {'identity': 'plotters-backend-0.3.7', 'sha256': 'df42e13c12958a16b3f7f4386b9ab1f3e7933914ecea48da7139435263a4172a'},
        {'identity': 'plotters-svg-0.3.7', 'sha256': '51bae2ac328883f7acdfea3d66a7c35751187f870bc81f94563733a154d7a670'},
        {'identity': 'powerfmt-0.2.0', 'sha256': '439ee305def115ba05938db6eb1644ff94165c5ab5e9420d1c1bcedbba909391'},
        {'identity': 'prettyplease-0.2.37', 'sha256': '479ca8adacdd7ce8f1fb39ce9ecccbfe93a3f1344b3d0d97f20bc0196208f62b'},
        {'identity': 'proc-macro2-1.0.106', 'sha256': '8fd00f0bb2e90d81d1044c2b32617f68fcb9fa3bb7640c23e9c748e53fb30934'},
        {'identity': 'prost-0.14.3', 'sha256': 'd2ea70524a2f82d518bce41317d0fae74151505651af45faf1ffbd6fd33f0568'},
        {'identity': 'prost-build-0.14.3', 'sha256': '343d3bd7056eda839b03204e68deff7d1b13aba7af2b2fd16890697274262ee7'},
        {'identity': 'prost-derive-0.14.3', 'sha256': '27c6023962132f4b30eb4c172c91ce92d933da334c59c23cddee82358ddafb0b'},
        {'identity': 'prost-types-0.14.3', 'sha256': '8991c4cbdb8bc5b11f0b074ffe286c30e523de90fee5ba8132f1399f23cb3dd7'},
        {'identity': 'pulldown-cmark-0.13.1', 'sha256': '83c41efbf8f90ac44de7f3a868f0867851d261b56291732d0cbf7cceaaeb55a6'},
        {'identity': 'pulldown-cmark-to-cmark-22.0.0', 'sha256': '50793def1b900256624a709439404384204a5dc3a6ec580281bfaac35e882e90'},
        {'identity': 'quote-1.0.45', 'sha256': '41f2619966050689382d2b44f664f4bc593e129785a36d6ee376ddf37259b924'},
        {'identity': 'r-efi-6.0.0', 'sha256': 'f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf'},
        {'identity': 'rand_core-0.6.4', 'sha256': 'ec0be4795e2f6a28069bec0b5ff3e2ac9bafc99e6a9a7dc3547996c5c816922c'},
        {'identity': 'rayon-1.11.0', 'sha256': '368f01d005bf8fd9b1206fb6fa653e6c4a81ceb1466406b81792d87c5677a58f'},
        {'identity': 'rayon-core-1.13.0', 'sha256': '22e18b0f0062d30d4230b2e85ff77fdfe4326feb054b9783a3460d8435c8ab91'},
        {'identity': 'rcgen-0.14.7', 'sha256': '10b99e0098aa4082912d4c649628623db6aba77335e4f4569ff5083a6448b32e'},
        {'identity': 'redox_syscall-0.5.18', 'sha256': 'ed2bf2547551a7053d6fdfafda3f938979645c44812fbfcda098faae3f1a362d'},
        {'identity': 'regex-1.12.3', 'sha256': 'e10754a14b9137dd7b1e3e5b0493cc9171fdd105e0ab477f51b72e7f3ac0e276'},
        {'identity': 'regex-automata-0.4.14', 'sha256': '6e1dd4122fc1595e8162618945476892eefca7b88c52820e74af6262213cae8f'},
        {'identity': 'regex-syntax-0.8.10', 'sha256': 'dc897dd8d9e8bd1ed8cdad82b5966c3e0ecae09fb1907d58efaa013543185d0a'},
        {'identity': 'ring-0.17.14', 'sha256': 'a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7'},
        {'identity': 'rustc_version-0.4.1', 'sha256': 'cfcb3a22ef46e85b45de6ee7e79d063319ebb6594faafcf1c225ea92ab6e9b92'},
        {'identity': 'rusticata-macros-4.1.0', 'sha256': 'faf0c4a6ece9950b9abdb62b1cfcf2a68b3b67a10ba445b3bb85be2a293d0632'},
        {'identity': 'rustix-1.1.4', 'sha256': 'b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190'},
        {'identity': 'rustls-0.23.45', 'sha256': '0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634'},
        {'identity': 'rustls-pki-types-1.14.0', 'sha256': 'be040f8b0a225e40375822a563fa9524378b9d63112f53e19ffff34df5d33fdd'},
        {'identity': 'rustls-webpki-0.103.15', 'sha256': 'f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2'},
        {'identity': 'rustversion-1.0.22', 'sha256': 'b39cdef0fa800fc44525c84ccb54a029961a8215f9619753635a9c0d2538d46d'},
        {'identity': 'same-file-1.0.6', 'sha256': '93fc1dc3aaa9bfed95e02e6eadabb4baf7e3078b0bd1b4d7b6b0b68378900502'},
        {'identity': 'scopeguard-1.2.0', 'sha256': '94143f37725109f92c262ed2cf5e59bce7498c01bcc1502d7b9afe439a4e9f49'},
        {'identity': 'semver-1.0.27', 'sha256': 'd767eb0aabc880b29956c35734170f26ed551a859dbd361d140cdbeca61ab1e2'},
        {'identity': 'serde-1.0.228', 'sha256': '9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e'},
        {'identity': 'serde_core-1.0.228', 'sha256': '41d385c7d4ca58e59fc732af25c3983b67ac852c1a25000afe1175de458b67ad'},
        {'identity': 'serde_derive-1.0.228', 'sha256': 'd540f220d3187173da220f885ab66608367b6574e925011a9353e4badda91d79'},
        {'identity': 'serde_json-1.0.149', 'sha256': '83fc039473c5595ace860d8c4fafa220ff474b3fc6bfdb4293327f1a37e94d86'},
        {'identity': 'serde_spanned-0.6.9', 'sha256': 'bf41e0cfaf7226dca15e8197172c295a782857fcb97fad1808a166870dee75a3'},
        {'identity': 'sha2-0.10.9', 'sha256': 'a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283'},
        {'identity': 'sharded-slab-0.1.7', 'sha256': 'f40ca3c46823713e0d4209592e8d6e826aa57e928f09752619fc696c499637f6'},
        {'identity': 'shlex-1.3.0', 'sha256': '0fda2ff0d084019ba4d7c6f371c95d8fd75ce3524c3cb8fb653a3023f6323e64'},
        {'identity': 'signal-hook-registry-1.4.8', 'sha256': 'c4db69cba1110affc0e9f7bcd48bbf87b3f4fc7c61fc9155afd4c469eb3d6c1b'},
        {'identity': 'signature-2.2.0', 'sha256': '77549399552de45a898a580c1b41d445bf730df867cc44e6c0233bbc4b8329de'},
        {'identity': 'simd-adler32-0.3.9', 'sha256': '703d5c7ef118737c72f1af64ad2f6f8c5e1921f818cdcb97b8fe6fc69bf66214'},
        {'identity': 'slab-0.4.12', 'sha256': '0c790de23124f9ab44544d7ac05d60440adc586479ce501c1d6d7da3cd8c9cf5'},
        {'identity': 'smallvec-1.15.1', 'sha256': '67b1b7a3b5fe4f1376887184045fcf45c69e92af734b7aaddc05fb777b6fbd03'},
        {'identity': 'socket2-0.6.3', 'sha256': '3a766e1110788c36f4fa1c2b71b387a7815aa65f88ce0229841826633d93723e'},
        {'identity': 'spki-0.7.3', 'sha256': 'd91ed6c858b01f942cd56b37a94b3e0a1798290327d1236e4d9cf4eaca44d29d'},
        {'identity': 'strsim-0.11.1', 'sha256': '7da8b5736845d9f2fcb837ea5d9e2628564b3b043a70948a3f0b778838c5fb4f'},
        {'identity': 'subtle-2.6.1', 'sha256': '13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292'},
        {'identity': 'syn-2.0.117', 'sha256': 'e665b8803e7b1d2a727f4023456bbbbe74da67099c585258af0ad9c5013b9b99'},
        {'identity': 'sync_wrapper-1.0.2', 'sha256': '0bf256ce5efdfa370213c1dabab5935a12e49f2c58d15e9eac2870d3b4f27263'},
        {'identity': 'synstructure-0.13.2', 'sha256': '728a70f3dbaf5bab7f0c4b1ac8d7ae5ea60a4b5549c8a5914361c99147a709d2'},
        {'identity': 'tempfile-3.27.0', 'sha256': '32497e9a4c7b38532efcdebeef879707aa9f794296a4f0244f6f69e9bc8574bd'},
        {'identity': 'thiserror-2.0.18', 'sha256': '4288b5bcbc7920c07a1149a35cf9590a2aa808e0bc1eafaade0b80947865fbc4'},
        {'identity': 'thiserror-impl-2.0.18', 'sha256': 'ebc4ee7f67670e9b64d05fa4253e753e016c6c95ff35b89b7941d6b856dec1d5'},
        {'identity': 'thread_local-1.1.9', 'sha256': 'f60246a4944f24f6e018aa17cdeffb7818b76356965d03b07d6a9886e8962185'},
        {'identity': 'time-0.3.47', 'sha256': '743bd48c283afc0388f9b8827b976905fb217ad9e647fae3a379a9283c4def2c'},
        {'identity': 'time-core-0.1.8', 'sha256': '7694e1cfe791f8d31026952abf09c69ca6f6fa4e1a1229e18988f06a04a12dca'},
        {'identity': 'time-macros-0.2.27', 'sha256': '2e70e4c5a0e0a8a4823ad65dfe1a6930e4f4d756dcd9dd7939022b5e8c501215'},
        {'identity': 'tinytemplate-1.2.1', 'sha256': 'be4d6b5f19ff7664e8c98d03e2139cb510db9b0a60b55f8e8709b689d939b6bc'},
        {'identity': 'tokio-1.50.0', 'sha256': '27ad5e34374e03cfffefc301becb44e9dc3c17584f414349ebe29ed26661822d'},
        {'identity': 'tokio-macros-2.6.1', 'sha256': '5c55a2eff8b69ce66c84f85e1da1c233edc36ceb85a2058d11b0d6a3c7e7569c'},
        {'identity': 'tokio-rustls-0.26.4', 'sha256': '1729aa945f29d91ba541258c8df89027d5792d85a8841fb65e8bf0f4ede4ef61'},
        {'identity': 'tokio-stream-0.1.18', 'sha256': '32da49809aab5c3bc678af03902d4ccddea2a87d028d86392a4b1560c6906c70'},
        {'identity': 'tokio-util-0.7.18', 'sha256': '9ae9cec805b01e8fc3fd2fe289f89149a9b66dd16786abd8b19cfa7b48cb0098'},
        {'identity': 'toml-0.8.23', 'sha256': 'dc1beb996b9d83529a9e75c17a1686767d148d70663143c7854d8b4a09ced362'},
        {'identity': 'toml_datetime-0.6.11', 'sha256': '22cddaf88f4fbc13c51aebbf5f8eceb5c7c5a9da2ac40a13519eb5b0a0e8f11c'},
        {'identity': 'toml_edit-0.22.27', 'sha256': '41fe8c660ae4257887cf66394862d21dbca4a6ddd26f04a3560410406a2f819a'},
        {'identity': 'toml_write-0.1.2', 'sha256': '5d99f8c9a7727884afe522e9bd5edbfc91a3312b36a77b5fb8926e4c31a41801'},
        {'identity': 'tonic-0.14.5', 'sha256': 'fec7c61a0695dc1887c1b53952990f3ad2e3a31453e1f49f10e75424943a93ec'},
        {'identity': 'tonic-build-0.14.5', 'sha256': '1882ac3bf5ef12877d7ed57aad87e75154c11931c2ba7e6cde5e22d63522c734'},
        {'identity': 'tonic-health-0.14.5', 'sha256': 'f4ff0636fef47afb3ec02818f5bceb4377b8abb9d6a386aeade18bd6212f8eb7'},
        {'identity': 'tonic-prost-0.14.5', 'sha256': 'a55376a0bbaa4975a3f10d009ad763d8f4108f067c7c2e74f3001fb49778d309'},
        {'identity': 'tonic-prost-build-0.14.5', 'sha256': 'f3144df636917574672e93d0f56d7edec49f90305749c668df5101751bb8f95a'},
        {'identity': 'tower-0.5.3', 'sha256': 'ebe5ef63511595f1344e2d5cfa636d973292adc0eec1f0ad45fae9f0851ab1d4'},
        {'identity': 'tower-layer-0.3.3', 'sha256': '121c2a6cda46980bb0fcd1647ffaf6cd3fc79a013de288782836f6df9c48780e'},
        {'identity': 'tower-service-0.3.3', 'sha256': '8df9b6e13f2d32c91b9bd719c00d1958837bc7dec474d94952798cc8e69eeec3'},
        {'identity': 'tracing-0.1.44', 'sha256': '63e71662fa4b2a2c3a26f570f037eb95bb1f85397f3cd8076caed2f026a6d100'},
        {'identity': 'tracing-attributes-0.1.31', 'sha256': '7490cfa5ec963746568740651ac6781f701c9c5ea257c58e057f3ba8cf69e8da'},
        {'identity': 'tracing-core-0.1.36', 'sha256': 'db97caf9d906fbde555dd62fa95ddba9eecfd14cb388e4f491a66d74cd5fb79a'},
        {'identity': 'tracing-log-0.2.0', 'sha256': 'ee855f1f400bd0e5c02d150ae5de3840039a3f54b025156404e34c23c03f47c3'},
        {'identity': 'tracing-serde-0.2.0', 'sha256': '704b1aeb7be0d0a84fc9828cae51dab5970fee5088f83d1dd7ee6f6246fc6ff1'},
        {'identity': 'tracing-subscriber-0.3.23', 'sha256': 'cb7f578e5945fb242538965c2d0b04418d38ec25c79d160cd279bf0731c8d319'},
        {'identity': 'try-lock-0.2.5', 'sha256': 'e421abadd41a4225275504ea4d6566923418b7f05506fbc9c0fe86ba7396114b'},
        {'identity': 'typenum-1.19.0', 'sha256': '562d481066bde0658276a35467c4af00bdc6ee726305698a55b86e61d7ad82bb'},
        {'identity': 'unicase-2.9.0', 'sha256': 'dbc4bc3a9f746d862c45cb89d705aa10f187bb96c76001afab07a0d35ce60142'},
        {'identity': 'unicode-ident-1.0.24', 'sha256': 'e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75'},
        {'identity': 'unicode-xid-0.2.6', 'sha256': 'ebc1c04c71510c7f702b52b7c350734c9ff1295c464a03335b00bb84fc54f853'},
        {'identity': 'untrusted-0.9.0', 'sha256': '8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1'},
        {'identity': 'utf8parse-0.2.2', 'sha256': '06abde3611657adf66d383f00b093d7faecc7fa57071cce2578660c9f1010821'},
        {'identity': 'uuid-1.22.0', 'sha256': 'a68d3c8f01c0cfa54a75291d83601161799e4a89a39e0929f4b0354d88757a37'},
        {'identity': 'valuable-0.1.1', 'sha256': 'ba73ea9cf16a25df0c8caa16c51acb937d5712a8429db78a3ee29d5dcacd3a65'},
        {'identity': 'version_check-0.9.5', 'sha256': '0b928f33d975fc6ad9f86c8f283853ad26bdd5b10b7f1542aa2fa15e2289105a'},
        {'identity': 'walkdir-2.5.0', 'sha256': '29790946404f91d9c5d06f9874efddea1dc06c5efe94541a7d6863108e3a5e4b'},
        {'identity': 'want-0.3.1', 'sha256': 'bfa7760aed19e106de2c7c0b581b509f2f25d3dacaf737cb82ac61bc6d760b0e'},
        {'identity': 'wasi-0.11.1+wasi-snapshot-preview1', 'sha256': 'ccf3ec651a847eb01de73ccad15eb7d99f80485de043efb2f370cd654f4ea44b'},
        {'identity': 'wasip2-1.0.2+wasi-0.2.9', 'sha256': '9517f9239f02c069db75e65f174b3da828fe5f5b945c4dd26bd25d89c03ebcf5'},
        {'identity': 'wasip3-0.4.0+wasi-0.3.0-rc-2026-01-06', 'sha256': '5428f8bf88ea5ddc08faddef2ac4a67e390b88186c703ce6dbd955e1c145aca5'},
        {'identity': 'wasm-bindgen-0.2.114', 'sha256': '6532f9a5c1ece3798cb1c2cfdba640b9b3ba884f5db45973a6f442510a87d38e'},
        {'identity': 'wasm-bindgen-macro-0.2.114', 'sha256': '18a2d50fcf105fb33bb15f00e7a77b772945a2ee45dcf454961fd843e74c18e6'},
        {'identity': 'wasm-bindgen-macro-support-0.2.114', 'sha256': '03ce4caeaac547cdf713d280eda22a730824dd11e6b8c3ca9e42247b25c631e3'},
        {'identity': 'wasm-bindgen-shared-0.2.114', 'sha256': '75a326b8c223ee17883a4251907455a2431acc2791c98c26279376490c378c16'},
        {'identity': 'wasm-encoder-0.244.0', 'sha256': '990065f2fe63003fe337b932cfb5e3b80e0b4d0f5ff650e6985b1048f62c8319'},
        {'identity': 'wasm-metadata-0.244.0', 'sha256': 'bb0e353e6a2fbdc176932bbaab493762eb1255a7900fe0fea1a2f96c296cc909'},
        {'identity': 'wasmparser-0.244.0', 'sha256': '47b807c72e1bac69382b3a6fb3dbe8ea4c0ed87ff5629b8685ae6b9a611028fe'},
        {'identity': 'web-sys-0.3.91', 'sha256': '854ba17bb104abfb26ba36da9729addc7ce7f06f5c0f90f3c391f8461cca21f9'},
        {'identity': 'winapi-0.3.9', 'sha256': '5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419'},
        {'identity': 'winapi-i686-pc-windows-gnu-0.4.0', 'sha256': 'ac3b87c63620426dd9b991e5ce0329eff545bccbbb34f3be09ff6fb6ab51b7b6'},
        {'identity': 'winapi-util-0.1.11', 'sha256': 'c2a7b1c03c876122aa43f3020e6c3c3ee5c05081c9a00739faf7503aeba10d22'},
        {'identity': 'winapi-x86_64-pc-windows-gnu-0.4.0', 'sha256': '712e227841d057c1ee1cd2fb22fa7e5a5461ae8e48fa2ca79ec42cfc1931183f'},
        {'identity': 'windows-link-0.2.1', 'sha256': 'f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5'},
        {'identity': 'windows-sys-0.52.0', 'sha256': '282be5f36a8ce781fad8c8ae18fa3f9beff57ec1b52cb3de0789201425d9a33d'},
        {'identity': 'windows-sys-0.61.2', 'sha256': 'ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc'},
        {'identity': 'windows-targets-0.52.6', 'sha256': '9b724f72796e036ab90c1021d4780d4d3d648aca59e491e6b98e725b84e99973'},
        {'identity': 'windows_aarch64_gnullvm-0.52.6', 'sha256': '32a4622180e7a0ec044bb555404c800bc9fd9ec262ec147edd5989ccd0c02cd3'},
        {'identity': 'windows_aarch64_msvc-0.52.6', 'sha256': '09ec2a7bb152e2252b53fa7803150007879548bc709c039df7627cabbd05d469'},
        {'identity': 'windows_i686_gnu-0.52.6', 'sha256': '8e9b5ad5ab802e97eb8e295ac6720e509ee4c243f69d781394014ebfe8bbfa0b'},
        {'identity': 'windows_i686_gnullvm-0.52.6', 'sha256': '0eee52d38c090b3caa76c563b86c3a4bd71ef1a819287c19d586d7334ae8ed66'},
        {'identity': 'windows_i686_msvc-0.52.6', 'sha256': '240948bc05c5e7c6dabba28bf89d89ffce3e303022809e73deaefe4f6ec56c66'},
        {'identity': 'windows_x86_64_gnu-0.52.6', 'sha256': '147a5c80aabfbf0c7d901cb5895d1de30ef2907eb21fbbab29ca94c5b08b1a78'},
        {'identity': 'windows_x86_64_gnullvm-0.52.6', 'sha256': '24d5b23dc417412679681396f2b49f3de8c1473deb516bd34410872eff51ed0d'},
        {'identity': 'windows_x86_64_msvc-0.52.6', 'sha256': '589f6da84c646204747d1270a2a5661ea66ed1cced2631d546fdfb155959f9ec'},
        {'identity': 'winnow-0.7.15', 'sha256': 'df79d97927682d2fd8adb29682d1140b343be4ac0f08fd68b7765d9c059d3945'},
        {'identity': 'wit-bindgen-0.51.0', 'sha256': 'd7249219f66ced02969388cf2bb044a09756a083d0fab1e566056b04d9fbcaa5'},
        {'identity': 'wit-bindgen-core-0.51.0', 'sha256': 'ea61de684c3ea68cb082b7a88508a8b27fcc8b797d738bfc99a82facf1d752dc'},
        {'identity': 'wit-bindgen-rust-0.51.0', 'sha256': 'b7c566e0f4b284dd6561c786d9cb0142da491f46a9fbed79ea69cdad5db17f21'},
        {'identity': 'wit-bindgen-rust-macro-0.51.0', 'sha256': '0c0f9bfd77e6a48eccf51359e3ae77140a7f50b1e2ebfe62422d8afdaffab17a'},
        {'identity': 'wit-component-0.244.0', 'sha256': '9d66ea20e9553b30172b5e831994e35fbde2d165325bec84fc43dbf6f4eb9cb2'},
        {'identity': 'wit-parser-0.244.0', 'sha256': 'ecc8ac4bc1dc3381b7f59c34f00b67e18f910c2c0f50015669dde7def656a736'},
        {'identity': 'x509-parser-0.18.1', 'sha256': 'd43b0f71ce057da06bc0851b23ee24f3f86190b07203dd8f567d0b706a185202'},
        {'identity': 'yasna-0.5.2', 'sha256': 'e17bb3549cc1321ae1296b9cdc2698e2b6cb1992adfa19a8c72e5b7a738f44cd'},
        {'identity': 'zerocopy-0.8.42', 'sha256': 'f2578b716f8a7a858b7f02d5bd870c14bf4ddbbcf3a4c05414ba6503640505e3'},
        {'identity': 'zerocopy-derive-0.8.42', 'sha256': '7e6cc098ea4d3bd6246687de65af3f920c430e236bee1e3bf2e441463f08a02f'},
        {'identity': 'zeroize-1.8.2', 'sha256': 'b97154e67e32c85465826e8bcc1c59429aaaf107c1e4a9e53c8d8ccd5eff88d0'},
        {'identity': 'zeroize_derive-1.4.3', 'sha256': '85a5b4158499876c763cb03bc4e49185d3cccbabb15b33c627f7884f43db852e'},
        {'identity': 'zmij-1.0.21', 'sha256': 'b8848ee67ecc8aedbaf3e4122217aff892639231befc6a1b58d29fff4c2cabaa'},
    ],
    'toolchain_manifest_sha256': '5aba2e7de287d689e9cb9476d7f2c234268319591f53eb0adcb76af80f51e3d5',
    'toolchain_image': {'engine_id': 'sha256:7d00db51b3b184c06482221b76545142d970b726a70e19fc089b923043fc2025', 'layers': ['sha256:8d9d35d1e1ec16aea046daa8655183d1da834773d867f119abf4859d72c00d4d']},
    'rust_protoc': {'rustc_version': 'rustc 1.98.1 (48a229cea 2026-09-01)', 'cargo_version': 'cargo 1.98.1 (797e8a9bc 2026-08-05)', 'protoc_version': 'libprotoc 36.1', 'rust_record_sha256': 'cd0da947db9fe2044b0bf8d0817d727d3bf3678d109f42697c43ec32f03ea2e5', 'protoc_record_sha256': '2b99d40ed3960abcdbfefafa515325e61faf63be909e3fa25657edad69ea3bce', 'crates_record_sha256': '7e2369937225fbbffcc75355247b6a5191c03f28d4378b1d9fe4ad8bca91f1a3'},
    'target': 'x86_64-unknown-linux-gnu',
    'packages': ['pkcs11-proxy-ng', 'pkcs11-proxy-ng-cli', 'pkcs11-proxy-ng-shim'],
    'features': 'default',
    'profile': {'name': 'release', 'lto': 'thin', 'codegen-units': 1, 'strip': 'symbols'},
    'rustflags': [],
    'cargo_args': ['build', '--locked', '--offline', '--release', '--target', 'x86_64-unknown-linux-gnu', '-p', 'pkcs11-proxy-ng', '-p', 'pkcs11-proxy-ng-cli', '-p', 'pkcs11-proxy-ng-shim'],
    'controller_cargo_config_sha256': '42be131d92724bcd8416e544381b06b3bc4b6f929d53614eaeb429e3364f40f4',
    'build_script_sha256': '48895b01bdf1d9d4eac6f809ed20b6c489beeb58eebc9dcb16850b55613b5428',
    'daemon': {'path': 'bin/pkcs11-proxy-ng', 'size': 13071320, 'mode': 493, 'sha256': '4a1505c910e285015704ed0f510338c73a7e371bdbb42486a73e90bb5ea78c28'},
    'cli': {'path': 'bin/pkcs11-proxy-ng-cli', 'size': 6851136, 'mode': 493, 'sha256': '07d258d1b8cfe1237f8c09f245df0940f67c741dad96025034b6955bde2e3f0c'},
    'shim': {'path': 'lib/libpkcs11_proxy_ng_shim.so', 'size': 6287192, 'mode': 493, 'sha256': 'cd68a5cd5bd4a83961a6958f845f01bbf417b4c47954aabf45a17fe13adfe768'},
    'abi': {
        'decision': 'conforming-recorded',
        'runtime_qualification': 'not-performed',
        'floors': {
            'bin/pkcs11-proxy-ng': {'ld-linux-x86-64.so.2': {'GLIBC': '2.3'}, 'libc.so.6': {'GLIBC': '2.34'}, 'libgcc_s.so.1': {'GCC': '4.2.0'}, 'libm.so.6': {'GLIBC': '2.29'}},
            'bin/pkcs11-proxy-ng-cli': {'ld-linux-x86-64.so.2': {'GLIBC': '2.3'}, 'libc.so.6': {'GLIBC': '2.34'}, 'libgcc_s.so.1': {'GCC': '4.2.0'}, 'libm.so.6': {'GLIBC': '2.29'}},
            'lib/libpkcs11_proxy_ng_shim.so': {'ld-linux-x86-64.so.2': {'GLIBC': '2.3'}, 'libc.so.6': {'GLIBC': '2.34'}, 'libgcc_s.so.1': {'GCC': '4.2.0'}, 'libm.so.6': {'GLIBC': '2.29'}},
        },
        'needed': {
            'bin/pkcs11-proxy-ng': ['libgcc_s.so.1', 'libm.so.6', 'libc.so.6', 'ld-linux-x86-64.so.2'],
            'bin/pkcs11-proxy-ng-cli': ['libgcc_s.so.1', 'libm.so.6', 'libc.so.6', 'ld-linux-x86-64.so.2'],
            'lib/libpkcs11_proxy_ng_shim.so': ['libgcc_s.so.1', 'libm.so.6', 'libc.so.6', 'ld-linux-x86-64.so.2'],
        },
        'interpreters': {
            'bin/pkcs11-proxy-ng': '/lib64/ld-linux-x86-64.so.2',
            'bin/pkcs11-proxy-ng-cli': '/lib64/ld-linux-x86-64.so.2',
            'lib/libpkcs11_proxy_ng_shim.so': None,
        },
        'shim_exports': ['C_GetFunctionList', 'C_GetInterface', 'C_GetInterfaceList'],
        'version_requirements': {
            'bin/pkcs11-proxy-ng': [
                {'file': 'ld-linux-x86-64.so.2', 'name': 'GLIBC_2.3'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.10'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.14'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.16'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.17'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.18'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.2.5'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.25'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.28'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.3'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.3.2'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.3.4'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.30'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.32'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.33'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.34'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.7'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.9'},
                {'file': 'libgcc_s.so.1', 'name': 'GCC_3.0'},
                {'file': 'libgcc_s.so.1', 'name': 'GCC_3.3'},
                {'file': 'libgcc_s.so.1', 'name': 'GCC_4.2.0'},
                {'file': 'libm.so.6', 'name': 'GLIBC_2.29'},
            ],
            'bin/pkcs11-proxy-ng-cli': [
                {'file': 'ld-linux-x86-64.so.2', 'name': 'GLIBC_2.3'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.14'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.16'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.17'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.18'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.2.5'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.25'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.28'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.3'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.3.2'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.3.4'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.30'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.32'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.33'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.34'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.7'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.9'},
                {'file': 'libgcc_s.so.1', 'name': 'GCC_3.0'},
                {'file': 'libgcc_s.so.1', 'name': 'GCC_3.3'},
                {'file': 'libgcc_s.so.1', 'name': 'GCC_4.2.0'},
                {'file': 'libm.so.6', 'name': 'GLIBC_2.29'},
            ],
            'lib/libpkcs11_proxy_ng_shim.so': [
                {'file': 'ld-linux-x86-64.so.2', 'name': 'GLIBC_2.3'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.14'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.16'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.17'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.18'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.2.5'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.25'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.28'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.3'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.3.2'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.3.4'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.30'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.32'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.33'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.34'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.7'},
                {'file': 'libc.so.6', 'name': 'GLIBC_2.9'},
                {'file': 'libgcc_s.so.1', 'name': 'GCC_3.0'},
                {'file': 'libgcc_s.so.1', 'name': 'GCC_3.3'},
                {'file': 'libgcc_s.so.1', 'name': 'GCC_4.2.0'},
                {'file': 'libm.so.6', 'name': 'GLIBC_2.29'},
            ],
        },
        'symbol_versions': {
            'bin/pkcs11-proxy-ng': [
                {'symbol': '_Unwind_Backtrace', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.3'},
                {'symbol': '_Unwind_DeleteException', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetDataRelBase', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetIP', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetIPInfo', 'file': 'libgcc_s.so.1', 'version': 'GCC_4.2.0'},
                {'symbol': '_Unwind_GetLanguageSpecificData', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetRegionStart', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetTextRelBase', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_RaiseException', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_Resume', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_SetGR', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_SetIP', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '__cxa_finalize', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__cxa_thread_atexit_impl', 'file': 'libc.so.6', 'version': 'GLIBC_2.18'},
                {'symbol': '__errno_location', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__libc_current_sigrtmax', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__libc_start_main', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': '__tls_get_addr', 'file': 'ld-linux-x86-64.so.2', 'version': 'GLIBC_2.3'},
                {'symbol': '__xpg_strerror_r', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.4'},
                {'symbol': 'abort', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'accept4', 'file': 'libc.so.6', 'version': 'GLIBC_2.10'},
                {'symbol': 'bcmp', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'bind', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'calloc', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'chmod', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'clock_gettime', 'file': 'libc.so.6', 'version': 'GLIBC_2.17'},
                {'symbol': 'close', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'closedir', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'dirfd', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'dl_iterate_phdr', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'dlclose', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'dlerror', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'dlopen', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'dlsym', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'dup', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'epoll_create1', 'file': 'libc.so.6', 'version': 'GLIBC_2.9'},
                {'symbol': 'epoll_ctl', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.2'},
                {'symbol': 'epoll_wait', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.2'},
                {'symbol': 'eventfd', 'file': 'libc.so.6', 'version': 'GLIBC_2.7'},
                {'symbol': 'exit', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'fcntl', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'free', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'fstat64', 'file': 'libc.so.6', 'version': 'GLIBC_2.33'},
                {'symbol': 'fsync', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getauxval', 'file': 'libc.so.6', 'version': 'GLIBC_2.16'},
                {'symbol': 'getcwd', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getenv', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getpeername', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getrandom', 'file': 'libc.so.6', 'version': 'GLIBC_2.25'},
                {'symbol': 'getsockname', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getsockopt', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'gettid', 'file': 'libc.so.6', 'version': 'GLIBC_2.30'},
                {'symbol': 'isatty', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'listen', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'lseek64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'lstat64', 'file': 'libc.so.6', 'version': 'GLIBC_2.33'},
                {'symbol': 'malloc', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'memcmp', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'memcpy', 'file': 'libc.so.6', 'version': 'GLIBC_2.14'},
                {'symbol': 'memmove', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'memset', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'mkdir', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'mlockall', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'mmap64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'mprotect', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'munmap', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'open', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'open64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'opendir', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pause', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'poll', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'posix_memalign', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pow', 'file': 'libm.so.6', 'version': 'GLIBC_2.29'},
                {'symbol': 'pthread_attr_destroy', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_attr_getguardsize', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_attr_getstack', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_attr_init', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_attr_setstacksize', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_create', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_detach', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_getattr_np', 'file': 'libc.so.6', 'version': 'GLIBC_2.32'},
                {'symbol': 'pthread_join', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_key_create', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_key_delete', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_mutex_lock', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_mutex_unlock', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_self', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_setname_np', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_setspecific', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'read', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'readdir64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'readlink', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'realloc', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'realpath', 'file': 'libc.so.6', 'version': 'GLIBC_2.3'},
                {'symbol': 'recv', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'rename', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sched_getaffinity', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.4'},
                {'symbol': 'sched_yield', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'send', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'setsockopt', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'shutdown', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sigaction', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sigaltstack', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'signal', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'socket', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'socketpair', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'stat64', 'file': 'libc.so.6', 'version': 'GLIBC_2.33'},
                {'symbol': 'statx', 'file': 'libc.so.6', 'version': 'GLIBC_2.28'},
                {'symbol': 'strlen', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'syscall', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sysconf', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'umask', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'unlink', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'write', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'writev', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
            ],
            'bin/pkcs11-proxy-ng-cli': [
                {'symbol': '_Unwind_Backtrace', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.3'},
                {'symbol': '_Unwind_DeleteException', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetDataRelBase', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetIP', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetIPInfo', 'file': 'libgcc_s.so.1', 'version': 'GCC_4.2.0'},
                {'symbol': '_Unwind_GetLanguageSpecificData', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetRegionStart', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetTextRelBase', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_RaiseException', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_Resume', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_SetGR', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_SetIP', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '__cxa_finalize', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__cxa_thread_atexit_impl', 'file': 'libc.so.6', 'version': 'GLIBC_2.18'},
                {'symbol': '__errno_location', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__libc_current_sigrtmax', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__libc_start_main', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': '__res_init', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__tls_get_addr', 'file': 'ld-linux-x86-64.so.2', 'version': 'GLIBC_2.3'},
                {'symbol': '__xpg_strerror_r', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.4'},
                {'symbol': 'abort', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'bcmp', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'bind', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'calloc', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'clock_gettime', 'file': 'libc.so.6', 'version': 'GLIBC_2.17'},
                {'symbol': 'close', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'closedir', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'connect', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'dirfd', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'dl_iterate_phdr', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'dlsym', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'dup', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'epoll_create1', 'file': 'libc.so.6', 'version': 'GLIBC_2.9'},
                {'symbol': 'epoll_ctl', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.2'},
                {'symbol': 'epoll_wait', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.2'},
                {'symbol': 'eventfd', 'file': 'libc.so.6', 'version': 'GLIBC_2.7'},
                {'symbol': 'exit', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'fcntl', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'free', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'freeaddrinfo', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'fstat64', 'file': 'libc.so.6', 'version': 'GLIBC_2.33'},
                {'symbol': 'gai_strerror', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getaddrinfo', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getauxval', 'file': 'libc.so.6', 'version': 'GLIBC_2.16'},
                {'symbol': 'getcwd', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getenv', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getrandom', 'file': 'libc.so.6', 'version': 'GLIBC_2.25'},
                {'symbol': 'getsockopt', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'gettid', 'file': 'libc.so.6', 'version': 'GLIBC_2.30'},
                {'symbol': 'gnu_get_libc_version', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'isatty', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'lseek64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'malloc', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'memcmp', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'memcpy', 'file': 'libc.so.6', 'version': 'GLIBC_2.14'},
                {'symbol': 'memmove', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'memset', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'mmap64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'mprotect', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'munmap', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'open', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'open64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'opendir', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pause', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'poll', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'posix_memalign', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pow', 'file': 'libm.so.6', 'version': 'GLIBC_2.29'},
                {'symbol': 'pthread_attr_destroy', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_attr_getguardsize', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_attr_getstack', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_attr_init', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_attr_setstacksize', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_create', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_detach', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_getattr_np', 'file': 'libc.so.6', 'version': 'GLIBC_2.32'},
                {'symbol': 'pthread_join', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_key_create', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_key_delete', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_mutex_lock', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_mutex_unlock', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_self', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_setname_np', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_setspecific', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'read', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'readdir64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'readlink', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'realloc', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'realpath', 'file': 'libc.so.6', 'version': 'GLIBC_2.3'},
                {'symbol': 'recv', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sched_getaffinity', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.4'},
                {'symbol': 'sched_yield', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'send', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'setsockopt', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'shutdown', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sigaction', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sigaltstack', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'signal', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'socket', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'socketpair', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'stat64', 'file': 'libc.so.6', 'version': 'GLIBC_2.33'},
                {'symbol': 'statx', 'file': 'libc.so.6', 'version': 'GLIBC_2.28'},
                {'symbol': 'strlen', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'syscall', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sysconf', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'write', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'writev', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
            ],
            'lib/libpkcs11_proxy_ng_shim.so': [
                {'symbol': '_Unwind_Backtrace', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.3'},
                {'symbol': '_Unwind_DeleteException', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetDataRelBase', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetIP', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetIPInfo', 'file': 'libgcc_s.so.1', 'version': 'GCC_4.2.0'},
                {'symbol': '_Unwind_GetLanguageSpecificData', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetRegionStart', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_GetTextRelBase', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_RaiseException', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_Resume', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_SetGR', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '_Unwind_SetIP', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
                {'symbol': '__cxa_finalize', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__cxa_thread_atexit_impl', 'file': 'libc.so.6', 'version': 'GLIBC_2.18'},
                {'symbol': '__errno_location', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__libc_current_sigrtmax', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__res_init', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': '__tls_get_addr', 'file': 'ld-linux-x86-64.so.2', 'version': 'GLIBC_2.3'},
                {'symbol': '__xpg_strerror_r', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.4'},
                {'symbol': 'abort', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'bcmp', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'bind', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'calloc', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'clock_gettime', 'file': 'libc.so.6', 'version': 'GLIBC_2.17'},
                {'symbol': 'close', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'connect', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'dl_iterate_phdr', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'dlsym', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'epoll_create1', 'file': 'libc.so.6', 'version': 'GLIBC_2.9'},
                {'symbol': 'epoll_ctl', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.2'},
                {'symbol': 'epoll_wait', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.2'},
                {'symbol': 'eventfd', 'file': 'libc.so.6', 'version': 'GLIBC_2.7'},
                {'symbol': 'fcntl', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'free', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'freeaddrinfo', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'fstat64', 'file': 'libc.so.6', 'version': 'GLIBC_2.33'},
                {'symbol': 'gai_strerror', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getaddrinfo', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getauxval', 'file': 'libc.so.6', 'version': 'GLIBC_2.16'},
                {'symbol': 'getcwd', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getenv', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getpid', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'getrandom', 'file': 'libc.so.6', 'version': 'GLIBC_2.25'},
                {'symbol': 'getsockopt', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'gettid', 'file': 'libc.so.6', 'version': 'GLIBC_2.30'},
                {'symbol': 'gnu_get_libc_version', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'lseek64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'malloc', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'memcmp', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'memcpy', 'file': 'libc.so.6', 'version': 'GLIBC_2.14'},
                {'symbol': 'memmove', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'memset', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'mmap64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'mprotect', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'munmap', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'open', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'open64', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pause', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'poll', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'posix_memalign', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pow', 'file': 'libm.so.6', 'version': 'GLIBC_2.29'},
                {'symbol': 'pthread_attr_destroy', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_attr_getguardsize', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_attr_getstack', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_attr_init', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_attr_setstacksize', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_create', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_detach', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_getattr_np', 'file': 'libc.so.6', 'version': 'GLIBC_2.32'},
                {'symbol': 'pthread_join', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_key_create', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_key_delete', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_mutex_lock', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_mutex_unlock', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_self', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'pthread_setname_np', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'pthread_setspecific', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
                {'symbol': 'read', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'readlink', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'realloc', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'realpath', 'file': 'libc.so.6', 'version': 'GLIBC_2.3'},
                {'symbol': 'recv', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sched_getaffinity', 'file': 'libc.so.6', 'version': 'GLIBC_2.3.4'},
                {'symbol': 'sched_yield', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'send', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'setsockopt', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'shutdown', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sigaltstack', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'socket', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'socketpair', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'stat64', 'file': 'libc.so.6', 'version': 'GLIBC_2.33'},
                {'symbol': 'statx', 'file': 'libc.so.6', 'version': 'GLIBC_2.28'},
                {'symbol': 'strlen', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'syscall', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'sysconf', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'write', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
                {'symbol': 'writev', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'},
            ],
        },
    },
    'daemon_config_sha256': 'a958111d2948445495502c5d25152246511bb43004e5dd75b7e1ef1870c2adf2',
    'entrypoint_sha256': 'c51aae8cf914d27c288e5634343601ddc74bd1a56e3a7ed14843f7706333861b',
    'hook_hashes': [],
    'build_context_digest': '990222a42e16041423a50fcc10b7ad6a3a84afaff25d1139aac94252c74cb51f',
    'caller': {'origin': 'local-controller', 'run_id': None, 'job_id': None},
    'provider_parent': {'family': None, 'platform': None, 'manifest_digest': None, 'config_digest': None},
}


def DEFAULT_PROXY_BUILD_IDENTITY() -> ProxyBuildIdentityV1:
    """Construct a fresh pinned-default proxy-build identity record.

    Named per the identity brief; a constructor (not a shared instance) so
    every caller receives independent nested containers. The absolute default
    used whenever no explicit expected identity is selected.
    """
    return ProxyBuildIdentityV1.from_dict(copy.deepcopy(_PINNED_DEFAULT_IDENTITY))


_DEFAULT_SELF_CHECK = DEFAULT_PROXY_BUILD_IDENTITY()
assert _DEFAULT_SELF_CHECK.to_dict() == _PINNED_DEFAULT_IDENTITY
del _DEFAULT_SELF_CHECK
