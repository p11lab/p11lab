"""Per-run mTLS material for the pinned proxy transport.

create_test_tls generates a disposable evaluation CA, server leaf and client
leaf with OpenSSL Ed25519 keys following the public transport contract, then
verifies SAN/EKU/chain before returning paths. Only server leaf/key+CA reach
the daemon and only client leaf/key+CA reach the consumer; the CA private key
never enters either mount set.
"""
from pathlib import Path
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess

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
