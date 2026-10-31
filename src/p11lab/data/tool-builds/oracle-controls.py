# SPDX-License-Identifier: Apache-2.0
"""Provider-free P-256 controls: fixed public SEC 2 P-256 generator key material.

This is a public test key. It grants no provider qualification. The exact script,
OpenSSL/config, invocation and native control outputs are retained by the driver.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any

# SEC1 P-256 private scalar 1; public generator from SEC 2 section 2.4.2.
# All bytes are fixed public mathematical test data, never application secrets.
KEY = bytes.fromhex('30770201010420' + '00' * 31 + '01' +
                    'a00a06082a8648ce3d030107a14403420004' +
                    '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296' +
                    '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
MESSAGE = b'P11Lab independent PKCS11 smoke v1\n'


def call(argv: list[str]) -> dict[str, Any]:
    result = subprocess.run(argv, capture_output=True, timeout=30)
    return {'argv': argv, 'returncode': result.returncode,
            'stdout': result.stdout.decode('utf-8', 'replace'), 'stderr': result.stderr.decode('utf-8', 'replace')}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix='p11lab-oracle-controls-') as root:
        path = Path(root)
        (path / 'key.der').write_bytes(KEY)
        (path / 'message.bin').write_bytes(MESSAGE)
        (path / 'digest.bin').write_bytes(hashlib.sha256(MESSAGE).digest())
        commands = [
            ['/usr/bin/openssl', 'pkey', '-inform', 'DER', '-in', str(path / 'key.der'), '-pubout', '-out', str(path / 'public-key.pem')],
            ['/usr/bin/openssl', 'dgst', '-sha256', '-keyform', 'DER', '-sign', str(path / 'key.der'), '-out', str(path / 'signature.der'), str(path / 'message.bin')]]
        setup = [call(command) for command in commands]
        if any(r['returncode'] for r in setup):
            raise ValueError('oracle public fixture creation failed: ' + json.dumps(setup))
        # Convert signature INTEGERs to the raw shape expected by verify.py.
        der = (path / 'signature.der').read_bytes()
        pos, integers = 2, []
        while pos < len(der):
            if der[pos] != 2:
                raise ValueError('unexpected ECDSA signature encoding')
            size = der[pos + 1]
            integers.append(int.from_bytes(der[pos + 2:pos + 2 + size], 'big').to_bytes(32, 'big'))
            pos += 2 + size
        (path / 'signature.raw').write_bytes(b''.join(integers))
        command = ['/usr/bin/python3.13', '-I', '/opt/p11lab-oracle/verify.py', root, '--openssl', '/usr/bin/openssl']
        positive = call(command)
        # Direct native altered-message proof plus packaged oracle altered-signature rejection.
        (path / 'altered.bin').write_bytes(MESSAGE + b'altered\n')
        negative = call(['/usr/bin/openssl', 'dgst', '-sha256', '-verify', str(path / 'public-key.pem'),
                         '-signature', str(path / 'signature.der'), str(path / 'altered.bin')])
        changed = bytearray(der)
        changed[-1] ^= 1
        (path / 'signature.der').write_bytes(changed)
        altered = call(command)
        print(json.dumps({'setup': setup, 'positive': positive, 'altered_message': negative,
                          'altered_signature': altered,
                          'fixture': 'SEC2-P256-generator-private-scalar-1-public-test-data',
                          'public_key_sha256': hashlib.sha256((path / 'public-key.pem').read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
