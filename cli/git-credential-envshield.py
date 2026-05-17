#!/usr/bin/env python3
"""
git-credential-envshield — Git credential helper backed by EnvShield.

This script implements the standard Git credential helper protocol:

    https://git-scm.com/docs/gitcredentials#_custom_helpers

When Git needs to authenticate an HTTPS operation against a host that
has been provisioned with EnvShield, this helper will:

    1. Retrieve the master key from the OS secure keyring.
    2. Decrypt the token JIT using AES-256-GCM via libcrypto.
    3. Print `password=<token>` to stdout.
    4. Exit — Python's GC wipes the plaintext from heap memory.

Setup
-----
    # 1. Store the token (key goes into the OS keyring automatically):
    python3 envshield-cli.py --store github "ghp_..."

    # 2. Register the helper with Git:
    git config --global credential.helper \\
        "/usr/bin/env python3 /path/to/git-credential-envshield.py"
"""

import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
from envshield.core import decrypt
from envshield import keyring

def _resolve_key(service: str) -> bytes:
    """
    Resolve the master key for *service* using the same priority chain
    as the main library:
        1. OS keyring  (envshield-<service>)
        2. ~/.envshield/<service>.key  (file fallback)
    """
    # --- OS keyring ---
    key_hex = keyring.get_key(f'envshield-{service}')
    if key_hex:
        return bytes.fromhex(key_hex)

    # --- File fallback ---
    key_file = os.path.join(os.path.expanduser('~'), '.envshield', f'{service}.key')
    if os.path.exists(key_file):
        with open(key_file, 'r') as f:
            return bytes.fromhex(f.read().strip())

    return None

def main():
    if len(sys.argv) < 2:
        sys.exit(0)

    # Git passes "get", "store", or "erase" as the first argument.
    op = sys.argv[1]
    if op != 'get':
        sys.exit(0)

    # Parse the key=value pairs Git sends on stdin.
    attrs = {}
    for line in sys.stdin.read().splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            attrs[k.strip()] = v.strip()

    host = attrs.get('host', '')

    # Map well-known hosts to their service names.
    # This can be extended to any git-compatible service.
    host_service_map = {
        'github.com': 'github',
        'gitlab.com': 'gitlab',
        'bitbucket.org': 'bitbucket',
    }

    service = host_service_map.get(host)
    if not service:
        sys.exit(0)

    enc_file = os.path.join(os.path.expanduser('~'), '.envshield', f'{service}.enc')
    if not os.path.exists(enc_file):
        sys.exit(0)

    master_key = _resolve_key(service)
    if not master_key:
        sys.exit(0)

    with open(enc_file, 'r') as f:
        encrypted_data = json.load(f)

    token = decrypt(encrypted_data, master_key)
    print(f"password={token}")

if __name__ == '__main__':
    main()
