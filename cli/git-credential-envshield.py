#!/usr/bin/env python3
"""
git-credential-envshield — Git credential helper backed by EnvShield.

Implements the standard Git credential helper protocol:
    https://git-scm.com/docs/gitcredentials#_custom_helpers

Secure lifecycle:
    1. Git calls this helper with "get" and the target host on stdin.
    2. Load the encrypted token from .enc file.
    3. Fetch the master key from the configured source (ENVSHIELD_MODE).
    4. Decrypt the token JIT.
    5. Wipe the master key from memory (memset to zero).
    6. Print password=<token> to stdout.
    7. Exit — Python's GC cleans the plaintext from heap.

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
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
from envshield.core import decrypt
from envshield import keyring

# ---------------------------------------------------------------------------
# Debug Logging
# ---------------------------------------------------------------------------

_logger = logging.getLogger('envshield.git-credential')
_log_handler = logging.StreamHandler(sys.stderr)
_log_handler.setFormatter(logging.Formatter(
    '[git-credential-envshield %(levelname)s] %(message)s'
))
_logger.addHandler(_log_handler)

if os.environ.get('ENVSHIELD_DEBUG', '').strip() in ('1', 'true', 'yes'):
    _logger.setLevel(logging.DEBUG)
else:
    _logger.setLevel(logging.WARNING)


def _debug(msg: str):
    _logger.debug(msg)


def _warn(msg: str):
    _logger.warning(msg)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_VALID_MODES = ('tpm', 'keyring', 'env', 'file')


def _get_mode() -> str:
    """
    Determine key storage mode from:
        1. ENVSHIELD_MODE env var
        2. ~/.envshield/config file
        3. 'auto' fallback
    """
    mode = os.environ.get('ENVSHIELD_MODE', '').strip().lower()
    if mode in _VALID_MODES:
        _debug(f'Mode from env: {mode}')
        return mode

    config_path = os.path.join(os.path.expanduser('~'), '.envshield', 'config')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                cfg = json.load(f)
            mode = cfg.get('mode', '').strip().lower()
            if mode in _VALID_MODES:
                _debug(f'Mode from config: {mode}')
                return mode
        except (json.JSONDecodeError, OSError):
            pass

    _debug('No mode configured, using auto-detect')
    return 'auto'


# ---------------------------------------------------------------------------
# Master Key Resolution (config-driven)
# ---------------------------------------------------------------------------

def _resolve_key(service: str) -> bytearray:
    """
    Fetch the master key for *service* from the configured source.
    Returns a mutable bytearray so the caller can wipe it after use.
    """
    mode = _get_mode()
    _debug(f'Resolving key for service={service}, mode={mode}')

    if mode == 'tpm':
        key_hex = keyring._tpm_get(f'envshield-{service}')
        if not key_hex:
            key_hex = keyring._tpm_get('envshield')
        if key_hex:
            _debug(f'Key unsealed from TPM for {service}')
            return bytearray(bytes.fromhex(key_hex))
        _warn(f'TPM mode: no sealed key found for {service}')
        return None

    elif mode == 'keyring':
        key_hex = keyring.get_key(f'envshield-{service}')
        if not key_hex:
            key_hex = keyring.get_key('envshield')
        if key_hex:
            _debug(f'Key retrieved from OS keyring for {service}')
            return bytearray(bytes.fromhex(key_hex))
        _warn(f'Keyring mode: no key found for {service}')
        return None

    elif mode == 'env':
        # Check service-specific first, then generic
        env_specific = f"ENV_SHIELD_{service.upper()}_KEY"
        raw = os.environ.get(env_specific) or os.environ.get("ENV_SHIELD_KEY")
        if raw:
            _debug(f'Key loaded from environment variable')
            return bytearray(bytes.fromhex(raw))
        _warn(f'Env mode: neither {env_specific} nor ENV_SHIELD_KEY is set')
        return None

    elif mode == 'file':
        key_file = os.path.join(os.path.expanduser('~'), '.envshield', f'{service}.key')
        if not os.path.exists(key_file):
            key_file = os.path.join(os.getcwd(), 'env-shield.key')
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                _debug(f'Key loaded from file: {key_file}')
                return bytearray(bytes.fromhex(f.read().strip()))
        _warn(f'File mode: no key file found for {service}')
        return None

    else:
        # Auto-detect: try env -> keyring/tpm -> file
        _debug('Auto-detect key resolution')

        env_specific = f"ENV_SHIELD_{service.upper()}_KEY"
        raw = os.environ.get(env_specific) or os.environ.get("ENV_SHIELD_KEY")
        if raw:
            _debug(f'Auto: key from env var')
            return bytearray(bytes.fromhex(raw))

        key_hex = keyring.get_key(f'envshield-{service}')
        if not key_hex:
            key_hex = keyring.get_key('envshield')
        if key_hex:
            _debug(f'Auto: key from keyring/TPM')
            return bytearray(bytes.fromhex(key_hex))

        key_file = os.path.join(os.path.expanduser('~'), '.envshield', f'{service}.key')
        if not os.path.exists(key_file):
            key_file = os.path.join(os.getcwd(), 'env-shield.key')
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                _debug(f'Auto: key from file {key_file}')
                return bytearray(bytes.fromhex(f.read().strip()))

        return None


def _wipe_bytes(buf: bytearray):
    """Overwrite a bytearray in-place with zeros."""
    for i in range(len(buf)):
        buf[i] = 0
    _debug(f'Wiped {len(buf)} bytes of key material from memory')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

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
    _debug(f'Credential request for host: {host}')

    # Map well-known hosts to their service names.
    host_service_map = {
        'github.com': 'github',
        'gitlab.com': 'gitlab',
        'bitbucket.org': 'bitbucket',
    }

    service = host_service_map.get(host)
    if not service:
        _debug(f'Unknown host: {host}, exiting')
        sys.exit(0)

    # Find the encrypted token file
    paths_to_check = [
        os.path.join(os.getcwd(), '.github', 'envshield', f'{service}.enc'),
        os.path.join(os.getcwd(), '.envshield', f'{service}.enc'),
        os.path.join(os.path.expanduser('~'), '.envshield', f'{service}.enc')
    ]

    enc_file = None
    for p in paths_to_check:
        if os.path.exists(p):
            enc_file = p
            _debug(f'Found encrypted token at: {enc_file}')
            break

    if not enc_file:
        _debug(f'No .enc file found for {service}')
        sys.exit(0)

    # Secure lifecycle: fetch key -> decrypt -> wipe key -> output
    master_key = _resolve_key(service)
    if not master_key:
        _warn(f'Could not resolve master key for {service}')
        sys.exit(0)

    try:
        with open(enc_file, 'r') as f:
            encrypted_data = json.load(f)

        token = decrypt(encrypted_data, bytes(master_key))
        _debug(f'Token decrypted successfully for {service}')
        print(f"password={token}")
    finally:
        # Destroy PK from memory
        _wipe_bytes(master_key)

if __name__ == '__main__':
    main()
