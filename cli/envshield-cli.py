#!/usr/bin/env python3
"""
envshield-cli — Encrypt .env files or individual service tokens.

This tool produces AES-256-GCM ciphertexts using the OS-native libcrypto
via ctypes.  Master keys are stored in the platform's secure keyring by
default (GNOME Keyring on Linux, Keychain on macOS, Credential Locker on
Windows).  Pass --file to fall back to a plaintext key file for headless
or testing scenarios.

Examples
--------
    # Encrypt a whole .env file (key stored in OS keyring by default):
    python3 envshield-cli.py .env

    # Encrypt a single integration token:
    python3 envshield-cli.py --store github "ghp_..."

    # Force key-file output instead of keyring:
    python3 envshield-cli.py --file .env
    python3 envshield-cli.py --store aws "AKIA..." --file
"""

import os
import sys
import json

# Resolve the library from the sibling python/ directory so the CLI
# works out-of-the-box without a pip install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
from envshield.core import encrypt
from envshield import keyring

_KEYRING_SERVICE = 'envshield'

def _store_key_to_keyring(service: str, key_hex: str) -> bool:
    """
    Attempt to persist the master key in the OS keyring.
    Returns True on success, False if the keyring is unavailable
    (e.g. headless CI without a session bus).
    """
    return keyring.store_key(service, key_hex)

def _handle_store(service: str, token: str, force_file: bool):
    """Encrypt a single token and persist it under ~/.envshield/<service>.enc."""
    home_dir = os.path.expanduser('~')
    envshield_dir = os.path.join(home_dir, '.envshield')
    os.makedirs(envshield_dir, exist_ok=True)

    master_key = os.urandom(32)
    encrypted_data = encrypt(token, master_key)

    enc_file = os.path.join(envshield_dir, f'{service}.enc')
    with open(enc_file, 'w') as f:
        json.dump(encrypted_data, f, indent=2)

    key_hex = master_key.hex()

    # Try OS keyring first, unless --file was explicitly requested.
    if not force_file and _store_key_to_keyring(f'envshield-{service}', key_hex):
        print(f"[✓] Token for '{service}' encrypted → {enc_file}")
        print(f"[✓] Master key stored in OS keyring under 'envshield-{service}'.")
    else:
        # Fallback: write the key file.
        key_file = os.path.join(envshield_dir, f'{service}.key')
        with open(key_file, 'w') as f:
            f.write(key_hex)
        os.chmod(key_file, 0o600)
        if force_file:
            print(f"[✓] Token for '{service}' encrypted → {enc_file}")
            print(f"[✓] Master key written to {key_file} (--file mode).")
        else:
            print(f"[!] OS keyring unavailable — falling back to key file.")
            print(f"[✓] Token for '{service}' encrypted → {enc_file}")
            print(f"[✓] Master key written to {key_file}")

def _handle_env_file(env_file: str, force_file: bool):
    """Encrypt an entire .env file into .env.enc."""
    if not os.path.exists(env_file):
        print(f"Error: {env_file} not found.")
        sys.exit(1)

    master_key = os.urandom(32)
    encrypted_data = {}

    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip("'").strip('"')
                encrypted_data[k] = encrypt(v, master_key)

    with open('.env.enc', 'w') as f:
        json.dump(encrypted_data, f, indent=2)

    key_hex = master_key.hex()

    if not force_file and _store_key_to_keyring(_KEYRING_SERVICE, key_hex):
        print("[✓] Encrypted variables → .env.enc  (AES-256-GCM)")
        print(f"[✓] Master key stored in OS keyring under '{_KEYRING_SERVICE}'.")
    else:
        with open('env-shield.key', 'w') as f:
            f.write(key_hex)
        os.chmod('env-shield.key', 0o600)
        if force_file:
            print("[✓] Encrypted variables → .env.enc  (AES-256-GCM)")
            print("[✓] Master key written to env-shield.key (--file mode).")
        else:
            print("[!] OS keyring unavailable — falling back to key file.")
            print("[✓] Encrypted variables → .env.enc  (AES-256-GCM)")
            print("[✓] Master key written to env-shield.key")

def main():
    args = sys.argv[1:]
    force_file = '--file' in args
    if force_file:
        args.remove('--file')

    if len(args) >= 2 and args[0] == '--store':
        service = args[1]
        token = args[2] if len(args) > 2 else None
        if not token:
            print("Usage: envshield-cli.py --store <service> <token> [--file]")
            sys.exit(1)
        _handle_store(service, token, force_file)
    else:
        env_file = args[0] if args else '.env'
        _handle_env_file(env_file, force_file)

if __name__ == '__main__':
    main()
