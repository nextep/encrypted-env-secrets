"""
envshield — Zero-dependency JIT environment variable decryption.

Transparently intercepts os.environ lookups and decrypts AES-256-GCM
ciphertexts on the fly. The master key is resolved from (in order):

    1. A local env-shield.key file (project-specific, paired with .env.enc)
    2. The ENV_SHIELD_KEY environment variable (wiped from /proc after read)
    3. The OS-native secure keyring / TPM (global key store)
    4. Google Colab's userdata API

Import this module once at the top of your application to activate the
interceptor.  No pip packages required — relies exclusively on the
system's libcrypto via ctypes.

Usage:
    import envshield
    import os

    api_key = os.environ['SECRET_API_KEY']   # decrypted JIT
"""

import os
import sys
import json
import ctypes
import ctypes.util

from .core import encrypt, decrypt
from . import keyring

__all__ = ['encrypt', 'decrypt', 'patch_environ', 'wipe_environ_key']

# ---------------------------------------------------------------------------
# Active Environment Wiping
# ---------------------------------------------------------------------------
# When a CI/CD runner injects secrets via environment variables, those values
# are visible in /proc/<pid>/environ to any process running as the same user.
# Supply-chain malware (e.g. the Trivy GH Actions breach of March 2026)
# actively scrapes this file.
#
# wipe_environ_key() walks the raw C environ array using ctypes and memsets
# the target entry to null bytes, physically eradicating it from /proc.
# This is NOT equivalent to `del os.environ[key]` — that only removes the
# entry from Python's internal dict; the kernel-level mapping persists.
# ---------------------------------------------------------------------------

def wipe_environ_key(key_name: str) -> bool:
    """
    Overwrites the raw C-level environ entry for *key_name* with null bytes.

    This destroys the value in /proc/self/environ so that background
    processes or malicious actions running in the same CI/CD runner cannot
    scrape it.  Returns True if the key was found and wiped, False otherwise.

    NOTE: This is a Linux-specific hardening measure.  On other platforms
    the function is a safe no-op (returns False).
    """
    if not sys.platform.startswith('linux'):
        return False

    try:
        libc = ctypes.CDLL(None)
        # char **environ — exported by libc on Linux
        environ_ptr = ctypes.POINTER(ctypes.c_char_p).in_dll(libc, "environ")
    except (OSError, ValueError):
        return False

    prefix = (key_name + '=').encode()
    i = 0
    while environ_ptr[i] is not None:
        raw = ctypes.string_at(environ_ptr[i])
        if raw.startswith(prefix):
            libc.memset(environ_ptr[i], 0, len(raw))
            # Also remove from Python's view so it stays consistent
            os.environ.pop(key_name, None)
            return True
        i += 1
    return False

# ---------------------------------------------------------------------------
# Master key resolution chain
# ---------------------------------------------------------------------------

_KEYRING_SERVICE = 'envshield'

def _get_master_key():
    """
    Resolves the 32-byte AES-256 master key using a strict priority chain:

    1. env-shield.key    — project-local file, paired with local .env.enc.
    2. ENV_SHIELD_KEY    — CI/CD fallback; immediately wiped from /proc after read.
    3. OS Keyring / TPM  — global key store, backed by the kernel credential store.
    4. Colab userdata    — Google Colab's encrypted secrets API.
    """

    # --- 1. Local key file (project-specific, paired with local .env.enc) ---
    key_path = os.path.join(os.getcwd(), 'env-shield.key')
    if os.path.exists(key_path):
        with open(key_path, 'r') as f:
            return bytes.fromhex(f.read().strip())

    # --- 2. Environment variable (CI/CD path) ---
    if 'ENV_SHIELD_KEY' in os.environ:
        key = bytes.fromhex(os.environ['ENV_SHIELD_KEY'])
        # Burn after reading — scrub the raw value from /proc/<pid>/environ
        wipe_environ_key('ENV_SHIELD_KEY')
        return key

    # --- 3. OS secure keyring / TPM (global key store) ---
    try:
        key_hex = keyring.get_key(_KEYRING_SERVICE)
        if key_hex:
            return bytes.fromhex(key_hex)
    except Exception:
        pass

    # --- 4. Google Colab userdata API ---
    try:
        from google.colab import userdata  # type: ignore
        key_hex = userdata.get('ENV_SHIELD_KEY')
        if key_hex:
            return bytes.fromhex(key_hex)
    except ImportError:
        pass

    raise RuntimeError(
        "EnvShield: master key not found.\n"
        "Checked: ./env-shield.key, ENV_SHIELD_KEY, OS keyring/TPM, Colab userdata\n"
        "Run `envshield-cli.py --store <service> <token>` to provision a key."
    )

# ---------------------------------------------------------------------------
# os.environ interceptor
# ---------------------------------------------------------------------------

def _load_enc_data():
    enc_path = os.path.join(os.getcwd(), '.env.enc')
    if not os.path.exists(enc_path):
        return {}
    with open(enc_path, 'r') as f:
        return json.load(f)

_original_getitem = os.environ.__class__.__getitem__
_original_get = os.environ.__class__.get
_enc_cache = None
_patched = False

def patch_environ():
    """
    Monkey-patches os.environ so that lookups transparently decrypt
    any key present in .env.enc.  Safe to call multiple times (idempotent).
    """
    global _patched
    if _patched:
        return

    def _envshield_getitem(self, key):
        try:
            return _original_getitem(self, key)
        except KeyError:
            global _enc_cache
            if _enc_cache is None:
                _enc_cache = _load_enc_data()

            if key in _enc_cache:
                master_key = _get_master_key()
                return decrypt(_enc_cache[key], master_key)
            raise

    def _envshield_get(self, key, default=None):
        try:
            return _envshield_getitem(self, key)
        except KeyError:
            return default

    os.environ.__class__.__getitem__ = _envshield_getitem
    os.environ.__class__.get = _envshield_get
    _patched = True

# Auto-patch on import (backwards-compatible behaviour)
patch_environ()
