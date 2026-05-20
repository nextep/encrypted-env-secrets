"""
envshield — Zero-dependency JIT environment variable decryption.

Transparently intercepts os.environ lookups and decrypts AES-256-GCM
ciphertexts on the fly.

The master key source is determined by ENVSHIELD_MODE (or ~/.envshield/config):

    tpm     — Unseal from TPM 2.0 hardware (strongest)
    keyring — OS-native credential store (GNOME Keyring / macOS Keychain / Windows)
    env     — Read from ENV_SHIELD_KEY, then wipe from /proc
    file    — Read from local env-shield.key (dev/testing only)

Set ENVSHIELD_DEBUG=1 for detailed step-by-step logging to stderr.

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
import logging

from .core import encrypt, decrypt
from . import keyring

__all__ = ['encrypt', 'decrypt', 'patch_environ', 'wipe_environ_key']

# ---------------------------------------------------------------------------
# Debug Logging
# ---------------------------------------------------------------------------

_logger = logging.getLogger('envshield')
_log_handler = logging.StreamHandler(sys.stderr)
_log_handler.setFormatter(logging.Formatter(
    '[envshield %(levelname)s] %(message)s'
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
        _debug(f'wipe_environ_key({key_name}): skipped (not linux)')
        return False

    try:
        libc = ctypes.CDLL(None)
        # char **environ — exported by libc on Linux
        environ_ptr = ctypes.POINTER(ctypes.c_char_p).in_dll(libc, "environ")
    except (OSError, ValueError):
        _warn(f'wipe_environ_key({key_name}): cannot access libc environ')
        return False

    prefix = (key_name + '=').encode()
    i = 0
    while environ_ptr[i] is not None:
        raw = ctypes.string_at(environ_ptr[i])
        if raw.startswith(prefix):
            libc.memset(environ_ptr[i], 0, len(raw))
            # Also remove from Python's view so it stays consistent
            os.environ.pop(key_name, None)
            _debug(f'wipe_environ_key({key_name}): wiped {len(raw)} bytes from /proc')
            return True
        i += 1

    _debug(f'wipe_environ_key({key_name}): key not found in raw environ')
    return False


def _wipe_bytes(buf: bytearray):
    """
    Overwrite a bytearray in-place with zeros.  This destroys the master key
    from Python heap memory after it has been used for decryption.
    """
    for i in range(len(buf)):
        buf[i] = 0
    _debug(f'_wipe_bytes: zeroed {len(buf)} bytes of key material')


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_VALID_MODES = ('tpm', 'keyring', 'env', 'file')
_KEYRING_SERVICE = 'envshield'


def _get_mode() -> str:
    """
    Determine the key storage mode.  Resolution order:

        1. ENVSHIELD_MODE environment variable
        2. ~/.envshield/config file  (JSON: {"mode": "tpm"})
        3. Auto-detect (legacy fallback — tries all sources)
    """
    # 1. Env var
    mode = os.environ.get('ENVSHIELD_MODE', '').strip().lower()
    if mode in _VALID_MODES:
        _debug(f'Mode resolved from ENVSHIELD_MODE env var: {mode}')
        return mode

    # 2. Config file
    config_path = os.path.join(os.path.expanduser('~'), '.envshield', 'config')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                cfg = json.load(f)
            mode = cfg.get('mode', '').strip().lower()
            if mode in _VALID_MODES:
                _debug(f'Mode resolved from config file: {mode}')
                return mode
        except (json.JSONDecodeError, OSError) as e:
            _warn(f'Failed to read config file {config_path}: {e}')

    # 3. Auto-detect fallback
    _debug('No mode configured — falling back to auto-detect')
    return 'auto'


# ---------------------------------------------------------------------------
# Master key resolution — config-driven
# ---------------------------------------------------------------------------

def _get_master_key() -> bytearray:
    """
    Resolves the 32-byte AES-256 master key from the configured source.

    The source is determined by ENVSHIELD_MODE or ~/.envshield/config:
        tpm     — Unseal from TPM 2.0 hardware
        keyring — OS-native credential store
        env     — ENV_SHIELD_KEY environment variable (wiped after read)
        file    — Local env-shield.key file
        auto    — Try all in order (legacy/unconfigured fallback)

    Returns a mutable bytearray so the caller can wipe it after use.
    """
    mode = _get_mode()
    _debug(f'Resolving master key (mode={mode})')

    if mode == 'tpm':
        return _fetch_from_tpm()
    elif mode == 'keyring':
        return _fetch_from_keyring()
    elif mode == 'env':
        return _fetch_from_env()
    elif mode == 'file':
        return _fetch_from_file()
    else:
        # auto-detect: try each source in order
        return _fetch_auto()


def _fetch_from_tpm() -> bytearray:
    _debug('Fetching master key from TPM 2.0...')
    key_hex = keyring._tpm_get(_KEYRING_SERVICE)
    if not key_hex:
        raise RuntimeError(
            "EnvShield: TPM mode configured but no sealed key found.\n"
            f"Expected sealed blob at ~/.envshield/tpm/{_KEYRING_SERVICE}/\n"
            "Run the setup wizard or `envshield-cli.py --store` to provision."
        )
    _debug('Master key unsealed from TPM successfully')
    return bytearray(bytes.fromhex(key_hex))


def _fetch_from_keyring() -> bytearray:
    _debug('Fetching master key from OS keyring...')
    key_hex = keyring.get_key(_KEYRING_SERVICE)
    if not key_hex:
        raise RuntimeError(
            "EnvShield: keyring mode configured but key not found.\n"
            f"Expected key under service '{_KEYRING_SERVICE}' in OS keyring.\n"
            "Run the setup wizard or `envshield-cli.py --store` to provision."
        )
    _debug('Master key retrieved from OS keyring successfully')
    return bytearray(bytes.fromhex(key_hex))


def _fetch_from_env() -> bytearray:
    _debug('Fetching master key from ENV_SHIELD_KEY...')
    raw = os.environ.get('ENV_SHIELD_KEY')
    if not raw:
        raise RuntimeError(
            "EnvShield: env mode configured but ENV_SHIELD_KEY is not set.\n"
            "Set it in your CI/CD secrets or shell profile."
        )
    key = bytearray(bytes.fromhex(raw))
    _debug('Master key read from ENV_SHIELD_KEY — wiping from /proc...')
    wipe_environ_key('ENV_SHIELD_KEY')
    return key


def _fetch_from_file() -> bytearray:
    key_path = os.path.join(os.getcwd(), 'env-shield.key')
    _debug(f'Fetching master key from file: {key_path}')
    if not os.path.exists(key_path):
        raise RuntimeError(
            f"EnvShield: file mode configured but {key_path} not found.\n"
            "Run `envshield-cli.py --file .env` to generate it."
        )
    with open(key_path, 'r') as f:
        key_hex = f.read().strip()
    _debug('Master key loaded from file')
    return bytearray(bytes.fromhex(key_hex))


def _fetch_auto() -> bytearray:
    """Legacy auto-detect fallback for unconfigured installations."""
    _debug('Auto-detect: trying file -> env -> keyring/tpm -> colab')

    # 1. Local key file
    key_path = os.path.join(os.getcwd(), 'env-shield.key')
    if os.path.exists(key_path):
        _debug(f'Auto-detect: found local key file {key_path}')
        with open(key_path, 'r') as f:
            return bytearray(bytes.fromhex(f.read().strip()))

    # 2. Environment variable
    if 'ENV_SHIELD_KEY' in os.environ:
        _debug('Auto-detect: found ENV_SHIELD_KEY')
        key = bytearray(bytes.fromhex(os.environ['ENV_SHIELD_KEY']))
        wipe_environ_key('ENV_SHIELD_KEY')
        return key

    # 3. OS keyring / TPM
    try:
        key_hex = keyring.get_key(_KEYRING_SERVICE)
        if key_hex:
            _debug('Auto-detect: found key in OS keyring/TPM')
            return bytearray(bytes.fromhex(key_hex))
    except Exception:
        pass

    # 4. Google Colab
    try:
        from google.colab import userdata  # type: ignore
        key_hex = userdata.get('ENV_SHIELD_KEY')
        if key_hex:
            _debug('Auto-detect: found key in Colab userdata')
            return bytearray(bytes.fromhex(key_hex))
    except ImportError:
        pass

    raise RuntimeError(
        "EnvShield: master key not found.\n"
        "Set ENVSHIELD_MODE to specify where your key lives (tpm/keyring/env/file)\n"
        "or run the setup wizard: bash scripts/envshield-setup.sh"
    )


# ---------------------------------------------------------------------------
# os.environ interceptor
# ---------------------------------------------------------------------------

def _load_enc_data():
    enc_path = os.path.join(os.getcwd(), '.env.enc')
    if not os.path.exists(enc_path):
        _debug(f'No .env.enc found at {enc_path}')
        return {}
    _debug(f'Loaded encrypted env data from {enc_path}')
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

    Secure lifecycle per lookup:
        1. Load .env.enc ciphertext
        2. Fetch PK from configured source (ENVSHIELD_MODE)
        3. Decrypt ciphertext JIT in memory
        4. Wipe PK from process memory (memset to zero)
        5. Return plaintext (never stored persistently)
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
                _debug(f'JIT decrypt: {key}')
                # 1. Fetch master key (mutable bytearray)
                master_key = _get_master_key()
                try:
                    # 2. Decrypt
                    plaintext = decrypt(_enc_cache[key], bytes(master_key))
                    _debug(f'JIT decrypt: {key} — success')
                    return plaintext
                finally:
                    # 3. Destroy PK from memory
                    _wipe_bytes(master_key)
            raise

    def _envshield_get(self, key, default=None):
        try:
            return _envshield_getitem(self, key)
        except KeyError:
            return default

    os.environ.__class__.__getitem__ = _envshield_getitem
    os.environ.__class__.get = _envshield_get
    _patched = True
    _debug('os.environ interceptor activated')

# Auto-patch on import (backwards-compatible behaviour)
patch_environ()
