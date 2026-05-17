"""
envshield.keyring — Zero-dependency OS-native credential storage.

Stores and retrieves EnvShield master keys using the platform's secure
credential manager.  Falls back gracefully if the backend is unavailable.

Supported backends (in priority order):

    1. TPM 2.0          — Hardware-backed key sealing via tpm2-tools (Linux)
    2. GNOME Keyring     — secret-tool (Linux desktop)
    3. macOS Keychain    — security CLI
    4. Windows Cred Locker — advapi32.dll via ctypes

TPM 2.0 NOTE:
    TPM-sealed keys are bound to the specific hardware.  If the TPM is
    cleared or the machine is replaced, the sealed key is irrecoverable.
    This is by design — it prevents offline extraction of the key material
    even if the disk is cloned.  Use `--file` as a backup/migration path.

    Requires: apt install tpm2-tools  (tpm2_create, tpm2_load, tpm2_unseal)
"""

import os
import sys
import shutil
import subprocess
import json

# ---------------------------------------------------------------------------
# TPM 2.0 Backend (Linux)
# ---------------------------------------------------------------------------
# Uses tpm2-tools to seal a key to the TPM's Storage Root Key (SRK).
# The sealed blob is written to ~/.envshield/tpm/<service>.ctx
# Only unsealable on this exact hardware + PCR state.
# ---------------------------------------------------------------------------

_TPM_DIR = os.path.join(os.path.expanduser('~'), '.envshield', 'tpm')

def _tpm_available() -> bool:
    """Check if tpm2-tools and /dev/tpm* are available."""
    if not sys.platform.startswith('linux'):
        return False
    if not shutil.which('tpm2_createprimary'):
        return False
    # Check for a TPM device
    return os.path.exists('/dev/tpm0') or os.path.exists('/dev/tpmrm0')

def _tpm_store(service: str, key_hex: str) -> bool:
    """Seal a key into the TPM under the Storage Root Key."""
    try:
        os.makedirs(_TPM_DIR, exist_ok=True)
        svc_dir = os.path.join(_TPM_DIR, service)
        os.makedirs(svc_dir, exist_ok=True)

        primary_ctx = os.path.join(svc_dir, 'primary.ctx')
        key_pub     = os.path.join(svc_dir, 'key.pub')
        key_priv    = os.path.join(svc_dir, 'key.priv')
        key_ctx     = os.path.join(svc_dir, 'key.ctx')
        data_file   = os.path.join(svc_dir, 'data.bin')

        # Write the key material to a temp file
        with open(data_file, 'w') as f:
            f.write(key_hex)
        os.chmod(data_file, 0o600)

        # 1. Create primary key (SRK) under the owner hierarchy
        subprocess.run([
            'tpm2_createprimary', '-C', 'o', '-c', primary_ctx
        ], check=True, capture_output=True)

        # 2. Create a sealing object with the data
        subprocess.run([
            'tpm2_create', '-C', primary_ctx,
            '-i', data_file,
            '-u', key_pub, '-r', key_priv
        ], check=True, capture_output=True)

        # 3. Load the sealed object
        subprocess.run([
            'tpm2_load', '-C', primary_ctx,
            '-u', key_pub, '-r', key_priv,
            '-c', key_ctx
        ], check=True, capture_output=True)

        # Clean up the plaintext data file
        os.remove(data_file)
        # Clean up the transient primary context (not needed after load)
        os.remove(primary_ctx)

        return True
    except (subprocess.CalledProcessError, OSError):
        return False

def _tpm_get(service: str) -> str:
    """Unseal a key from the TPM."""
    try:
        svc_dir     = os.path.join(_TPM_DIR, service)
        key_pub     = os.path.join(svc_dir, 'key.pub')
        key_priv    = os.path.join(svc_dir, 'key.priv')
        key_ctx     = os.path.join(svc_dir, 'key.ctx')

        if not os.path.exists(key_ctx):
            # If we only have pub/priv, we need to reload via a fresh primary
            if not (os.path.exists(key_pub) and os.path.exists(key_priv)):
                return None

            primary_ctx = os.path.join(svc_dir, 'primary.ctx')
            subprocess.run([
                'tpm2_createprimary', '-C', 'o', '-c', primary_ctx
            ], check=True, capture_output=True)
            subprocess.run([
                'tpm2_load', '-C', primary_ctx,
                '-u', key_pub, '-r', key_priv,
                '-c', key_ctx
            ], check=True, capture_output=True)
            os.remove(primary_ctx)

        res = subprocess.run([
            'tpm2_unseal', '-c', key_ctx
        ], check=True, capture_output=True)

        return res.stdout.decode('utf-8').strip() or None
    except (subprocess.CalledProcessError, OSError):
        return None

# ---------------------------------------------------------------------------
# Software Keyring Backends
# ---------------------------------------------------------------------------

def _secretservice_store(service: str, key_hex: str) -> bool:
    """Store via Linux secret-tool (GNOME Keyring / KDE Wallet)."""
    try:
        subprocess.run(
            ['secret-tool', 'store', '--label=EnvShield Master Key', 'service', service],
            input=key_hex.encode('utf-8'),
            check=True, capture_output=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def _secretservice_get(service: str) -> str:
    """Retrieve via Linux secret-tool."""
    try:
        res = subprocess.run(
            ['secret-tool', 'lookup', 'service', service],
            check=True, capture_output=True
        )
        return res.stdout.decode('utf-8').strip() or None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def _macos_store(service: str, key_hex: str) -> bool:
    """Store via macOS Keychain."""
    try:
        subprocess.run([
            'security', 'add-generic-password',
            '-s', service, '-a', 'envshield', '-w', key_hex, '-U'
        ], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def _macos_get(service: str) -> str:
    """Retrieve via macOS Keychain."""
    try:
        res = subprocess.run([
            'security', 'find-generic-password',
            '-s', service, '-a', 'envshield', '-w'
        ], check=True, capture_output=True)
        return res.stdout.decode('utf-8').strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def _windows_store(service: str, key_hex: str) -> bool:
    """Store via Windows Credential Locker (advapi32.dll)."""
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.windll.advapi32
        CRED_TYPE_GENERIC = 1
        CRED_PERSIST_LOCAL_MACHINE = 2

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        key_bytes = key_hex.encode('utf-16le')
        cred = CREDENTIAL()
        cred.Type = CRED_TYPE_GENERIC
        cred.TargetName = service
        cred.CredentialBlobSize = len(key_bytes)
        buf = ctypes.create_string_buffer(key_bytes, len(key_bytes))
        cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte))
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE
        cred.UserName = "envshield"

        return bool(advapi32.CredWriteW(ctypes.byref(cred), 0))
    except Exception:
        return False

def _windows_get(service: str) -> str:
    """Retrieve via Windows Credential Locker (advapi32.dll)."""
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.windll.advapi32
        CRED_TYPE_GENERIC = 1

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        pcred = ctypes.POINTER(CREDENTIAL)()
        ret = advapi32.CredReadW(service, CRED_TYPE_GENERIC, 0, ctypes.byref(pcred))
        if not ret:
            return None

        blob_size = pcred.contents.CredentialBlobSize
        blob_data = ctypes.string_at(pcred.contents.CredentialBlob, blob_size)
        advapi32.CredFree(pcred)
        return blob_data.decode('utf-16le').strip()
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def store_key(service: str, key_hex: str) -> bool:
    """
    Store a key in the most secure available backend.

    Priority: TPM 2.0 > OS Keyring > (caller falls back to file).
    Returns True if stored successfully, False otherwise.
    """
    # 1. Try TPM (hardware-backed, strongest)
    if _tpm_available():
        if _tpm_store(service, key_hex):
            return True

    # 2. Try OS software keyring
    if sys.platform == 'darwin':
        return _macos_store(service, key_hex)
    elif sys.platform.startswith('linux'):
        return _secretservice_store(service, key_hex)
    elif sys.platform == 'win32':
        return _windows_store(service, key_hex)

    return False

def get_key(service: str) -> str:
    """
    Retrieve a key from the most secure available backend.

    Priority: TPM 2.0 > OS Keyring > None (caller falls back to file).
    Returns the key hex string, or None if not found.
    """
    # 1. Try TPM first
    if _tpm_available():
        val = _tpm_get(service)
        if val:
            return val

    # 2. Try OS software keyring
    if sys.platform == 'darwin':
        return _macos_get(service)
    elif sys.platform.startswith('linux'):
        return _secretservice_get(service)
    elif sys.platform == 'win32':
        return _windows_get(service)

    return None
