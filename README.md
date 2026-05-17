# EnvShield

**Zero-dependency, JIT-decrypted environment variable encryption for Python, Node.js, and C.**

EnvShield encrypts your `.env` secrets at rest using AES-256-GCM and decrypts them strictly Just-In-Time in memory.  No plaintext keys on disk.  No `pip install cryptography`.  No `npm install dotenv-vault`.  Just native OS primitives and raw libcrypto bindings.

---

## Why This Exists

Every major supply-chain breach in the last year shares the same root cause: **plaintext secrets sitting where they shouldn't be.**

- [Grafana (May 2026)](https://thehackernews.com/2026/05/grafana-github-token-breach-led-to.html) — A stolen GitHub token gave attackers full codebase access.  
- [Trivy (March 2026)](https://thehackernews.com/2026/03/trivy-security-scanner-github-actions.html) — Compromised GH Actions scraped `/proc/*/environ` to exfiltrate PATs, AWS keys, and crypto wallets from CI runners.

EnvShield was built to kill this attack vector dead:

1. **Secrets are never stored in plaintext** — `.env.enc` contains AES-256-GCM ciphertexts.
2. **Master keys live in the OS keyring** — GNOME Keyring, macOS Keychain, or Windows Credential Locker.  Not in files.  Not in env vars.
3. **Active environment wiping** — If a CI runner injects a key via `ENV_SHIELD_KEY`, EnvShield reads it once, then `memset`s the raw C environ block to null bytes.  Any malware polling `/proc` finds nothing.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Developer Machine                         │
│                                                                  │
│   .env (plaintext)                                               │
│       │                                                          │
│       ▼                                                          │
│   envshield-cli.py --store github "ghp_..."                      │
│       │                                                          │
│       ├──► ~/.envshield/github.enc   (AES-256-GCM ciphertext)    │
│       └──► OS Keyring                (master key, encrypted)     │
│                                                                  │
│   ┌─── Your Application ────────────────────────────────────┐    │
│   │  import envshield                                       │    │
│   │  api_key = os.environ['SECRET_API_KEY']                 │    │
│   │           │                                             │    │
│   │           ▼                                             │    │
│   │  1. Check OS keyring for master key                     │    │
│   │  2. If ENV_SHIELD_KEY in env → read + memset(0)         │    │
│   │  3. Decrypt ciphertext JIT via libcrypto ctypes          │    │
│   │  4. Return plaintext (never stored persistently)        │    │
│   └─────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

## Getting Started — Interactive Setup Wizard

The fastest way to get running is the interactive wizard. It detects your system, lets you pick a key storage mode, generates keys, and sets up integrations:

### Linux / macOS

```bash
bash scripts/envshield-setup.sh
```

### Windows (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\envshield-setup.ps1
```

The wizard will walk you through:

1. **System detection** — Checks for Python 3, libcrypto, TPM 2.0, and OS keyring availability.
2. **Mode selection** — TPM (hardware), OS Keyring (software), CI/CD env var, or file-based.
3. **Key generation** — Generate a new 256-bit key or import an existing one.
4. **Encryption** — Encrypt a `.env` file or store individual service tokens.
5. **Git integration** — Optionally configure the Git credential helper.

> **Tip:** For CI/CD pipelines, select the "CI/CD Environment Variable" mode. The wizard will display the key for you to paste into your provider's secrets UI.

---

## Quick Start (Manual)

### 1. Encrypt a `.env` file

```bash
python3 cli/envshield-cli.py .env
```

This generates:
- `.env.enc` — JSON containing IV + auth tag + ciphertext per variable.
- Master key → stored in your **OS keyring** automatically.

> **Headless / CI mode:** Pass `--file` to write the key to `env-shield.key` instead.
> ```bash
> python3 cli/envshield-cli.py --file .env
> ```

### 2. Decrypt in Python

Drop the `python/envshield/` directory into your project (or `pip install .` from `python/`):

```python
import envshield   # patches os.environ on import
import os

# Transparently decrypted JIT — the value never touches os.environ
api_key = os.environ['SECRET_API_KEY']
```

The interceptor resolves the master key using this priority chain:

| Priority | Source | Use Case |
|----------|--------|----------|
| 1 | OS Keyring | Production (workstations, locked-down servers) |
| 2 | `ENV_SHIELD_KEY` env var | CI/CD runners (auto-wiped from memory after read) |
| 3 | Colab `userdata` | Google Colab notebooks |
| 4 | `env-shield.key` file | Local development / testing only |

### 3. Decrypt in Node.js

```javascript
require('./node/envshield');

// process.env is intercepted via Proxy
const apiKey = process.env.SECRET_API_KEY;
```

### 4. Decrypt in C

```c
#include "envshield.h"

char *key = envshield_get("SECRET_API_KEY");
// Use key...
free(key);  // caller owns the allocation
```

---

## Protecting Integration Tokens (GitHub, AWS, NPM, etc.)

The `--store` command encrypts a single token and saves it globally under `~/.envshield/`:

```bash
# GitHub PAT
python3 cli/envshield-cli.py --store github "ghp_xxxxxxxxxxxx"

# AWS Access Key
python3 cli/envshield-cli.py --store aws "AKIAIOSFODNN7EXAMPLE"

# NPM Token
python3 cli/envshield-cli.py --store npm "npm_xxxxxxxxxxxx"
```

Master keys are stored in the most secure available backend (TPM 2.0 > OS keyring) under `envshield-<service>`.

### Git Credential Helper

EnvShield ships a native Git credential helper that decrypts your PAT JIT for every `git push` / `git pull`:

```bash
# 1. Store the token:
python3 cli/envshield-cli.py --store github "ghp_your_token"

# 2. Register the helper:
git config --global credential.helper \
    "/usr/bin/env python3 $(realpath cli/git-credential-envshield.py)"
```

The helper implements the [standard Git credential protocol](https://git-scm.com/docs/gitcredentials).  It maps hosts to service names automatically:

| Host | Service |
|------|---------|
| `github.com` | `github` |
| `gitlab.com` | `gitlab` |
| `bitbucket.org` | `bitbucket` |

---

## Active Environment Wiping

When `ENV_SHIELD_KEY` is passed as an environment variable (typical in CI/CD), EnvShield performs a **C-level memory scrub** immediately after reading it:

```python
# What happens internally:
libc = ctypes.CDLL(None)
environ_ptr = ctypes.POINTER(ctypes.c_char_p).in_dll(libc, "environ")
# Walk the array, find the entry, memset it to 0x00
libc.memset(environ_ptr[i], 0, len(raw_entry))
```

**Result:** `getenv("ENV_SHIELD_KEY")` returns `NULL`.  Child processes don't inherit it.  Background malware scraping the environ array finds nothing.

> **Note:** `/proc/self/environ` is a kernel-level snapshot created at `execve()` time and is immutable.  The wipe targets the live C `environ` array, which is what `getenv()`, child process inheritance, and most scraping tools actually read.

You can also call the wipe function directly:

```python
from envshield import wipe_environ_key

wipe_environ_key('AWS_SECRET_ACCESS_KEY')
wipe_environ_key('GITHUB_TOKEN')
```

---

## Master Key Storage: The Priority Chain

EnvShield resolves the master key using a strict, defense-in-depth priority chain:

### 1. TPM 2.0 (Hardware-Backed — Strongest)

If a TPM 2.0 chip and `tpm2-tools` are available, EnvShield seals the master key directly to the hardware's Storage Root Key (SRK).  The sealed blob is stored at `~/.envshield/tpm/<service>/` and can **only** be unsealed on the same physical machine.

```bash
# Install TPM tools (Ubuntu/Debian):
sudo apt install tpm2-tools

# EnvShield automatically uses TPM if /dev/tpmrm0 exists.
# No extra flags needed — it's the highest-priority backend.
python3 cli/envshield-cli.py --store github "ghp_..."
```

| Property | Detail |
|----------|--------|
| **Seal target** | Owner hierarchy SRK (`tpm2_createprimary -C o`) |
| **Operations** | `tpm2_create` → `tpm2_load` → `tpm2_unseal` |
| **Portability** | None (by design — key is bound to the silicon) |
| **Disk artifact** | `~/.envshield/tpm/<service>/key.pub` + `key.priv` (useless without the TPM) |

> **Recovery:** If the TPM is cleared or the hardware changes, the sealed key is irrecoverable.  Use `--file` to create an offline backup before provisioning.

### 2. OS Software Keyring

| Platform | Backend | Command |
|----------|---------|--------|
| Linux | GNOME Keyring / KDE Wallet via `secret-tool` | `secret-tool lookup service envshield` |
| macOS | Keychain via `security` | `security find-generic-password -s envshield -w` |
| Windows | Credential Locker via `advapi32.dll` | `CredReadW` / `CredWriteW` |

The CLI stores keys here by default when TPM is unavailable.  No files.  No env vars.  The key material is managed by the OS kernel's credential subsystem.

### 3. Environment Variable (CI/CD Fallback)

In headless environments (GitHub Actions, GitLab CI, Jenkins), inject the key via:

```yaml
env:
  ENV_SHIELD_KEY: ${{ secrets.ENV_SHIELD_KEY }}
```

EnvShield reads it **once**, then immediately wipes it from the process environ block.

### 4. File Fallback (Development Only)

For local development, pass `--file` to the CLI:

```bash
python3 cli/envshield-cli.py --file .env
```

This writes `env-shield.key`.  **Do not commit this file.**  Add it to `.gitignore`.

---

## Distributing the Library

The Python package has zero external dependencies.  Install it locally:

```bash
cd python && pip install .
```

Then use it in any script:

```python
from envshield.core import encrypt, decrypt
from envshield import keyring

# Encrypt a value
key = os.urandom(32)
ciphertext = encrypt("my_secret", key)

# Store the key in the OS keyring
keyring.store_key("my-service", key.hex())

# Later: retrieve and decrypt
key_hex = keyring.get_key("my-service")
plaintext = decrypt(ciphertext, bytes.fromhex(key_hex))
```

---

## Security Model

| Property | Implementation |
|----------|---------------|
| **Algorithm** | AES-256-GCM (authenticated encryption with associated data) |
| **Crypto Backend** | OS-native `libcrypto.so` via Python `ctypes` / Node `crypto` / C `libssl` |
| **Key Storage** | TPM 2.0 (hardware) > OS keyring (software) — never plaintext on disk in production |
| **Memory Safety** | Decrypted values are transient — never written to `os.environ` or `process.env` |
| **Environment Wiping** | C-level `memset(0)` on the raw `environ` block after key extraction |
| **Dependencies** | **Zero.** No pip.  No npm.  No cgo.  Pure native bindings. |

---

## Building the C Library

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt install build-essential libssl-dev

# RHEL / Fedora
sudo yum install gcc openssl-devel

# macOS (Homebrew)
brew install openssl
```

### Compilation

```bash
# Static library (libenvshield.a)
make

# Shared library (libenvshield.so)
make shared

# Build and run tests
make test

# Install to /usr/local
sudo make install
```

### Linking Against Your Application

```bash
# Static linking
gcc -o myapp myapp.c -L. -lenvshield -lssl -lcrypto

# Shared linking
gcc -o myapp myapp.c -L. -lenvshield -lssl -lcrypto
export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH
```

### Usage in C

```c
#include "envshield.h"

int main() {
    char *key = envshield_getenv("SECRET_API_KEY");
    if (key) {
        printf("Key: %s\n", key);
        envshield_free(key);  // securely wipes + frees
    }
    return 0;
}
```

> **Important:** Always call `envshield_free()` on the returned pointer.  It uses `volatile` memory zeroing before `free()` to ensure the plaintext doesn't linger in freed heap blocks.

### macOS Notes

Homebrew installs OpenSSL to a non-standard path.  Uncomment the `OPENSSL_DIR` lines in the `Makefile` or pass it explicitly:

```bash
make OPENSSL_DIR=/usr/local/opt/openssl@3
```

---

## File Structure

```
env-shield-project/
├── Makefile                         # C library build system
├── cli/
│   ├── envshield-cli.py            # Encryption CLI (AES-256-GCM via libcrypto ctypes)
│   └── git-credential-envshield.py # Git credential helper (standard protocol)
├── python/
│   ├── setup.py                    # pip-installable package
│   └── envshield/
│       ├── __init__.py             # os.environ interceptor + env wiping
│       ├── core.py                 # AES-256-GCM encrypt/decrypt via ctypes
│       └── keyring.py             # Cross-platform keyring (TPM + OS + Windows)
├── node/
│   └── envshield.js                # process.env Proxy interceptor
├── c/
│   ├── envshield.h                 # Public API header
│   └── envshield.c                 # Native C interceptor (links libssl)
├── scripts/
│   ├── envshield-setup.sh          # Interactive setup wizard (Linux/macOS)
│   └── envshield-setup.ps1         # Interactive setup wizard (Windows)
├── test.sh                         # E2E integration tests
└── README.md
```

---

## Testing

```bash
# Full E2E (Python + Node.js + C)
./test.sh

# C library only
make test
```

---

## License

MIT
