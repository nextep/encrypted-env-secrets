# EnvShield

EnvShield is a universal, zero-dependency Just-In-Time (JIT) environment variable encryption system.

It allows you to keep your `.env` variables completely encrypted at rest in a `.env.enc` file, and decrypt them strictly JIT in memory—without installing complex external cryptographic packages like `cryptography` via pip or npm.

## Core Features
- **Language-Agnostic Encryption**: The CLI generates a `.env.enc` and an `env-shield.key`.
- **Zero-Dependency**: Uses native `crypto` in Node.js, and shells out to OS-level `openssl enc` in Python. 
- **Security First**: Uses AES-256-CBC with an HMAC-SHA256 Auth Tag. Keys are wiped from memory immediately after decryption via Python and Node.js garbage collectors. Plaintext values are never stored persistently in `os.environ` or `process.env`.

## 1. Encrypting Variables

Run the universal CLI (requires Python 3 and OpenSSL installed on the system):

```bash
python3 cli/envshield-cli.py .env
```

This generates two files:
- `.env.enc` (The encrypted values + Initialization Vectors + Auth Tags)
- `env-shield.key` (The Master Key - **DO NOT COMMIT THIS!**)

## 2. Using in Python (Jupyter, Colab, Scripts)

This is a single drop-in file. No `pip install` required! 

1. Copy `python/envshield.py` into your project.
2. Ensure `.env.enc` and `env-shield.key` are accessible, or set the `ENV_SHIELD_KEY` environment variable (e.g., via Colab Secrets).
3. Import the module!

```python
import envshield
import os

# os.environ is now patched to seamlessly decrypt values Just-In-Time
api_key = os.environ.get('SECRET_API_KEY')
print("My Key:", api_key)
```

## 3. Using in Node.js

This is a single drop-in file. No `npm install` required!

1. Copy `node/envshield.js` into your project.
2. Require it at the top of your app.

```javascript
require('./envshield');

// process.env is seamlessly intercepted via Proxy
const apiKey = process.env.SECRET_API_KEY;
console.log("My Key:", apiKey);
```

## Testing

Run the end-to-end test script to verify encryption and cross-language decryption works correctly:

```bash
./test.sh
```
