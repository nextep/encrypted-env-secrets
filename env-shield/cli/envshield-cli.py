#!/usr/bin/env python3
import os
import sys
import json
import base64
import hmac
import hashlib
import subprocess

def encrypt_value(value: str, key: bytes):
    iv = os.urandom(16)
    value_bytes = value.encode('utf-8')
    
    # We use aes-256-cbc and manual HMAC because openssl enc does not support AEAD (GCM)
    cmd = ['openssl', 'enc', '-aes-256-cbc', '-K', key.hex(), '-iv', iv.hex()]
    proc = subprocess.run(cmd, input=value_bytes, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"OpenSSL encryption failed: {proc.stderr.decode('utf-8')}")
    ciphertext = proc.stdout
    
    # Generate HMAC-SHA256 (Auth Tag)
    hmac_key = hashlib.sha256(key).digest()
    auth_tag = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    
    return {
        "iv": iv.hex(),
        "auth_tag": auth_tag.hex(),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def main():
    env_file = ".env"
    if len(sys.argv) > 1:
        env_file = sys.argv[1]
    
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
                v = v.strip().strip("'").strip('"') # Basic unquoting
                encrypted_data[k] = encrypt_value(v, master_key)
                
    with open('.env.enc', 'w') as f:
        json.dump(encrypted_data, f, indent=2)
        
    with open('env-shield.key', 'w') as f:
        f.write(master_key.hex())
        
    os.chmod('env-shield.key', 0o600)
        
    print("Successfully encrypted variables.")
    print("Output: .env.enc")
    print("Key: env-shield.key (KEEP THIS SAFE!)")

if __name__ == '__main__':
    main()
