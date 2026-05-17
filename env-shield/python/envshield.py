import os
import json
import base64
import hmac
import hashlib
import subprocess

def _get_master_key():
    # 1. Check ENV_SHIELD_KEY in environment
    if 'ENV_SHIELD_KEY' in os.environ:
        return bytes.fromhex(os.environ['ENV_SHIELD_KEY'])
        
    # 2. Check Colab userdata
    try:
        from google.colab import userdata
        key = userdata.get('ENV_SHIELD_KEY')
        if key:
            return bytes.fromhex(key)
    except ImportError:
        pass
        
    # 3. Check local env-shield.key file
    key_path = os.path.join(os.getcwd(), 'env-shield.key')
    if os.path.exists(key_path):
        with open(key_path, 'r') as f:
            return bytes.fromhex(f.read().strip())
            
    raise RuntimeError("Master key not found. Set ENV_SHIELD_KEY or provide env-shield.key")

def _load_enc_data():
    enc_path = os.path.join(os.getcwd(), '.env.enc')
    if not os.path.exists(enc_path):
        return {}
    with open(enc_path, 'r') as f:
        return json.load(f)

def _decrypt_value(encrypted_obj):
    key = _get_master_key()
    iv = bytes.fromhex(encrypted_obj['iv'])
    auth_tag = bytes.fromhex(encrypted_obj['auth_tag'])
    ciphertext = base64.b64decode(encrypted_obj['ciphertext'])
    
    # Verify HMAC (Auth Tag)
    hmac_key = hashlib.sha256(key).digest()
    computed_tag = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    
    if not hmac.compare_digest(auth_tag, computed_tag):
        raise RuntimeError("Authentication failed! Data has been tampered with.")
        
    # Decrypt via openssl
    cmd = ['openssl', 'enc', '-d', '-aes-256-cbc', '-K', key.hex(), '-iv', iv.hex()]
    proc = subprocess.run(cmd, input=ciphertext, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"OpenSSL decryption failed: {proc.stderr.decode('utf-8')}")
        
    return proc.stdout.decode('utf-8')

# We patch os.environ.__class__.__getitem__ and .get dynamically
_original_getitem = os.environ.__class__.__getitem__
_original_get = os.environ.__class__.get
_enc_cache = None

def _envshield_getitem(self, key):
    try:
        return _original_getitem(self, key)
    except KeyError:
        global _enc_cache
        if _enc_cache is None:
            _enc_cache = _load_enc_data()
            
        if key in _enc_cache:
            return _decrypt_value(_enc_cache[key])
        raise

def _envshield_get(self, key, default=None):
    try:
        return _envshield_getitem(self, key)
    except KeyError:
        return default

os.environ.__class__.__getitem__ = _envshield_getitem
os.environ.__class__.get = _envshield_get
