import os
import json
import base64
import ctypes
import ctypes.util

EVP_CTRL_AEAD_GET_TAG = 16
EVP_CTRL_AEAD_SET_TAG = 17
_libcrypto = None

def _get_libcrypto():
    global _libcrypto
    if _libcrypto is not None:
        return _libcrypto

    lib_path = ctypes.util.find_library('crypto')
    if not lib_path:
        raise RuntimeError("libcrypto not found. OpenSSL is required.")
    lib = ctypes.CDLL(lib_path)
    
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
    
    # Encrypt args
    lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
    lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    
    # Decrypt args
    lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
    lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    
    # Shared args
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    
    _libcrypto = lib
    return lib

def encrypt(plaintext: str, key: bytes) -> dict:
    lib = _get_libcrypto()
        
    iv = os.urandom(12) # GCM standard IV size
    value_bytes = plaintext.encode('utf-8')
    
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("Failed to create EVP_CIPHER_CTX")
        
    try:
        lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None)
        lib.EVP_EncryptInit_ex(ctx, None, None, key, iv)
        
        out = ctypes.create_string_buffer(len(value_bytes) + 16)
        outl = ctypes.c_int(0)
        
        lib.EVP_EncryptUpdate(ctx, out, ctypes.byref(outl), value_bytes, len(value_bytes))
        cipher_len = outl.value
        
        lib.EVP_EncryptFinal_ex(ctx, ctypes.byref(out, cipher_len), ctypes.byref(outl))
        cipher_len += outl.value
        
        ciphertext = out.raw[:cipher_len]
        
        tag = ctypes.create_string_buffer(16)
        lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)
        auth_tag = tag.raw
        
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
    
    return {
        "iv": iv.hex(),
        "auth_tag": auth_tag.hex(),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt(encrypted_obj: dict, key: bytes) -> str:
    lib = _get_libcrypto()
        
    iv = bytes.fromhex(encrypted_obj['iv'])
    auth_tag = bytes.fromhex(encrypted_obj['auth_tag'])
    ciphertext = base64.b64decode(encrypted_obj['ciphertext'])
    
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("Failed to create EVP_CIPHER_CTX")
        
    try:
        lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None)
        lib.EVP_DecryptInit_ex(ctx, None, None, key, iv)
        
        out = ctypes.create_string_buffer(len(ciphertext))
        outl = ctypes.c_int(0)
        
        lib.EVP_DecryptUpdate(ctx, out, ctypes.byref(outl), ciphertext, len(ciphertext))
        plaintext_len = outl.value
        
        # Set expected tag
        lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, len(auth_tag), auth_tag)
        
        ret = lib.EVP_DecryptFinal_ex(ctx, ctypes.byref(out, plaintext_len), ctypes.byref(outl))
        if ret <= 0:
            raise RuntimeError("Authentication failed! Data has been tampered with.")
            
        plaintext_len += outl.value
        plaintext = out.raw[:plaintext_len]
        
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
        
    return plaintext.decode('utf-8')
