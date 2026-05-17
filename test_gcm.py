import ctypes
import ctypes.util

libcrypto_path = ctypes.util.find_library('crypto')
libcrypto = ctypes.CDLL(libcrypto_path)

libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

libcrypto.EVP_aes_256_gcm.restype = ctypes.c_void_p

libcrypto.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
libcrypto.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
libcrypto.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
libcrypto.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]

EVP_CTRL_AEAD_GET_TAG = 16

ctx = libcrypto.EVP_CIPHER_CTX_new()
libcrypto.EVP_EncryptInit_ex(ctx, libcrypto.EVP_aes_256_gcm(), None, None, None)

key = b'01234567890123456789012345678901'
iv = b'012345678901'

libcrypto.EVP_EncryptInit_ex(ctx, None, None, key, iv)

out = ctypes.create_string_buffer(100)
outl = ctypes.c_int(0)
in_data = b'hello world'
libcrypto.EVP_EncryptUpdate(ctx, out, ctypes.byref(outl), in_data, len(in_data))
cipher = out.raw[:outl.value]

outl2 = ctypes.c_int(0)
libcrypto.EVP_EncryptFinal_ex(ctx, out, ctypes.byref(outl2))

tag = ctypes.create_string_buffer(16)
libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)

print("Cipher:", cipher.hex())
print("Tag:", tag.raw.hex())

libcrypto.EVP_CIPHER_CTX_free(ctx)
