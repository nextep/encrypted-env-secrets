#include "envshield.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

/* Helper to wipe memory */
static void secure_wipe(void *v, size_t n) {
    if (!v) return;
#ifdef __STDC_LIB_EXT1__
    memset_s(v, n, 0, n);
#else
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
#endif
}

void envshield_free(char* ptr) {
    if (!ptr) return;
    secure_wipe(ptr, strlen(ptr));
    free(ptr);
}

/* Helper to convert hex string to byte array */
static int hex2bin(const char *hex, unsigned char *bin, size_t bin_max_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > bin_max_len) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        unsigned int val;
        if (sscanf(hex + 2*i, "%2x", &val) != 1) return -1;
        bin[i] = (unsigned char)val;
    }
    return len / 2;
}

/* Base64 decoding using OpenSSL */
static int b64decode(const char *b64, unsigned char *out) {
    size_t len = strlen(b64);
    int pad = 0;
    if (len > 0 && b64[len-1] == '=') pad++;
    if (len > 1 && b64[len-2] == '=') pad++;
    int out_len = EVP_DecodeBlock(out, (const unsigned char*)b64, len);
    if (out_len < 0) return -1;
    return out_len - pad;
}

/* Extract a JSON string value given a key. Very rudimentary string matching. */
static int extract_json_value(const char *json, const char *key, char *out, size_t out_max) {
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\": \"", key);
    const char *pos = strstr(json, search_key);
    if (!pos) return -1;
    pos += strlen(search_key);
    const char *end = strchr(pos, '"');
    if (!end) return -1;
    size_t len = end - pos;
    if (len >= out_max) return -1;
    strncpy(out, pos, len);
    out[len] = '\0';
    return 0;
}

/* Find the block for a specific environment variable */
static const char* find_env_block(const char *json, const char *env_name) {
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\": {", env_name);
    return strstr(json, search_key);
}

/* Get master key (returns 32 bytes) */
static int get_master_key(unsigned char *key) {
    char *env_key = getenv("ENV_SHIELD_KEY");
    if (env_key) {
        if (hex2bin(env_key, key, 32) == 32) return 0;
    }
    
    FILE *f = fopen("env-shield.key", "r");
    if (f) {
        char hex[65] = {0};
        if (fread(hex, 1, 64, f) == 64) {
            fclose(f);
            if (hex2bin(hex, key, 32) == 32) return 0;
        } else {
            fclose(f);
        }
    }
    return -1;
}

char* envshield_getenv(const char* name) {
    /* 1. Check native environment first */
    char *native_val = getenv(name);
    if (native_val) {
        return strdup(native_val);
    }

    /* 2. Read .env.enc */
    FILE *f = fopen(".env.enc", "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *json = malloc(fsize + 1);
    if (!json) { fclose(f); return NULL; }
    if (fread(json, 1, fsize, f) != (size_t)fsize) {
        fclose(f);
        free(json);
        return NULL;
    }
    fclose(f);
    json[fsize] = '\0';

    /* 3. Find block for the variable */
    const char *block = find_env_block(json, name);
    if (!block) {
        free(json);
        return NULL;
    }

    /* Extract fields */
    char iv_hex[64] = {0};
    char auth_hex[128] = {0};
    char b64_cipher[1024] = {0}; /* Max 1KB for env var ciphertext should be enough */

    if (extract_json_value(block, "iv", iv_hex, sizeof(iv_hex)) != 0 ||
        extract_json_value(block, "auth_tag", auth_hex, sizeof(auth_hex)) != 0 ||
        extract_json_value(block, "ciphertext", b64_cipher, sizeof(b64_cipher)) != 0) {
        free(json);
        return NULL;
    }
    free(json);

    /* Decode hex and base64 */
    unsigned char iv[12];
    unsigned char auth_tag[16];
    unsigned char ciphertext[1024];
    
    if (hex2bin(iv_hex, iv, sizeof(iv)) != 12) return NULL;
    if (hex2bin(auth_hex, auth_tag, sizeof(auth_tag)) != 16) return NULL;
    int cipher_len = b64decode(b64_cipher, ciphertext);
    if (cipher_len < 0) return NULL;

    /* Get master key */
    unsigned char master_key[32];
    if (get_master_key(master_key) != 0) {
        fprintf(stderr, "EnvShield Error: Master key not found.\n");
        return NULL;
    }

    /* Set up GCM decryption */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secure_wipe(master_key, 32);
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_wipe(master_key, 32);
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, master_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_wipe(master_key, 32);
        return NULL;
    }

    unsigned char *plaintext = malloc(cipher_len + 32); /* Extra for padding */
    int len1 = 0, len2 = 0;

    if (EVP_DecryptUpdate(ctx, plaintext, &len1, ciphertext, cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        secure_wipe(master_key, 32);
        return NULL;
    }

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, auth_tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        secure_wipe(master_key, 32);
        return NULL;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len1, &len2);
    if (ret <= 0) {
        fprintf(stderr, "EnvShield Error: Authentication failed. Data tampered.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        secure_wipe(master_key, 32);
        return NULL;
    }

    int total_len = len1 + len2;
    plaintext[total_len] = '\0';
    
    EVP_CIPHER_CTX_free(ctx);
    
    /* Wipe sensitive keys */
    secure_wipe(master_key, 32);

    return (char*)plaintext;
}
