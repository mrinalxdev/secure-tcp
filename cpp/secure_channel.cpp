#include "secure_channel.h"

#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define KEY_LEN     32
#define NONCE_LEN   12
#define TAG_LEN     16

struct SecureChannel {
    uint8_t psk[KEY_LEN];
    uint8_t client_key[KEY_LEN];  
    uint8_t server_key[KEY_LEN];   
    int     keys_derived;
};

static void secure_wipe(void* p, size_t n) {
    if (p && n) {
        sodium_memzero(p, n);
    }
}

SecureChannel* sc_create(const uint8_t* psk, size_t psk_len) {
    if (!psk || psk_len != KEY_LEN){
        return NULL;
    }



    if (sodium_init() < 0){
        return NULL;
    }

    SecureChannel* sc = (SecureChannel*)sodium_malloc(sizeof(SecureChannel));
    if (!sc) return NULL;

    memcpy(sc->psk, psk, KEY_LEN);
    sodium_memzero(sc->client_key, KEY_LEN);
    sodium_memzero(sc->server_key, KEY_LEN);
    sc->keys_derived = 0;
    return sc;
}


void sc_destroy(SecureChannel* sc) {
    if (!sc) return;
    secure_wipe(sc, sizeof(SecureChannel));
    sodium_free(sc);
}

int sc_derive_keys(SecureChannel* sc,
                   const uint8_t* client_random,
                   const uint8_t* server_random) {
    if (!sc || !client_random || !server_random || sc->keys_derived) {
        return -1;
    }

    
    uint8_t salt[64];
    memcpy(salt, client_random, 32);
    memcpy(salt + 32, server_random, 32);

   
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    if (crypto_kdf_hkdf_sha256_extract(prk, salt, sizeof(salt),
                                       sc->psk, KEY_LEN) != 0) {
        return -1;
    }

    const char* info_client = "psk-secure-channel-v1-client";
    const char* info_server = "psk-secure-channel-v1-server";

    if (crypto_kdf_hkdf_sha256_expand(sc->client_key, KEY_LEN,
                                      (const uint8_t*)info_client, strlen(info_client),
                                      prk) != 0) {
        return -1;
    }
    if (crypto_kdf_hkdf_sha256_expand(sc->server_key, KEY_LEN,
                                      (const uint8_t*)info_server, strlen(info_server),
                                      prk) != 0) {
        return -1;
    }

    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(salt, sizeof(salt));
    sc->keys_derived = 1;
    return 0;
}

static void make_nonce(uint8_t nonce[NONCE_LEN], uint64_t seqno) {
    memset(nonce, 0, NONCE_LEN);
    for (int i = 0; i < 8; i++) {
        nonce[NONCE_LEN - 1 - i] = (uint8_t)(seqno >> (i * 8));
    }
}

int sc_seal(SecureChannel* sc,
            int is_client_to_server,
            uint64_t seqno,
            const uint8_t* plaintext,
            size_t pt_len,
            uint8_t* ciphertext,
            size_t* ct_len) {
    if (!sc || !sc->keys_derived || !ciphertext || !ct_len) {
        return -1;
    }
    if (pt_len > 0 && !plaintext) return -1;

    const uint8_t* key = is_client_to_server ? sc->client_key : sc->server_key;

    uint8_t nonce[NONCE_LEN];
    make_nonce(nonce, seqno);

    unsigned long long actual_ct_len = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, &actual_ct_len,
        plaintext, pt_len,
        NULL, 0,          
        NULL,           
        nonce,
        key);

    if (rc != 0) return -1;

    *ct_len = (size_t)actual_ct_len;
    return 0;
}

int sc_open(SecureChannel* sc,
            int is_client_to_server,
            uint64_t seqno,
            const uint8_t* ciphertext,
            size_t ct_len,
            uint8_t* plaintext,
            size_t* pt_len) {
    if (!sc || !sc->keys_derived || !ciphertext || !plaintext || !pt_len) {
        return -1;
    }
    if (ct_len < TAG_LEN) return -1;

    const uint8_t* key = is_client_to_server ? sc->client_key : sc->server_key;

    uint8_t nonce[NONCE_LEN];
    make_nonce(nonce, seqno);

    unsigned long long actual_pt_len = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext, &actual_pt_len,
        NULL,            
        ciphertext, ct_len,
        NULL, 0,          
        nonce,
        key);

    if (rc != 0) {
        return -1;
    }

    *pt_len = (size_t)actual_pt_len;
    return 0;
}