#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SecureChannel SecureChannel;
SecureChannel* sc_create(const uint8_t* psk, size_t psk_len);
void sc_destroy(SecureChannel* sc);

int sc_derive_keys(SecureChannel* sc,
                   const uint8_t* client_random,
                   const uint8_t* server_random);

int sc_seal(SecureChannel* sc,
            int is_client_to_server,
            uint64_t seqno,
            const uint8_t* plaintext,
            size_t pt_len,
            uint8_t* ciphertext,
            size_t* ct_len);

int sc_open(SecureChannel* sc,
            int is_client_to_server,
            uint64_t seqno,
            const uint8_t* ciphertext,
            size_t ct_len,
            uint8_t* plaintext,
            size_t* pt_len);

#ifdef __cplusplus
}
#endif

#endif 