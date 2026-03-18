// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_SECURITY_H
#define LSL_SECURITY_H

#include "lsl_esp32_types.h"
#include "lsl_key_manager.h"
#include <stdint.h>
#include <stddef.h>

/* Crypto sizes (from libsodium ChaCha20-Poly1305 IETF) */
#define LSL_SECURITY_SESSION_KEY_SIZE 32
#define LSL_SECURITY_AUTH_TAG_SIZE    16
#define LSL_SECURITY_NONCE_WIRE_SIZE  8 /* nonce on wire is 8 bytes (uint64_t LE) */

/* Security session state for one TCP connection */
typedef struct {
    uint8_t session_key[LSL_SECURITY_SESSION_KEY_SIZE];
    uint64_t send_nonce;
    uint64_t recv_nonce_high;
    int active;           /* 1 if session key is derived */
    int recv_nonce_valid; /* 1 after first message received */
} lsl_security_session_t;

/* Security configuration (loaded from NVS, shared across connections) */
typedef struct {
    int enabled;
    uint8_t public_key[LSL_KEY_PUBLIC_SIZE];
    uint8_t secret_key[LSL_KEY_SECRET_SIZE];
} lsl_security_config_t;

/* Domain separator for BLAKE2b key derivation (matches secureLSL) */
#define LSL_SECURITY_HKDF_CONTEXT "lsl-sess"

/* Derive a session key from our Ed25519 secret key and the peer's Ed25519 public key.
 * Uses Ed25519->X25519 conversion + DH + BLAKE2b with canonical key ordering.
 * Returns LSL_ESP32_OK on success. */
lsl_esp32_err_t security_derive_session_key(const uint8_t *our_ed25519_pk,
                                            const uint8_t *our_ed25519_sk,
                                            const uint8_t *peer_ed25519_pk,
                                            lsl_security_session_t *session);

/* Encrypt plaintext using ChaCha20-Poly1305 with the session's send nonce.
 * Increments send_nonce after encryption.
 * ciphertext_out must be at least plaintext_len + LSL_SECURITY_AUTH_TAG_SIZE bytes.
 * nonce_out receives the 8-byte nonce used (for wire framing).
 * Returns number of ciphertext bytes, or -1 on error. */
int security_encrypt(lsl_security_session_t *session, const uint8_t *plaintext,
                     size_t plaintext_len, uint8_t *ciphertext_out, size_t ciphertext_max,
                     uint64_t *nonce_out);

/* Decrypt ciphertext using ChaCha20-Poly1305 with the given nonce.
 * Verifies nonce is greater than recv_nonce_high (replay prevention).
 * plaintext_out must be at least ciphertext_len - LSL_SECURITY_AUTH_TAG_SIZE bytes.
 * Returns number of plaintext bytes, or -1 on error (auth failure or replay). */
int security_decrypt(lsl_security_session_t *session, uint64_t wire_nonce,
                     const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext_out,
                     size_t plaintext_max);

/* Initialize a session to inactive state */
void security_session_init(lsl_security_session_t *session);

/* Clear session key material */
void security_session_clear(lsl_security_session_t *session);

/* Load security config from NVS if globally enabled.
 * On return: cfg->enabled=1 with keys if security active,
 * cfg->enabled=0 with zeroed keys if security not active.
 * Returns LSL_ESP32_OK on success (including security-not-enabled),
 * or error if security is enabled but keys cannot be loaded. */
lsl_esp32_err_t security_config_load(lsl_security_config_t *cfg);

/* Clear security config, zeroing all key material */
void security_config_clear(lsl_security_config_t *cfg);

/* Verify peer's base64-encoded public key matches ours and derive session key.
 * Returns LSL_ESP32_OK on success (session_out populated),
 * LSL_ESP32_ERR_INVALID_ARG if peer key is missing or invalid base64,
 * LSL_ESP32_ERR_SECURITY if peer key does not match (unauthorized),
 * or other error on derivation failure. */
lsl_esp32_err_t security_handshake_verify(const lsl_security_config_t *our_config,
                                          const char *peer_pubkey_b64,
                                          lsl_security_session_t *session_out);

#endif /* LSL_SECURITY_H */
