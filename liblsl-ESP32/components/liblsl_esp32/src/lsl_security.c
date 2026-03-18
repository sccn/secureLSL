// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_security.h"
#include "lsl_esp32.h"
#include "lsl_key_manager.h"
#include "lsl_protocol.h" /* LE compile-time check for nonce byte order */
#include "esp_log.h"
#include "sodium.h"
#include <string.h>

static const char *TAG = "lsl_security";

void security_session_init(lsl_security_session_t *session)
{
    if (session) {
        sodium_memzero(session, sizeof(*session));
    }
}

void security_session_clear(lsl_security_session_t *session)
{
    if (session) {
        sodium_memzero(session, sizeof(*session));
    }
}

lsl_esp32_err_t security_derive_session_key(const uint8_t *our_ed25519_pk,
                                            const uint8_t *our_ed25519_sk,
                                            const uint8_t *peer_ed25519_pk,
                                            lsl_security_session_t *session)
{
    if (!our_ed25519_pk || !our_ed25519_sk || !peer_ed25519_pk || !session) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    /* Step 1: Convert Ed25519 keys to X25519 */
    uint8_t our_x25519_sk[crypto_scalarmult_SCALARBYTES];
    uint8_t peer_x25519_pk[crypto_scalarmult_BYTES];

    if (crypto_sign_ed25519_sk_to_curve25519(our_x25519_sk, our_ed25519_sk) != 0) {
        ESP_LOGE(TAG, "Failed to convert our secret key to X25519 (key corrupted?)");
        sodium_memzero(our_x25519_sk, sizeof(our_x25519_sk));
        return LSL_ESP32_ERR_SECURITY;
    }
    if (crypto_sign_ed25519_pk_to_curve25519(peer_x25519_pk, peer_ed25519_pk) != 0) {
        ESP_LOGE(TAG, "Failed to convert peer public key to X25519");
        sodium_memzero(our_x25519_sk, sizeof(our_x25519_sk));
        return LSL_ESP32_ERR_SECURITY;
    }

    /* Step 2: X25519 Diffie-Hellman */
    uint8_t shared_secret[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared_secret, our_x25519_sk, peer_x25519_pk) != 0) {
        ESP_LOGE(TAG, "DH key exchange produced degenerate shared secret");
        sodium_memzero(our_x25519_sk, sizeof(our_x25519_sk));
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return LSL_ESP32_ERR_SECURITY;
    }

    /* Step 3: Derive session key with BLAKE2b.
     * Hash: shared_secret || HKDF_CONTEXT || pk_smaller || pk_larger
     * Canonical key ordering ensures both sides derive the same key. */
    crypto_generichash_state state;
    if (crypto_generichash_init(&state, NULL, 0, LSL_SECURITY_SESSION_KEY_SIZE) != 0) {
        sodium_memzero(our_x25519_sk, sizeof(our_x25519_sk));
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return LSL_ESP32_ERR_SECURITY;
    }

    crypto_generichash_update(&state, shared_secret, sizeof(shared_secret));
    crypto_generichash_update(&state, (const uint8_t *)LSL_SECURITY_HKDF_CONTEXT,
                              sizeof(LSL_SECURITY_HKDF_CONTEXT) - 1);

    /* Order public keys consistently (smaller first) */
    if (memcmp(our_ed25519_pk, peer_ed25519_pk, LSL_KEY_PUBLIC_SIZE) < 0) {
        crypto_generichash_update(&state, our_ed25519_pk, LSL_KEY_PUBLIC_SIZE);
        crypto_generichash_update(&state, peer_ed25519_pk, LSL_KEY_PUBLIC_SIZE);
    } else {
        crypto_generichash_update(&state, peer_ed25519_pk, LSL_KEY_PUBLIC_SIZE);
        crypto_generichash_update(&state, our_ed25519_pk, LSL_KEY_PUBLIC_SIZE);
    }

    crypto_generichash_final(&state, session->session_key, LSL_SECURITY_SESSION_KEY_SIZE);

    /* Clear sensitive intermediates */
    sodium_memzero(our_x25519_sk, sizeof(our_x25519_sk));
    sodium_memzero(peer_x25519_pk, sizeof(peer_x25519_pk));
    sodium_memzero(shared_secret, sizeof(shared_secret));

    session->send_nonce = 1; /* nonce 0 is reserved (desktop secureLSL rejects it) */
    session->recv_nonce_high = 0;
    session->active = 1;

    ESP_LOGI(TAG, "Session key derived successfully");
    return LSL_ESP32_OK;
}

int security_encrypt(lsl_security_session_t *session, const uint8_t *plaintext,
                     size_t plaintext_len, uint8_t *ciphertext_out, size_t ciphertext_max,
                     uint64_t *nonce_out)
{
    if (!session || !session->active || !plaintext || !ciphertext_out || !nonce_out) {
        ESP_LOGE(TAG, "security_encrypt: invalid args (session=%p, active=%d)", (void *)session,
                 session ? session->active : -1);
        return -1;
    }

    if (session->send_nonce == UINT64_MAX) {
        ESP_LOGE(TAG, "Send nonce exhausted; session must be rekeyed");
        session->active = 0;
        return -1;
    }

    size_t ct_len = plaintext_len + LSL_SECURITY_AUTH_TAG_SIZE;
    if (ct_len > ciphertext_max) {
        ESP_LOGE(TAG, "Ciphertext buffer too small: need %zu, have %zu", ct_len, ciphertext_max);
        return -1;
    }

    /* Build 12-byte IETF nonce from 8-byte counter (zero-padded) */
    uint8_t nonce_bytes[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    memset(nonce_bytes, 0, sizeof(nonce_bytes));
    memcpy(nonce_bytes, &session->send_nonce, 8); /* LE uint64 in first 8 bytes */

    unsigned long long actual_ct_len;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext_out, &actual_ct_len, plaintext,
                                                  plaintext_len, NULL, 0, NULL, nonce_bytes,
                                                  session->session_key) != 0) {
        ESP_LOGE(TAG, "Encryption failed");
        return -1;
    }

    *nonce_out = session->send_nonce;
    session->send_nonce++;

    return (int)actual_ct_len;
}

int security_decrypt(lsl_security_session_t *session, uint64_t wire_nonce,
                     const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext_out,
                     size_t plaintext_max)
{
    if (!session || !session->active || !ciphertext || !plaintext_out) {
        return -1;
    }

    if (ciphertext_len < LSL_SECURITY_AUTH_TAG_SIZE) {
        ESP_LOGE(TAG, "Ciphertext too short: %zu bytes", ciphertext_len);
        return -1;
    }

    size_t pt_len = ciphertext_len - LSL_SECURITY_AUTH_TAG_SIZE;
    if (pt_len > plaintext_max) {
        ESP_LOGE(TAG, "Plaintext buffer too small: need %zu, have %zu", pt_len, plaintext_max);
        return -1;
    }

    /* Nonce 0 is reserved (matching desktop secureLSL) */
    if (wire_nonce == 0) {
        ESP_LOGW(TAG, "Rejected reserved nonce 0");
        return -1;
    }

    /* Replay prevention: nonce must be strictly increasing.
     * This is stricter than desktop secureLSL's windowed NonceTracker
     * (which allows out-of-order within 64 nonces). The strict policy
     * is correct for TCP (ordered delivery) and simpler for ESP32.
     * A windowed tracker would be needed for UDP transport. */
    if (session->recv_nonce_valid && wire_nonce <= session->recv_nonce_high) {
        ESP_LOGW(TAG, "Nonce replay detected: received %llu, high=%llu",
                 (unsigned long long)wire_nonce, (unsigned long long)session->recv_nonce_high);
        return -1;
    }

    /* Build 12-byte IETF nonce from 8-byte wire nonce */
    uint8_t nonce_bytes[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    memset(nonce_bytes, 0, sizeof(nonce_bytes));
    memcpy(nonce_bytes, &wire_nonce, 8);

    unsigned long long actual_pt_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(plaintext_out, &actual_pt_len, NULL, ciphertext,
                                                  ciphertext_len, NULL, 0, nonce_bytes,
                                                  session->session_key) != 0) {
        ESP_LOGE(TAG, "Decryption failed: authentication error");
        return -1;
    }

    session->recv_nonce_high = wire_nonce;
    session->recv_nonce_valid = 1;
    return (int)actual_pt_len;
}

lsl_esp32_err_t security_config_load(lsl_security_config_t *cfg)
{
    if (!cfg) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    sodium_memzero(cfg, sizeof(*cfg));

    if (!lsl_esp32_security_enabled()) {
        return LSL_ESP32_OK; /* security not requested; cfg->enabled stays 0 */
    }

    lsl_esp32_err_t err = key_manager_load(cfg->public_key, cfg->secret_key);
    if (err != LSL_ESP32_OK) {
        ESP_LOGE(TAG, "Security enabled but keys not loadable");
        sodium_memzero(cfg, sizeof(*cfg));
        return err;
    }

    cfg->enabled = 1;
    return LSL_ESP32_OK;
}

void security_config_clear(lsl_security_config_t *cfg)
{
    if (cfg) {
        sodium_memzero(cfg, sizeof(*cfg));
    }
}

lsl_esp32_err_t security_handshake_verify(const lsl_security_config_t *our_config,
                                          const char *peer_pubkey_b64,
                                          lsl_security_session_t *session_out)
{
    if (!our_config || !session_out) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    /* Decode peer's public key from base64 */
    uint8_t peer_pk[LSL_KEY_PUBLIC_SIZE];
    size_t peer_pk_len = 0;

    if (!peer_pubkey_b64 || peer_pubkey_b64[0] == '\0' ||
        sodium_base642bin(peer_pk, sizeof(peer_pk), peer_pubkey_b64, strlen(peer_pubkey_b64), NULL,
                          &peer_pk_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        peer_pk_len != LSL_KEY_PUBLIC_SIZE) {
        ESP_LOGW(TAG, "Peer public key missing or invalid base64");
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    /* Shared keypair model: authorization = public key match (constant-time) */
    if (sodium_memcmp(peer_pk, our_config->public_key, LSL_KEY_PUBLIC_SIZE) != 0) {
        ESP_LOGW(TAG, "Peer public key does not match (different keypair)");
        sodium_memzero(peer_pk, sizeof(peer_pk));
        return LSL_ESP32_ERR_SECURITY;
    }

    /* Derive per-connection session key */
    security_session_init(session_out);
    lsl_esp32_err_t err = security_derive_session_key(our_config->public_key,
                                                      our_config->secret_key, peer_pk, session_out);
    sodium_memzero(peer_pk, sizeof(peer_pk));
    return err;
}
