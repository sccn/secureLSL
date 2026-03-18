// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_KEY_MANAGER_H
#define LSL_KEY_MANAGER_H

#include "lsl_esp32_types.h"
#include <stdint.h>

/* Ed25519 key sizes (from libsodium) */
#define LSL_KEY_PUBLIC_SIZE  32
#define LSL_KEY_SECRET_SIZE  64
#define LSL_KEY_BASE64_SIZE  45 /* sodium_base64_ENCODED_LEN(32, VARIANT_ORIGINAL) */
#define LSL_KEY_SBASE64_SIZE 89 /* sodium_base64_ENCODED_LEN(64, VARIANT_ORIGINAL) */

/* Generate a new Ed25519 keypair and store in NVS.
 * Returns LSL_ESP32_OK on success. */
lsl_esp32_err_t key_manager_generate(void);

/* Import a keypair from base64-encoded strings and store in NVS.
 * Returns LSL_ESP32_OK on success. */
lsl_esp32_err_t key_manager_import(const char *base64_pub, const char *base64_priv);

/* Load the stored keypair from NVS.
 * pk_out must be LSL_KEY_PUBLIC_SIZE bytes, sk_out must be LSL_KEY_SECRET_SIZE bytes.
 * Returns LSL_ESP32_OK on success, LSL_ESP32_ERR_NOT_FOUND if no key stored. */
lsl_esp32_err_t key_manager_load(uint8_t *pk_out, uint8_t *sk_out);

/* Export the public key as base64 string.
 * out must be at least LSL_KEY_BASE64_SIZE bytes.
 * Returns LSL_ESP32_OK on success. */
lsl_esp32_err_t key_manager_export_pubkey(char *out, size_t out_len);

/* Check if security is enabled (keypair exists in NVS).
 * Returns 1 if enabled, 0 if not. */
int key_manager_is_enabled(void);

#endif /* LSL_KEY_MANAGER_H */
