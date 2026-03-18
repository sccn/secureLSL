// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/* Public API entry points for liblsl_esp32.
 * Thin wrappers that delegate to internal modules. */

#include "lsl_esp32.h"
#include "lsl_resolver.h"
#include "lsl_stream_info.h"
#include "lsl_key_manager.h"
#include "esp_log.h"
#include "sodium.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "lsl_esp32";

/* Global security state. Not thread-safe; must be set before creating outlets/inlets. */
static volatile int s_security_enabled = 0;

lsl_esp32_err_t lsl_esp32_generate_keypair(void)
{
    if (sodium_init() < 0) {
        return LSL_ESP32_ERR_SECURITY;
    }
    return key_manager_generate();
}

lsl_esp32_err_t lsl_esp32_import_keypair(const char *base64_pub, const char *base64_priv)
{
    return key_manager_import(base64_pub, base64_priv);
}

lsl_esp32_err_t lsl_esp32_export_pubkey(char *out, size_t out_len)
{
    return key_manager_export_pubkey(out, out_len);
}

int lsl_esp32_has_keypair(void)
{
    return key_manager_is_enabled();
}

lsl_esp32_err_t lsl_esp32_enable_security(void)
{
    if (sodium_init() < 0) {
        ESP_LOGE(TAG, "sodium_init failed");
        return LSL_ESP32_ERR_SECURITY;
    }

    if (!key_manager_is_enabled()) {
        ESP_LOGE(TAG, "No keypair provisioned in NVS; call key_manager_generate first");
        return LSL_ESP32_ERR_NOT_FOUND;
    }

    /* Verify we can actually load the keys */
    uint8_t pk[LSL_KEY_PUBLIC_SIZE];
    uint8_t sk[LSL_KEY_SECRET_SIZE];
    lsl_esp32_err_t err = key_manager_load(pk, sk);
    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(pk, sizeof(pk));

    if (err != LSL_ESP32_OK) {
        ESP_LOGE(TAG, "Failed to load keypair from NVS");
        return err;
    }

    s_security_enabled = 1;
    ESP_LOGI(TAG, "Security enabled globally");
    return LSL_ESP32_OK;
}

int lsl_esp32_security_enabled(void)
{
    return s_security_enabled;
}

int lsl_esp32_resolve_stream(const char *prop, const char *value, double timeout,
                             lsl_esp32_stream_info_t *result)
{
    if (!result) {
        return 0;
    }

    /* Allocate heap struct and pass directly to resolver (avoids double-copy) */
    struct lsl_esp32_stream_info *info = malloc(sizeof(*info));
    if (!info) {
        ESP_LOGE(TAG, "Failed to allocate stream info for resolve result");
        *result = NULL;
        return 0;
    }

    int n = resolver_find(prop, value, timeout, info, 1);
    if (n < 1) {
        free(info);
        *result = NULL;
        return 0;
    }

    *result = info;
    return 1;
}

int lsl_esp32_resolve_streams(double timeout, lsl_esp32_stream_info_t *results, int max_results)
{
    if (!results || max_results < 1) {
        return 0;
    }

    /* Clamp to resolver maximum to bound memory usage */
    if (max_results > LSL_RESOLVER_MAX_RESULTS) {
        max_results = LSL_RESOLVER_MAX_RESULTS;
    }

    /* Use stack-allocated buffer for resolver results */
    struct lsl_esp32_stream_info found[LSL_RESOLVER_MAX_RESULTS];

    int n = resolver_find_all(timeout, found, max_results);

    /* Allocate individual heap handles for each result */
    for (int i = 0; i < n; i++) {
        struct lsl_esp32_stream_info *info = malloc(sizeof(*info));
        if (!info) {
            for (int j = 0; j < i; j++) {
                free(results[j]);
                results[j] = NULL;
            }
            return 0;
        }
        memcpy(info, &found[i], sizeof(*info));
        results[i] = info;
    }

    return n;
}
