// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_key_manager.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "sodium.h"
#include <string.h>

static const char *TAG = "lsl_key_mgr";
static const char *NVS_NAMESPACE = "lsl_security";

lsl_esp32_err_t key_manager_generate(void)
{
    if (sodium_init() < 0) {
        ESP_LOGE(TAG, "sodium_init failed");
        return LSL_ESP32_ERR_SECURITY;
    }

    uint8_t pk[LSL_KEY_PUBLIC_SIZE];
    uint8_t sk[LSL_KEY_SECRET_SIZE];
    crypto_sign_keypair(pk, sk);

    /* Store in NVS */
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        sodium_memzero(sk, sizeof(sk));
        return LSL_ESP32_ERR_SECURITY;
    }

    err = nvs_set_blob(handle, "public_key", pk, sizeof(pk));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to store public key: %s", esp_err_to_name(err));
        nvs_close(handle);
        sodium_memzero(sk, sizeof(sk));
        return LSL_ESP32_ERR_SECURITY;
    }

    err = nvs_set_blob(handle, "private_key", sk, sizeof(sk));
    sodium_memzero(sk, sizeof(sk)); /* zero immediately after use */
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to store private key: %s", esp_err_to_name(err));
        nvs_close(handle);
        return LSL_ESP32_ERR_SECURITY;
    }

    err = nvs_set_u8(handle, "enabled", 1);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set enabled flag: %s", esp_err_to_name(err));
        nvs_close(handle);
        return LSL_ESP32_ERR_SECURITY;
    }
    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS commit failed: %s", esp_err_to_name(err));
        return LSL_ESP32_ERR_SECURITY;
    }

    /* Log truncated fingerprint, not the full key (shared keypair model:
     * the public key is the authorization credential) */
    char b64[LSL_KEY_BASE64_SIZE];
    sodium_bin2base64(b64, sizeof(b64), pk, sizeof(pk), sodium_base64_VARIANT_ORIGINAL);
    ESP_LOGI(TAG, "Generated keypair. Public key fingerprint: %.8s...", b64);

    return LSL_ESP32_OK;
}

lsl_esp32_err_t key_manager_import(const char *base64_pub, const char *base64_priv)
{
    if (!base64_pub || !base64_priv) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    if (sodium_init() < 0) {
        return LSL_ESP32_ERR_SECURITY;
    }

    uint8_t pk[LSL_KEY_PUBLIC_SIZE];
    uint8_t sk[LSL_KEY_SECRET_SIZE];
    size_t pk_len, sk_len;

    if (sodium_base642bin(pk, sizeof(pk), base64_pub, strlen(base64_pub), NULL, &pk_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        pk_len != LSL_KEY_PUBLIC_SIZE) {
        ESP_LOGE(TAG, "Invalid base64 public key");
        sodium_memzero(pk, sizeof(pk));
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    if (sodium_base642bin(sk, sizeof(sk), base64_priv, strlen(base64_priv), NULL, &sk_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        sk_len != LSL_KEY_SECRET_SIZE) {
        ESP_LOGE(TAG, "Invalid base64 private key");
        sodium_memzero(sk, sizeof(sk));
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    /* Store in NVS */
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        sodium_memzero(sk, sizeof(sk));
        return LSL_ESP32_ERR_SECURITY;
    }

    err = nvs_set_blob(handle, "public_key", pk, sizeof(pk));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to store imported public key: %s", esp_err_to_name(err));
        nvs_close(handle);
        sodium_memzero(sk, sizeof(sk));
        return LSL_ESP32_ERR_SECURITY;
    }

    err = nvs_set_blob(handle, "private_key", sk, sizeof(sk));
    sodium_memzero(sk, sizeof(sk));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to store imported private key: %s", esp_err_to_name(err));
        nvs_close(handle);
        return LSL_ESP32_ERR_SECURITY;
    }

    err = nvs_set_u8(handle, "enabled", 1);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set enabled flag: %s", esp_err_to_name(err));
        nvs_close(handle);
        return LSL_ESP32_ERR_SECURITY;
    }
    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS commit failed: %s", esp_err_to_name(err));
        return LSL_ESP32_ERR_SECURITY;
    }

    ESP_LOGI(TAG, "Imported keypair successfully");
    return LSL_ESP32_OK;
}

lsl_esp32_err_t key_manager_load(uint8_t *pk_out, uint8_t *sk_out)
{
    if (!pk_out || !sk_out) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        if (err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        }
        return LSL_ESP32_ERR_NOT_FOUND;
    }

    size_t pk_len = LSL_KEY_PUBLIC_SIZE;
    size_t sk_len = LSL_KEY_SECRET_SIZE;

    err = nvs_get_blob(handle, "public_key", pk_out, &pk_len);
    if (err != ESP_OK || pk_len != LSL_KEY_PUBLIC_SIZE) {
        if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to read public key: %s", esp_err_to_name(err));
        }
        nvs_close(handle);
        sodium_memzero(pk_out, LSL_KEY_PUBLIC_SIZE);
        sodium_memzero(sk_out, LSL_KEY_SECRET_SIZE);
        return LSL_ESP32_ERR_NOT_FOUND;
    }

    err = nvs_get_blob(handle, "private_key", sk_out, &sk_len);
    if (err != ESP_OK || sk_len != LSL_KEY_SECRET_SIZE) {
        nvs_close(handle);
        sodium_memzero(sk_out, LSL_KEY_SECRET_SIZE);
        return LSL_ESP32_ERR_NOT_FOUND;
    }

    nvs_close(handle);
    return LSL_ESP32_OK;
}

lsl_esp32_err_t key_manager_export_pubkey(char *out, size_t out_len)
{
    if (!out || out_len < LSL_KEY_BASE64_SIZE) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    uint8_t pk[LSL_KEY_PUBLIC_SIZE];
    uint8_t sk[LSL_KEY_SECRET_SIZE];
    lsl_esp32_err_t ret = key_manager_load(pk, sk);
    sodium_memzero(sk, sizeof(sk)); /* don't need secret key for export */
    if (ret != LSL_ESP32_OK) {
        return ret;
    }

    sodium_bin2base64(out, out_len, pk, sizeof(pk), sodium_base64_VARIANT_ORIGINAL);
    return LSL_ESP32_OK;
}

int key_manager_is_enabled(void)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) {
        return 0;
    }

    uint8_t enabled = 0;
    nvs_get_u8(handle, "enabled", &enabled);
    nvs_close(handle);
    return enabled ? 1 : 0;
}
