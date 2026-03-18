// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/* Secure LSL Outlet Example for ESP32
 *
 * Demonstrates encrypted LSL streaming with secureLSL:
 * 1. Connect to WiFi
 * 2. Import or generate Ed25519 keypair in NVS
 * 3. Enable secureLSL encryption
 * 4. Create an encrypted outlet
 * 5. Push sine wave samples at 250 Hz (encrypted on the wire)
 *
 * Desktop test (requires secureLSL with matching keypair):
 *   ./cpp_secure_inlet --name ESP32Secure
 *
 * Key provisioning:
 *   Option A: Set keys via menuconfig -> Example Configuration
 *   Option B: Leave blank to auto-generate (export and import to desktop)
 *
 * Configure WiFi: idf.py menuconfig -> Example Configuration
 *
 * Walkthrough:
 *   1. Build: idf.py build
 *   2. Flash: idf.py -p /dev/cu.usbserial-XXXX flash monitor
 *   3. On first boot with no keys configured, generates a new keypair
 *      and prints the public key fingerprint
 *   4. To share keys with desktop, use key_provisioning example
 *      or set keys in menuconfig
 */

#include "lsl_esp32.h"
#include "wifi_helper.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <math.h>
#include <string.h>

static const char *TAG = "secure_outlet";

#define NUM_CHANNELS 8
#define SAMPLE_RATE  250.0

/* Provision keypair: import from config or generate new */
static int provision_keys(void)
{
    /* If keys already exist in NVS, use them */
    if (lsl_esp32_has_keypair()) {
        ESP_LOGI(TAG, "Keypair already provisioned in NVS");
        char pubkey[LSL_ESP32_KEY_BASE64_SIZE];
        if (lsl_esp32_export_pubkey(pubkey, sizeof(pubkey)) == LSL_ESP32_OK) {
            ESP_LOGI(TAG, "Public key fingerprint: %.8s...", pubkey);
        }
        return 0;
    }

    /* Try importing from menuconfig */
    const char *pub = CONFIG_LSL_SECURITY_PUBKEY;
    const char *priv = CONFIG_LSL_SECURITY_PRIVKEY;

    if (pub[0] != '\0' && priv[0] != '\0') {
        ESP_LOGI(TAG, "Importing keypair from menuconfig...");
        if (lsl_esp32_import_keypair(pub, priv) == LSL_ESP32_OK) {
            ESP_LOGI(TAG, "Keypair imported successfully");
            return 0;
        }
        ESP_LOGE(TAG, "Failed to import keypair from config");
        return -1;
    }

    /* No keys configured; generate new keypair */
    ESP_LOGI(TAG, "No keypair configured, generating new Ed25519 keypair...");
    if (lsl_esp32_generate_keypair() != LSL_ESP32_OK) {
        ESP_LOGE(TAG, "Key generation failed");
        return -1;
    }

    char pubkey[LSL_ESP32_KEY_BASE64_SIZE];
    if (lsl_esp32_export_pubkey(pubkey, sizeof(pubkey)) == LSL_ESP32_OK) {
        ESP_LOGI(TAG, "Generated new keypair. Public key: %s", pubkey);
        ESP_LOGW(TAG, "Import this key to all lab devices for encrypted communication");
    }
    return 0;
}

void app_main(void)
{
    /* Initialize NVS (required for WiFi and key storage) */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Provision keypair (sodium_init is called by enable_security) */
    if (provision_keys() != 0) {
        ESP_LOGE(TAG, "Key provisioning failed, cannot start secure outlet");
        return;
    }

    /* Enable secureLSL encryption */
    lsl_esp32_err_t err = lsl_esp32_enable_security();
    if (err != LSL_ESP32_OK) {
        ESP_LOGE(TAG, "Failed to enable security: %d", err);
        return;
    }

    /* Connect to WiFi */
    ESP_LOGI(TAG, "Connecting to WiFi...");
    if (wifi_helper_init_sta() != ESP_OK) {
        ESP_LOGE(TAG, "WiFi connection failed");
        return;
    }

    /* Create stream info */
    lsl_esp32_stream_info_t info =
        lsl_esp32_create_streaminfo("ESP32Secure", "EEG", NUM_CHANNELS, SAMPLE_RATE,
                                    LSL_ESP32_FMT_FLOAT32, "esp32_secure_outlet_1");
    if (!info) {
        ESP_LOGE(TAG, "Failed to create stream info");
        return;
    }

    /* Create outlet (encryption is automatic when security is enabled) */
    lsl_esp32_outlet_t outlet = lsl_esp32_create_outlet(info, 0, 360);
    if (!outlet) {
        ESP_LOGE(TAG, "Failed to create outlet");
        lsl_esp32_destroy_streaminfo(info);
        return;
    }

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "=== Secure LSL Outlet Ready ===");
    ESP_LOGI(TAG, "Stream: ESP32Secure (%dch float32 @ %.0fHz, ENCRYPTED)", NUM_CHANNELS,
             SAMPLE_RATE);
    ESP_LOGI(TAG, "");

    /* Push sine wave samples at 250 Hz */
    float channels[NUM_CHANNELS];
    uint32_t sample_count = 0;
    TickType_t last_wake = xTaskGetTickCount();

    while (1) {
        double timestamp = lsl_esp32_local_clock();

        for (int ch = 0; ch < NUM_CHANNELS; ch++) {
            channels[ch] = sinf((float)timestamp * 2.0f * 3.14159f * (float)(ch + 1));
        }

        err = lsl_esp32_push_sample_f(outlet, channels, timestamp);
        if (err != LSL_ESP32_OK) {
            ESP_LOGW(TAG, "Push failed: %d", err);
        }
        sample_count++;

        if (sample_count % (5 * (uint32_t)SAMPLE_RATE) == 0) {
            ESP_LOGI(TAG, "Pushed %lu samples (heap=%lu, consumers=%d)",
                     (unsigned long)sample_count, (unsigned long)esp_get_free_heap_size(),
                     lsl_esp32_have_consumers(outlet));
        }

        vTaskDelayUntil(&last_wake, pdMS_TO_TICKS(4));
    }
}
