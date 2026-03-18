// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/* Secure LSL Inlet Example for ESP32
 *
 * Demonstrates receiving encrypted LSL data with secureLSL:
 * 1. Connect to WiFi
 * 2. Import or generate Ed25519 keypair in NVS
 * 3. Enable secureLSL encryption
 * 4. Resolve a secure stream on the network
 * 5. Create an encrypted inlet and receive samples
 *
 * Desktop test (requires secureLSL with matching keypair):
 *   ./cpp_secure_outlet --name DesktopTest --samples 5000 --channels 8
 *
 * Key provisioning:
 *   Option A: Set keys via menuconfig -> Example Configuration
 *   Option B: Leave blank to auto-generate (then export to desktop)
 *
 * Configure: idf.py menuconfig -> Example Configuration
 *
 * Walkthrough:
 *   1. Build: idf.py build
 *   2. Flash: idf.py -p /dev/cu.usbserial-XXXX flash monitor
 *   3. Start a secure outlet on the desktop with matching keypair
 *   4. ESP32 resolves the stream, connects, and receives encrypted data
 */

#include "lsl_esp32.h"
#include "wifi_helper.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "secure_inlet";

/* Provision keypair: import from config or generate new */
static int provision_keys(void)
{
    if (lsl_esp32_has_keypair()) {
        ESP_LOGI(TAG, "Keypair already provisioned in NVS");
        char pubkey[LSL_ESP32_KEY_BASE64_SIZE];
        if (lsl_esp32_export_pubkey(pubkey, sizeof(pubkey)) == LSL_ESP32_OK) {
            ESP_LOGI(TAG, "Public key fingerprint: %.8s...", pubkey);
        }
        return 0;
    }

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
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    if (provision_keys() != 0) {
        ESP_LOGE(TAG, "Key provisioning failed");
        return;
    }

    lsl_esp32_err_t err = lsl_esp32_enable_security();
    if (err != LSL_ESP32_OK) {
        ESP_LOGE(TAG, "Failed to enable security: %d", err);
        return;
    }

    ESP_LOGI(TAG, "Connecting to WiFi...");
    if (wifi_helper_init_sta() != ESP_OK) {
        ESP_LOGE(TAG, "WiFi connection failed");
        return;
    }

    /* Resolve target stream */
    const char *target = CONFIG_LSL_TARGET_STREAM;
    ESP_LOGI(TAG, "Resolving secure stream '%s'...", target);

    lsl_esp32_stream_info_t info = NULL;
    int found = lsl_esp32_resolve_stream("name", target, 15.0, &info);
    if (!found || !info) {
        ESP_LOGE(TAG, "Stream '%s' not found within 15s", target);
        return;
    }

    ESP_LOGI(TAG, "Found: %s (%s, %dch @ %.0fHz)", lsl_esp32_get_name(info),
             lsl_esp32_get_type(info), lsl_esp32_get_channel_count(info),
             lsl_esp32_get_nominal_srate(info));

    /* Create inlet (encryption is automatic when security is enabled) */
    lsl_esp32_inlet_t inlet = lsl_esp32_create_inlet(info);
    if (!inlet) {
        ESP_LOGE(TAG, "Failed to create inlet (handshake may have failed)");
        lsl_esp32_destroy_streaminfo(info);
        return;
    }

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "=== Secure LSL Inlet Ready ===");
    ESP_LOGI(TAG, "Receiving from: %s (ENCRYPTED)", target);
    ESP_LOGI(TAG, "");

    /* Receive samples */
    int nch = lsl_esp32_get_channel_count(info);
    float *buf = malloc((size_t)nch * sizeof(float));
    if (!buf) {
        ESP_LOGE(TAG, "Failed to allocate sample buffer");
        lsl_esp32_destroy_inlet(inlet);
        return;
    }

    uint32_t received = 0;
    uint32_t timeouts = 0;

    while (1) {
        double timestamp;
        err = lsl_esp32_inlet_pull_sample_f(inlet, buf, nch * (int)sizeof(float), &timestamp, 5.0);

        if (err == LSL_ESP32_OK) {
            received++;
            if (received <= 3 || received % 250 == 0) {
                ESP_LOGI(TAG, "Sample %lu: ts=%.6f ch0=%.4f ch1=%.4f (heap=%lu)",
                         (unsigned long)received, timestamp, buf[0], nch > 1 ? buf[1] : 0.0f,
                         (unsigned long)esp_get_free_heap_size());
            }
        } else if (err == LSL_ESP32_ERR_TIMEOUT) {
            timeouts++;
            if (timeouts >= 6) {
                ESP_LOGW(TAG, "No samples for 30s, outlet may have stopped");
                break;
            }
            ESP_LOGW(TAG, "Timeout (received=%lu so far)", (unsigned long)received);
        } else {
            ESP_LOGE(TAG, "Pull error: %d", err);
            break;
        }
    }

    ESP_LOGI(TAG, "Total received: %lu samples", (unsigned long)received);
    free(buf);
    lsl_esp32_destroy_inlet(inlet);
}
