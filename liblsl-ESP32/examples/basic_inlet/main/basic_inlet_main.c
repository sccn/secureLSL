// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/* Basic LSL Inlet Example for ESP32
 *
 * Demonstrates receiving LSL samples from a desktop outlet:
 * 1. Connect to WiFi
 * 2. Resolve a stream by name
 * 3. Create an inlet (connects to outlet, validates test patterns)
 * 4. Pull and display samples
 *
 * Desktop setup (run before flashing ESP32):
 *   python3 -c "
 *   import pylsl, time
 *   info = pylsl.StreamInfo('DesktopTest','EEG',8,250,'float32','desktop1')
 *   o = pylsl.StreamOutlet(info)
 *   print('Outlet started')
 *   while True:
 *       o.push_sample([float(i) for i in range(8)])
 *       time.sleep(0.004)
 *   "
 *
 * Configure WiFi: idf.py menuconfig -> Example Configuration
 * Configure stream name: idf.py menuconfig -> Example Configuration -> Target LSL stream name
 */

#include "lsl_esp32.h"
#include "wifi_helper.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "basic_inlet";

void app_main(void)
{
    /* Initialize NVS (required for WiFi) */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Connect to WiFi */
    ESP_LOGI(TAG, "Connecting to WiFi...");
    if (wifi_helper_init_sta() != ESP_OK) {
        ESP_LOGE(TAG, "WiFi connection failed. Cannot start LSL inlet.");
        return;
    }

    /* Resolve a stream by name */
    ESP_LOGI(TAG, "Resolving stream '%s'...", CONFIG_LSL_TARGET_STREAM);
    lsl_esp32_stream_info_t info = NULL;
    int found = lsl_esp32_resolve_stream("name", CONFIG_LSL_TARGET_STREAM, 10.0, &info);
    if (!found || !info) {
        ESP_LOGE(TAG, "Stream '%s' not found within 10 seconds", CONFIG_LSL_TARGET_STREAM);
        return;
    }

    int ch_count = lsl_esp32_get_channel_count(info);
    ESP_LOGI(TAG, "Found stream: %s (%s, %dch @ %.0fHz)", lsl_esp32_get_name(info),
             lsl_esp32_get_type(info), ch_count, lsl_esp32_get_nominal_srate(info));

    /* Create inlet (connects to outlet, validates test patterns) */
    ESP_LOGI(TAG, "Creating inlet...");
    lsl_esp32_inlet_t inlet = lsl_esp32_create_inlet(info);
    if (!inlet) {
        ESP_LOGE(TAG, "Failed to create inlet");
        lsl_esp32_destroy_streaminfo(info);
        return;
    }

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "=== LSL Inlet Ready ===");
    ESP_LOGI(TAG, "Receiving from: %s", CONFIG_LSL_TARGET_STREAM);
    ESP_LOGI(TAG, "");

    /* Pull and display samples */
    float sample[LSL_ESP32_MAX_CHANNELS];
    double timestamp;
    uint32_t sample_count = 0;
    uint32_t timeout_count = 0;

    while (1) {
        lsl_esp32_err_t err = lsl_esp32_inlet_pull_sample_f(
            inlet, sample, (int)(ch_count * sizeof(float)), &timestamp, 1.0);

        if (err == LSL_ESP32_OK) {
            sample_count++;

            /* Print first sample and every 250th sample */
            if (sample_count == 1 || sample_count % 250 == 0) {
                ESP_LOGI(TAG, "Sample %lu: ts=%.6f ch0=%.4f ch1=%.4f ch2=%.4f ch3=%.4f",
                         (unsigned long)sample_count, timestamp, sample[0], sample[1], sample[2],
                         sample[3]);
                ESP_LOGI(TAG, "  (heap=%lu)", (unsigned long)esp_get_free_heap_size());
            }
        } else if (err == LSL_ESP32_ERR_TIMEOUT) {
            timeout_count++;
            if (timeout_count % 5 == 0) {
                ESP_LOGW(TAG, "No samples received (timeouts=%lu, received=%lu)",
                         (unsigned long)timeout_count, (unsigned long)sample_count);
            }
        } else {
            ESP_LOGE(TAG, "Pull error: %d", err);
            break;
        }
    }

    lsl_esp32_destroy_inlet(inlet);
    ESP_LOGI(TAG, "Inlet destroyed. Total samples: %lu", (unsigned long)sample_count);
}
