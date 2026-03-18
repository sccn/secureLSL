// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/* Basic LSL Outlet Example for ESP32
 *
 * Demonstrates the public liblsl_esp32 API:
 * 1. Connect to WiFi
 * 2. Create a stream info descriptor
 * 3. Create an outlet (starts discovery + TCP servers automatically)
 * 4. Push sine wave samples at 250 Hz
 *
 * Desktop test:
 *   python -c "import pylsl; i=pylsl.StreamInlet(pylsl.resolve_byprop(
 *     'name','ESP32Test',timeout=5)[0]); print(i.pull_sample())"
 *
 * Configure WiFi: idf.py menuconfig -> Example Configuration
 */

#include "lsl_esp32.h"
#include "wifi_helper.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <math.h>

static const char *TAG = "basic_outlet";

#define NUM_CHANNELS 8
#define SAMPLE_RATE  250.0

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
        ESP_LOGE(TAG, "WiFi connection failed. Cannot start LSL outlet.");
        return;
    }

    /* Create stream info */
    lsl_esp32_stream_info_t info = lsl_esp32_create_streaminfo(
        "ESP32Test", "EEG", NUM_CHANNELS, SAMPLE_RATE, LSL_ESP32_FMT_FLOAT32, "esp32_outlet_1");
    if (!info) {
        ESP_LOGE(TAG, "Failed to create stream info");
        return;
    }

    /* Create outlet (starts UDP discovery + TCP data server) */
    lsl_esp32_outlet_t outlet = lsl_esp32_create_outlet(info, 0, 360);
    if (!outlet) {
        ESP_LOGE(TAG, "Failed to create outlet");
        lsl_esp32_destroy_streaminfo(info);
        return;
    }

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "=== LSL Outlet Ready ===");
    ESP_LOGI(TAG, "Stream: ESP32Test (%dch float32 @ %.0fHz)", NUM_CHANNELS, SAMPLE_RATE);
    ESP_LOGI(TAG, "");

    /* Push sine wave samples at 250 Hz */
    float channels[NUM_CHANNELS];
    uint32_t sample_count = 0;
    TickType_t last_wake = xTaskGetTickCount();

    while (1) {
        double timestamp = lsl_esp32_local_clock();

        /* Generate sine wave data (different frequency per channel) */
        for (int ch = 0; ch < NUM_CHANNELS; ch++) {
            channels[ch] = sinf((float)timestamp * 2.0f * 3.14159f * (float)(ch + 1));
        }

        /* Push sample through public API */
        lsl_esp32_err_t err = lsl_esp32_push_sample_f(outlet, channels, timestamp);
        if (err != LSL_ESP32_OK) {
            ESP_LOGW(TAG, "Push failed: %d", err);
        }
        sample_count++;

        /* Report status every 5 seconds */
        if (sample_count % (5 * (uint32_t)SAMPLE_RATE) == 0) {
            ESP_LOGI(TAG, "Pushed %lu samples (heap=%lu, consumers=%d)",
                     (unsigned long)sample_count, (unsigned long)esp_get_free_heap_size(),
                     lsl_esp32_have_consumers(outlet));
        }

        vTaskDelayUntil(&last_wake, pdMS_TO_TICKS(4)); /* ~250 Hz at 1000Hz tick rate */
    }
}
