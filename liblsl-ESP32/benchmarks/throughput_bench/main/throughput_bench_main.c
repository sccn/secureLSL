// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/* LSL Throughput Benchmark for ESP32
 *
 * Measures push/pull timing, throughput, jitter, and resource usage
 * for both encrypted and unencrypted LSL streaming.
 *
 * Configure via: idf.py menuconfig -> Benchmark Configuration
 *
 * Output: JSON lines on serial for desktop collection.
 *
 * Usage:
 *   Terminal 1: idf.py -p PORT flash monitor
 *   Terminal 2: uv run python serial_monitor.py --port PORT
 *   Terminal 3: uv run python esp32_benchmark_inlet.py  (if outlet mode)
 */

#include "bench_inlet.h"
#include "bench_monitor.h"
#include "bench_outlet.h"
#include "lsl_esp32.h"
#include "wifi_helper.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "bench_main";

/* Key provisioning (same pattern as secure examples) */
static int provision_keys(void)
{
#if CONFIG_BENCH_SECURITY_ENABLE
    if (lsl_esp32_has_keypair()) {
        ESP_LOGI(TAG, "Keypair already in NVS");
        return 0;
    }

    const char *pub = CONFIG_LSL_SECURITY_PUBKEY;
    const char *priv = CONFIG_LSL_SECURITY_PRIVKEY;

    if (pub[0] != '\0' && priv[0] != '\0') {
        ESP_LOGI(TAG, "Importing keypair from config...");
        if (lsl_esp32_import_keypair(pub, priv) == LSL_ESP32_OK) {
            return 0;
        }
        ESP_LOGE(TAG, "Key import failed");
        return -1;
    }

    ESP_LOGI(TAG, "Generating new keypair...");
    if (lsl_esp32_generate_keypair() != LSL_ESP32_OK) {
        ESP_LOGE(TAG, "Key generation failed");
        return -1;
    }
    char pk[LSL_ESP32_KEY_BASE64_SIZE];
    if (lsl_esp32_export_pubkey(pk, sizeof(pk)) == LSL_ESP32_OK) {
        ESP_LOGI(TAG, "Public key: %s", pk);
    }
#endif
    return 0;
}

void app_main(void)
{
    /* NVS init */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Security setup */
#if CONFIG_BENCH_SECURITY_ENABLE
    if (provision_keys() != 0) {
        ESP_LOGE(TAG, "Key provisioning failed");
        return;
    }
    lsl_esp32_err_t sec_err = lsl_esp32_enable_security();
    if (sec_err != LSL_ESP32_OK) {
        ESP_LOGE(TAG, "Failed to enable security: %d", sec_err);
        return;
    }
    ESP_LOGI(TAG, "Security enabled");
#else
    ESP_LOGI(TAG, "Security disabled (plaintext mode)");
#endif

    /* WiFi */
    ESP_LOGI(TAG, "Connecting to WiFi...");
    if (wifi_helper_init_sta() != ESP_OK) {
        ESP_LOGE(TAG, "WiFi failed");
        return;
    }

    /* Print config header as JSON */
    printf("{\"type\":\"config\","
           "\"mode\":\"%s\","
           "\"channels\":%d,"
           "\"rate\":%d,"
           "\"duration\":%d,"
           "\"security\":%s,"
           "\"heap_at_start\":%lu}\n",
#if CONFIG_BENCH_MODE_OUTLET
           "outlet",
#else
           "inlet",
#endif
           CONFIG_BENCH_CHANNELS, CONFIG_BENCH_SAMPLE_RATE, CONFIG_BENCH_DURATION,
#if CONFIG_BENCH_SECURITY_ENABLE
           "true",
#else
           "false",
#endif
           (unsigned long)esp_get_free_heap_size());

    /* Start resource monitor */
    bench_monitor_start();

    /* Run benchmark */
#if CONFIG_BENCH_MODE_OUTLET
    bench_outlet_run();
#else
    bench_inlet_run();
#endif

    bench_monitor_stop();
    ESP_LOGI(TAG, "Benchmark finished");
}
