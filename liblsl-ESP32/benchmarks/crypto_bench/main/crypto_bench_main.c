/* ESP32 Cryptographic Benchmark Suite for secureLSL
 *
 * Benchmarks all libsodium operations used by secureLSL:
 * - ChaCha20-Poly1305 IETF AEAD (per-sample encryption)
 * - Ed25519 keygen, sign, verify (device identity)
 * - X25519 scalar mult (session key exchange)
 * - BLAKE2b / generichash (session key derivation, fingerprints)
 * - Base64 encode/decode (key serialization in headers)
 *
 * Results are printed via UART serial (baud rate set in sdkconfig).
 *
 * Build and run:
 *   idf.py set-target esp32
 *   idf.py build
 *   idf.py -p /dev/cu.usbserial-XXXX flash monitor
 */

#include "bench_chacha20.h"
#include "bench_ed25519.h"
#include "bench_x25519.h"
#include "bench_utils.h"

#include "esp_flash.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_chip_info.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sodium.h"

static const char *TAG = "crypto_bench";

static void print_system_info(void)
{
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);

    ESP_LOGI(TAG, "============================================================");
    ESP_LOGI(TAG, " ESP32 Crypto Benchmark for secureLSL");
    ESP_LOGI(TAG, "============================================================");
    ESP_LOGI(TAG, "Chip: ESP32 rev %d, %d cores, WiFi%s%s", chip_info.revision, chip_info.cores,
             (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
             (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");
    uint32_t flash_size = 0;
    if (esp_flash_get_size(NULL, &flash_size) != ESP_OK) {
        ESP_LOGW(TAG, "Failed to read flash size");
    }
    ESP_LOGI(TAG, "Flash: %lu MB %s", (unsigned long)(flash_size / (1024 * 1024)),
             (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "(embedded)" : "(external)");
    ESP_LOGI(TAG, "libsodium version: %s", sodium_version_string());
    ESP_LOGI(TAG, "Iterations per benchmark: %d", BENCH_ITERATIONS);
    ESP_LOGI(TAG, "");
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition issue (%s), erasing...", esp_err_to_name(ret));
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "NVS init failed: %s (non-fatal, continuing)", esp_err_to_name(ret));
    }

    /* Brief delay so serial monitor can connect before output starts */
    ESP_LOGI(TAG, "Starting in 2 seconds...");
    vTaskDelay(pdMS_TO_TICKS(2000));

    print_system_info();

    bench_print_memory("Before sodium_init");

    if (sodium_init() < 0) {
        ESP_LOGE(TAG, "FATAL: sodium_init() failed!");
        return;
    }
    ESP_LOGI(TAG, "sodium_init() OK");

    bench_print_memory("After sodium_init");

    bench_chacha20_run();
    bench_ed25519_run();
    bench_x25519_run();

    bench_print_memory("After all benchmarks");

    bench_print_header("BENCHMARK COMPLETE");
    ESP_LOGI(TAG, "All benchmarks finished. Results above.");
    ESP_LOGI(TAG, "Key metric: ChaCha20 encrypt 256B (64ch float32) should be < 1ms");
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "To re-run, press the EN (reset) button on the ESP32 board.");
}
