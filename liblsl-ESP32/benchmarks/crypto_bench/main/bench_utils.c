// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "bench_utils.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "bench";

int64_t bench_time_us(void)
{
    return esp_timer_get_time();
}

void bench_run(const char *name, bench_fn_t fn, void *arg, uint32_t iterations,
               size_t payload_bytes, bench_result_t *result)
{
    /* Zero result so early return leaves a safe state.
     * NOTE: result->name points to caller-owned memory;
     * caller must ensure name outlives result. */
    memset(result, 0, sizeof(*result));
    result->name = name;

    if (iterations == 0) {
        return;
    }

    /* Allocate timing array on heap (too large for stack) */
    double *times_us = malloc(iterations * sizeof(double));
    if (!times_us) {
        ESP_LOGE(TAG, "Failed to allocate timing array for %s", name);
        return;
    }

    /* Warmup: run a few iterations to prime caches */
    for (uint32_t i = 0; i < 10 && i < iterations; i++) {
        fn(arg);
    }

    /* Timed runs.
     * vTaskDelay(1) every 50 iterations lets the IDLE task run so the
     * task watchdog (which monitors IDLE0) doesn't trigger. taskYIELD()
     * alone is insufficient because IDLE runs at lower priority.
     * For slow operations (Ed25519/X25519 at ~10-16ms each), 50 iterations
     * is ~500-800ms of CPU time, well within the WDT timeout configured
     * in sdkconfig.defaults (CONFIG_ESP_TASK_WDT_TIMEOUT_S=30). */
    for (uint32_t i = 0; i < iterations; i++) {
        int64_t start = bench_time_us();
        fn(arg);
        int64_t end = bench_time_us();
        times_us[i] = (double)(end - start);

        if ((i + 1) % 50 == 0) {
            vTaskDelay(1);
        }
    }

    /* Compute statistics */
    double sum = 0.0;
    double min_val = times_us[0];
    double max_val = times_us[0];

    for (uint32_t i = 0; i < iterations; i++) {
        sum += times_us[i];
        if (times_us[i] < min_val)
            min_val = times_us[i];
        if (times_us[i] > max_val)
            max_val = times_us[i];
    }

    double mean = sum / iterations;

    double var_sum = 0.0;
    for (uint32_t i = 0; i < iterations; i++) {
        double diff = times_us[i] - mean;
        var_sum += diff * diff;
    }
    double stddev = sqrt(var_sum / iterations);

    /* Fill result */
    result->iterations = iterations;
    result->mean_us = mean;
    result->min_us = min_val;
    result->max_us = max_val;
    result->stddev_us = stddev;
    result->ops_per_sec = (mean > 0) ? (1000000.0 / mean) : 0;
    result->payload_bytes = payload_bytes;

    if (payload_bytes > 0 && mean > 0) {
        /* throughput: (bytes * 8 bits/byte) / mean_us = Mbps */
        result->throughput_mbps = (payload_bytes * 8.0) / mean;
    }

    free(times_us);
}

void bench_print_result(const bench_result_t *result)
{
    if (result->iterations == 0) {
        ESP_LOGW(TAG, "  %-40s  SKIPPED (no results)", result->name);
        return;
    }
    ESP_LOGI(TAG, "  %-40s %8.1f us  (min=%.1f, max=%.1f, std=%.1f)  %8.0f ops/s", result->name,
             result->mean_us, result->min_us, result->max_us, result->stddev_us,
             result->ops_per_sec);
    if (result->payload_bytes > 0) {
        ESP_LOGI(TAG, "    payload=%zu bytes, throughput=%.2f Mbps", result->payload_bytes,
                 result->throughput_mbps);
    }
}

void bench_print_header(const char *section)
{
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "============================================================");
    ESP_LOGI(TAG, " %s", section);
    ESP_LOGI(TAG, "============================================================");
}

void bench_print_memory(const char *label)
{
    ESP_LOGI(TAG, "[MEM] %s: free_heap=%lu, min_free_heap=%lu", label,
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)esp_get_minimum_free_heap_size());
}
