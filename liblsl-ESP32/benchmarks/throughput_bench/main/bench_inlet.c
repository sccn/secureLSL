// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "bench_inlet.h"
#include "bench_monitor.h"
#include "lsl_esp32.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "bench_in";

/* Timing ring buffer for percentile computation */
#define TIMING_RING_SIZE 10000
static uint32_t s_pull_times[TIMING_RING_SIZE];
static uint32_t s_intervals[TIMING_RING_SIZE];
static uint32_t s_sort_buf[TIMING_RING_SIZE]; /* pre-allocated sort buffer */
static int s_pull_count = 0;

static int cmp_uint32(const void *a, const void *b)
{
    uint32_t va = *(const uint32_t *)a;
    uint32_t vb = *(const uint32_t *)b;
    return (va > vb) - (va < vb);
}

static uint32_t percentile(const uint32_t *ring, int count, int pct)
{
    int n = (count < TIMING_RING_SIZE) ? count : TIMING_RING_SIZE;
    if (n == 0) {
        return 0;
    }
    /* Sort pre-allocated copy (no heap allocation) */
    memcpy(s_sort_buf, ring, n * sizeof(uint32_t));
    qsort(s_sort_buf, n, sizeof(uint32_t), cmp_uint32);
    int idx = (int)((double)pct / 100.0 * (n - 1));
    return s_sort_buf[idx];
}

void bench_inlet_run(void)
{
    int channels = CONFIG_BENCH_CHANNELS;
    int rate = CONFIG_BENCH_SAMPLE_RATE;
    int duration = CONFIG_BENCH_DURATION;
    int report_interval = CONFIG_BENCH_REPORT_INTERVAL;
#ifdef CONFIG_BENCH_SECURITY_ENABLE
    int secure = 1;
#else
    int secure = 0;
#endif

    ESP_LOGI(TAG, "Inlet benchmark: %dch @ %dHz, %ds, security=%s", channels, rate, duration,
             secure ? "on" : "off");

    /* Resolve target stream */
    ESP_LOGI(TAG, "Resolving '%s'...", CONFIG_BENCH_TARGET_STREAM);
    lsl_esp32_stream_info_t info = NULL;
    int found = lsl_esp32_resolve_stream("name", CONFIG_BENCH_TARGET_STREAM, 30.0, &info);
    if (!found || !info) {
        ESP_LOGE(TAG, "Stream not found within 30s");
        return;
    }
    ESP_LOGI(TAG, "Found: %s (%dch @ %.0fHz)", lsl_esp32_get_name(info),
             lsl_esp32_get_channel_count(info), lsl_esp32_get_nominal_srate(info));

    /* Create inlet */
    lsl_esp32_inlet_t inlet = lsl_esp32_create_inlet(info);
    if (!inlet) {
        ESP_LOGE(TAG, "Failed to create inlet");
        lsl_esp32_destroy_streaminfo(info);
        return;
    }

    /* Allocate sample buffer */
    float *sample = calloc(channels, sizeof(float));
    if (!sample) {
        ESP_LOGE(TAG, "Failed to allocate sample buffer");
        lsl_esp32_destroy_inlet(inlet);
        return;
    }

    /* Warmup: 2 seconds */
    ESP_LOGI(TAG, "Warmup (2s)...");
    for (int i = 0; i < rate * 2; i++) {
        double ts;
        lsl_esp32_inlet_pull_sample_f(inlet, sample, channels * (int)sizeof(float), &ts, 2.0);
    }

    /* Measurement loop */
    s_pull_count = 0;
    int received = 0;
    int timeouts = 0;
    int64_t bench_start = esp_timer_get_time();
    int64_t next_report = bench_start + (int64_t)report_interval * 1000000;
    int64_t last_pull_time = 0;

    /* Running stats for pull timing */
    uint64_t pull_sum = 0;
    uint64_t pull_sum_sq = 0;
    uint32_t pull_min = UINT32_MAX;
    uint32_t pull_max = 0;

    /* Running stats for intervals */
    uint64_t interval_sum = 0;
    uint64_t interval_sum_sq = 0;
    int interval_count = 0;

    ESP_LOGI(TAG, "Measurement started");

    while (1) {
        /* Check duration */
        int64_t now = esp_timer_get_time();
        if (duration > 0 && (now - bench_start) >= (int64_t)duration * 1000000) {
            break;
        }

        /* Time the pull */
        double ts;
        int64_t t0 = esp_timer_get_time();
        lsl_esp32_err_t err =
            lsl_esp32_inlet_pull_sample_f(inlet, sample, channels * (int)sizeof(float), &ts, 5.0);
        int64_t t1 = esp_timer_get_time();

        if (err == LSL_ESP32_OK) {
            uint32_t pull_us = (uint32_t)(t1 - t0);
            pull_sum += pull_us;
            pull_sum_sq += (uint64_t)pull_us * pull_us;
            if (pull_us < pull_min) {
                pull_min = pull_us;
            }
            if (pull_us > pull_max) {
                pull_max = pull_us;
            }
            s_pull_times[s_pull_count % TIMING_RING_SIZE] = pull_us;

            /* Inter-sample interval */
            if (last_pull_time > 0) {
                uint32_t interval_us = (uint32_t)(t1 - last_pull_time);
                s_intervals[interval_count % TIMING_RING_SIZE] = interval_us;
                interval_sum += interval_us;
                interval_sum_sq += (uint64_t)interval_us * interval_us;
                interval_count++;
            }
            last_pull_time = t1;

            s_pull_count++;
            received++;
        } else if (err == LSL_ESP32_ERR_TIMEOUT) {
            timeouts++;
            if (timeouts > 12) {
                ESP_LOGW(TAG, "Too many timeouts (%d), stopping", timeouts);
                break;
            }
        } else {
            ESP_LOGE(TAG, "Pull error: %d", err);
            break;
        }

        /* Periodic report */
        if (t1 >= next_report) {
            double elapsed = (double)(t1 - bench_start) / 1000000.0;
            double actual_rate = (double)received / elapsed;
            printf("{\"type\":\"progress\","
                   "\"t\":%.0f,"
                   "\"samples\":%d,"
                   "\"rate_hz\":%.1f,"
                   "\"pull_mean_us\":%lu,"
                   "\"timeouts\":%d,"
                   "\"heap\":%lu}\n",
                   elapsed, received, actual_rate,
                   (unsigned long)(received > 0 ? pull_sum / received : 0), timeouts,
                   (unsigned long)esp_get_free_heap_size());
            next_report = t1 + (int64_t)report_interval * 1000000;
        }
    }

    int64_t bench_end = esp_timer_get_time();
    double actual_duration = (double)(bench_end - bench_start) / 1000000.0;
    double actual_rate = (double)received / actual_duration;
    int expected = (int)(rate * actual_duration);
    double loss_pct = (expected > 0) ? 100.0 * (expected - received) / expected : 0;

    /* Compute stats */
    double pull_mean = (received > 0) ? (double)pull_sum / received : 0;
    double pull_var = (received > 0) ? (double)pull_sum_sq / received - pull_mean * pull_mean : 0;
    double pull_std = (pull_var > 0) ? sqrt(pull_var) : 0;

    double interval_mean = (interval_count > 0) ? (double)interval_sum / interval_count : 0;
    double interval_var = (interval_count > 0) ? (double)interval_sum_sq / interval_count -
                                                     interval_mean * interval_mean
                                               : 0;
    double jitter_std = (interval_var > 0) ? sqrt(interval_var) : 0;

    /* Final summary */
    printf("{\"type\":\"summary\","
           "\"mode\":\"inlet\","
           "\"channels\":%d,"
           "\"rate\":%d,"
           "\"security\":%s,"
           "\"duration\":%.1f,"
           "\"samples_received\":%d,"
           "\"expected_samples\":%d,"
           "\"actual_rate\":%.1f,"
           "\"packet_loss_pct\":%.2f,"
           "\"pull_mean_us\":%.1f,"
           "\"pull_std_us\":%.1f,"
           "\"pull_min_us\":%lu,"
           "\"pull_max_us\":%lu,"
           "\"pull_p95_us\":%lu,"
           "\"pull_p99_us\":%lu,"
           "\"jitter_std_us\":%.1f,"
           "\"interval_mean_us\":%.1f,"
           "\"timeouts\":%d,"
           "\"heap_free\":%lu,"
           "\"heap_min\":%lu,"
           "\"stack_hwm\":%u}\n",
           channels, rate, secure ? "true" : "false", actual_duration, received, expected,
           actual_rate, loss_pct, pull_mean, pull_std, (unsigned long)(received > 0 ? pull_min : 0),
           (unsigned long)pull_max, (unsigned long)percentile(s_pull_times, s_pull_count, 95),
           (unsigned long)percentile(s_pull_times, s_pull_count, 99), jitter_std, interval_mean,
           timeouts, (unsigned long)esp_get_free_heap_size(),
           (unsigned long)bench_monitor_get_heap_min(),
           (unsigned)uxTaskGetStackHighWaterMark(NULL));

    free(sample);
    bench_monitor_print_summary();

    ESP_LOGI(TAG, "Benchmark complete: %d/%d samples (%.1f%% loss), jitter=%.1f us", received,
             expected, loss_pct, jitter_std);

    lsl_esp32_destroy_inlet(inlet);
}
