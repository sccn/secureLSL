// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "bench_outlet.h"
#include "bench_monitor.h"
#include "lsl_esp32.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "bench_out";

/* Timing ring buffer for percentile computation */
#define TIMING_RING_SIZE 10000
static uint32_t s_push_times[TIMING_RING_SIZE];
static uint32_t s_sort_buf[TIMING_RING_SIZE]; /* pre-allocated sort buffer */
static int s_push_count = 0;

/* Running statistics (no heap allocation in hot path) */
typedef struct {
    uint64_t sum;
    uint64_t sum_sq;
    uint32_t min;
    uint32_t max;
    uint32_t count;
} running_stats_t;

static void stats_reset(running_stats_t *s)
{
    memset(s, 0, sizeof(*s));
    s->min = UINT32_MAX;
}

static void stats_add(running_stats_t *s, uint32_t val)
{
    s->sum += val;
    s->sum_sq += (uint64_t)val * val;
    if (val < s->min) {
        s->min = val;
    }
    if (val > s->max) {
        s->max = val;
    }
    s->count++;
}

static int cmp_uint32(const void *a, const void *b)
{
    uint32_t va = *(const uint32_t *)a;
    uint32_t vb = *(const uint32_t *)b;
    return (va > vb) - (va < vb);
}

/* Compute percentile from the timing ring buffer */
static uint32_t compute_percentile(int pct)
{
    int count = (s_push_count < TIMING_RING_SIZE) ? s_push_count : TIMING_RING_SIZE;
    if (count == 0) {
        return 0;
    }

    /* Sort pre-allocated copy (no heap allocation) */
    memcpy(s_sort_buf, s_push_times, count * sizeof(uint32_t));
    qsort(s_sort_buf, count, sizeof(uint32_t), cmp_uint32);

    int idx = (int)((double)pct / 100.0 * (count - 1));
    return s_sort_buf[idx];
}

void bench_outlet_run(void)
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

    ESP_LOGI(TAG, "Outlet benchmark: %dch @ %dHz, %ds, security=%s", channels, rate, duration,
             secure ? "on" : "off");

    /* Create stream info */
    lsl_esp32_stream_info_t info =
        lsl_esp32_create_streaminfo(CONFIG_BENCH_STREAM_NAME, "Benchmark", channels, (double)rate,
                                    LSL_ESP32_FMT_FLOAT32, "esp32_bench_outlet");
    if (!info) {
        ESP_LOGE(TAG, "Failed to create stream info");
        return;
    }

    /* Create outlet */
    lsl_esp32_outlet_t outlet = lsl_esp32_create_outlet(info, 0, 360);
    if (!outlet) {
        ESP_LOGE(TAG, "Failed to create outlet");
        lsl_esp32_destroy_streaminfo(info);
        return;
    }

    ESP_LOGI(TAG, "Outlet created, waiting for consumer...");
    while (!lsl_esp32_have_consumers(outlet)) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    ESP_LOGI(TAG, "Consumer connected, starting benchmark");

    /* Allocate sample buffer */
    float *sample = calloc(channels, sizeof(float));
    if (!sample) {
        ESP_LOGE(TAG, "Failed to allocate sample buffer");
        lsl_esp32_destroy_outlet(outlet);
        return;
    }

    /* Warmup: 2 seconds */
    ESP_LOGI(TAG, "Warmup (2s)...");
    TickType_t pace = xTaskGetTickCount();
    TickType_t delay_ticks = pdMS_TO_TICKS(1000 / rate);
    for (int i = 0; i < rate * 2; i++) {
        double ts = lsl_esp32_local_clock();
        sample[0] = (float)ts;
        for (int ch = 1; ch < channels; ch++) {
            sample[ch] = sinf((float)ts * 2.0f * 3.14159f * (float)ch);
        }
        lsl_esp32_push_sample_f(outlet, sample, 0.0);
        vTaskDelayUntil(&pace, delay_ticks);
    }

    /* Measurement loop */
    running_stats_t stats;
    stats_reset(&stats);
    s_push_count = 0;

    int total_samples = (duration > 0) ? rate * duration : 0;
    int samples_pushed = 0;
    int64_t bench_start = esp_timer_get_time();
    int64_t next_report = bench_start + (int64_t)report_interval * 1000000;

    ESP_LOGI(TAG, "Measurement started");

    pace = xTaskGetTickCount();
    while (1) {
        /* Check duration */
        if (total_samples > 0 && samples_pushed >= total_samples) {
            break;
        }

        /* Generate sample with embedded timestamp */
        double ts = lsl_esp32_local_clock();
        sample[0] = (float)ts;
        for (int ch = 1; ch < channels; ch++) {
            sample[ch] = sinf((float)ts * 2.0f * 3.14159f * (float)ch);
        }

        /* Time the push */
        int64_t t0 = esp_timer_get_time();
        lsl_esp32_push_sample_f(outlet, sample, 0.0);
        int64_t t1 = esp_timer_get_time();

        uint32_t push_us = (uint32_t)(t1 - t0);
        stats_add(&stats, push_us);

        /* Store in ring buffer for percentiles */
        s_push_times[s_push_count % TIMING_RING_SIZE] = push_us;
        s_push_count++;
        samples_pushed++;

        /* Periodic report */
        if (t1 >= next_report) {
            double elapsed = (double)(t1 - bench_start) / 1000000.0;
            double actual_rate = (double)samples_pushed / elapsed;
            printf("{\"type\":\"progress\","
                   "\"t\":%.0f,"
                   "\"samples\":%d,"
                   "\"rate_hz\":%.1f,"
                   "\"push_mean_us\":%lu,"
                   "\"push_max_us\":%lu,"
                   "\"heap\":%lu}\n",
                   elapsed, samples_pushed, actual_rate, (unsigned long)(stats.sum / stats.count),
                   (unsigned long)stats.max, (unsigned long)esp_get_free_heap_size());
            next_report = t1 + (int64_t)report_interval * 1000000;
        }

        vTaskDelayUntil(&pace, delay_ticks);
    }

    int64_t bench_end = esp_timer_get_time();
    double actual_duration = (double)(bench_end - bench_start) / 1000000.0;
    double actual_rate = (double)samples_pushed / actual_duration;

    /* Compute stats */
    double mean = (double)stats.sum / stats.count;
    double variance = (double)stats.sum_sq / stats.count - mean * mean;
    double stddev = (variance > 0) ? sqrt(variance) : 0;

    /* Final summary */
    printf("{\"type\":\"summary\","
           "\"mode\":\"outlet\","
           "\"channels\":%d,"
           "\"rate\":%d,"
           "\"security\":%s,"
           "\"duration\":%.1f,"
           "\"samples_pushed\":%d,"
           "\"actual_rate\":%.1f,"
           "\"push_mean_us\":%.1f,"
           "\"push_std_us\":%.1f,"
           "\"push_min_us\":%lu,"
           "\"push_max_us\":%lu,"
           "\"push_p95_us\":%lu,"
           "\"push_p99_us\":%lu,"
           "\"heap_free\":%lu,"
           "\"heap_min\":%lu,"
           "\"stack_hwm\":%u}\n",
           channels, rate, secure ? "true" : "false", actual_duration, samples_pushed, actual_rate,
           mean, stddev, (unsigned long)stats.min, (unsigned long)stats.max,
           (unsigned long)compute_percentile(95), (unsigned long)compute_percentile(99),
           (unsigned long)esp_get_free_heap_size(), (unsigned long)bench_monitor_get_heap_min(),
           (unsigned)uxTaskGetStackHighWaterMark(NULL));

    free(sample);
    bench_monitor_print_summary();

    ESP_LOGI(TAG, "Benchmark complete: %d samples in %.1fs (%.1f Hz)", samples_pushed,
             actual_duration, actual_rate);
    ESP_LOGI(TAG, "Push: mean=%.1f us, std=%.1f us, p95=%lu us", mean, stddev,
             (unsigned long)compute_percentile(95));

    lsl_esp32_destroy_outlet(outlet);
}
