// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "bench_monitor.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <limits.h>
#include <string.h>

static const char *TAG = "bench_mon";

#define MONITOR_RING_SIZE  120 /* 2 minutes at 1 sample/second */
#define MONITOR_STACK_SIZE 4096

typedef struct {
    uint32_t heap_free;
    int8_t rssi;
} monitor_sample_t;

static monitor_sample_t s_ring[MONITOR_RING_SIZE];
static volatile int s_ring_count = 0;
static volatile uint32_t s_heap_min = UINT32_MAX;
static volatile uint32_t s_heap_max = 0;
static volatile bool s_running = false;
static volatile bool s_exited = false;
static TaskHandle_t s_task = NULL;

static void monitor_task(void *arg)
{
    (void)arg;
    while (s_running) {
        monitor_sample_t sample;
        sample.heap_free = esp_get_free_heap_size();

        /* WiFi RSSI */
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            sample.rssi = ap_info.rssi;
        } else {
            sample.rssi = 0;
        }

        /* Update min/max (atomic on 32-bit ESP32) */
        if (sample.heap_free < s_heap_min) {
            s_heap_min = sample.heap_free;
        }
        if (sample.heap_free > s_heap_max) {
            s_heap_max = sample.heap_free;
        }

        /* Store in ring */
        int idx = s_ring_count % MONITOR_RING_SIZE;
        s_ring[idx] = sample;
        s_ring_count++;

        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    s_exited = true;
    vTaskDelete(NULL);
}

void bench_monitor_start(void)
{
    s_ring_count = 0;
    s_heap_min = UINT32_MAX;
    s_heap_max = 0;
    s_exited = false;
    s_running = true;

    xTaskCreatePinnedToCore(monitor_task, "bench_mon", MONITOR_STACK_SIZE, NULL, 3, &s_task, 0);
    ESP_LOGI(TAG, "Resource monitor started");
}

void bench_monitor_stop(void)
{
    s_running = false;
    /* Wait for task to confirm exit (up to 3s) */
    for (int i = 0; i < 30 && !s_exited; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (!s_exited) {
        ESP_LOGW(TAG, "Monitor task did not exit within 3s");
    }
    s_task = NULL;
    ESP_LOGI(TAG, "Resource monitor stopped (%d samples)", s_ring_count);
}

uint32_t bench_monitor_get_heap_min(void)
{
    return s_heap_min;
}

void bench_monitor_print_summary(void)
{
    if (s_ring_count == 0) {
        return;
    }

    /* Compute averages (safe to read: monitor task has exited) */
    int count = (s_ring_count < MONITOR_RING_SIZE) ? s_ring_count : MONITOR_RING_SIZE;
    uint64_t heap_sum = 0;
    int32_t rssi_sum = 0;
    int8_t rssi_min = INT8_MAX;
    int8_t rssi_max = INT8_MIN;

    for (int i = 0; i < count; i++) {
        heap_sum += s_ring[i].heap_free;
        rssi_sum += s_ring[i].rssi;
        if (s_ring[i].rssi < rssi_min) {
            rssi_min = s_ring[i].rssi;
        }
        if (s_ring[i].rssi > rssi_max) {
            rssi_max = s_ring[i].rssi;
        }
    }

    printf("{\"type\":\"monitor\","
           "\"heap_mean\":%lu,"
           "\"heap_min\":%lu,"
           "\"heap_max\":%lu,"
           "\"rssi_mean\":%d,"
           "\"rssi_min\":%d,"
           "\"rssi_max\":%d,"
           "\"samples\":%d}\n",
           (unsigned long)(heap_sum / count), (unsigned long)s_heap_min, (unsigned long)s_heap_max,
           (int)(rssi_sum / count), (int)rssi_min, (int)rssi_max, s_ring_count);
}
