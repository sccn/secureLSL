// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_outlet.h"
#include "lsl_esp32.h"
#include "lsl_clock.h"
#include "lsl_protocol.h"
#include "lsl_sample.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "lsl_outlet";

/* Get the local IPv4 address from the default STA interface */
static int get_local_ip(char *out, size_t out_len)
{
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!netif) {
        ESP_LOGW(TAG, "No WiFi STA interface found");
        return -1;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) {
        ESP_LOGW(TAG, "Failed to get IP info");
        return -1;
    }

    snprintf(out, out_len, IPSTR, IP2STR(&ip_info.ip));
    return 0;
}

lsl_esp32_outlet_t lsl_esp32_create_outlet(lsl_esp32_stream_info_t info, int chunk_size,
                                           int max_buffered)
{
    if (!info) {
        ESP_LOGE(TAG, "NULL stream info");
        return NULL;
    }

    struct lsl_esp32_outlet *outlet = calloc(1, sizeof(*outlet));
    if (!outlet) {
        ESP_LOGE(TAG, "Failed to allocate outlet");
        return NULL;
    }

    outlet->info = info;
    outlet->chunk_size = chunk_size;

    /* Compute sample slot size: tag + timestamp + channel data */
    size_t bpc = stream_info_bytes_per_channel(info->channel_format);
    if (bpc == 0) {
        ESP_LOGE(TAG, "Invalid channel format: %d", info->channel_format);
        free(outlet);
        return NULL;
    }
    outlet->sample_bytes = 1 + 8 + (size_t)info->channel_count * bpc;

    /* Set local IP in stream info (required for discovery) */
    if (get_local_ip(info->v4addr, sizeof(info->v4addr)) < 0) {
        ESP_LOGE(TAG, "Could not determine local IP; ensure WiFi is connected");
        free(outlet);
        return NULL;
    }

    /* Initialize ring buffer.
     * TODO: use max_buffered * nominal_srate to compute slot count,
     * capped by memory budget. For now, fixed at SAMPLE_POOL_SIZE. */
    (void)max_buffered;
    size_t slot_count = LSL_ESP32_SAMPLE_POOL_SIZE;
    if (ring_buffer_init(&outlet->ring, outlet->sample_bytes, slot_count) != 0) {
        ESP_LOGE(TAG, "Failed to init ring buffer");
        free(outlet);
        return NULL;
    }

    /* Load security configuration (if globally enabled via lsl_esp32_enable_security) */
    lsl_esp32_err_t sec_err = security_config_load(&outlet->security);
    if (sec_err != LSL_ESP32_OK) {
        ring_buffer_deinit(&outlet->ring);
        free(outlet);
        return NULL;
    }
    if (outlet->security.enabled) {
        ESP_LOGI(TAG, "Security enabled for outlet");
    } else {
        ESP_LOGI(TAG, "Security not enabled for outlet (plaintext mode)");
    }

    /* Start TCP data server (must start before UDP so v4data_port is set) */
    const lsl_security_config_t *sec_ptr = outlet->security.enabled ? &outlet->security : NULL;
    lsl_esp32_err_t err = tcp_server_start(&outlet->tcp, info, &outlet->ring, sec_ptr);
    if (err != LSL_ESP32_OK) {
        ESP_LOGE(TAG, "Failed to start TCP server: %d", err);
        security_config_clear(&outlet->security);
        ring_buffer_deinit(&outlet->ring);
        free(outlet);
        return NULL;
    }

    /* Start UDP discovery server */
    err = udp_server_start(&outlet->udp, info);
    if (err != LSL_ESP32_OK) {
        ESP_LOGE(TAG, "Failed to start UDP server: %d", err);
        tcp_server_stop(&outlet->tcp);
        security_config_clear(&outlet->security);
        ring_buffer_deinit(&outlet->ring);
        free(outlet);
        return NULL;
    }

    outlet->active = true;

    ESP_LOGI(TAG, "Outlet created: %s (%dch %s @ %.0fHz) on %s:%d", info->name, info->channel_count,
             stream_info_format_string(info->channel_format), info->nominal_srate, info->v4addr,
             info->v4data_port);

    return outlet;
}

void lsl_esp32_destroy_outlet(lsl_esp32_outlet_t outlet)
{
    if (!outlet) {
        return;
    }

    ESP_LOGI(TAG, "Destroying outlet: %s", outlet->info->name);
    outlet->active = false;
    __sync_synchronize(); /* ensure visibility across cores */

    /* Allow any in-flight push_sample calls to complete */
    vTaskDelay(pdMS_TO_TICKS(10));

    udp_server_stop(&outlet->udp);
    int remaining = tcp_server_stop(&outlet->tcp);
    if (remaining > 0) {
        ESP_LOGE(TAG, "Feed tasks did not exit (%d remaining), leaking outlet to avoid UAF",
                 remaining);
        /* Do not free resources that feed tasks may still reference */
        return;
    }
    ring_buffer_deinit(&outlet->ring);
    security_config_clear(&outlet->security);
    lsl_esp32_destroy_streaminfo(outlet->info);
    free(outlet);
}

lsl_esp32_err_t lsl_esp32_push_sample_f(lsl_esp32_outlet_t outlet, const float *data,
                                        double timestamp)
{
    if (!outlet || !outlet->active || !data) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }
    if (outlet->info->channel_format != LSL_ESP32_FMT_FLOAT32) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    if (timestamp == 0.0) {
        timestamp = clock_get_time();
    }

    uint8_t buf[LSL_SAMPLE_MAX_BYTES];
    size_t data_len = (size_t)outlet->info->channel_count * sizeof(float);
    int nbytes = sample_serialize(data, data_len, timestamp, buf, sizeof(buf));
    if (nbytes <= 0) {
        return LSL_ESP32_ERR_PROTOCOL;
    }

    ring_buffer_push(&outlet->ring, buf, (size_t)nbytes);
    return LSL_ESP32_OK;
}

lsl_esp32_err_t lsl_esp32_push_sample_d(lsl_esp32_outlet_t outlet, const double *data,
                                        double timestamp)
{
    if (!outlet || !outlet->active || !data) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }
    if (outlet->info->channel_format != LSL_ESP32_FMT_DOUBLE64) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    if (timestamp == 0.0) {
        timestamp = clock_get_time();
    }

    uint8_t buf[LSL_SAMPLE_MAX_BYTES];
    size_t data_len = (size_t)outlet->info->channel_count * sizeof(double);
    int nbytes = sample_serialize(data, data_len, timestamp, buf, sizeof(buf));
    if (nbytes <= 0) {
        return LSL_ESP32_ERR_PROTOCOL;
    }

    ring_buffer_push(&outlet->ring, buf, (size_t)nbytes);
    return LSL_ESP32_OK;
}

lsl_esp32_err_t lsl_esp32_push_sample_i(lsl_esp32_outlet_t outlet, const int32_t *data,
                                        double timestamp)
{
    if (!outlet || !outlet->active || !data) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }
    if (outlet->info->channel_format != LSL_ESP32_FMT_INT32) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    if (timestamp == 0.0) {
        timestamp = clock_get_time();
    }

    uint8_t buf[LSL_SAMPLE_MAX_BYTES];
    size_t data_len = (size_t)outlet->info->channel_count * sizeof(int32_t);
    int nbytes = sample_serialize(data, data_len, timestamp, buf, sizeof(buf));
    if (nbytes <= 0) {
        return LSL_ESP32_ERR_PROTOCOL;
    }

    ring_buffer_push(&outlet->ring, buf, (size_t)nbytes);
    return LSL_ESP32_OK;
}

lsl_esp32_err_t lsl_esp32_push_sample_s(lsl_esp32_outlet_t outlet, const int16_t *data,
                                        double timestamp)
{
    if (!outlet || !outlet->active || !data) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }
    if (outlet->info->channel_format != LSL_ESP32_FMT_INT16) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    if (timestamp == 0.0) {
        timestamp = clock_get_time();
    }

    uint8_t buf[LSL_SAMPLE_MAX_BYTES];
    size_t data_len = (size_t)outlet->info->channel_count * sizeof(int16_t);
    int nbytes = sample_serialize(data, data_len, timestamp, buf, sizeof(buf));
    if (nbytes <= 0) {
        return LSL_ESP32_ERR_PROTOCOL;
    }

    ring_buffer_push(&outlet->ring, buf, (size_t)nbytes);
    return LSL_ESP32_OK;
}

lsl_esp32_err_t lsl_esp32_push_sample_c(lsl_esp32_outlet_t outlet, const int8_t *data,
                                        double timestamp)
{
    if (!outlet || !outlet->active || !data) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }
    if (outlet->info->channel_format != LSL_ESP32_FMT_INT8) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    if (timestamp == 0.0) {
        timestamp = clock_get_time();
    }

    uint8_t buf[LSL_SAMPLE_MAX_BYTES];
    size_t data_len = (size_t)outlet->info->channel_count * sizeof(int8_t);
    int nbytes = sample_serialize(data, data_len, timestamp, buf, sizeof(buf));
    if (nbytes <= 0) {
        return LSL_ESP32_ERR_PROTOCOL;
    }

    ring_buffer_push(&outlet->ring, buf, (size_t)nbytes);
    return LSL_ESP32_OK;
}

int lsl_esp32_have_consumers(lsl_esp32_outlet_t outlet)
{
    if (!outlet || !outlet->active) {
        return 0;
    }
    int count = 0;
    if (outlet->tcp.conn_mutex &&
        xSemaphoreTake(outlet->tcp.conn_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        count = outlet->tcp.active_connections;
        xSemaphoreGive(outlet->tcp.conn_mutex);
    }
    return count > 0 ? 1 : 0;
}
