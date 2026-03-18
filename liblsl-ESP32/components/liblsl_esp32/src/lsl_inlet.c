// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_inlet.h"
#include "lsl_esp32.h"
#include "lsl_tcp_client.h"
#include "lsl_tcp_common.h"
#include "lsl_protocol.h"
#include "lsl_sample.h"
#include "lsl_clock.h"
#include "esp_log.h"
#include "sodium.h"

#include "lwip/sockets.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "lsl_inlet";

#define INLET_RECV_STACK 6144
#define INLET_RECV_PRIO  7

/* Queue item layout: [double timestamp][channel_data bytes] */

static void inlet_recv_task(void *arg)
{
    struct lsl_esp32_inlet *inlet = (struct lsl_esp32_inlet *)arg;
    /* Session state is fixed for the connection's lifetime: established
     * before this task starts, or never activated. Does not change mid-stream. */
    int encrypted = inlet->session.active;
    size_t wire_size = 1 + 8 + inlet->sample_data_size; /* max: tag + ts + data */
    uint8_t *wire_buf = malloc(wire_size);
    uint8_t *queue_buf = malloc(inlet->queue_item_size);

    /* Allocate ciphertext buffer only when encrypted */
    size_t ct_size = wire_size + LSL_SECURITY_AUTH_TAG_SIZE;
    uint8_t *ct_buf = encrypted ? malloc(ct_size) : NULL;

    if (!wire_buf || !queue_buf || (encrypted && !ct_buf)) {
        ESP_LOGE(TAG, "Failed to allocate receive buffers");
        free(wire_buf);
        free(queue_buf);
        free(ct_buf);
        inlet->connected = false;
        xEventGroupSetBits(inlet->events, INLET_STOPPED_BIT);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Inlet receiver task started (sample_size=%zu, encrypted=%d)",
             inlet->sample_data_size, encrypted);

    while (inlet->active && inlet->connected) {
        size_t sample_len;

        if (encrypted) {
            /* Read encrypted chunk and decrypt */
            int pt_len = tcp_recv_encrypted_chunk(inlet->sock, &inlet->session, wire_buf, wire_size,
                                                  ct_buf, ct_size);
            if (pt_len < 0) {
                ESP_LOGW(TAG, "Encrypted stream error: connection lost or auth failure");
                break;
            }
            sample_len = (size_t)pt_len;
        } else {
            /* Read unencrypted: tag byte first, then rest */
            uint8_t tag;
            if (tcp_recv_exact(inlet->sock, &tag, 1) < 0) {
                ESP_LOGI(TAG, "Connection lost (tag read failed)");
                break;
            }

            size_t to_read = 0;
            if (tag == LSL_ESP32_TAG_TRANSMITTED) {
                to_read = 8 + inlet->sample_data_size;
            } else if (tag == LSL_ESP32_TAG_DEDUCED) {
                to_read = inlet->sample_data_size;
            } else {
                ESP_LOGW(TAG, "Unknown tag byte: 0x%02x", tag);
                break;
            }

            wire_buf[0] = tag;
            if (tcp_recv_exact(inlet->sock, wire_buf + 1, to_read) < 0) {
                ESP_LOGI(TAG, "Connection lost (data read failed)");
                break;
            }
            sample_len = 1 + to_read;
        }

        /* Deserialize */
        double timestamp = 0.0;
        int consumed = sample_deserialize(wire_buf, sample_len, inlet->info->channel_count,
                                          inlet->info->channel_format, queue_buf + sizeof(double),
                                          inlet->sample_data_size, &timestamp);
        if (consumed <= 0) {
            if (encrypted) {
                /* Auth-decrypt succeeded but deserialization failed: protocol mismatch */
                ESP_LOGE(TAG, "Deserialization failed after decryption (len=%zu), disconnecting",
                         sample_len);
                break;
            }
            ESP_LOGW(TAG, "Failed to deserialize sample");
            continue;
        }

        /* Pack timestamp + channel data into queue item */
        memcpy(queue_buf, &timestamp, sizeof(double));

        /* Push to queue (non-blocking; drop oldest if full) */
        if (xQueueSend(inlet->sample_queue, queue_buf, 0) != pdTRUE) {
            xQueueReceive(inlet->sample_queue, wire_buf, 0); /* reuse wire_buf as discard */
            xQueueSend(inlet->sample_queue, queue_buf, 0);
            inlet->drop_count++;
            if (inlet->drop_count == 1 || inlet->drop_count % 100 == 0) {
                ESP_LOGW(TAG, "Queue overflow: %lu samples dropped total",
                         (unsigned long)inlet->drop_count);
            }
        }
    }

    free(wire_buf);
    free(queue_buf);
    free(ct_buf);
    inlet->connected = false;

    ESP_LOGI(TAG, "Inlet receiver task stopped");
    xEventGroupSetBits(inlet->events, INLET_STOPPED_BIT);
    vTaskDelete(NULL);
}

lsl_esp32_inlet_t lsl_esp32_create_inlet(lsl_esp32_stream_info_t info)
{
    if (!info) {
        ESP_LOGE(TAG, "NULL stream info");
        return NULL;
    }

    size_t bpc = stream_info_bytes_per_channel(info->channel_format);
    if (bpc == 0) {
        ESP_LOGE(TAG, "Invalid channel format: %d", info->channel_format);
        return NULL;
    }

    struct lsl_esp32_inlet *inlet = calloc(1, sizeof(*inlet));
    if (!inlet) {
        ESP_LOGE(TAG, "Failed to allocate inlet");
        return NULL;
    }

    /* Take ownership of stream info */
    inlet->info = info;
    inlet->sample_data_size = (size_t)info->channel_count * bpc;
    inlet->queue_item_size = sizeof(double) + inlet->sample_data_size;

    /* Create event group for shutdown */
    inlet->events = xEventGroupCreate();
    if (!inlet->events) {
        ESP_LOGE(TAG, "Failed to create event group");
        free(inlet);
        return NULL;
    }

    /* Create sample queue */
    inlet->sample_queue = xQueueCreate(INLET_QUEUE_SLOTS, inlet->queue_item_size);
    if (!inlet->sample_queue) {
        ESP_LOGE(TAG, "Failed to create sample queue (%d x %zu bytes)", INLET_QUEUE_SLOTS,
                 inlet->queue_item_size);
        vEventGroupDelete(inlet->events);
        free(inlet);
        return NULL;
    }

    /* Load security configuration (if globally enabled via lsl_esp32_enable_security) */
    security_session_init(&inlet->session);
    lsl_esp32_err_t sec_err = security_config_load(&inlet->security);
    if (sec_err != LSL_ESP32_OK) {
        vQueueDelete(inlet->sample_queue);
        vEventGroupDelete(inlet->events);
        free(inlet);
        return NULL;
    }
    if (inlet->security.enabled) {
        ESP_LOGI(TAG, "Security enabled for inlet");
    } else {
        ESP_LOGI(TAG, "Security not enabled for inlet (plaintext mode)");
    }

    /* Connect to outlet via TCP */
    const lsl_security_config_t *sec_ptr = inlet->security.enabled ? &inlet->security : NULL;
    inlet->sock = tcp_client_connect(info, sec_ptr, &inlet->session);
    if (inlet->sock < 0) {
        ESP_LOGE(TAG, "Failed to connect to outlet");
        security_config_clear(&inlet->security);
        security_session_clear(&inlet->session);
        vQueueDelete(inlet->sample_queue);
        vEventGroupDelete(inlet->events);
        free(inlet);
        return NULL;
    }

    inlet->active = true;
    inlet->connected = true;

    /* Start receiver task */
    BaseType_t ret = xTaskCreatePinnedToCore(inlet_recv_task, "lsl_inlet", INLET_RECV_STACK,
                                             (void *)inlet, INLET_RECV_PRIO, &inlet->recv_task, 1);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create receiver task");
        close(inlet->sock);
        security_config_clear(&inlet->security);
        security_session_clear(&inlet->session);
        vQueueDelete(inlet->sample_queue);
        vEventGroupDelete(inlet->events);
        free(inlet);
        return NULL;
    }

    ESP_LOGI(TAG, "Inlet created: %s (%dch %s @ %.0fHz)", info->name, info->channel_count,
             stream_info_format_string(info->channel_format), info->nominal_srate);

    return inlet;
}

void lsl_esp32_destroy_inlet(lsl_esp32_inlet_t inlet)
{
    if (!inlet) {
        return;
    }

    ESP_LOGI(TAG, "Destroying inlet: %s", inlet->info->name);
    inlet->active = false;
    __sync_synchronize();

    /* Close socket to unblock recv */
    if (inlet->sock >= 0) {
        close(inlet->sock);
        inlet->sock = -1;
    }

    /* Wait for receiver task to exit */
    if (inlet->events) {
        EventBits_t bits = xEventGroupWaitBits(inlet->events, INLET_STOPPED_BIT, pdFALSE, pdFALSE,
                                               pdMS_TO_TICKS(5000));
        if (!(bits & INLET_STOPPED_BIT)) {
            ESP_LOGE(TAG, "Receiver task did not stop within 5s, resources may leak");
            /* Do not free resources the task may still be using */
            return;
        }
        vEventGroupDelete(inlet->events);
    }

    if (inlet->sample_queue) {
        vQueueDelete(inlet->sample_queue);
    }

    security_session_clear(&inlet->session);
    security_config_clear(&inlet->security);
    lsl_esp32_destroy_streaminfo(inlet->info);
    free(inlet);
}

lsl_esp32_err_t lsl_esp32_inlet_pull_sample_f(lsl_esp32_inlet_t inlet, float *buf, int buf_len,
                                              double *timestamp, double timeout)
{
    if (!inlet || !inlet->active || !buf || !timestamp) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }
    if (inlet->info->channel_format != LSL_ESP32_FMT_FLOAT32) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    size_t expected = (size_t)inlet->info->channel_count * sizeof(float);
    if ((size_t)buf_len < expected) {
        return LSL_ESP32_ERR_INVALID_ARG;
    }

    /* Stack buffer for queue item (timestamp + channel data).
     * Capped at 520 bytes (128ch float32); larger formats use heap. */
    uint8_t item_stack[520];
    uint8_t *item;
    uint8_t *item_heap = NULL;

    if (inlet->queue_item_size <= sizeof(item_stack)) {
        item = item_stack;
    } else {
        item_heap = malloc(inlet->queue_item_size);
        if (!item_heap) {
            return LSL_ESP32_ERR_NO_MEMORY;
        }
        item = item_heap;
    }
    TickType_t ticks = (timeout <= 0) ? 0 : pdMS_TO_TICKS((uint32_t)(timeout * 1000.0));

    if (xQueueReceive(inlet->sample_queue, item, ticks) != pdTRUE) {
        free(item_heap);
        return LSL_ESP32_ERR_TIMEOUT;
    }

    /* Extract timestamp and channel data from queue item */
    memcpy(timestamp, item, sizeof(double));
    memcpy(buf, item + sizeof(double), expected);

    free(item_heap);
    return LSL_ESP32_OK;
}
