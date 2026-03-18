// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_ring_buffer.h"
#include "esp_log.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "lsl_ring_buf";

int ring_buffer_init(lsl_ring_buffer_t *rb, size_t slot_size, size_t slot_count)
{
    if (!rb || slot_size == 0 || slot_count == 0) {
        ESP_LOGE(TAG, "Invalid args: rb=%p, slot_size=%zu, slot_count=%zu", (void *)rb, slot_size,
                 slot_count);
        return -1;
    }

    /* Overflow check for allocation size */
    if (slot_count > SIZE_MAX / slot_size) {
        ESP_LOGE(TAG, "Ring buffer size overflow: %zu * %zu", slot_size, slot_count);
        return -1;
    }

    rb->slot_size = slot_size;
    rb->slot_count = slot_count;
    rb->write_idx = 0;

    size_t total = slot_size * slot_count;
    rb->buffer = calloc(1, total);
    if (!rb->buffer) {
        ESP_LOGE(TAG, "Failed to allocate ring buffer (%zu bytes)", total);
        return -1;
    }

    ESP_LOGI(TAG, "Ring buffer: %zu slots x %zu bytes = %zu bytes total", slot_count, slot_size,
             total);
    return 0;
}

void ring_buffer_deinit(lsl_ring_buffer_t *rb)
{
    if (rb && rb->buffer) {
        free(rb->buffer);
        rb->buffer = NULL;
    }
}

void ring_buffer_push(lsl_ring_buffer_t *rb, const uint8_t *data, size_t data_len)
{
    if (!rb || !rb->buffer || !data || data_len == 0) {
        ESP_LOGW(TAG, "ring_buffer_push: invalid args");
        return;
    }

    /* Write to current slot (wrapping within the buffer) */
    size_t slot_idx = (size_t)(rb->write_idx % rb->slot_count);
    uint8_t *dst = rb->buffer + (slot_idx * rb->slot_size);

    if (data_len <= rb->slot_size) {
        memcpy(dst, data, data_len);
        if (data_len < rb->slot_size) {
            memset(dst + data_len, 0, rb->slot_size - data_len);
        }
    } else {
        ESP_LOGW(TAG, "Data truncated: data_len=%zu > slot_size=%zu", data_len, rb->slot_size);
        memcpy(dst, data, rb->slot_size);
    }

    /* Full memory barrier: ensure data is written before index advances.
     * Required for cross-core visibility on ESP32 (Xtensa dual-core). */
    __sync_synchronize();
    rb->write_idx++;
}

void ring_buffer_consumer_init(const lsl_ring_buffer_t *rb, lsl_ring_consumer_t *consumer)
{
    if (!rb || !consumer) {
        return;
    }
    consumer->read_idx = rb->write_idx;
}

size_t ring_buffer_read(const lsl_ring_buffer_t *rb, lsl_ring_consumer_t *consumer,
                        uint8_t *out_buf, size_t out_len)
{
    if (!rb || !rb->buffer || !consumer || !out_buf) {
        return 0;
    }

    uint64_t w = rb->write_idx;
    __sync_synchronize(); /* ensure we see latest write_idx and data */

    if (consumer->read_idx >= w) {
        return 0; /* no new data */
    }

    /* If consumer fell behind, skip to oldest available */
    if (w - consumer->read_idx > rb->slot_count) {
        ESP_LOGD(TAG, "Consumer fell behind, skipping %llu samples",
                 (unsigned long long)(w - consumer->read_idx - rb->slot_count));
        consumer->read_idx = w - rb->slot_count;
    }

    size_t slot_idx = (size_t)(consumer->read_idx % rb->slot_count);
    const uint8_t *src = rb->buffer + (slot_idx * rb->slot_size);
    size_t copy_len = (rb->slot_size < out_len) ? rb->slot_size : out_len;
    memcpy(out_buf, src, copy_len);

    /* Double-check: verify the slot wasn't overwritten while we were reading.
     * This prevents returning a mix of old and new data when the producer
     * wraps around and overwrites the slot we just read. */
    __sync_synchronize();
    uint64_t w2 = rb->write_idx;
    if (w2 - consumer->read_idx > rb->slot_count) {
        /* Slot was overwritten during our read; data is invalid */
        consumer->read_idx = w2 - rb->slot_count;
        return 0;
    }

    consumer->read_idx++;
    return copy_len;
}

uint64_t ring_buffer_available(const lsl_ring_buffer_t *rb, const lsl_ring_consumer_t *consumer)
{
    if (!rb || !consumer) {
        return 0;
    }

    uint64_t w = rb->write_idx;
    if (consumer->read_idx >= w) {
        return 0;
    }

    uint64_t avail = w - consumer->read_idx;
    if (avail > rb->slot_count) {
        avail = rb->slot_count;
    }
    return avail;
}
