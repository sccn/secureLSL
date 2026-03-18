// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_sample.h"
#include "lsl_stream_info.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "lsl_sample";

int sample_serialize(const void *channel_data, size_t channel_data_len, double timestamp,
                     uint8_t *out, size_t out_len)
{
    if (!channel_data || !out || channel_data_len == 0) {
        ESP_LOGE(TAG, "Invalid args: data=%p, out=%p, data_len=%zu", (void *)channel_data,
                 (void *)out, channel_data_len);
        return -1;
    }

    int deduced = (timestamp == 0.0);
    size_t need = 1 + (deduced ? 0 : 8) + channel_data_len;
    if (need > out_len) {
        ESP_LOGE(TAG, "Buffer too small: need %zu, have %zu", need, out_len);
        return -1;
    }

    size_t pos = 0;

    /* Tag byte */
    out[pos++] = deduced ? LSL_ESP32_TAG_DEDUCED : LSL_ESP32_TAG_TRANSMITTED;

    /* Timestamp (native byte order double, only if transmitted).
     * ESP32 (Xtensa LX6) is little-endian, matching x86 desktop liblsl. */
    if (!deduced) {
        memcpy(&out[pos], &timestamp, 8);
        pos += 8;
    }

    /* Channel data (already in native byte order = little-endian on ESP32) */
    memcpy(&out[pos], channel_data, channel_data_len);
    pos += channel_data_len;

    return (int)pos;
}

int sample_generate_test_pattern(int channel_count, lsl_esp32_channel_format_t channel_format,
                                 int offset, double timestamp, uint8_t *out, size_t out_len)
{
    size_t bpc = stream_info_bytes_per_channel(channel_format);
    if (bpc == 0 || channel_count < 1 || channel_count > LSL_ESP32_MAX_CHANNELS) {
        ESP_LOGE(TAG, "Invalid format (%d) or channel count (%d, max %d)", channel_format,
                 channel_count, LSL_ESP32_MAX_CHANNELS);
        return -1;
    }

    size_t data_len = (size_t)channel_count * bpc;
    /* Temporary buffer for channel data (stack-allocated, 1024 bytes max) */
    uint8_t data[LSL_ESP32_MAX_CHANNELS * 8];
    if (data_len > sizeof(data)) {
        ESP_LOGE(TAG, "Channel data too large: %zu bytes", data_len);
        return -1;
    }

    /* Fill test pattern per liblsl sample.cpp:356-406.
     * float32:  value = (k + offset) * sign
     * double64: value = (k + offset + 16777217) * sign
     * int types: value = ((k + offset + adj) % max_val) * sign
     *   where adj = 65537 (int32), 257 (int16), 1 (int8)
     * sign = (k % 2 == 0) ? 1 : -1 */
    for (int k = 0; k < channel_count; k++) {
        int sign = (k % 2 == 0) ? 1 : -1;

        switch (channel_format) {
        case LSL_ESP32_FMT_FLOAT32: {
            float val = (float)((k + offset) * sign);
            memcpy(&data[k * bpc], &val, bpc);
            break;
        }
        case LSL_ESP32_FMT_DOUBLE64: {
            double val = (double)(((long long)k + offset + 16777217) * sign);
            memcpy(&data[k * bpc], &val, bpc);
            break;
        }
        case LSL_ESP32_FMT_INT32: {
            size_t v = ((size_t)k + (size_t)offset + 65537) % 2147483647u;
            int32_t val = (int32_t)(v)*sign;
            memcpy(&data[k * bpc], &val, bpc);
            break;
        }
        case LSL_ESP32_FMT_INT16: {
            size_t v = ((size_t)k + (size_t)offset + 257) % 32767u;
            int16_t val = (int16_t)(v) * (int16_t)sign;
            memcpy(&data[k * bpc], &val, bpc);
            break;
        }
        case LSL_ESP32_FMT_INT8: {
            size_t v = ((size_t)k + (size_t)offset + 1) % 127u;
            int8_t val = (int8_t)(v) * (int8_t)sign;
            memcpy(&data[k * bpc], &val, bpc);
            break;
        }
        default:
            ESP_LOGE(TAG, "Unsupported channel format in test pattern: %d", channel_format);
            return -1;
        }
    }

    return sample_serialize(data, data_len, timestamp, out, out_len);
}

int sample_deserialize(const uint8_t *in, size_t in_len, int channel_count,
                       lsl_esp32_channel_format_t fmt, void *channel_data_out,
                       size_t channel_data_len, double *timestamp_out)
{
    if (!in || !channel_data_out || !timestamp_out || in_len == 0) {
        ESP_LOGE(TAG, "Invalid args to sample_deserialize");
        return -1;
    }

    size_t bpc = stream_info_bytes_per_channel(fmt);
    if (bpc == 0 || channel_count < 1) {
        ESP_LOGE(TAG, "Invalid format (%d) or channel count (%d)", fmt, channel_count);
        return -1;
    }

    size_t expected_data = (size_t)channel_count * bpc;
    if (expected_data > channel_data_len) {
        ESP_LOGE(TAG, "Channel data buffer too small: need %zu, have %zu", expected_data,
                 channel_data_len);
        return -1;
    }

    size_t pos = 0;

    /* Tag byte (in_len >= 1 guaranteed by check above) */
    uint8_t tag = in[pos++];

    /* Timestamp */
    if (tag == LSL_ESP32_TAG_TRANSMITTED) {
        if (pos + 8 > in_len) {
            ESP_LOGE(TAG, "Truncated timestamp");
            return -1;
        }
        memcpy(timestamp_out, &in[pos], 8);
        pos += 8;
    } else if (tag == LSL_ESP32_TAG_DEDUCED) {
        *timestamp_out = 0.0;
    } else {
        ESP_LOGE(TAG, "Unknown sample tag: 0x%02x", tag);
        return -1;
    }

    /* Channel data */
    if (pos + expected_data > in_len) {
        ESP_LOGE(TAG, "Truncated channel data: need %zu, have %zu", expected_data, in_len - pos);
        return -1;
    }
    memcpy(channel_data_out, &in[pos], expected_data);
    pos += expected_data;

    return (int)pos;
}

int sample_validate_test_pattern(int channel_count, lsl_esp32_channel_format_t fmt, int offset,
                                 double expected_timestamp, const void *channel_data,
                                 double actual_timestamp)
{
    if (!channel_data) {
        return -1;
    }

    /* Check timestamp */
    if (expected_timestamp != 0.0 && actual_timestamp != expected_timestamp) {
        ESP_LOGW(TAG, "Test pattern timestamp mismatch: expected=%.6f actual=%.6f",
                 expected_timestamp, actual_timestamp);
        return -1;
    }

    /* Generate expected pattern and compare */
    size_t bpc = stream_info_bytes_per_channel(fmt);
    if (bpc == 0) {
        return -1;
    }
    size_t data_len = (size_t)channel_count * bpc;

    uint8_t expected[LSL_ESP32_MAX_CHANNELS * 8];
    uint8_t serialized[LSL_SAMPLE_MAX_BYTES];

    int n = sample_generate_test_pattern(channel_count, fmt, offset, expected_timestamp, serialized,
                                         sizeof(serialized));
    if (n <= 0) {
        return -1;
    }

    /* Extract channel data from serialized pattern (skip tag + optional timestamp) */
    size_t skip = (expected_timestamp != 0.0) ? (1 + 8) : 1;
    if ((size_t)n < skip + data_len) {
        return -1;
    }
    memcpy(expected, serialized + skip, data_len);

    if (memcmp(channel_data, expected, data_len) != 0) {
        ESP_LOGW(TAG, "Test pattern data mismatch (offset=%d, ch=%d, fmt=%d)", offset,
                 channel_count, fmt);
        return -1;
    }

    return 0;
}
