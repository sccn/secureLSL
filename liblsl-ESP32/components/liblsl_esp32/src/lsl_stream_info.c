// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_stream_info.h"
#include "lsl_protocol.h"
#include "lsl_clock.h"
#include "lsl_esp32.h"
#include "esp_log.h"
#include "esp_random.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "lsl_stream_info";

void stream_info_generate_uuid4(char *out)
{
    uint8_t bytes[16];
    /* Use ESP32 hardware RNG for all 16 bytes */
    uint32_t r;
    for (int i = 0; i < 16; i += 4) {
        r = esp_random();
        memcpy(&bytes[i], &r, 4);
    }
    /* Set version 4 (two MSBs of time_hi = 0100b, per RFC 4122) */
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    /* Set variant 1 (two MSBs of clock_seq_hi_and_reserved = 10b, per RFC 4122) */
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    snprintf(out, LSL_ESP32_UUID_STR_LEN,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", bytes[0],
             bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
             bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

const char *stream_info_format_string(lsl_esp32_channel_format_t fmt)
{
    switch (fmt) {
    case LSL_ESP32_FMT_FLOAT32:
        return "float32";
    case LSL_ESP32_FMT_DOUBLE64:
        return "double64";
    case LSL_ESP32_FMT_INT32:
        return "int32";
    case LSL_ESP32_FMT_INT16:
        return "int16";
    case LSL_ESP32_FMT_INT8:
        return "int8";
    default:
        ESP_LOGW(TAG, "Unknown channel format: %d", fmt);
        return "undefined";
    }
}

size_t stream_info_bytes_per_channel(lsl_esp32_channel_format_t fmt)
{
    switch (fmt) {
    case LSL_ESP32_FMT_FLOAT32:
        return 4;
    case LSL_ESP32_FMT_DOUBLE64:
        return 8;
    case LSL_ESP32_FMT_INT32:
        return 4;
    case LSL_ESP32_FMT_INT16:
        return 2;
    case LSL_ESP32_FMT_INT8:
        return 1;
    default:
        return 0;
    }
}

/* Check if snprintf truncated and log a warning. Returns 1 if truncated. */
static int check_truncation(const char *field, int written, size_t max_len)
{
    if (written >= 0 && (size_t)written >= max_len) {
        ESP_LOGW(TAG, "Field '%s' truncated (%d chars, max %zu)", field, written, max_len - 1);
        return 1;
    }
    return 0;
}

lsl_esp32_stream_info_t lsl_esp32_create_streaminfo(const char *name, const char *type,
                                                    int channel_count, double nominal_srate,
                                                    lsl_esp32_channel_format_t channel_format,
                                                    const char *source_id)
{
    if (!name || channel_count < 1 || channel_count > LSL_ESP32_MAX_CHANNELS) {
        ESP_LOGE(TAG, "Invalid arguments: name=%p, channels=%d (max %d)", (void *)name,
                 channel_count, LSL_ESP32_MAX_CHANNELS);
        return NULL;
    }

    if (stream_info_bytes_per_channel(channel_format) == 0) {
        ESP_LOGE(TAG, "Invalid channel format: %d", channel_format);
        return NULL;
    }

    if (nominal_srate < 0.0) {
        ESP_LOGE(TAG, "Invalid nominal_srate: %g", nominal_srate);
        return NULL;
    }

    struct lsl_esp32_stream_info *info = calloc(1, sizeof(*info));
    if (!info) {
        ESP_LOGE(TAG, "Failed to allocate stream info");
        return NULL;
    }

    int n;
    n = snprintf(info->name, sizeof(info->name), "%s", name);
    check_truncation("name", n, sizeof(info->name));
    n = snprintf(info->type, sizeof(info->type), "%s", type ? type : "");
    check_truncation("type", n, sizeof(info->type));
    info->channel_count = channel_count;
    info->nominal_srate = nominal_srate;
    info->channel_format = channel_format;
    n = snprintf(info->source_id, sizeof(info->source_id), "%s", source_id ? source_id : "");
    check_truncation("source_id", n, sizeof(info->source_id));
    stream_info_generate_uuid4(info->uid);
    snprintf(info->hostname, sizeof(info->hostname), "ESP32");
    snprintf(info->session_id, sizeof(info->session_id), "default");
    info->created_at = clock_get_time();
    info->protocol_version = LSL_ESP32_PROTOCOL_VERSION;
    info->v4service_port = LSL_ESP32_MULTICAST_PORT;
    info->v4data_port = 0; /* set later when TCP server starts */

    ESP_LOGI(TAG, "Created stream: name=%s type=%s ch=%d fmt=%s srate=%.1f uid=%s", info->name,
             info->type, info->channel_count, stream_info_format_string(info->channel_format),
             info->nominal_srate, info->uid);

    return info;
}

const char *lsl_esp32_get_name(lsl_esp32_stream_info_t info)
{
    return info ? info->name : "";
}

const char *lsl_esp32_get_type(lsl_esp32_stream_info_t info)
{
    return info ? info->type : "";
}

int lsl_esp32_get_channel_count(lsl_esp32_stream_info_t info)
{
    return info ? info->channel_count : 0;
}

double lsl_esp32_get_nominal_srate(lsl_esp32_stream_info_t info)
{
    return info ? info->nominal_srate : 0.0;
}

lsl_esp32_channel_format_t lsl_esp32_get_channel_format(lsl_esp32_stream_info_t info)
{
    return info ? info->channel_format : (lsl_esp32_channel_format_t)0;
}

void lsl_esp32_destroy_streaminfo(lsl_esp32_stream_info_t info)
{
    if (info) {
        ESP_LOGD(TAG, "Destroying stream: %s", info->name);
    }
    free(info);
}

/* XML field order matches desktop liblsl stream_info_impl.cpp:write_xml().
 * Both shortinfo and fullinfo include <desc> (empty if no description set). */

int stream_info_to_shortinfo_xml(const struct lsl_esp32_stream_info *info, char *buf,
                                 size_t buf_len)
{
    if (!info || !buf || buf_len == 0) {
        ESP_LOGE(TAG, "Invalid args to shortinfo_xml");
        return -1;
    }

    int n = snprintf(buf, buf_len,
                     "<?xml version=\"1.0\"?>"
                     "<info>"
                     "<name>%s</name>"
                     "<type>%s</type>"
                     "<channel_count>%d</channel_count>"
                     "<channel_format>%s</channel_format>"
                     "<source_id>%s</source_id>"
                     "<nominal_srate>%g</nominal_srate>"
                     "<version>1.10</version>"
                     "<created_at>%g</created_at>"
                     "<uid>%s</uid>"
                     "<session_id>%s</session_id>"
                     "<hostname>%s</hostname>"
                     "<v4address>%s</v4address>"
                     "<v4data_port>%d</v4data_port>"
                     "<v4service_port>%d</v4service_port>"
                     "<v6address></v6address>"
                     "<v6data_port>0</v6data_port>"
                     "<v6service_port>0</v6service_port>"
                     "<desc></desc>"
                     "</info>",
                     info->name, info->type, info->channel_count,
                     stream_info_format_string(info->channel_format), info->source_id,
                     info->nominal_srate, info->created_at, info->uid, info->session_id,
                     info->hostname, info->v4addr, info->v4data_port, info->v4service_port);
    if (n < 0 || (size_t)n >= buf_len) {
        ESP_LOGE(TAG, "shortinfo XML truncated: need %d, have %zu", n, buf_len);
        return -1;
    }
    return n;
}

int stream_info_to_fullinfo_xml(const struct lsl_esp32_stream_info *info, char *buf, size_t buf_len)
{
    if (!info || !buf || buf_len == 0) {
        ESP_LOGE(TAG, "Invalid args to fullinfo_xml");
        return -1;
    }

    int n = snprintf(buf, buf_len,
                     "<?xml version=\"1.0\"?>"
                     "<info>"
                     "<name>%s</name>"
                     "<type>%s</type>"
                     "<channel_count>%d</channel_count>"
                     "<channel_format>%s</channel_format>"
                     "<source_id>%s</source_id>"
                     "<nominal_srate>%g</nominal_srate>"
                     "<version>1.10</version>"
                     "<created_at>%g</created_at>"
                     "<uid>%s</uid>"
                     "<session_id>%s</session_id>"
                     "<hostname>%s</hostname>"
                     "<v4address>%s</v4address>"
                     "<v4data_port>%d</v4data_port>"
                     "<v4service_port>%d</v4service_port>"
                     "<v6address></v6address>"
                     "<v6data_port>0</v6data_port>"
                     "<v6service_port>0</v6service_port>"
                     "<desc></desc>"
                     "</info>",
                     info->name, info->type, info->channel_count,
                     stream_info_format_string(info->channel_format), info->source_id,
                     info->nominal_srate, info->created_at, info->uid, info->session_id,
                     info->hostname, info->v4addr, info->v4data_port, info->v4service_port);
    if (n < 0 || (size_t)n >= buf_len) {
        ESP_LOGE(TAG, "fullinfo XML truncated: need %d, have %zu", n, buf_len);
        return -1;
    }
    return n;
}

/* Parse a query string with AND semantics.
 * Supports: "name='X'", "type='Y'", "source_id='Z'", empty (match all).
 * Compound queries: "name='X' and type='Y'" requires ALL conditions to match.
 * Fields not mentioned in the query are not checked (implicit match).
 * Returns 1 if all conditions match, 0 if any condition fails. */
int stream_info_match_query(const struct lsl_esp32_stream_info *info, const char *query)
{
    if (!info) {
        ESP_LOGE(TAG, "NULL stream info in match_query");
        return 0;
    }

    if (!query || query[0] == '\0') {
        return 1; /* empty query matches everything */
    }

    /* Known queryable fields */
    const char *field_names[] = {"name", "type", "source_id"};
    const size_t field_lens[] = {4, 4, 9};
    const char *field_values[] = {info->name, info->type, info->source_id};
    int num_fields = 3;

    int conditions_found = 0;
    int conditions_matched = 0;

    for (int i = 0; i < num_fields; i++) {
        /* Search for this field in the query, checking word boundaries
         * to avoid matching "name" inside "hostname". */
        const char *search = query;
        while ((search = strstr(search, field_names[i])) != NULL) {
            /* Check word boundary: character before must not be alphanumeric */
            if (search != query && isalnum((unsigned char)search[-1])) {
                search += field_lens[i];
                continue;
            }

            /* Skip field name */
            const char *pos = search + field_lens[i];
            while (*pos == ' ') {
                pos++;
            }
            if (*pos != '=') {
                search = pos;
                continue;
            }
            pos++;
            while (*pos == ' ') {
                pos++;
            }

            /* Extract quoted value */
            char quote_char = *pos;
            if (quote_char != '\'' && quote_char != '"') {
                search = pos;
                continue;
            }
            pos++;
            const char *end = strchr(pos, quote_char);
            if (!end) {
                search = pos;
                continue;
            }

            /* Compare field value */
            size_t vlen = (size_t)(end - pos);
            conditions_found++;
            if (strlen(field_values[i]) == vlen && strncmp(field_values[i], pos, vlen) == 0) {
                conditions_matched++;
            }

            /* Move past this match to avoid re-matching */
            search = end + 1;
            break;
        }
    }

    /* AND semantics: all found conditions must match */
    if (conditions_found == 0) {
        /* Query had no recognized fields; treat as no match */
        ESP_LOGD(TAG, "No recognized fields in query: '%s'", query);
        return 0;
    }

    return (conditions_matched == conditions_found) ? 1 : 0;
}
