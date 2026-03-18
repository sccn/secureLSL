// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_xml_parser.h"
#include "esp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "lsl_xml_parser";

int xml_extract_tag(const char *xml, const char *tag_name, char *out, size_t out_len)
{
    if (!xml || !tag_name || !out || out_len == 0) {
        return -1;
    }

    /* Build opening tag: "<tag_name>" */
    char open_tag[64];
    int open_len = snprintf(open_tag, sizeof(open_tag), "<%s>", tag_name);
    if (open_len < 0 || (size_t)open_len >= sizeof(open_tag)) {
        return -1;
    }

    /* Build closing tag: "</tag_name>" */
    char close_tag[64];
    int close_len = snprintf(close_tag, sizeof(close_tag), "</%s>", tag_name);
    if (close_len < 0 || (size_t)close_len >= sizeof(close_tag)) {
        return -1;
    }

    /* Find opening tag */
    const char *start = strstr(xml, open_tag);
    if (!start) {
        return -1;
    }
    start += open_len;

    /* Find closing tag */
    const char *end = strstr(start, close_tag);
    if (!end) {
        return -1;
    }

    /* Copy content, warn on truncation */
    size_t content_len = (size_t)(end - start);
    if (content_len >= out_len) {
        ESP_LOGW(TAG, "Tag '%s' content truncated: %zu >= %zu", tag_name, content_len, out_len);
        content_len = out_len - 1;
    }
    memcpy(out, start, content_len);
    out[content_len] = '\0';

    return (int)content_len;
}

/* Parse channel format string to enum value */
static lsl_esp32_channel_format_t parse_channel_format(const char *str)
{
    if (strcmp(str, "float32") == 0) {
        return LSL_ESP32_FMT_FLOAT32;
    }
    if (strcmp(str, "double64") == 0) {
        return LSL_ESP32_FMT_DOUBLE64;
    }
    if (strcmp(str, "int32") == 0) {
        return LSL_ESP32_FMT_INT32;
    }
    if (strcmp(str, "int16") == 0) {
        return LSL_ESP32_FMT_INT16;
    }
    if (strcmp(str, "int8") == 0) {
        return LSL_ESP32_FMT_INT8;
    }
    return (lsl_esp32_channel_format_t)0; /* invalid */
}

int xml_parse_stream_info(const char *xml, size_t xml_len, struct lsl_esp32_stream_info *out)
{
    if (!xml || xml_len == 0 || !out) {
        ESP_LOGE(TAG, "Invalid arguments to xml_parse_stream_info");
        return -1;
    }

    /* Verify null-termination within declared length (strstr requires it) */
    if (strnlen(xml, xml_len + 1) > xml_len) {
        ESP_LOGE(TAG, "XML buffer not null-terminated within declared length");
        return -1;
    }

    /* Find <info> root and restrict parsing to its content.
     * This prevents matching tags inside <desc> that might have
     * the same names as top-level fields (e.g., <name> inside channel desc). */
    const char *info_start = strstr(xml, "<info>");
    if (!info_start) {
        ESP_LOGE(TAG, "Missing <info> root element");
        return -1;
    }
    info_start += 6; /* skip "<info>" */

    /* Find the end of the top-level fields (before <desc> if present) */
    const char *desc_start = strstr(info_start, "<desc>");
    const char *info_end = strstr(info_start, "</info>");
    if (!info_end) {
        ESP_LOGE(TAG, "Missing </info> closing element");
        return -1;
    }

    /* Use desc boundary to limit search scope if desc contains nested elements */
    size_t search_len;
    if (desc_start && desc_start < info_end) {
        search_len = (size_t)(desc_start - info_start);
    } else {
        search_len = (size_t)(info_end - info_start);
    }

    /* Create a bounded copy for safe parsing */
    char *bounded = malloc(search_len + 1);
    if (!bounded) {
        ESP_LOGE(TAG, "Failed to allocate parse buffer");
        return -1;
    }
    memcpy(bounded, info_start, search_len);
    bounded[search_len] = '\0';

    memset(out, 0, sizeof(*out));
    char buf[256];

    /* Required fields */
    if (xml_extract_tag(bounded, "name", out->name, sizeof(out->name)) < 0) {
        ESP_LOGE(TAG, "Missing <name> element");
        free(bounded);
        return -1;
    }

    /* Optional string fields (empty string if missing) */
    xml_extract_tag(bounded, "type", out->type, sizeof(out->type));
    xml_extract_tag(bounded, "source_id", out->source_id, sizeof(out->source_id));
    xml_extract_tag(bounded, "uid", out->uid, sizeof(out->uid));
    xml_extract_tag(bounded, "session_id", out->session_id, sizeof(out->session_id));
    xml_extract_tag(bounded, "hostname", out->hostname, sizeof(out->hostname));
    xml_extract_tag(bounded, "v4address", out->v4addr, sizeof(out->v4addr));

    /* Numeric fields */
    if (xml_extract_tag(bounded, "channel_count", buf, sizeof(buf)) >= 0) {
        out->channel_count = atoi(buf);
    }

    if (xml_extract_tag(bounded, "nominal_srate", buf, sizeof(buf)) >= 0) {
        out->nominal_srate = atof(buf);
    }

    if (xml_extract_tag(bounded, "channel_format", buf, sizeof(buf)) >= 0) {
        out->channel_format = parse_channel_format(buf);
        if (out->channel_format == 0) {
            ESP_LOGE(TAG, "Unknown or unsupported channel format: '%s'", buf);
            free(bounded);
            return -1;
        }
    }

    if (xml_extract_tag(bounded, "v4data_port", buf, sizeof(buf)) >= 0) {
        out->v4data_port = atoi(buf);
    }

    if (xml_extract_tag(bounded, "v4service_port", buf, sizeof(buf)) >= 0) {
        out->v4service_port = atoi(buf);
    }

    if (xml_extract_tag(bounded, "created_at", buf, sizeof(buf)) >= 0) {
        out->created_at = atof(buf);
    }

    if (xml_extract_tag(bounded, "version", buf, sizeof(buf)) >= 0) {
        /* Parse "1.10" -> 110 */
        double ver = atof(buf);
        out->protocol_version = (int)(ver * 100.0 + 0.5);
    }

    free(bounded);

    /* Validate minimum required fields */
    if (out->channel_count < 1) {
        ESP_LOGE(TAG, "Invalid channel_count: %d", out->channel_count);
        return -1;
    }
    if (out->channel_format == 0) {
        ESP_LOGE(TAG, "Missing or invalid channel_format");
        return -1;
    }

    ESP_LOGD(TAG, "Parsed stream: name=%s type=%s ch=%d fmt=%d uid=%s addr=%s:%d", out->name,
             out->type, out->channel_count, out->channel_format, out->uid, out->v4addr,
             out->v4data_port);

    return 0;
}
