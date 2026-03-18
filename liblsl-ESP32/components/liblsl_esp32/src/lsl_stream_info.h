// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_STREAM_INFO_H
#define LSL_STREAM_INFO_H

#include "lsl_esp32_types.h"

/* Maximum length for string fields in stream info */
#define STREAM_INFO_NAME_MAX      64
#define STREAM_INFO_TYPE_MAX      32
#define STREAM_INFO_SOURCE_ID_MAX 64
#define STREAM_INFO_HOSTNAME_MAX  32
#define STREAM_INFO_SESSION_MAX   32
#define STREAM_INFO_ADDR_MAX      16 /* "xxx.xxx.xxx.xxx" */

/* Internal stream info structure */
struct lsl_esp32_stream_info {
    char name[STREAM_INFO_NAME_MAX];
    char type[STREAM_INFO_TYPE_MAX];
    int channel_count;
    double nominal_srate;
    lsl_esp32_channel_format_t channel_format;
    char source_id[STREAM_INFO_SOURCE_ID_MAX];
    char uid[LSL_ESP32_UUID_STR_LEN];
    char hostname[STREAM_INFO_HOSTNAME_MAX];
    char session_id[STREAM_INFO_SESSION_MAX];
    double created_at;
    int protocol_version;
    char v4addr[STREAM_INFO_ADDR_MAX];
    int v4data_port;
    int v4service_port;
};

/* Generate a UUID4 string using ESP32 hardware RNG.
 * out must be at least LSL_ESP32_UUID_STR_LEN bytes. */
void stream_info_generate_uuid4(char *out);

/* Serialize stream info to shortinfo XML (for discovery responses).
 * Returns number of bytes written (excluding null), or -1 on error. */
int stream_info_to_shortinfo_xml(const struct lsl_esp32_stream_info *info, char *buf,
                                 size_t buf_len);

/* Serialize stream info to fullinfo XML (for detailed queries).
 * Returns number of bytes written (excluding null), or -1 on error. */
int stream_info_to_fullinfo_xml(const struct lsl_esp32_stream_info *info, char *buf,
                                size_t buf_len);

/* Check if a stream info matches a query string.
 * Query format: "name='X'" or "type='Y'" or "source_id='Z'" or empty (match all).
 * Returns 1 if match, 0 if no match. */
int stream_info_match_query(const struct lsl_esp32_stream_info *info, const char *query);

/* Return the channel format as a string (e.g., "float32") */
const char *stream_info_format_string(lsl_esp32_channel_format_t fmt);

/* Return bytes per channel for a given format */
size_t stream_info_bytes_per_channel(lsl_esp32_channel_format_t fmt);

#endif /* LSL_STREAM_INFO_H */
