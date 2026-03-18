// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_ESP32_TYPES_H
#define LSL_ESP32_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* --- Error codes --- */
typedef enum {
    LSL_ESP32_OK = 0,
    LSL_ESP32_ERR_NO_MEMORY,
    LSL_ESP32_ERR_NETWORK,
    LSL_ESP32_ERR_PROTOCOL,
    LSL_ESP32_ERR_SECURITY,
    LSL_ESP32_ERR_INVALID_ARG,
    LSL_ESP32_ERR_TIMEOUT,
    LSL_ESP32_ERR_NOT_FOUND,
} lsl_esp32_err_t;

/* --- Channel formats (matching liblsl wire values) ---
 * Values 0 (undefined), 3 (string32), 7 (int64) intentionally absent;
 * ESP32 implementation supports numeric types only. */
typedef enum {
    LSL_ESP32_FMT_FLOAT32 = 1,
    LSL_ESP32_FMT_DOUBLE64 = 2,
    /* 3 = cft_string32, not supported */
    LSL_ESP32_FMT_INT32 = 4,
    LSL_ESP32_FMT_INT16 = 5,
    LSL_ESP32_FMT_INT8 = 6,
    /* 7 = cft_int64, not supported */
} lsl_esp32_channel_format_t;

/* --- Public protocol constants --- */
#define LSL_ESP32_MULTICAST_ADDR   "239.255.172.215"
#define LSL_ESP32_MULTICAST_PORT   16571
#define LSL_ESP32_PROTOCOL_VERSION 110
#define LSL_ESP32_MAX_CONNECTIONS  3
#define LSL_ESP32_SAMPLE_POOL_SIZE 64
#define LSL_ESP32_MAX_CHANNELS     128
#define LSL_ESP32_UUID_STR_LEN     37 /* 36 chars + null */
#define LSL_ESP32_TCP_PORT_MIN     16572
#define LSL_ESP32_TCP_PORT_MAX     16604

/* --- Opaque handles --- */
typedef struct lsl_esp32_stream_info *lsl_esp32_stream_info_t;
typedef struct lsl_esp32_outlet *lsl_esp32_outlet_t;
typedef struct lsl_esp32_inlet *lsl_esp32_inlet_t;

#endif /* LSL_ESP32_TYPES_H */
