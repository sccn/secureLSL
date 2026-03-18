// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_PROTOCOL_H
#define LSL_PROTOCOL_H

/* Internal protocol constants. These are implementation details
 * that library users should not depend on. */

/* Sample tag bytes (protocol 1.10) */
#define LSL_ESP32_TAG_DEDUCED     1 /* timestamp deduced by receiver */
#define LSL_ESP32_TAG_TRANSMITTED 2 /* timestamp included in sample */

/* Test pattern constants (matching liblsl sample.cpp) */
#define LSL_ESP32_TEST_TIMESTAMP 123456.789
#define LSL_ESP32_TEST_OFFSET_1  4
#define LSL_ESP32_TEST_OFFSET_2  2

/* Wire format assumes little-endian byte order (ESP32 Xtensa is LE) */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "LSL wire format implementation assumes little-endian byte order"
#endif

/* Internal buffer sizes */
#define LSL_ESP32_SHORTINFO_MAX 1024
#define LSL_ESP32_FULLINFO_MAX  2048

#endif /* LSL_PROTOCOL_H */
