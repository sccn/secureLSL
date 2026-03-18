// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_SAMPLE_H
#define LSL_SAMPLE_H

#include "lsl_esp32_types.h"
#include "lsl_protocol.h"
#include <stddef.h>

/* Maximum serialized sample size:
 * 1 (tag) + 8 (timestamp) + MAX_CHANNELS * 8 (double64) */
#define LSL_SAMPLE_MAX_BYTES (1 + 8 + LSL_ESP32_MAX_CHANNELS * 8)

/* Serialize a sample into the LSL binary wire format (protocol 1.10).
 *
 * Format: [1-byte tag][optional 8-byte LE double timestamp][channel data]
 * Tag 0x01 = deduced timestamp (no timestamp field)
 * Tag 0x02 = transmitted timestamp (8-byte double follows)
 *
 * channel_data: raw sample data (channel_count * bytes_per_channel)
 * channel_data_len: size of channel_data in bytes
 * timestamp: sample timestamp (0 = deduced, omit from wire)
 * out: output buffer (must be at least 1 + 8 + channel_data_len bytes)
 * out_len: size of output buffer
 *
 * Returns number of bytes written, or -1 on error. */
int sample_serialize(const void *channel_data, size_t channel_data_len, double timestamp,
                     uint8_t *out, size_t out_len);

/* Generate a test-pattern sample matching liblsl's sample.cpp.
 *
 * For numeric types, each channel value is:
 *   value = (channel_index + offset) * ((channel_index % 2 == 0) ? 1 : -1)
 *
 * For int types, offset is adjusted: +65537 (int32), +257 (int16), +1 (int8).
 *
 * channel_count: number of channels
 * channel_format: data type
 * offset: test pattern offset (typically 4 or 2)
 * timestamp: timestamp to include (typically 123456.789)
 * out: output buffer for serialized sample
 * out_len: size of output buffer
 *
 * Returns number of bytes written, or -1 on error. */
int sample_generate_test_pattern(int channel_count, lsl_esp32_channel_format_t channel_format,
                                 int offset, double timestamp, uint8_t *out, size_t out_len);

/* Deserialize a sample from the LSL binary wire format.
 *
 * Parses the tag byte, optional timestamp, and channel data.
 *
 * in: input buffer containing the serialized sample
 * in_len: number of bytes available in input buffer
 * channel_count: expected number of channels
 * fmt: expected channel format
 * channel_data_out: output buffer for channel data (channel_count * bpc bytes)
 * channel_data_len: size of channel_data_out
 * timestamp_out: receives the sample timestamp (0 if deduced)
 *
 * Returns number of bytes consumed from input, or -1 on error. */
int sample_deserialize(const uint8_t *in, size_t in_len, int channel_count,
                       lsl_esp32_channel_format_t fmt, void *channel_data_out,
                       size_t channel_data_len, double *timestamp_out);

/* Validate a deserialized sample against the expected test pattern.
 * Returns 0 if the pattern matches, -1 if it does not. */
int sample_validate_test_pattern(int channel_count, lsl_esp32_channel_format_t fmt, int offset,
                                 double expected_timestamp, const void *channel_data,
                                 double actual_timestamp);

#endif /* LSL_SAMPLE_H */
