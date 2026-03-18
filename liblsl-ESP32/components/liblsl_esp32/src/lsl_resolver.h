// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_RESOLVER_H
#define LSL_RESOLVER_H

#include "lsl_stream_info.h"

#define LSL_RESOLVER_MAX_RESULTS 8

/* Resolve streams matching a property=value query.
 * Sends multicast discovery queries and collects responses.
 * Blocks for up to timeout_sec seconds.
 *
 * prop: property name ("name", "type", or "source_id")
 * value: value to match
 * timeout_sec: maximum time to wait for responses
 * results: output array for discovered stream infos
 * max_results: size of results array
 *
 * Returns number of unique streams found (deduplicated by UID). */
int resolver_find(const char *prop, const char *value, double timeout_sec,
                  struct lsl_esp32_stream_info *results, int max_results);

/* Resolve all visible streams (empty query matches everything).
 * Blocks for up to timeout_sec seconds.
 * Returns number of unique streams found. */
int resolver_find_all(double timeout_sec, struct lsl_esp32_stream_info *results, int max_results);

#endif /* LSL_RESOLVER_H */
