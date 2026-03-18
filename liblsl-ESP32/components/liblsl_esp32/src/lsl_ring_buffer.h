// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_RING_BUFFER_H
#define LSL_RING_BUFFER_H

#include <stddef.h>
#include <stdint.h>

/* Single-producer, multi-consumer ring buffer for LSL samples.
 *
 * The producer (push_sample) writes serialized samples sequentially.
 * Each consumer maintains its own read cursor. If a consumer falls
 * behind (more than slot_count samples), it skips to the latest data
 * (same behavior as desktop liblsl). */

typedef struct {
    uint8_t *buffer;             /* pre-allocated byte array */
    size_t slot_size;            /* bytes per sample slot */
    size_t slot_count;           /* number of slots */
    volatile uint64_t write_idx; /* producer write position (monotonic, never wraps) */
} lsl_ring_buffer_t;

/* Per-consumer read cursor */
typedef struct {
    uint64_t read_idx; /* consumer's current read position */
} lsl_ring_consumer_t;

/* Initialize the ring buffer. Allocates slot_count * slot_size bytes.
 * Returns 0 on success, -1 on allocation failure. */
int ring_buffer_init(lsl_ring_buffer_t *rb, size_t slot_size, size_t slot_count);

/* Free the ring buffer memory. */
void ring_buffer_deinit(lsl_ring_buffer_t *rb);

/* Push a serialized sample into the ring buffer.
 * data_len must be <= slot_size. Overwrites oldest slot if full. */
void ring_buffer_push(lsl_ring_buffer_t *rb, const uint8_t *data, size_t data_len);

/* Initialize a consumer cursor at the current write position. */
void ring_buffer_consumer_init(const lsl_ring_buffer_t *rb, lsl_ring_consumer_t *consumer);

/* Read the next available sample into out_buf.
 * Returns bytes copied (> 0) if a sample was available, 0 if no new data.
 * If consumer fell behind, skips to latest available data. */
size_t ring_buffer_read(const lsl_ring_buffer_t *rb, lsl_ring_consumer_t *consumer,
                        uint8_t *out_buf, size_t out_len);

/* Returns number of unread samples available to this consumer. */
uint64_t ring_buffer_available(const lsl_ring_buffer_t *rb, const lsl_ring_consumer_t *consumer);

#endif /* LSL_RING_BUFFER_H */
