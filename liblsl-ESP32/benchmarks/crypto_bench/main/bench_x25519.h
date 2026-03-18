// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef BENCH_X25519_H
#define BENCH_X25519_H

/* Benchmark X25519 key exchange operations:
 * - Ed25519 to X25519 key conversion
 * - X25519 scalar multiplication (DH)
 * - Full session key derivation (convert + DH + BLAKE2b)
 *
 * These operations happen once per LSL connection setup. */
void bench_x25519_run(void);

#endif /* BENCH_X25519_H */
