// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef BENCH_CHACHA20_H
#define BENCH_CHACHA20_H

/* Benchmark ChaCha20-Poly1305 IETF AEAD encrypt and decrypt
 * at various payload sizes matching LSL channel configurations. */
void bench_chacha20_run(void);

#endif /* BENCH_CHACHA20_H */
