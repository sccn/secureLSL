#ifndef BENCH_ED25519_H
#define BENCH_ED25519_H

/* Benchmark Ed25519 key generation, signing, and verification.
 * Also benchmarks BLAKE2b (generichash) and base64 encode/decode. */
void bench_ed25519_run(void);

#endif /* BENCH_ED25519_H */
