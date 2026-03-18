#ifndef BENCH_CHACHA20_H
#define BENCH_CHACHA20_H

/* Benchmark ChaCha20-Poly1305 IETF AEAD encrypt and decrypt
 * at various payload sizes matching LSL channel configurations. */
void bench_chacha20_run(void);

#endif /* BENCH_CHACHA20_H */
