// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "bench_chacha20.h"
#include "bench_utils.h"
#include "esp_log.h"
#include "sodium.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "bench_chacha20";

/* Payload sizes to benchmark.
 * These correspond to typical LSL sample sizes:
 *   4B   = 1ch int32
 *   32B  = 8ch float32
 *   64B  = 16ch float32
 *   256B = 64ch float32 (standard EEG)
 *   512B = 64ch double64
 *   1024B = 128ch double64
 *   4096B = large payload stress test
 */
static const size_t PAYLOAD_SIZES[] = {4, 32, 64, 256, 512, 1024, 4096};
static const size_t NUM_PAYLOADS = sizeof(PAYLOAD_SIZES) / sizeof(PAYLOAD_SIZES[0]);

/* Context for a single encrypt/decrypt benchmark run */
typedef struct {
    uint8_t *plaintext;
    uint8_t *ciphertext;
    uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    size_t plaintext_len;
    unsigned long long ciphertext_len;
} chacha20_ctx_t;

/* Benchmark callback: return value intentionally unchecked in hot path.
 * crypto_aead_chacha20poly1305_ietf_encrypt always returns 0 per libsodium docs.
 * Correctness is verified in the verification section at the end of bench_chacha20_run. */
static void do_encrypt(void *arg)
{
    chacha20_ctx_t *ctx = (chacha20_ctx_t *)arg;
    crypto_aead_chacha20poly1305_ietf_encrypt(ctx->ciphertext, &ctx->ciphertext_len, ctx->plaintext,
                                              ctx->plaintext_len, NULL, 0, /* no additional data */
                                              NULL,                        /* nsec unused */
                                              ctx->nonce, ctx->key);
    /* Increment nonce per-sample (secureLSL uses a uint64_t counter;
     * sodium_increment is equivalent for benchmarking purposes) */
    sodium_increment(ctx->nonce, sizeof(ctx->nonce));
}

static void do_decrypt(void *arg)
{
    chacha20_ctx_t *ctx = (chacha20_ctx_t *)arg;
    unsigned long long decrypted_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            ctx->plaintext, &decrypted_len, NULL,          /* nsec unused */
            ctx->ciphertext, ctx->ciphertext_len, NULL, 0, /* no additional data */
            ctx->nonce, ctx->key) != 0) {
        ESP_LOGE(TAG, "decrypt auth failed during benchmark");
    }
}

void bench_chacha20_run(void)
{
    bench_print_header("ChaCha20-Poly1305 IETF AEAD");
    ESP_LOGI(TAG, "Key size: %d bytes, Nonce size: %d bytes, Auth tag: %d bytes",
             crypto_aead_chacha20poly1305_ietf_KEYBYTES,
             crypto_aead_chacha20poly1305_ietf_NPUBBYTES, crypto_aead_chacha20poly1305_ietf_ABYTES);

    for (size_t i = 0; i < NUM_PAYLOADS; i++) {
        size_t payload_len = PAYLOAD_SIZES[i];
        size_t ciphertext_max = payload_len + crypto_aead_chacha20poly1305_ietf_ABYTES;

        /* Allocate buffers */
        chacha20_ctx_t ctx;
        ctx.plaintext = malloc(payload_len);
        ctx.ciphertext = malloc(ciphertext_max);
        ctx.plaintext_len = payload_len;

        if (!ctx.plaintext || !ctx.ciphertext) {
            ESP_LOGE(TAG, "Allocation failed for payload %zu", payload_len);
            free(ctx.plaintext);
            free(ctx.ciphertext);
            continue;
        }

        /* Generate random key, nonce, and plaintext */
        crypto_aead_chacha20poly1305_ietf_keygen(ctx.key);
        randombytes_buf(ctx.nonce, sizeof(ctx.nonce));
        randombytes_buf(ctx.plaintext, payload_len);

        /* Benchmark encrypt */
        bench_result_t result;
        char name[64];
        snprintf(name, sizeof(name), "encrypt %zu bytes", payload_len);
        bench_run(name, do_encrypt, &ctx, BENCH_ITERATIONS, payload_len, &result);
        bench_print_result(&result);

        /* Prepare valid ciphertext for decrypt benchmark.
         * Encrypt once with current nonce; decrypt will reuse this
         * nonce+ciphertext pair (each decrypt is independent). */
        if (crypto_aead_chacha20poly1305_ietf_encrypt(ctx.ciphertext, &ctx.ciphertext_len,
                                                      ctx.plaintext, ctx.plaintext_len, NULL, 0,
                                                      NULL, ctx.nonce, ctx.key) != 0) {
            ESP_LOGE(TAG, "Failed to prepare ciphertext for decrypt benchmark (%zu bytes)",
                     payload_len);
            sodium_memzero(ctx.key, sizeof(ctx.key));
            free(ctx.plaintext);
            free(ctx.ciphertext);
            continue;
        }

        /* Benchmark decrypt */
        snprintf(name, sizeof(name), "decrypt %zu bytes", payload_len);
        bench_run(name, do_decrypt, &ctx, BENCH_ITERATIONS, payload_len, &result);
        bench_print_result(&result);

        sodium_memzero(ctx.key, sizeof(ctx.key));
        free(ctx.plaintext);
        free(ctx.ciphertext);
    }

    /* Verify correctness: encrypt then decrypt, compare */
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Correctness verification...");
    uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    uint8_t original[256];
    uint8_t encrypted[256 + crypto_aead_chacha20poly1305_ietf_ABYTES];
    uint8_t decrypted[256];
    unsigned long long enc_len, dec_len;

    crypto_aead_chacha20poly1305_ietf_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(original, sizeof(original));

    if (crypto_aead_chacha20poly1305_ietf_encrypt(encrypted, &enc_len, original, sizeof(original),
                                                  NULL, 0, NULL, nonce, key) != 0) {
        ESP_LOGE(TAG, "  FAIL: encryption step failed");
        sodium_memzero(key, sizeof(key));
        return;
    }

    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &dec_len, NULL, encrypted,
                                                        enc_len, NULL, 0, nonce, key);

    if (ret == 0 && dec_len == sizeof(original) &&
        memcmp(original, decrypted, sizeof(original)) == 0) {
        ESP_LOGI(TAG, "  PASS: encrypt/decrypt roundtrip correct");
    } else {
        ESP_LOGE(TAG, "  FAIL: encrypt/decrypt roundtrip mismatch!");
    }

    /* Tamper detection test */
    encrypted[10] ^= 0x01; /* flip one bit */
    ret = crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &dec_len, NULL, encrypted, enc_len,
                                                    NULL, 0, nonce, key);

    if (ret != 0) {
        ESP_LOGI(TAG, "  PASS: tampered ciphertext correctly rejected");
    } else {
        ESP_LOGE(TAG, "  FAIL: tampered ciphertext was NOT rejected!");
    }

    sodium_memzero(key, sizeof(key));
}
