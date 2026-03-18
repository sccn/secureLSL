#include "bench_ed25519.h"
#include "bench_utils.h"
#include "esp_log.h"
#include "sodium.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "bench_ed25519";

/* Contexts for benchmarks */
typedef struct {
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
} keygen_ctx_t;

typedef struct {
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    uint8_t sig[crypto_sign_BYTES];
    uint8_t message[64];
    size_t message_len;
} sign_ctx_t;

typedef struct {
    uint8_t input[256];
    uint8_t output[crypto_generichash_BYTES_MAX];
    size_t input_len;
    size_t output_len;
} hash_ctx_t;

typedef struct {
    uint8_t binary[64];
    char base64[128];
    size_t binary_len;
} b64_ctx_t;

/* Ed25519 keygen */
static void do_keygen(void *arg)
{
    keygen_ctx_t *ctx = (keygen_ctx_t *)arg;
    crypto_sign_keypair(ctx->pk, ctx->sk);
}

/* Benchmark callbacks: return values intentionally unchecked in hot path.
 * These run 1000x in a tight loop; correctness is verified at the end
 * of bench_ed25519_run. */
static void do_sign(void *arg)
{
    sign_ctx_t *ctx = (sign_ctx_t *)arg;
    crypto_sign_detached(ctx->sig, NULL, ctx->message, ctx->message_len, ctx->sk);
}

static void do_verify(void *arg)
{
    sign_ctx_t *ctx = (sign_ctx_t *)arg;
    crypto_sign_verify_detached(ctx->sig, ctx->message, ctx->message_len, ctx->pk);
}

static void do_blake2b(void *arg)
{
    hash_ctx_t *ctx = (hash_ctx_t *)arg;
    crypto_generichash(ctx->output, ctx->output_len, ctx->input, ctx->input_len, NULL, 0);
}

/* Base64 encode */
static void do_b64_encode(void *arg)
{
    b64_ctx_t *ctx = (b64_ctx_t *)arg;
    sodium_bin2base64(ctx->base64, sizeof(ctx->base64), ctx->binary, ctx->binary_len,
                      sodium_base64_VARIANT_ORIGINAL);
}

/* Base64 decode: return value intentionally unchecked in hot path.
 * Input is always valid (produced by do_b64_encode). */
static void do_b64_decode(void *arg)
{
    b64_ctx_t *ctx = (b64_ctx_t *)arg;
    size_t bin_len;
    sodium_base642bin(ctx->binary, sizeof(ctx->binary), ctx->base64, strlen(ctx->base64), NULL,
                      &bin_len, NULL, sodium_base64_VARIANT_ORIGINAL);
}

void bench_ed25519_run(void)
{
    bench_result_t result;

    /* --- Ed25519 Key Generation --- */
    bench_print_header("Ed25519 Key Operations");

    keygen_ctx_t kctx;
    bench_run("Ed25519 keygen", do_keygen, &kctx, BENCH_ITERATIONS, 0, &result);
    bench_print_result(&result);

    /* --- Ed25519 Sign --- */
    sign_ctx_t sctx;
    crypto_sign_keypair(sctx.pk, sctx.sk);
    randombytes_buf(sctx.message, sizeof(sctx.message));
    sctx.message_len = sizeof(sctx.message);

    bench_run("Ed25519 sign (64B msg)", do_sign, &sctx, BENCH_ITERATIONS, 0, &result);
    bench_print_result(&result);

    /* --- Ed25519 Verify --- */
    if (crypto_sign_detached(sctx.sig, NULL, sctx.message, sctx.message_len, sctx.sk) != 0) {
        ESP_LOGE(TAG, "Failed to produce signature, skipping verify benchmark");
    } else {
        bench_run("Ed25519 verify (64B msg)", do_verify, &sctx, BENCH_ITERATIONS, 0, &result);
        bench_print_result(&result);
    }

    /* --- BLAKE2b (generichash) --- */
    bench_print_header("BLAKE2b (generichash)");

    hash_ctx_t hctx;
    randombytes_buf(hctx.input, sizeof(hctx.input));

    hctx.input_len = 64;  /* representative size for short-input hashing */
    hctx.output_len = 32; /* session key length */
    bench_run("BLAKE2b 64B->32B (session key)", do_blake2b, &hctx, BENCH_ITERATIONS, 64, &result);
    bench_print_result(&result);

    /* Fingerprint: 32-byte input -> 32-byte output */
    hctx.input_len = 32; /* public key */
    hctx.output_len = 32;
    bench_run("BLAKE2b 32B->32B (fingerprint)", do_blake2b, &hctx, BENCH_ITERATIONS, 32, &result);
    bench_print_result(&result);

    /* --- Base64 encode/decode --- */
    bench_print_header("Base64 Encode/Decode");

    b64_ctx_t bctx;
    randombytes_buf(bctx.binary, 32); /* 32-byte public key */
    bctx.binary_len = 32;

    bench_run("base64 encode (32B key)", do_b64_encode, &bctx, BENCH_ITERATIONS, 32, &result);
    bench_print_result(&result);

    /* Prepare encoded string for decode benchmark */
    sodium_bin2base64(bctx.base64, sizeof(bctx.base64), bctx.binary, bctx.binary_len,
                      sodium_base64_VARIANT_ORIGINAL);

    bench_run("base64 decode (32B key)", do_b64_decode, &bctx, BENCH_ITERATIONS, 32, &result);
    bench_print_result(&result);

    /* --- Correctness verification --- */
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Correctness verification...");

    /* Sign/verify roundtrip */
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    uint8_t sig[crypto_sign_BYTES];
    uint8_t msg[] = "test message for ed25519";

    crypto_sign_keypair(pk, sk);
    if (crypto_sign_detached(sig, NULL, msg, sizeof(msg) - 1, sk) != 0) {
        ESP_LOGE(TAG, "  FAIL: signing step failed");
        sodium_memzero(sk, sizeof(sk));
        sodium_memzero(sctx.sk, sizeof(sctx.sk));
        return;
    }

    if (crypto_sign_verify_detached(sig, msg, sizeof(msg) - 1, pk) == 0) {
        ESP_LOGI(TAG, "  PASS: Ed25519 sign/verify roundtrip correct");
    } else {
        ESP_LOGE(TAG, "  FAIL: Ed25519 sign/verify roundtrip failed!");
    }

    /* Tampered signature */
    sig[0] ^= 0x01;
    if (crypto_sign_verify_detached(sig, msg, sizeof(msg) - 1, pk) != 0) {
        ESP_LOGI(TAG, "  PASS: tampered signature correctly rejected");
    } else {
        ESP_LOGE(TAG, "  FAIL: tampered signature was NOT rejected!");
    }

    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(sctx.sk, sizeof(sctx.sk));
}
