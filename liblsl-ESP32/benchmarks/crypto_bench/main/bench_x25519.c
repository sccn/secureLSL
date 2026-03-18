// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "bench_x25519.h"
#include "bench_utils.h"
#include "esp_log.h"
#include "sodium.h"
#include <string.h>

static const char *TAG = "bench_x25519";

/* Context for key conversion benchmark */
typedef struct {
    uint8_t ed25519_pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t ed25519_sk[crypto_sign_SECRETKEYBYTES];
    uint8_t x25519_pk[crypto_scalarmult_BYTES];
    uint8_t x25519_sk[crypto_scalarmult_SCALARBYTES];
} convert_ctx_t;

/* Context for scalar multiplication (DH) */
typedef struct {
    uint8_t our_sk[crypto_scalarmult_SCALARBYTES];
    uint8_t peer_pk[crypto_scalarmult_BYTES];
    uint8_t shared_secret[crypto_scalarmult_BYTES];
} scalarmult_ctx_t;

/* Context for full session key derivation */
typedef struct {
    uint8_t our_ed25519_pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t our_ed25519_sk[crypto_sign_SECRETKEYBYTES];
    uint8_t peer_ed25519_pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t session_key[32];
} session_ctx_t;

/* Benchmark callbacks: return values intentionally unchecked in hot path.
 * These run 1000x in a tight loop with known-valid inputs from setup code.
 * Correctness is verified at the end of bench_x25519_run. */
static void do_pk_convert(void *arg)
{
    convert_ctx_t *ctx = (convert_ctx_t *)arg;
    crypto_sign_ed25519_pk_to_curve25519(ctx->x25519_pk, ctx->ed25519_pk);
}

static void do_sk_convert(void *arg)
{
    convert_ctx_t *ctx = (convert_ctx_t *)arg;
    crypto_sign_ed25519_sk_to_curve25519(ctx->x25519_sk, ctx->ed25519_sk);
}

static void do_scalarmult(void *arg)
{
    scalarmult_ctx_t *ctx = (scalarmult_ctx_t *)arg;
    crypto_scalarmult(ctx->shared_secret, ctx->our_sk, ctx->peer_pk);
}

/* Domain separator matching secureLSL's lsl_security.h */
static const char HKDF_CONTEXT[] = "lsl-sess";

/* Full session key derivation (matching secureLSL's derive_session_key):
 * 1. Convert both Ed25519 keys to X25519
 * 2. Compute shared secret via scalar multiplication
 * 3. Derive session key via BLAKE2b with HKDF_CONTEXT and canonical key order
 *
 * Note: secureLSL pre-converts our own sk during key loading (one-time cost).
 * This benchmark includes that conversion to measure total cost. */
static void do_full_session_derive(void *arg)
{
    session_ctx_t *ctx = (session_ctx_t *)arg;

    uint8_t our_x25519_sk[crypto_scalarmult_SCALARBYTES];
    uint8_t peer_x25519_pk[crypto_scalarmult_BYTES];
    uint8_t shared_secret[crypto_scalarmult_BYTES];

    /* Step 1: Convert keys */
    crypto_sign_ed25519_sk_to_curve25519(our_x25519_sk, ctx->our_ed25519_sk);
    if (crypto_sign_ed25519_pk_to_curve25519(peer_x25519_pk, ctx->peer_ed25519_pk) != 0) {
        ESP_LOGE(TAG, "pk conversion failed");
        sodium_memzero(our_x25519_sk, sizeof(our_x25519_sk));
        return;
    }

    /* Step 2: DH key exchange */
    if (crypto_scalarmult(shared_secret, our_x25519_sk, peer_x25519_pk) != 0) {
        ESP_LOGE(TAG, "DH key exchange produced degenerate shared secret");
        sodium_memzero(our_x25519_sk, sizeof(our_x25519_sk));
        return;
    }

    /* Step 3: Derive session key with BLAKE2b.
     * Hash: shared_secret || HKDF_CONTEXT || pk_smaller || pk_larger
     * Canonical key ordering (smaller first) ensures both parties
     * derive the same key, matching secureLSL. */
    crypto_generichash_state state;
    if (crypto_generichash_init(&state, NULL, 0, 32) != 0) {
        ESP_LOGE(TAG, "BLAKE2b init failed");
        sodium_memzero(our_x25519_sk, sizeof(our_x25519_sk));
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return;
    }
    crypto_generichash_update(&state, shared_secret, sizeof(shared_secret));
    crypto_generichash_update(&state, (const uint8_t *)HKDF_CONTEXT, sizeof(HKDF_CONTEXT) - 1);

    /* Order public keys consistently (smaller first) */
    if (memcmp(ctx->our_ed25519_pk, ctx->peer_ed25519_pk, crypto_sign_PUBLICKEYBYTES) < 0) {
        crypto_generichash_update(&state, ctx->our_ed25519_pk, crypto_sign_PUBLICKEYBYTES);
        crypto_generichash_update(&state, ctx->peer_ed25519_pk, crypto_sign_PUBLICKEYBYTES);
    } else {
        crypto_generichash_update(&state, ctx->peer_ed25519_pk, crypto_sign_PUBLICKEYBYTES);
        crypto_generichash_update(&state, ctx->our_ed25519_pk, crypto_sign_PUBLICKEYBYTES);
    }

    crypto_generichash_final(&state, ctx->session_key, 32);

    /* Clear sensitive data */
    sodium_memzero(our_x25519_sk, sizeof(our_x25519_sk));
    sodium_memzero(peer_x25519_pk, sizeof(peer_x25519_pk));
    sodium_memzero(shared_secret, sizeof(shared_secret));
}

void bench_x25519_run(void)
{
    bench_result_t result;

    bench_print_header("X25519 Key Exchange");

    /* Generate test keypairs */
    convert_ctx_t cctx;
    crypto_sign_keypair(cctx.ed25519_pk, cctx.ed25519_sk);

    /* Benchmark pk conversion */
    bench_run("Ed25519->X25519 pk convert", do_pk_convert, &cctx, BENCH_ITERATIONS, 0, &result);
    bench_print_result(&result);

    /* Benchmark sk conversion */
    bench_run("Ed25519->X25519 sk convert", do_sk_convert, &cctx, BENCH_ITERATIONS, 0, &result);
    bench_print_result(&result);

    /* Benchmark scalar multiplication */
    scalarmult_ctx_t sctx;
    uint8_t peer_ed_pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t peer_ed_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(peer_ed_pk, peer_ed_sk);
    crypto_sign_ed25519_sk_to_curve25519(sctx.our_sk, cctx.ed25519_sk);
    if (crypto_sign_ed25519_pk_to_curve25519(sctx.peer_pk, peer_ed_pk) != 0) {
        ESP_LOGE(TAG, "pk conversion failed, skipping DH benchmark");
    } else {
        bench_run("X25519 scalar mult (DH)", do_scalarmult, &sctx, BENCH_ITERATIONS, 0, &result);
        bench_print_result(&result);
    }
    sodium_memzero(peer_ed_sk, sizeof(peer_ed_sk));

    /* Benchmark full session key derivation */
    bench_print_header("Full Session Key Derivation");
    ESP_LOGI(TAG, "(Ed25519->X25519 + DH + BLAKE2b, as in secureLSL)");

    session_ctx_t sess;
    crypto_sign_keypair(sess.our_ed25519_pk, sess.our_ed25519_sk);
    memcpy(sess.peer_ed25519_pk, peer_ed_pk, crypto_sign_PUBLICKEYBYTES);

    bench_run("Full session key derivation", do_full_session_derive, &sess, BENCH_ITERATIONS, 0,
              &result);
    bench_print_result(&result);

    /* This is the one-time cost per LSL connection */
    ESP_LOGI(TAG, "  (This cost is paid once per LSL connection setup)");

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Correctness verification...");

    /* Both sides derive a session key with different keypairs.
     * With canonical key ordering, both sides should derive the
     * same session key regardless of which is "our" vs "peer". */
    session_ctx_t side_a, side_b;
    crypto_sign_keypair(side_a.our_ed25519_pk, side_a.our_ed25519_sk);
    crypto_sign_keypair(side_b.our_ed25519_pk, side_b.our_ed25519_sk);

    memcpy(side_a.peer_ed25519_pk, side_b.our_ed25519_pk, crypto_sign_PUBLICKEYBYTES);
    memcpy(side_b.peer_ed25519_pk, side_a.our_ed25519_pk, crypto_sign_PUBLICKEYBYTES);

    do_full_session_derive(&side_a);
    do_full_session_derive(&side_b);

    /* With canonical key ordering (smaller pk first), both sides
     * should derive the same session key. */
    if (sodium_is_zero(side_a.session_key, 32) || sodium_is_zero(side_b.session_key, 32)) {
        ESP_LOGE(TAG, "  FAIL: session key derivation produced zero key!");
    } else if (memcmp(side_a.session_key, side_b.session_key, 32) == 0) {
        ESP_LOGI(TAG, "  PASS: both sides derived identical session keys");
    } else {
        ESP_LOGE(TAG, "  FAIL: sides derived different session keys!");
    }

    /* Clear secret keys */
    sodium_memzero(side_a.our_ed25519_sk, sizeof(side_a.our_ed25519_sk));
    sodium_memzero(side_b.our_ed25519_sk, sizeof(side_b.our_ed25519_sk));
}
