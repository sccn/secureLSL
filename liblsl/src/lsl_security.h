// Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/**
 * @file lsl_security.h (internal)
 * @brief Internal declarations for LSL Security implementation
 */

#ifndef LSL_SECURITY_INTERNAL_H
#define LSL_SECURITY_INTERNAL_H

#ifdef LSL_SECURITY_ENABLED

#include <lsl_security.h>
#include <chrono>

namespace lsl {
namespace security {

// Internal constants
constexpr size_t HKDF_CONTEXT_SIZE = 8;
constexpr char HKDF_CONTEXT[] = "lsl-sess";
constexpr uint64_t SESSION_KEY_SUBKEY_ID = 1;

// Nonce management for replay prevention
class NonceTracker {
public:
    NonceTracker() : last_nonce_(0), window_base_(0), window_bitmap_(0) {}

    /**
     * @brief Check if nonce is valid (not replayed)
     * @param nonce The nonce to check
     * @return true if nonce is valid (never seen before)
     *
     * Uses a sliding window to track recent nonces, allowing for
     * some out-of-order delivery while preventing replay attacks.
     */
    bool check_and_update(uint64_t nonce);

    /**
     * @brief Reset the tracker (for new sessions)
     */
    void reset();

    /**
     * @brief Get the last accepted nonce
     */
    uint64_t last_nonce() const { return last_nonce_; }

private:
    static constexpr size_t WINDOW_SIZE = 64;
    uint64_t last_nonce_;
    uint64_t window_base_;
    uint64_t window_bitmap_;
};

// Session state for a single connection
struct SessionState {
    std::array<uint8_t, SESSION_KEY_SIZE> session_key;
    std::array<uint8_t, PUBLIC_KEY_SIZE> peer_public_key;
    uint64_t send_nonce;
    NonceTracker recv_nonce_tracker;
    std::chrono::steady_clock::time_point key_established;
    bool is_initiator;
    bool authenticated;

    SessionState()
        : send_nonce(1)  // Start at 1 since nonce 0 is reserved
        , is_initiator(false)
        , authenticated(false) {
        session_key.fill(0);
        peer_public_key.fill(0);
    }

    ~SessionState() {
        // Securely zero sensitive data
        secure_zero(session_key.data(), session_key.size());
    }
};

} // namespace security
} // namespace lsl

#endif // LSL_SECURITY_ENABLED

#endif // LSL_SECURITY_INTERNAL_H
