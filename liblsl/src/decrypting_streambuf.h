// Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef DECRYPTING_STREAMBUF_H
#define DECRYPTING_STREAMBUF_H

#ifdef LSL_SECURITY_ENABLED

#include "lsl_security.h"
#include <loguru.hpp>
#include <streambuf>
#include <vector>

namespace lsl {

/**
 * @brief A streambuf wrapper that decrypts incoming data on-demand.
 *
 * This class wraps a network streambuf and transparently handles encrypted
 * chunks. It reads length-prefixed encrypted chunks, decrypts them, and
 * provides the decrypted data to callers.
 *
 * Protocol format:
 * - 4-byte big-endian length prefix
 * - 8-byte little-endian nonce
 * - Ciphertext with 16-byte auth tag
 */
class decrypting_streambuf : public std::streambuf {
public:
	decrypting_streambuf(std::streambuf& source, security::SessionState& session)
		: source_(source), session_(session) {}

	int_type underflow() override {
		if (gptr() < egptr()) {
			return traits_type::to_int_type(*gptr());
		}

		// Need to read and decrypt a new chunk
		if (!read_and_decrypt_chunk()) {
			return traits_type::eof();
		}

		return traits_type::to_int_type(*gptr());
	}

private:
	bool read_and_decrypt_chunk() {
		// Read 4-byte length prefix (big-endian)
		uint8_t len_buf[4];
		if (source_.sgetn(reinterpret_cast<char*>(len_buf), 4) != 4) {
			return false;
		}
		uint32_t payload_len = (static_cast<uint32_t>(len_buf[0]) << 24) |
							   (static_cast<uint32_t>(len_buf[1]) << 16) |
							   (static_cast<uint32_t>(len_buf[2]) << 8) |
							   static_cast<uint32_t>(len_buf[3]);

		// Sanity check
		if (payload_len < 8 + security::AUTH_TAG_SIZE || payload_len > 64 * 1024 * 1024) {
			LOG_F(ERROR, "Invalid encrypted payload length: %u", payload_len);
			return false;
		}

		// Read the encrypted payload (nonce + ciphertext)
		encrypted_buf_.resize(payload_len);
		if (source_.sgetn(reinterpret_cast<char*>(encrypted_buf_.data()), payload_len) !=
			static_cast<std::streamsize>(payload_len)) {
			return false;
		}

		// Extract nonce (little-endian)
		uint64_t nonce = 0;
		for (int i = 0; i < 8; i++) {
			nonce |= static_cast<uint64_t>(encrypted_buf_[i]) << (i * 8);
		}

		// Check for replay attack
		if (!session_.recv_nonce_tracker.check_and_update(nonce)) {
			LOG_F(ERROR, "Replay attack detected: nonce %llu already seen",
				  (unsigned long long)nonce);
			return false;
		}

		// Decrypt (ciphertext starts after 8-byte nonce)
		size_t ciphertext_len = payload_len - 8;
		decrypted_buf_.resize(ciphertext_len);
		std::copy(encrypted_buf_.begin() + 8, encrypted_buf_.end(), decrypted_buf_.begin());

		size_t plaintext_len;
		auto& sec = security::LSLSecurity::instance();
		auto result = sec.decrypt(
			decrypted_buf_.data(),
			ciphertext_len,
			nonce,
			session_.session_key,
			plaintext_len);

		if (result != security::SecurityResult::SUCCESS) {
			LOG_F(ERROR, "Decryption failed: %s", security::security_result_string(result));
			return false;
		}

		// Set up the get area to point to decrypted data
		decrypted_buf_.resize(plaintext_len);
		char* begin = reinterpret_cast<char*>(decrypted_buf_.data());
		setg(begin, begin, begin + plaintext_len);
		return true;
	}

	std::streambuf& source_;
	security::SessionState& session_;
	std::vector<uint8_t> encrypted_buf_;
	std::vector<uint8_t> decrypted_buf_;
};

} // namespace lsl

#endif // LSL_SECURITY_ENABLED
#endif // DECRYPTING_STREAMBUF_H
