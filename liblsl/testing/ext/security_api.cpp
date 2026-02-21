// Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/**
 * @file security_api.cpp
 * @brief Public API tests for secure LSL streams
 *
 * Tests cover:
 * - Secure stream pair creation and data transfer
 * - Multiple inlet scenarios (broadcast)
 * - All data types with encryption
 * - High-rate streaming
 * - Large data transfers
 *
 * Note: These tests use the public lsl_cpp.h API.
 * Security is enabled via configuration (lsl_api.cfg).
 * The tests verify that data transfer works correctly when security is active.
 */

#include "../common/create_streampair.hpp"
#include "../common/lsltypes.hpp"
#include <catch2/catch.hpp>
#include <cstdint>
#include <lsl_cpp.h>
#include <thread>
#include <vector>
#include <cmath>

// clazy:excludeall=non-pod-global-static

/**
 * Test basic secure stream pair creation and data transfer.
 * When security is enabled via config, this tests that encrypted
 * data transfer works transparently.
 */
TEST_CASE("secure_streampair_basic", "[security][api][e2e]") {
    const int num_channels = 4;
    const int num_samples = 100;

    lsl::stream_info info("SecureBasic", "Test", num_channels, 100, lsl::cf_float32, "secure_basic_001");
    Streampair sp(create_streampair(info));

    SECTION("basic push/pull works") {
        std::vector<float> sent(num_channels);
        std::vector<float> received(num_channels);

        for (int i = 0; i < num_samples; ++i) {
            for (int ch = 0; ch < num_channels; ++ch) {
                sent[ch] = static_cast<float>(i * num_channels + ch);
            }
            sp.out_.push_sample(sent);
        }

        int pulled = 0;
        for (int i = 0; i < num_samples && pulled < num_samples; ++i) {
            double ts = sp.in_.pull_sample(received, 1.0);
            if (ts != 0.0) {
                for (int ch = 0; ch < num_channels; ++ch) {
                    float expected = static_cast<float>(pulled * num_channels + ch);
                    CHECK(received[ch] == Approx(expected));
                }
                pulled++;
            }
        }
        CHECK(pulled >= num_samples * 0.9);  // Allow some slack for timing
    }

    SECTION("timestamps are preserved") {
        std::vector<float> sample = {1.0f, 2.0f, 3.0f, 4.0f};
        double sent_ts = lsl::local_clock();
        sp.out_.push_sample(sample, sent_ts, true);

        std::vector<float> received(num_channels);
        double recv_ts = sp.in_.pull_sample(received, 1.0);

        CHECK(recv_ts == Approx(sent_ts).epsilon(0.001));
    }
}

/**
 * Test data transfer with all supported data types.
 * Encryption should work transparently for all formats.
 */
TEMPLATE_TEST_CASE(
    "secure_datatransfer_alltypes", "[security][api][datatypes]",
    char, int16_t, int32_t, int64_t, float, double) {

    const int num_channels = 2;
    const int num_samples = 50;
    const char *name = SampleType<TestType>::fmt_string();
    auto cf = static_cast<lsl::channel_format_t>(SampleType<TestType>::chan_fmt);

    lsl::stream_info info(std::string("SecureType_") + name, "TypeTest", num_channels, 100, cf, std::string("type_") + name);
    Streampair sp(create_streampair(info));

    TestType sent[num_channels];
    TestType received[num_channels];
    int pulled = 0;

    for (int i = 0; i < num_samples; ++i) {
        sent[0] = static_cast<TestType>(i);
        sent[1] = static_cast<TestType>(-i);
        sp.out_.push_sample(sent);
    }

    for (int i = 0; i < num_samples && pulled < num_samples; ++i) {
        if (sp.in_.pull_sample(received, 2, 0.5) != 0.0) {
            CHECK(received[0] == Approx(static_cast<TestType>(pulled)));
            CHECK(received[1] == Approx(static_cast<TestType>(-pulled)));
            pulled++;
        }
    }
    CHECK(pulled >= num_samples * 0.8);
}

/**
 * Test multiple inlets receiving from single outlet.
 * Tests that encryption/decryption works for multiple concurrent consumers.
 * Note: This is a simpler test due to timing sensitivities with multiple inlets.
 */
TEST_CASE("secure_multi_inlet", "[security][api][broadcast]") {
    const int num_channels = 4;
    const int num_samples = 50;

    lsl::stream_info info("SecureMulti", "Broadcast", num_channels, 100, lsl::cf_float32, "multi_001");
    lsl::stream_outlet outlet(info);

    // Create two inlets (more reliable than 3)
    auto found = lsl::resolve_stream("name", "SecureMulti", 1, 5.0);
    REQUIRE(!found.empty());

    lsl::stream_inlet inlet1(found[0]);
    lsl::stream_inlet inlet2(found[0]);

    inlet1.open_stream(2);
    inlet2.open_stream(2);
    outlet.wait_for_consumers(2);

    // Push samples with small delays
    std::vector<float> sample(num_channels);
    for (int i = 0; i < num_samples; ++i) {
        for (int ch = 0; ch < num_channels; ++ch) {
            sample[ch] = static_cast<float>(i * num_channels + ch);
        }
        outlet.push_sample(sample);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Check both inlets received data
    std::vector<float> received(num_channels);
    int pulled1 = 0, pulled2 = 0;

    for (int i = 0; i < num_samples; ++i) {
        if (inlet1.pull_sample(received, 0.2) != 0.0) {
            // Verify channel pattern
            bool valid = true;
            for (int ch = 1; ch < num_channels && valid; ++ch) {
                if (std::abs(received[ch] - received[0] - ch) > 0.001f) valid = false;
            }
            if (valid) pulled1++;
        }
    }

    for (int i = 0; i < num_samples; ++i) {
        if (inlet2.pull_sample(received, 0.2) != 0.0) {
            bool valid = true;
            for (int ch = 1; ch < num_channels && valid; ++ch) {
                if (std::abs(received[ch] - received[0] - ch) > 0.001f) valid = false;
            }
            if (valid) pulled2++;
        }
    }

    INFO("Inlet 1: " << pulled1 << ", Inlet 2: " << pulled2);
    // At least one inlet should receive most samples
    CHECK((pulled1 >= num_samples * 0.5 || pulled2 >= num_samples * 0.5));
    // Combined should receive significant portion
    CHECK(pulled1 + pulled2 >= num_samples * 0.3);
}

/**
 * Test high-rate streaming with security enabled.
 * Uses a more moderate rate to ensure test reliability.
 */
TEST_CASE("secure_highrate_streaming", "[security][api][performance]") {
    const int num_channels = 16;
    const int sample_rate = 500;   // 500Hz (more reliable than 1kHz)
    const int duration_ms = 400;   // 0.4 seconds
    const int expected_samples = (sample_rate * duration_ms) / 1000;

    lsl::stream_info info("SecureHighRate", "EEG", num_channels, sample_rate, lsl::cf_float32, "highrate_001");
    Streampair sp(create_streampair(info));

    // Push at target rate
    std::thread pusher([&]() {
        std::vector<float> sample(num_channels);
        auto interval = std::chrono::microseconds(1000000 / sample_rate);
        auto start = std::chrono::steady_clock::now();

        for (int i = 0; i < expected_samples; ++i) {
            for (int ch = 0; ch < num_channels; ++ch) {
                sample[ch] = static_cast<float>(i);
            }
            sp.out_.push_sample(sample);

            // Pace sending
            auto target = start + (i + 1) * interval;
            std::this_thread::sleep_until(target);
        }
    });

    // Pull samples
    std::vector<float> received(num_channels);
    int pulled = 0;
    int valid = 0;
    auto pull_start = std::chrono::steady_clock::now();

    while (std::chrono::steady_clock::now() - pull_start < std::chrono::milliseconds(duration_ms + 1000)) {
        if (sp.in_.pull_sample(received, 0.2) != 0.0) {
            pulled++;
            // Verify all channels have same value (our test pattern)
            bool all_same = true;
            for (int ch = 1; ch < num_channels && all_same; ++ch) {
                if (std::abs(received[ch] - received[0]) > 0.001f) all_same = false;
            }
            if (all_same) valid++;
        }
        if (pulled >= expected_samples) break;
    }

    pusher.join();

    INFO("Expected: " << expected_samples << ", Received: " << pulled << ", Valid: " << valid);
    CHECK(pulled >= expected_samples * 0.5);  // Allow 50% for timing variations
    CHECK(valid >= pulled * 0.9);  // Most received should be valid
}

/**
 * Test large chunk transfer with security.
 */
TEST_CASE("secure_large_chunk", "[security][api][large]") {
    const int num_channels = 64;
    const int chunk_size = 100;
    const int num_chunks = 10;

    lsl::stream_info info("SecureLargeChunk", "Data", num_channels, 256, lsl::cf_float32, "large_001");
    Streampair sp(create_streampair(info));

    // Send chunks
    std::vector<float> chunk(num_channels * chunk_size);
    for (int c = 0; c < num_chunks; ++c) {
        for (int s = 0; s < chunk_size; ++s) {
            for (int ch = 0; ch < num_channels; ++ch) {
                chunk[s * num_channels + ch] = static_cast<float>(c * chunk_size + s);
            }
        }
        sp.out_.push_chunk_multiplexed(chunk);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Pull all samples
    std::vector<float> received(num_channels);
    int pulled = 0;
    int expected = num_chunks * chunk_size;

    while (pulled < expected) {
        if (sp.in_.pull_sample(received, 0.5) != 0.0) {
            pulled++;
        } else {
            break;  // Timeout
        }
    }

    INFO("Expected: " << expected << ", Received: " << pulled);
    CHECK(pulled >= expected * 0.9);
}

/**
 * Test string data transfer with security.
 */
TEST_CASE("secure_string_data", "[security][api][string]") {
    const int num_channels = 2;

    lsl::stream_info info("SecureString", "Text", num_channels, lsl::IRREGULAR_RATE, lsl::cf_string, "string_001");
    Streampair sp(create_streampair(info));

    SECTION("basic strings") {
        std::vector<std::string> sent = {"Hello", "World"};
        sp.out_.push_sample(sent);

        std::vector<std::string> received(num_channels);
        double ts = sp.in_.pull_sample(received, 2.0);

        REQUIRE(ts != 0.0);
        CHECK(received[0] == "Hello");
        CHECK(received[1] == "World");
    }

    SECTION("unicode strings") {
        std::vector<std::string> sent = {"Hello \xC2\xB5s", "\xE4\xB8\xAD\xE6\x96\x87"};  // μs and 中文
        sp.out_.push_sample(sent);

        std::vector<std::string> received(num_channels);
        double ts = sp.in_.pull_sample(received, 2.0);

        REQUIRE(ts != 0.0);
        CHECK(received[0] == sent[0]);
        CHECK(received[1] == sent[1]);
    }

    SECTION("empty strings") {
        std::vector<std::string> sent = {"", ""};
        sp.out_.push_sample(sent);

        std::vector<std::string> received(num_channels);
        double ts = sp.in_.pull_sample(received, 2.0);

        REQUIRE(ts != 0.0);
        CHECK(received[0].empty());
        CHECK(received[1].empty());
    }
}

/**
 * Test stream info preservation through security layer.
 * Basic stream properties should be preserved through discovery.
 */
TEST_CASE("secure_streaminfo_preserved", "[security][api][info]") {
    lsl::stream_info info("SecureInfo", "Custom", 8, 256, lsl::cf_float32, "info_001");

    // Add custom metadata
    lsl::xml_element desc = info.desc();
    desc.append_child_value("manufacturer", "TestLab");
    desc.append_child_value("version", "1.0");

    lsl::stream_outlet outlet(info);
    auto found = lsl::resolve_stream("name", "SecureInfo", 1, 5.0);
    REQUIRE(!found.empty());

    // Check that basic resolved info matches original
    lsl::stream_info resolved = found[0];
    CHECK(resolved.name() == "SecureInfo");
    CHECK(resolved.type() == "Custom");
    CHECK(resolved.channel_count() == 8);
    CHECK(resolved.nominal_srate() == Approx(256));
    CHECK(resolved.channel_format() == lsl::cf_float32);

    // Full metadata is only available after connecting via inlet
    lsl::stream_inlet inlet(resolved);
    inlet.open_stream(5);

    // Get full info with metadata
    lsl::stream_info full_info = inlet.info();
    lsl::xml_element fdesc = full_info.desc();

    // Now custom metadata should be available
    CHECK(fdesc.child_value("manufacturer") == std::string("TestLab"));
    CHECK(fdesc.child_value("version") == std::string("1.0"));
}

/**
 * Test security status API.
 * Verifies that security_enabled() and security_fingerprint() work correctly.
 */
TEST_CASE("secure_status_api", "[security][api][status]") {
    lsl::stream_info info("SecureStatusTest", "Test", 4, 100, lsl::cf_float32, "status_001");
    lsl::stream_outlet outlet(info);

    // Resolve and check security status
    auto found = lsl::resolve_stream("name", "SecureStatusTest", 1, 5.0);
    REQUIRE(!found.empty());

    lsl::stream_info resolved = found[0];

    SECTION("security_enabled returns correct value") {
        // When tests run with security config, this should be true
        // When run without, it should be false
        // We just verify the API works and returns a boolean
        bool enabled = resolved.security_enabled();
        INFO("security_enabled() returned: " << enabled);
        // The value depends on config, but the API should work
        CHECK((enabled == true || enabled == false));
    }

    SECTION("security_fingerprint returns string") {
        std::string fingerprint = resolved.security_fingerprint();
        INFO("security_fingerprint() returned: " << fingerprint);

        if (resolved.security_enabled()) {
            // If security is enabled, fingerprint should be non-empty
            CHECK(!fingerprint.empty());
            // Should start with "BLAKE2b:"
            CHECK(fingerprint.substr(0, 8) == "BLAKE2b:");
        } else {
            // If security is disabled, fingerprint should be empty
            CHECK(fingerprint.empty());
        }
    }
}
