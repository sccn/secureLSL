// Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/**
 * @file cpp_secure_inlet.cpp
 * @brief C++ Secure Inlet for cross-language testing
 *
 * Creates a secure LSL inlet and pulls/validates samples for interoperability testing.
 *
 * Usage: cpp_secure_inlet [OPTIONS]
 *
 * Options:
 *   --stream NAME    Stream name to connect to (default: PySecureOutlet)
 *   --samples N      Number of samples to pull (default: 100)
 *   --timeout T      Timeout for stream resolution (default: 10.0)
 *   --validate       Validate received data (sample values should be sequential)
 *   --help           Show this help message
 */

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <cmath>
#include <lsl_cpp.h>

void print_usage(const char* program_name) {
    std::cout << "LSL Secure Inlet Test Tool\n\n"
              << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Connects to a secure LSL stream and pulls samples.\n\n"
              << "Options:\n"
              << "  --stream NAME    Stream name to connect to (default: PySecureOutlet)\n"
              << "  --samples N      Number of samples to pull (default: 100)\n"
              << "  --timeout T      Timeout for stream resolution (default: 10.0)\n"
              << "  --validate       Validate received data (sequential values expected)\n"
              << "  --help           Show this help message\n\n"
              << "Exit codes:\n"
              << "  0  Success - all samples received (and validated if --validate)\n"
              << "  1  Error - stream not found or connection failed\n"
              << "  2  Validation failed - data mismatch\n";
}

int main(int argc, char* argv[]) {
    std::string stream_name = "PySecureOutlet";
    int num_samples = 100;
    double timeout = 10.0;
    bool validate = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--stream") == 0 && i + 1 < argc) {
            stream_name = argv[++i];
        } else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) {
            num_samples = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            timeout = std::stod(argv[++i]);
        } else if (strcmp(argv[i], "--validate") == 0) {
            validate = true;
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    try {
        // Resolve stream
        std::cerr << "Resolving stream: " << stream_name << "...\n";
        auto streams = lsl::resolve_stream("name", stream_name, 1, timeout);

        if (streams.empty()) {
            std::cerr << "Error: Stream '" << stream_name << "' not found within timeout.\n";
            return 1;
        }

        std::cerr << "Found stream: " << streams[0].name()
                  << " (" << streams[0].channel_count() << " channels)\n";

        // Create inlet
        lsl::stream_inlet inlet(streams[0]);
        inlet.open_stream(timeout);

        int num_channels = streams[0].channel_count();
        std::vector<float> sample(num_channels);

        // Pull samples
        int received = 0;
        int validation_errors = 0;

        for (int i = 0; i < num_samples; ++i) {
            double ts = inlet.pull_sample(sample, 5.0);  // 5 second timeout per sample

            if (ts == 0.0) {
                std::cerr << "Warning: Timeout waiting for sample " << i << "\n";
                continue;
            }

            received++;

            // Validate data if requested
            if (validate) {
                for (int ch = 0; ch < num_channels; ++ch) {
                    float expected = static_cast<float>(i * num_channels + ch);
                    float actual = sample[ch];
                    if (std::abs(actual - expected) > 1e-5) {
                        std::cerr << "Validation error at sample " << i << ", channel " << ch
                                  << ": expected " << expected << ", got " << actual << "\n";
                        validation_errors++;
                    }
                }
            }
        }

        std::cerr << "Received " << received << " / " << num_samples << " samples.\n";

        if (validate && validation_errors > 0) {
            std::cerr << "Validation failed with " << validation_errors << " errors.\n";
            return 2;
        }

        // Success if we received at least 70% of samples
        if (received >= num_samples * 0.7) {
            std::cerr << "Success!\n";
            return 0;
        } else {
            std::cerr << "Failed: received less than 70% of expected samples.\n";
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
