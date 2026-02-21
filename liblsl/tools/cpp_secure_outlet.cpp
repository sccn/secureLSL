// Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/**
 * @file cpp_secure_outlet.cpp
 * @brief C++ Secure Outlet for cross-language testing
 *
 * Creates a secure LSL outlet and pushes samples for interoperability testing.
 *
 * Usage: cpp_secure_outlet [OPTIONS]
 *
 * Options:
 *   --name NAME      Stream name (default: CppSecureOutlet)
 *   --samples N      Number of samples to push (default: 100)
 *   --channels N     Number of channels (default: 4)
 *   --rate N         Nominal sample rate (default: 100)
 *   --help           Show this help message
 */

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <chrono>
#include <thread>
#include <lsl_cpp.h>

void print_usage(const char* program_name) {
    std::cout << "LSL Secure Outlet Test Tool\n\n"
              << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Creates a secure LSL outlet and pushes samples.\n\n"
              << "Options:\n"
              << "  --name NAME      Stream name (default: CppSecureOutlet)\n"
              << "  --samples N      Number of samples to push (default: 100)\n"
              << "  --channels N     Number of channels (default: 4)\n"
              << "  --rate N         Nominal sample rate (default: 100)\n"
              << "  --wait-for-inlet Wait for an inlet before pushing samples\n"
              << "  --help           Show this help message\n";
}

int main(int argc, char* argv[]) {
    std::string stream_name = "CppSecureOutlet";
    int num_samples = 100;
    int num_channels = 4;
    double sample_rate = 100.0;
    bool wait_for_inlet = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            stream_name = argv[++i];
        } else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) {
            num_samples = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--channels") == 0 && i + 1 < argc) {
            num_channels = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--rate") == 0 && i + 1 < argc) {
            sample_rate = std::stod(argv[++i]);
        } else if (strcmp(argv[i], "--wait-for-inlet") == 0) {
            wait_for_inlet = true;
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    try {
        // Create stream info
        lsl::stream_info info(stream_name, "Test", num_channels, sample_rate,
                              lsl::cf_float32, "cpp_secure_outlet_001");

        // Create outlet
        lsl::stream_outlet outlet(info);
        std::cerr << "Created outlet: " << stream_name << " with " << num_channels << " channels\n";

        // Wait for inlet if requested
        if (wait_for_inlet) {
            std::cerr << "Waiting for inlet...\n";
            outlet.wait_for_consumers(30.0);
            std::cerr << "Inlet connected.\n";
        }

        // Push samples
        std::vector<float> sample(num_channels);
        for (int i = 0; i < num_samples; ++i) {
            for (int ch = 0; ch < num_channels; ++ch) {
                sample[ch] = static_cast<float>(i * num_channels + ch);
            }
            outlet.push_sample(sample);

            // Small delay to simulate realistic streaming
            std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(1000.0 / sample_rate)));
        }

        std::cerr << "Pushed " << num_samples << " samples.\n";

        // Keep outlet alive briefly for last samples to be received
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
