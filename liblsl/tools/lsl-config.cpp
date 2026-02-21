// Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/**
 * @file lsl-config.cpp
 * @brief LSL Configuration Validation Tool
 *
 * Validates LSL security configuration and displays status.
 *
 * Usage: lsl-config [OPTIONS]
 *
 * Options:
 *   --check          Check and display security configuration status
 *   --show-public    Display public key and fingerprint for sharing
 *   --show-device-id Display this device's unique identifier
 *   --forget-device  Remove device session token (requires passphrase on next use)
 *   --check-network  Scan network for LSL streams and check security consistency
 *   --help           Show this help message
 */

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#ifdef LSL_SECURITY_ENABLED
#include <lsl_security.h>
#endif

#include <lsl_cpp.h>

// Read passphrase with echo disabled
std::string read_passphrase(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();

    std::string passphrase;

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
    std::getline(std::cin, passphrase);
    SetConsoleMode(hStdin, mode);
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, passphrase);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    std::cout << "\n";
    return passphrase;
}

void print_usage(const char* program_name) {
    std::cout << "LSL Configuration Validator\n\n"
              << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --check          Display security configuration status (default)\n"
              << "  --show-public    Display public key and fingerprint for sharing\n"
              << "  --show-device-id Display this device's unique identifier\n"
              << "  --remember-device Create device session token (avoids passphrase prompt)\n"
              << "    --days N       Token expiry in days (default: 30, use -1 for never)\n"
              << "    --passphrase   Prompt for passphrase (instead of LSL_KEY_PASSPHRASE env)\n"
              << "  --forget-device  Remove device session token\n"
              << "  --check-network  Scan network for LSL streams and verify security\n"
              << "  --help           Show this help message\n\n"
              << "Key Sharing:\n"
              << "  Use --show-public to get your device's public key for sharing with\n"
              << "  other lab members. The public key can be safely shared; only the\n"
              << "  private key must be kept secret.\n\n"
              << "Device Session Tokens:\n"
              << "  When using passphrase-protected keys, you can use 'remember_device'\n"
              << "  during unlock to create a device-bound session token. This allows\n"
              << "  automatic unlock on subsequent reboots. The token is bound to this\n"
              << "  device's hardware and cannot be used on other machines.\n"
              << "  Use --forget-device to remove the token and require passphrase again.\n";
}

void check_config() {
    std::cout << "LSL Security Configuration Status\n";
    std::cout << "==================================\n\n";

#ifdef LSL_SECURITY_ENABLED
    using namespace lsl::security;

    auto& sec = LSLSecurity::instance();
    SecurityResult init_result = sec.initialize();

    if (init_result != SecurityResult::SUCCESS) {
        std::cout << "  Security subsystem: FAILED TO INITIALIZE\n";
        std::cout << "  Error: " << security_result_string(init_result) << "\n";
        return;
    }

    std::cout << "  Security subsystem: initialized\n";

    // Try to load credentials
    sec.load_credentials();

    if (sec.is_enabled()) {
        std::cout << "  Security enabled:   YES\n";
        std::cout << "  Config file:        " << LSLSecurity::get_default_config_path() << "\n";

        const auto& pk = sec.get_public_key();
        std::cout << "  Key fingerprint:    " << LSLSecurity::compute_fingerprint(pk) << "\n";

        const std::string& created = sec.get_key_created();
        if (!created.empty()) {
            std::cout << "  Key created:        " << created << "\n";
        }

        std::cout << "  Session lifetime:   " << sec.get_session_key_lifetime() << " seconds\n";

        if (sec.is_locked()) {
            std::cout << "  Key status:         LOCKED (passphrase-protected)\n";
        }

        // Show device token status
        if (sec.has_device_token()) {
            std::cout << "  Device token:       ";
            if (sec.is_token_expired()) {
                std::cout << "EXPIRED\n";
            } else {
                int64_t expiry = sec.get_token_expiry();
                if (expiry == 0) {
                    std::cout << "valid (never expires)\n";
                } else {
                    std::cout << "valid (expires at " << expiry << ")\n";
                }
            }
            std::cout << "  Token file:         " << LSLSecurity::get_default_token_path() << "\n";
        } else {
            std::cout << "  Device token:       not set\n";
        }

        std::cout << "\n  [OK] Configuration valid\n";
    } else {
        std::cout << "  Security enabled:   NO\n";
        std::cout << "\n  No security credentials found.\n";
        std::cout << "  Run 'lsl-keygen' to generate keys and enable security.\n";
    }
#else
    std::cout << "  Security support:   NOT COMPILED\n";
    std::cout << "\n  LSL was built without security support.\n";
    std::cout << "  Rebuild with -DLSL_SECURITY=ON to enable.\n";
#endif
}

void show_public_key() {
    std::cout << "LSL Device Public Key\n";
    std::cout << "=====================\n\n";

#ifdef LSL_SECURITY_ENABLED
    using namespace lsl::security;

    auto& sec = LSLSecurity::instance();
    SecurityResult init_result = sec.initialize();

    if (init_result != SecurityResult::SUCCESS) {
        std::cerr << "Error: Failed to initialize security subsystem.\n";
        return;
    }

    // Load credentials
    sec.load_credentials();

    if (!sec.is_enabled() && !sec.is_locked()) {
        std::cerr << "Error: No security credentials found.\n";
        std::cerr << "Run 'lsl-keygen' to generate keys first.\n";
        return;
    }

    const auto& pk = sec.get_public_key();

    // Check if public key is all zeros (not loaded yet due to locked key)
    bool pk_empty = true;
    for (size_t i = 0; i < pk.size(); ++i) {
        if (pk[i] != 0) {
            pk_empty = false;
            break;
        }
    }

    if (pk_empty) {
        std::cerr << "Error: Public key not available.\n";
        if (sec.is_locked()) {
            std::cerr << "The private key is passphrase-protected. Unlock it first.\n";
        }
        return;
    }

    std::string fingerprint = LSLSecurity::compute_fingerprint(pk);
    std::string public_key_b64 = base64_encode(pk.data(), pk.size());

    std::cout << "Fingerprint:\n";
    std::cout << "  " << fingerprint << "\n\n";

    std::cout << "Public Key (base64):\n";
    std::cout << "  " << public_key_b64 << "\n\n";

    std::cout << "This public key can be safely shared with other lab members.\n";
    std::cout << "They can use it to verify your device's identity.\n";
#else
    std::cerr << "Error: LSL was built without security support.\n";
    std::cerr << "Rebuild with -DLSL_SECURITY=ON to enable.\n";
#endif
}

void show_device_id() {
    std::cout << "LSL Device Identifier\n";
    std::cout << "=====================\n\n";

#ifdef LSL_SECURITY_ENABLED
    using namespace lsl::security;

    auto& sec = LSLSecurity::instance();
    SecurityResult init_result = sec.initialize();

    if (init_result != SecurityResult::SUCCESS) {
        std::cerr << "Error: Failed to initialize security subsystem.\n";
        return;
    }

    std::string device_id = LSLSecurity::get_device_id_string();
    if (device_id.empty()) {
        std::cerr << "Error: Failed to compute device identifier.\n";
        return;
    }

    std::cout << "Device ID:\n";
    std::cout << "  " << device_id << "\n\n";
    std::cout << "This identifier is derived from:\n";
    std::cout << "  - Hostname\n";
    std::cout << "  - Primary MAC address\n";
    std::cout << "  - Machine ID (platform-specific)\n\n";
    std::cout << "Device session tokens are bound to this identifier.\n";
    std::cout << "If hardware changes significantly, tokens will become invalid.\n";
#else
    std::cerr << "Error: LSL was built without security support.\n";
    std::cerr << "Rebuild with -DLSL_SECURITY=ON to enable.\n";
#endif
}

void forget_device() {
    std::cout << "Removing Device Session Token\n";
    std::cout << "=============================\n\n";

#ifdef LSL_SECURITY_ENABLED
    using namespace lsl::security;

    auto& sec = LSLSecurity::instance();
    SecurityResult init_result = sec.initialize();

    if (init_result != SecurityResult::SUCCESS) {
        std::cerr << "Error: Failed to initialize security subsystem.\n";
        return;
    }

    if (!sec.has_device_token()) {
        std::cout << "No device session token found.\n";
        return;
    }

    std::string token_path = LSLSecurity::get_default_token_path();
    SecurityResult result = sec.forget_device();

    if (result == SecurityResult::SUCCESS) {
        std::cout << "Device session token removed.\n";
        std::cout << "Token file: " << token_path << "\n\n";
        std::cout << "You will need to enter your passphrase on the next use.\n";
    } else {
        std::cerr << "Error: Failed to remove token: " << security_result_string(result) << "\n";
    }
#else
    std::cerr << "Error: LSL was built without security support.\n";
    std::cerr << "Rebuild with -DLSL_SECURITY=ON to enable.\n";
#endif
}

void remember_device_cmd(int expiry_days, bool prompt_passphrase) {
    std::cout << "Creating Device Session Token\n";
    std::cout << "=============================\n\n";

#ifdef LSL_SECURITY_ENABLED
    using namespace lsl::security;

    // Get passphrase - either prompt or from environment
    std::string passphrase;
    if (prompt_passphrase) {
        passphrase = read_passphrase("Enter passphrase: ");
        if (passphrase.empty()) {
            std::cerr << "Error: Passphrase cannot be empty.\n";
            return;
        }
    } else if (auto* env_pass = std::getenv("LSL_KEY_PASSPHRASE")) {
        passphrase = env_pass;
        std::cout << "Using passphrase from LSL_KEY_PASSPHRASE environment variable.\n";
        std::cout << "\nWARNING: Environment variables are visible to other processes on this system.\n";
        std::cout << "         This is less secure than entering the passphrase interactively.\n";
        std::cout << "         Use --passphrase to enter it securely instead.\n\n";
    } else {
        std::cerr << "Error: No passphrase provided.\n";
        std::cerr << "Use --passphrase to enter it securely, or set LSL_KEY_PASSPHRASE.\n";
        return;
    }

    auto& sec = LSLSecurity::instance();
    SecurityResult init_result = sec.initialize();

    if (init_result != SecurityResult::SUCCESS) {
        std::cerr << "Error: Failed to initialize security subsystem.\n";
        return;
    }

    // Load credentials (this will auto-unlock if LSL_KEY_PASSPHRASE is set)
    sec.load_credentials();

    if (!sec.is_enabled()) {
        // Try manual unlock if not auto-unlocked
        SecurityResult unlock_result = sec.unlock(passphrase);
        if (unlock_result != SecurityResult::SUCCESS) {
            std::cerr << "Error: Failed to unlock key: " << security_result_string(unlock_result) << "\n";
            return;
        }
    }

    // Check if key has passphrase protection
    if (!sec.has_encrypted_key()) {
        std::cout << "Key is not passphrase-protected. No session token needed.\n";
        return;
    }

    // Create device token
    uint32_t days = (expiry_days < 0) ? 0 : static_cast<uint32_t>(expiry_days);
    SecurityResult result = sec.remember_device(passphrase, days);
    if (result == SecurityResult::SUCCESS) {
        std::cout << "[OK] Device session token created.\n";
        std::cout << "Token file: " << LSLSecurity::get_default_token_path() << "\n\n";
        if (expiry_days < 0) {
            std::cout << "This device will auto-unlock without passphrase (never expires).\n";
        } else {
            std::cout << "This device will auto-unlock without passphrase for " << expiry_days << " days.\n";
        }
        std::cout << "Use --forget-device to remove the token.\n";
    } else {
        std::cerr << "Error: Failed to create token: " << security_result_string(result) << "\n";
    }
#else
    (void)expiry_days;
    (void)prompt_passphrase;
    std::cerr << "Error: LSL was built without security support.\n";
    std::cerr << "Rebuild with -DLSL_SECURITY=ON to enable.\n";
#endif
}

void check_network() {
    std::cout << "LSL Network Security Scan\n";
    std::cout << "=========================\n\n";
    std::cout << "Scanning for LSL streams on the network...\n\n";

    // Resolve all streams on the network
    std::vector<lsl::stream_info> streams = lsl::resolve_streams(2.0);

    if (streams.empty()) {
        std::cout << "No LSL streams found on the network.\n";
        return;
    }

    std::cout << "Found " << streams.size() << " stream(s):\n\n";

    int secure_count = 0;
    int insecure_count = 0;

    for (const auto& info : streams) {
        std::cout << "  " << info.name() << " (" << info.hostname() << ")\n";
        std::cout << "    Type: " << info.type() << "\n";
        std::cout << "    Channels: " << info.channel_count() << " @ " << info.nominal_srate() << " Hz\n";

        // Check for security metadata in stream info
        // Note: This requires the security metadata to be added to stream_info
        // For now, we just report the stream
        std::cout << "    Security: (requires protocol extension)\n";
        std::cout << "\n";
    }

    std::cout << "Network scan complete.\n";
    std::cout << "\nNote: Full security status reporting requires protocol extension.\n";
    std::cout << "This will be available after Phase 2 implementation.\n";
}

int main(int argc, char* argv[]) {
    enum class Command { CHECK, SHOW_PUBLIC, SHOW_DEVICE_ID, REMEMBER_DEVICE, FORGET_DEVICE, CHECK_NETWORK };
    Command cmd = Command::CHECK;
    int expiry_days = 30;  // Default expiry
    bool prompt_passphrase = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--check") == 0 || strcmp(argv[i], "-c") == 0) {
            cmd = Command::CHECK;
        } else if (strcmp(argv[i], "--show-public") == 0 || strcmp(argv[i], "-p") == 0) {
            cmd = Command::SHOW_PUBLIC;
        } else if (strcmp(argv[i], "--show-device-id") == 0 || strcmp(argv[i], "-d") == 0) {
            cmd = Command::SHOW_DEVICE_ID;
        } else if (strcmp(argv[i], "--remember-device") == 0 || strcmp(argv[i], "-r") == 0) {
            cmd = Command::REMEMBER_DEVICE;
        } else if (strcmp(argv[i], "--forget-device") == 0 || strcmp(argv[i], "-f") == 0) {
            cmd = Command::FORGET_DEVICE;
        } else if (strcmp(argv[i], "--check-network") == 0 || strcmp(argv[i], "-n") == 0) {
            cmd = Command::CHECK_NETWORK;
        } else if (strcmp(argv[i], "--days") == 0 && i + 1 < argc) {
            expiry_days = std::atoi(argv[++i]);
        } else if (strcmp(argv[i], "--passphrase") == 0) {
            prompt_passphrase = true;
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    switch (cmd) {
        case Command::CHECK:
            check_config();
            break;
        case Command::SHOW_PUBLIC:
            show_public_key();
            break;
        case Command::SHOW_DEVICE_ID:
            show_device_id();
            break;
        case Command::REMEMBER_DEVICE:
            remember_device_cmd(expiry_days, prompt_passphrase);
            break;
        case Command::FORGET_DEVICE:
            forget_device();
            break;
        case Command::CHECK_NETWORK:
            check_network();
            break;
    }

    return 0;
}
