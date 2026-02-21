// Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/**
 * @file lsl-keygen.cpp
 * @brief LSL Key Generation Tool
 *
 * Generates Ed25519 keypairs for LSL security and saves them to the configuration file.
 * Also supports exporting and importing keys for portable key distribution.
 *
 * Usage: lsl-keygen [OPTIONS]
 *
 * Options:
 *   --output PATH     Specify configuration file path (default: $LSLAPICFG or ~/.lsl_api/lsl_api.cfg)
 *   --force           Overwrite existing keys
 *   --show-public     Display public key after generation
 *   --insecure        Store private key WITHOUT passphrase protection (not recommended)
 *   --export NAME           Generate NEW keypair and export to NAME.pub and NAME.key.enc files
 *   --export-existing NAME  Export EXISTING key from config to NAME.pub and NAME.key.enc files
 *   --export-public         Display public key for sharing
 *   --import FILE           Import encrypted key file into config
 *   --help            Show this help message
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

#ifdef LSL_SECURITY_ENABLED
#include <lsl_security.h>
#include <sodium.h>

using namespace lsl::security;

// Get config path: --output > $LSLAPICFG > default
std::string get_config_path(const std::string& output_path) {
    if (!output_path.empty()) {
        return output_path;
    }
    const char* env_path = std::getenv("LSLAPICFG");
    if (env_path && env_path[0] != '\0') {
        return std::string(env_path);
    }
    return LSLSecurity::get_default_config_path();
}

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
    std::cout << "LSL Security Key Generator\n\n"
              << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Generates Ed25519 keypair for secure LSL communication.\n\n"
              << "Key Generation:\n"
              << "  --output PATH     Configuration file path (default: $LSLAPICFG or ~/.lsl_api/lsl_api.cfg)\n"
              << "  --force           Overwrite existing keys without prompting\n"
              << "  --show-public     Display public key and fingerprint after generation\n"
              << "  --insecure        Store private key WITHOUT passphrase protection (not recommended)\n\n"
              << "Key Export (for sharing across devices):\n"
              << "  --export NAME          Generate NEW keypair and export to NAME.pub and NAME.key.enc\n"
              << "  --export-existing NAME Export the EXISTING key from your config to NAME.pub and NAME.key.enc\n"
              << "  --export-public        Display current public key for sharing\n\n"
              << "Key Import:\n"
              << "  --import FILE     Import encrypted key file (.key.enc) into local config\n\n"
              << "Other:\n"
              << "  --help            Show this help message\n\n"
              << "Passphrase Protection (Default):\n"
              << "  By default, lsl-keygen prompts for a passphrase to encrypt the private key.\n"
              << "  This provides two-factor authentication: something you have (the key file)\n"
              << "  plus something you know (the passphrase). Required for EU NIS2 Art. 21(2)(j).\n\n"
              << "  You may press Enter for an empty passphrase, but this is NOT recommended\n"
              << "  for environments with regulatory requirements (EU CRA, NIS2, HIPAA, GDPR).\n\n"
              << "  To unlock at runtime:\n"
              << "    - Use device-bound session token: lsl-config --remember-device (recommended)\n"
              << "    - Set LSL_KEY_PASSPHRASE environment variable (less secure)\n"
              << "    - Call lsl_security_unlock() in your application\n\n"
              << "Portable Key Workflow (new key for all devices):\n"
              << "  1. On admin machine: lsl-keygen --export lab_eeg\n"
              << "     (This generates a NEW keypair and exports it to files)\n"
              << "  2. Copy lab_eeg.key.enc to ALL devices (including admin)\n"
              << "  3. On EVERY device: lsl-keygen --import lab_eeg.key.enc\n"
              << "  4. All devices now share the same identity\n\n"
              << "Portable Key Workflow (export existing key):\n"
              << "  1. On admin machine: lsl-keygen              (generate key)\n"
              << "  2. On admin machine: lsl-keygen --export-existing lab_eeg\n"
              << "  3. Copy lab_eeg.key.enc to OTHER devices\n"
              << "  4. On each other device: lsl-keygen --import lab_eeg.key.enc\n\n"
              << "After generation/import, security is automatically enabled when LSL starts.\n";
}

// Export public key to stdout
int cmd_export_public() {
    auto& sec = LSLSecurity::instance();
    SecurityResult init_result = sec.initialize();
    if (init_result != SecurityResult::SUCCESS) {
        std::cerr << "Error: Failed to initialize security subsystem.\n";
        return 1;
    }
    SecurityResult load_result = sec.load_credentials();
    if (load_result != SecurityResult::SUCCESS &&
        load_result != SecurityResult::KEY_LOCKED) {
        std::cerr << "Error: Failed to load security credentials.\n";
        return 1;
    }

    if (!sec.is_enabled() && !sec.is_locked()) {
        std::cerr << "Error: No security credentials found.\n";
        std::cerr << "Run 'lsl-keygen' to generate keys first.\n";
        return 1;
    }

    if (sec.is_locked()) {
        std::cerr << "Error: Key is passphrase-protected.\n";
        std::cerr << "Set LSL_KEY_PASSPHRASE environment variable or unlock first.\n";
        return 1;
    }

    const auto& pk = sec.get_public_key();
    std::string fingerprint = LSLSecurity::compute_fingerprint(pk);
    std::string public_key_b64 = base64_encode(pk.data(), pk.size());

    std::cout << "Fingerprint:\n  " << fingerprint << "\n\n";
    std::cout << "Public Key (base64):\n  " << public_key_b64 << "\n\n";
    std::cout << "This public key can be safely shared with other lab members.\n";

    return 0;
}

// Export keys to files (NAME.pub and NAME.key.enc)
int cmd_export(const std::string& name, bool force) {
    std::string pub_path = name + ".pub";
    std::string key_path = name + ".key.enc";

    // Check if files already exist
    if (!force) {
        std::ifstream check_pub(pub_path);
        std::ifstream check_key(key_path);
        if (check_pub.good() || check_key.good()) {
            std::cerr << "Error: Export files already exist. Use --force to overwrite.\n";
            return 1;
        }
    }

    std::cout << "LSL Security Key Generator - Export Mode\n";
    std::cout << "========================================\n\n";

    auto& sec = LSLSecurity::instance();
    SecurityResult init_result = sec.initialize();
    if (init_result != SecurityResult::SUCCESS) {
        std::cerr << "Error: Failed to initialize security subsystem.\n";
        return 1;
    }

    // For export, we always require a passphrase to protect the key file
    std::cout << "Exported keys are always passphrase-protected for security.\n\n";

    std::string passphrase = read_passphrase("Enter passphrase for exported key: ");
    if (passphrase.empty()) {
        std::cerr << "Error: Passphrase cannot be empty.\n";
        return 1;
    }

    std::string confirm = read_passphrase("Confirm passphrase: ");
    if (passphrase != confirm) {
        std::cerr << "Error: Passphrases do not match.\n";
        return 1;
    }

    if (passphrase.length() < 8) {
        std::cout << "Warning: Passphrase is short. Consider using at least 8 characters.\n";
    }
    std::cout << "\n";

    // Generate keypair
    std::array<uint8_t, PUBLIC_KEY_SIZE> pk;
    std::array<uint8_t, SECRET_KEY_SIZE> sk;
    SecurityResult gen_result = sec.generate_keypair(pk, sk);
    if (gen_result != SecurityResult::SUCCESS) {
        std::cerr << "Error: Failed to generate keypair.\n";
        return 1;
    }

    // Encrypt the private key
    // We need to manually call encrypt_private_key since it's private
    // Instead, let's generate to a temp config and read the encrypted key back

    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream timestamp;
    timestamp << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");

    // Derive encryption key from passphrase using Argon2id
    std::array<uint8_t, PASSPHRASE_SALT_SIZE> salt;
    std::array<uint8_t, NONCE_SIZE> nonce;
    randombytes_buf(salt.data(), salt.size());
    randombytes_buf(nonce.data(), nonce.size());

    std::array<uint8_t, SESSION_KEY_SIZE> derived_key;
    if (crypto_pwhash(
            derived_key.data(), derived_key.size(),
            passphrase.c_str(), passphrase.length(),
            salt.data(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        std::cerr << "Error: Failed to derive key from passphrase.\n";
        secure_zero(sk.data(), sk.size());
        return 1;
    }

    // Encrypt the secret key
    std::vector<uint8_t> ciphertext(SECRET_KEY_SIZE + AUTH_TAG_SIZE);
    unsigned long long ciphertext_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            sk.data(), sk.size(),
            nullptr, 0,
            nullptr,
            nonce.data(),
            derived_key.data()) != 0) {
        std::cerr << "Error: Failed to encrypt private key.\n";
        secure_zero(sk.data(), sk.size());
        secure_zero(derived_key.data(), derived_key.size());
        return 1;
    }

    secure_zero(sk.data(), sk.size());
    secure_zero(derived_key.data(), derived_key.size());

    // Combine: salt + nonce + ciphertext
    std::vector<uint8_t> encrypted_key;
    encrypted_key.insert(encrypted_key.end(), salt.begin(), salt.end());
    encrypted_key.insert(encrypted_key.end(), nonce.begin(), nonce.end());
    encrypted_key.insert(encrypted_key.end(), ciphertext.begin(), ciphertext.end());

    // Write .pub file
    {
        std::ofstream pub_file(pub_path);
        if (!pub_file.good()) {
            std::cerr << "Error: Could not create " << pub_path << "\n";
            return 1;
        }
        pub_file << "# LSL Security Public Key\n";
        pub_file << "# Generated: " << timestamp.str() << "\n";
        pub_file << "# Fingerprint: " << LSLSecurity::compute_fingerprint(pk) << "\n";
        pub_file << "#\n";
        pub_file << "# This public key can be safely shared with other lab members.\n";
        pub_file << "# They can use it to verify your device's identity.\n";
        pub_file << "\n";
        pub_file << base64_encode(pk.data(), pk.size()) << "\n";
        pub_file.flush();
        if (!pub_file.good()) {
            std::cerr << "Error: Failed to write " << pub_path << "\n";
            std::remove(pub_path.c_str());
            return 1;
        }
    }

    // Write .key.enc file
    {
        std::ofstream key_file(key_path);
        if (!key_file.good()) {
            std::cerr << "Error: Could not create " << key_path << "\n";
            std::remove(pub_path.c_str());
            return 1;
        }
        key_file << "# LSL Security Encrypted Private Key\n";
        key_file << "# Generated: " << timestamp.str() << "\n";
        key_file << "# Fingerprint: " << LSLSecurity::compute_fingerprint(pk) << "\n";
        key_file << "#\n";
        key_file << "# This file is encrypted with your passphrase.\n";
        key_file << "# Import to another device with: lsl-keygen --import " << key_path << "\n";
        key_file << "\n";
        key_file << base64_encode(encrypted_key.data(), encrypted_key.size()) << "\n";
        key_file.flush();
        if (!key_file.good()) {
            std::cerr << "Error: Failed to write " << key_path << "\n";
            std::remove(pub_path.c_str());
            std::remove(key_path.c_str());
            return 1;
        }
    }

    std::cout << "[OK] Keypair generated successfully!\n";
    std::cout << "[OK] Public key saved to: " << pub_path << "\n";
    std::cout << "[OK] Encrypted private key saved to: " << key_path << "\n\n";
    std::cout << "Fingerprint: " << LSLSecurity::compute_fingerprint(pk) << "\n\n";
    std::cout << "To use this key on another device:\n";
    std::cout << "  1. Copy " << key_path << " to the target device\n";
    std::cout << "  2. Run: lsl-keygen --import " << key_path << "\n";
    std::cout << "  3. Enter the same passphrase when prompted\n";

    return 0;
}

// Export EXISTING key from local config to files (NAME.pub and NAME.key.enc)
int cmd_export_existing(const std::string& name, const std::string& config_path_override, bool force) {
    std::string pub_path = name + ".pub";
    std::string key_path = name + ".key.enc";

    // Check if files already exist
    if (!force) {
        std::ifstream check_pub(pub_path);
        std::ifstream check_key(key_path);
        if (check_pub.good() || check_key.good()) {
            std::cerr << "Error: Export files already exist. Use --force to overwrite.\n";
            return 1;
        }
    }

    std::cout << "LSL Security Key Generator - Export Existing Key\n";
    std::cout << "=================================================\n\n";

    // Find and read the config file
    std::string config_path = get_config_path(config_path_override);
    std::ifstream infile(config_path);
    if (!infile.good()) {
        std::cerr << "Error: Could not open config file: " << config_path << "\n";
        std::cerr << "Generate keys first with: lsl-keygen\n";
        return 1;
    }

    // Parse config for private_key or encrypted_private_key
    std::string private_key_b64;
    std::string encrypted_key_b64;
    std::string line;
    while (std::getline(infile, line)) {
        // Trim leading whitespace
        size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        line = line.substr(start);

        // Skip comments
        if (line[0] == '#' || line[0] == ';') continue;

        // Look for private_key = ... or encrypted_private_key = ...
        if (line.find("encrypted_private_key") == 0) {
            size_t eq = line.find('=');
            if (eq != std::string::npos) {
                encrypted_key_b64 = line.substr(eq + 1);
                // Trim whitespace
                size_t s = encrypted_key_b64.find_first_not_of(" \t");
                if (s != std::string::npos) encrypted_key_b64 = encrypted_key_b64.substr(s);
                size_t e = encrypted_key_b64.find_last_not_of(" \t\r\n");
                if (e != std::string::npos) encrypted_key_b64 = encrypted_key_b64.substr(0, e + 1);
            }
        } else if (line.find("private_key") == 0) {
            size_t eq = line.find('=');
            if (eq != std::string::npos) {
                private_key_b64 = line.substr(eq + 1);
                size_t s = private_key_b64.find_first_not_of(" \t");
                if (s != std::string::npos) private_key_b64 = private_key_b64.substr(s);
                size_t e = private_key_b64.find_last_not_of(" \t\r\n");
                if (e != std::string::npos) private_key_b64 = private_key_b64.substr(0, e + 1);
            }
        }
    }

    if (infile.bad()) {
        std::cerr << "Error: I/O error reading config file: " << config_path << "\n";
        return 1;
    }

    if (private_key_b64.empty() && encrypted_key_b64.empty()) {
        std::cerr << "Error: No private key found in " << config_path << "\n";
        std::cerr << "Generate keys first with: lsl-keygen\n";
        return 1;
    }

    if (!private_key_b64.empty() && !encrypted_key_b64.empty()) {
        std::cout << "Warning: Config contains both encrypted and plaintext keys. Using encrypted key.\n";
    }

    // Initialize security subsystem
    auto& sec = LSLSecurity::instance();
    SecurityResult init_result = sec.initialize();
    if (init_result != SecurityResult::SUCCESS) {
        std::cerr << "Error: Failed to initialize security subsystem.\n";
        return 1;
    }

    // Get the raw secret key
    std::array<uint8_t, SECRET_KEY_SIZE> sk;

    if (!encrypted_key_b64.empty()) {
        // Encrypted key: need config passphrase to decrypt
        std::vector<uint8_t> encrypted_key;
        if (!base64_decode(encrypted_key_b64, encrypted_key) ||
            encrypted_key.size() != ENCRYPTED_KEY_SIZE) {
            std::cerr << "Error: Invalid encrypted key format in config.\n";
            return 1;
        }

        std::string config_passphrase = read_passphrase("Enter passphrase for existing key (from config): ");
        if (config_passphrase.empty()) {
            std::cerr << "Error: Passphrase cannot be empty.\n";
            return 1;
        }

        // Decrypt using the same logic as cmd_import
        const uint8_t* salt = encrypted_key.data();
        const uint8_t* nonce = salt + PASSPHRASE_SALT_SIZE;
        const uint8_t* ciphertext = nonce + NONCE_SIZE;
        size_t ciphertext_len = SECRET_KEY_SIZE + AUTH_TAG_SIZE;

        std::array<uint8_t, SESSION_KEY_SIZE> derived_key;
        if (crypto_pwhash(
                derived_key.data(), derived_key.size(),
                config_passphrase.c_str(), config_passphrase.length(),
                salt,
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                crypto_pwhash_ALG_ARGON2ID13) != 0) {
            secure_zero(derived_key.data(), derived_key.size());
            std::cerr << "Error: Failed to derive key from passphrase.\n";
            return 1;
        }

        unsigned long long plaintext_len = 0;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                sk.data(), &plaintext_len,
                nullptr,
                ciphertext, ciphertext_len,
                nullptr, 0,
                nonce,
                derived_key.data()) != 0) {
            secure_zero(derived_key.data(), derived_key.size());
            std::cerr << "Error: Invalid passphrase for existing key.\n";
            return 1;
        }
        secure_zero(derived_key.data(), derived_key.size());

        std::cout << "\n[OK] Existing key decrypted successfully.\n\n";
    } else {
        // Plaintext key: decode base64
        std::vector<uint8_t> sk_vec;
        if (!base64_decode(private_key_b64, sk_vec) || sk_vec.size() != SECRET_KEY_SIZE) {
            std::cerr << "Error: Invalid private key format in config.\n";
            return 1;
        }
        std::copy(sk_vec.begin(), sk_vec.end(), sk.begin());
        secure_zero(sk_vec.data(), sk_vec.size());

        std::cout << "Found plaintext key in config.\n\n";
    }

    // Extract public key (Ed25519 sk is seed||pk, pk is last PUBLIC_KEY_SIZE bytes)
    static_assert(SECRET_KEY_SIZE == 2 * PUBLIC_KEY_SIZE, "Ed25519 sk must be seed||pk");
    std::array<uint8_t, PUBLIC_KEY_SIZE> pk;
    std::copy(sk.begin() + (SECRET_KEY_SIZE - PUBLIC_KEY_SIZE), sk.end(), pk.begin());

    std::cout << "Existing key fingerprint: " << LSLSecurity::compute_fingerprint(pk) << "\n\n";

    // Now encrypt for export (always passphrase-protected)
    std::cout << "Exported keys are always passphrase-protected for security.\n";
    std::cout << "You may use the same passphrase as the existing key, or a different one.\n\n";

    std::string export_passphrase = read_passphrase("Enter passphrase for exported key: ");
    if (export_passphrase.empty()) {
        std::cerr << "Error: Passphrase cannot be empty for exported keys.\n";
        secure_zero(sk.data(), sk.size());
        return 1;
    }

    std::string confirm = read_passphrase("Confirm passphrase: ");
    if (export_passphrase != confirm) {
        std::cerr << "Error: Passphrases do not match.\n";
        secure_zero(sk.data(), sk.size());
        return 1;
    }

    if (export_passphrase.length() < 8) {
        std::cout << "Warning: Passphrase is short. Consider using at least 8 characters.\n";
    }
    std::cout << "\n";

    // Get timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream timestamp;
    timestamp << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");

    // Derive encryption key from export passphrase
    std::array<uint8_t, PASSPHRASE_SALT_SIZE> salt;
    std::array<uint8_t, NONCE_SIZE> nonce;
    randombytes_buf(salt.data(), salt.size());
    randombytes_buf(nonce.data(), nonce.size());

    std::array<uint8_t, SESSION_KEY_SIZE> derived_key;
    if (crypto_pwhash(
            derived_key.data(), derived_key.size(),
            export_passphrase.c_str(), export_passphrase.length(),
            salt.data(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        std::cerr << "Error: Failed to derive key from passphrase.\n";
        secure_zero(sk.data(), sk.size());
        return 1;
    }

    // Encrypt the secret key
    std::vector<uint8_t> ciphertext(SECRET_KEY_SIZE + AUTH_TAG_SIZE);
    unsigned long long ciphertext_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            sk.data(), sk.size(),
            nullptr, 0,
            nullptr,
            nonce.data(),
            derived_key.data()) != 0) {
        std::cerr << "Error: Failed to encrypt private key.\n";
        secure_zero(sk.data(), sk.size());
        secure_zero(derived_key.data(), derived_key.size());
        return 1;
    }

    secure_zero(sk.data(), sk.size());
    secure_zero(derived_key.data(), derived_key.size());

    // Combine: salt + nonce + ciphertext
    std::vector<uint8_t> encrypted_key;
    encrypted_key.insert(encrypted_key.end(), salt.begin(), salt.end());
    encrypted_key.insert(encrypted_key.end(), nonce.begin(), nonce.end());
    encrypted_key.insert(encrypted_key.end(), ciphertext.begin(), ciphertext.end());

    // Write .pub file
    {
        std::ofstream pub_file(pub_path);
        if (!pub_file.good()) {
            std::cerr << "Error: Could not create " << pub_path << "\n";
            return 1;
        }
        pub_file << "# LSL Security Public Key\n";
        pub_file << "# Exported from: " << config_path << "\n";
        pub_file << "# Exported: " << timestamp.str() << "\n";
        pub_file << "# Fingerprint: " << LSLSecurity::compute_fingerprint(pk) << "\n";
        pub_file << "#\n";
        pub_file << "# This public key can be safely shared with other lab members.\n";
        pub_file << "\n";
        pub_file << base64_encode(pk.data(), pk.size()) << "\n";
        pub_file.flush();
        if (!pub_file.good()) {
            std::cerr << "Error: Failed to write " << pub_path << "\n";
            std::remove(pub_path.c_str());
            return 1;
        }
    }

    // Write .key.enc file
    {
        std::ofstream key_file(key_path);
        if (!key_file.good()) {
            std::cerr << "Error: Could not create " << key_path << "\n";
            std::remove(pub_path.c_str());
            return 1;
        }
        key_file << "# LSL Security Encrypted Private Key\n";
        key_file << "# Exported from: " << config_path << "\n";
        key_file << "# Exported: " << timestamp.str() << "\n";
        key_file << "# Fingerprint: " << LSLSecurity::compute_fingerprint(pk) << "\n";
        key_file << "#\n";
        key_file << "# This file is encrypted with your passphrase.\n";
        key_file << "# Import to another device with: lsl-keygen --import " << key_path << "\n";
        key_file << "\n";
        key_file << base64_encode(encrypted_key.data(), encrypted_key.size()) << "\n";
        key_file.flush();
        if (!key_file.good()) {
            std::cerr << "Error: Failed to write " << key_path << "\n";
            std::remove(pub_path.c_str());
            std::remove(key_path.c_str());
            return 1;
        }
    }

    std::cout << "[OK] Existing key exported successfully!\n";
    std::cout << "[OK] Public key saved to: " << pub_path << "\n";
    std::cout << "[OK] Encrypted private key saved to: " << key_path << "\n\n";
    std::cout << "Fingerprint: " << LSLSecurity::compute_fingerprint(pk) << "\n\n";
    std::cout << "To use this key on another device:\n";
    std::cout << "  1. Copy " << key_path << " to the target device\n";
    std::cout << "  2. Run: lsl-keygen --import " << key_path << "\n";
    std::cout << "  3. Enter the same passphrase when prompted\n\n";
    std::cout << "Note: The admin machine already has this key. Only import on OTHER devices.\n";

    return 0;
}

// Import encrypted key file into local config
int cmd_import(const std::string& file_path, const std::string& output_path, bool force) {
    std::cout << "LSL Security Key Generator - Import Mode\n";
    std::cout << "========================================\n\n";

    // Read the key file
    std::ifstream key_file(file_path);
    if (!key_file.good()) {
        std::cerr << "Error: Could not open " << file_path << "\n";
        return 1;
    }

    // Parse the file, skip comments
    std::string encrypted_key_b64;
    std::string line;
    while (std::getline(key_file, line)) {
        // Trim whitespace
        size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        line = line.substr(start);

        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;

        encrypted_key_b64 = line;
        break;
    }

    if (encrypted_key_b64.empty()) {
        std::cerr << "Error: No key data found in " << file_path << "\n";
        return 1;
    }

    // Decode the encrypted key
    std::vector<uint8_t> encrypted_key;
    if (!base64_decode(encrypted_key_b64, encrypted_key)) {
        std::cerr << "Error: Invalid base64 encoding in key file.\n";
        return 1;
    }

    if (encrypted_key.size() != ENCRYPTED_KEY_SIZE) {
        std::cerr << "Error: Invalid key file format (wrong size).\n";
        return 1;
    }

    // Initialize security
    auto& sec = LSLSecurity::instance();
    SecurityResult init_result = sec.initialize();
    if (init_result != SecurityResult::SUCCESS) {
        std::cerr << "Error: Failed to initialize security subsystem.\n";
        return 1;
    }

    // Get passphrase to verify the key can be decrypted
    std::string passphrase = read_passphrase("Enter passphrase to verify key: ");
    if (passphrase.empty()) {
        std::cerr << "Error: Passphrase cannot be empty.\n";
        return 1;
    }

    // Try to decrypt to verify passphrase is correct
    const uint8_t* salt = encrypted_key.data();
    const uint8_t* nonce = salt + PASSPHRASE_SALT_SIZE;
    const uint8_t* ciphertext = nonce + NONCE_SIZE;
    size_t ciphertext_len = SECRET_KEY_SIZE + AUTH_TAG_SIZE;

    std::array<uint8_t, SESSION_KEY_SIZE> derived_key;
    if (crypto_pwhash(
            derived_key.data(), derived_key.size(),
            passphrase.c_str(), passphrase.length(),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        std::cerr << "Error: Failed to derive key from passphrase.\n";
        return 1;
    }

    std::array<uint8_t, SECRET_KEY_SIZE> sk;
    unsigned long long plaintext_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            sk.data(), &plaintext_len,
            nullptr,
            ciphertext, ciphertext_len,
            nullptr, 0,
            nonce,
            derived_key.data()) != 0) {
        secure_zero(derived_key.data(), derived_key.size());
        std::cerr << "Error: Invalid passphrase.\n";
        return 1;
    }

    secure_zero(derived_key.data(), derived_key.size());

    // Extract public key for display (Ed25519 sk is seed||pk)
    std::array<uint8_t, PUBLIC_KEY_SIZE> pk;
    std::copy(sk.begin() + (SECRET_KEY_SIZE - PUBLIC_KEY_SIZE), sk.end(), pk.begin());
    secure_zero(sk.data(), sk.size());

    std::cout << "\n[OK] Passphrase verified successfully!\n";
    std::cout << "Fingerprint: " << LSLSecurity::compute_fingerprint(pk) << "\n\n";

    // Determine output path
    std::string path = get_config_path(output_path);

    // Check if config already has keys
    if (!force) {
        std::ifstream check(path);
        if (check.good()) {
            std::string check_line;
            while (std::getline(check, check_line)) {
                if (check_line.find("private_key") != std::string::npos ||
                    check_line.find("encrypted_private_key") != std::string::npos) {
                    std::cerr << "Error: Keys already exist in " << path << ". Use --force to overwrite.\n";
                    return 1;
                }
            }
        }
    }

    // Get timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream timestamp;
    timestamp << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");

    // Create directory if needed
    size_t last_slash = path.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        std::string dir = path.substr(0, last_slash);
#ifdef _WIN32
        _mkdir(dir.c_str());
#else
        mkdir(dir.c_str(), 0700);
#endif
        // Ignore return; failure will be caught by the subsequent ofstream open
    }

    // Read existing config
    std::string existing_content;
    {
        std::ifstream existing(path);
        if (existing.good()) {
            std::stringstream buffer;
            buffer << existing.rdbuf();
            existing_content = buffer.str();
        }
    }

    // Remove existing [security] section
    size_t sec_start = existing_content.find("[security]");
    if (sec_start != std::string::npos) {
        size_t sec_end = existing_content.find('[', sec_start + 1);
        if (sec_end == std::string::npos) sec_end = existing_content.length();
        existing_content.erase(sec_start, sec_end - sec_start);
    }

    // Write config
    std::ofstream outfile(path);
    if (!outfile.good()) {
        std::cerr << "Error: Could not write to " << path << "\n";
        return 1;
    }

    outfile << existing_content;
    if (!existing_content.empty() && existing_content.back() != '\n') {
        outfile << "\n";
    }

    outfile << "[security]\n";
    outfile << "enabled = true\n";
    outfile << "encrypted_private_key = " << encrypted_key_b64 << "\n";
    outfile << "key_created = " << timestamp.str() << "\n";
    outfile << "session_key_lifetime = 3600\n";
    outfile << "\n";

    std::cout << "[OK] Key imported to: " << path << "\n";
    std::cout << "[OK] Security is now enabled for this device.\n\n";
    std::cout << "To unlock at runtime (in order of preference):\n";
    std::cout << "  1. Device-bound session token: lsl-config --remember-device (recommended)\n";
    std::cout << "  2. Environment variable: LSL_KEY_PASSPHRASE (less secure)\n";
    std::cout << "  3. Programmatic: call lsl_security_unlock() in your application\n";

    return 0;
}

// Standard key generation - passphrase protected by default
int cmd_generate(const std::string& output_path, bool force, bool insecure_mode, bool show_public) {
    std::cout << "LSL Security Key Generator\n";
    std::cout << "==========================\n\n";

    auto& sec = LSLSecurity::instance();
    SecurityResult init_result = sec.initialize();
    if (init_result != SecurityResult::SUCCESS) {
        std::cerr << "Error: Failed to initialize security subsystem: "
                  << security_result_string(init_result) << "\n";
        return 1;
    }

    std::string path = get_config_path(output_path);

    std::string passphrase;
    bool use_passphrase = false;

    if (insecure_mode) {
        // Explicit --insecure flag: skip passphrase with warning
        std::cout << "WARNING: --insecure flag used.\n";
        std::cout << "         Private key will be stored WITHOUT encryption.\n";
        std::cout << "         This is NOT recommended for production environments.\n";
        std::cout << "         For regulatory compliance (EU CRA, NIS2, HIPAA, GDPR),\n";
        std::cout << "         use passphrase-protected keys instead.\n\n";
        use_passphrase = false;
    } else {
        // Default: prompt for passphrase (like SSH)
        std::cout << "Private key will be encrypted with a passphrase for security.\n";
        std::cout << "(Press Enter for no passphrase, but this is NOT recommended)\n\n";

        passphrase = read_passphrase("Enter passphrase: ");

        if (passphrase.empty()) {
            // Empty passphrase: warn and confirm
            std::cout << "\nWARNING: No passphrase provided.\n";
            std::cout << "         Private key will be stored WITHOUT encryption.\n";
            std::cout << "         This is a security risk: anyone with file access can read your key.\n";
            std::cout << "         Consider using a passphrase for compliance with EU CRA/NIS2/HIPAA/GDPR.\n\n";

            std::string confirm;
            std::cout << "Continue without passphrase? [y/N]: ";
            std::getline(std::cin, confirm);

            if (confirm.empty() || (confirm[0] != 'y' && confirm[0] != 'Y')) {
                std::cout << "Aborted. Run again to set a passphrase.\n";
                return 1;
            }
            std::cout << "\n";
            use_passphrase = false;
        } else {
            // Non-empty passphrase: confirm it
            std::string confirm = read_passphrase("Confirm passphrase: ");
            if (passphrase != confirm) {
                std::cerr << "Error: Passphrases do not match.\n";
                return 1;
            }

            if (passphrase.length() < 8) {
                std::cout << "Warning: Passphrase is short. Consider using at least 8 characters.\n";
            }

            std::cout << "\n";
            use_passphrase = true;
        }
    }

    std::cout << "Generating Ed25519 keypair...\n";

    SecurityResult gen_result = sec.generate_and_save_keypair(path, force, use_passphrase ? passphrase : "");

    if (gen_result != SecurityResult::SUCCESS) {
        if (gen_result == SecurityResult::CONFIG_PARSE_ERROR && !force) {
            std::cerr << "\nError: Keys already exist. Use --force to overwrite.\n";
        } else {
            std::cerr << "Error: " << security_result_string(gen_result) << "\n";
        }
        return 1;
    }

    std::cout << "\n[OK] Keypair generated successfully!\n";
    std::cout << "[OK] Configuration saved to: " << path << "\n";

    if (use_passphrase) {
        std::cout << "[OK] Private key encrypted with passphrase (2FA enabled)\n";
        std::cout << "\nTo unlock at runtime (in order of preference):\n";
        std::cout << "  1. Device-bound session token: lsl-config --remember-device (recommended)\n";
        std::cout << "  2. Environment variable: LSL_KEY_PASSPHRASE (less secure)\n";
        std::cout << "  3. Programmatic: call lsl_security_unlock() in your application\n";
    } else {
        std::cout << "[!!] Private key stored WITHOUT encryption\n";
        std::cout << "     For better security, regenerate with a passphrase:\n";
        std::cout << "       lsl-keygen --force\n";
    }

    if (show_public) {
        if (use_passphrase) {
            sec.load_credentials();
            if (sec.is_locked()) {
                SecurityResult unlock_result = sec.unlock(passphrase);
                if (unlock_result != SecurityResult::SUCCESS) {
                    std::cerr << "Warning: Could not unlock key to display public key\n";
                }
            }
        } else {
            sec.load_credentials();
        }

        if (sec.is_enabled()) {
            const auto& pk = sec.get_public_key();
            std::cout << "\nPublic Key (base64):\n  " << base64_encode(pk.data(), pk.size()) << "\n";
            std::cout << "\nFingerprint:\n  " << LSLSecurity::compute_fingerprint(pk) << "\n";
        }
    }

    std::cout << "\nSecurity is now enabled for this device.\n";
    std::cout << "Note: All devices on your network need the same key for secure communication.\n";

    return 0;
}

int main(int argc, char* argv[]) {
    std::string output_path;
    std::string export_name;
    std::string import_file;
    bool force = false;
    bool show_public = false;
    bool insecure_mode = false;
    bool do_export_public = false;
    bool export_existing = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0) {
            force = true;
        } else if (strcmp(argv[i], "--show-public") == 0 || strcmp(argv[i], "-s") == 0) {
            show_public = true;
        } else if (strcmp(argv[i], "--insecure") == 0) {
            insecure_mode = true;
        } else if (strcmp(argv[i], "--export-public") == 0) {
            do_export_public = true;
        } else if (strcmp(argv[i], "--output") == 0 || strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --output requires a PATH argument.\n";
                return 1;
            }
            output_path = argv[++i];
        } else if (strcmp(argv[i], "--export") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --export requires a NAME argument.\n";
                std::cerr << "Usage: " << argv[0] << " --export NAME\n";
                return 1;
            }
            export_name = argv[++i];
        } else if (strcmp(argv[i], "--export-existing") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --export-existing requires a NAME argument.\n";
                std::cerr << "Usage: " << argv[0] << " --export-existing NAME\n";
                return 1;
            }
            export_name = argv[++i];
            export_existing = true;
        } else if (strcmp(argv[i], "--import") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --import requires a FILE argument.\n";
                std::cerr << "Usage: " << argv[0] << " --import FILE\n";
                return 1;
            }
            import_file = argv[++i];
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Dispatch to appropriate command
    if (do_export_public) {
        return cmd_export_public();
    } else if (!export_name.empty() && export_existing) {
        return cmd_export_existing(export_name, output_path, force);
    } else if (!export_name.empty()) {
        return cmd_export(export_name, force);
    } else if (!import_file.empty()) {
        return cmd_import(import_file, output_path, force);
    } else {
        return cmd_generate(output_path, force, insecure_mode, show_public);
    }
}

#else // LSL_SECURITY_ENABLED not defined

int main() {
    std::cerr << "Error: LSL was compiled without security support.\n"
              << "Rebuild with -DLSL_SECURITY=ON to enable security features.\n";
    return 1;
}

#endif // LSL_SECURITY_ENABLED
