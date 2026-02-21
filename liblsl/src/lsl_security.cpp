// Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/**
 * @file lsl_security.cpp
 * @brief Implementation of LSL Security Layer using libsodium
 */

#ifdef LSL_SECURITY_ENABLED

#include "lsl_security.h"  // Internal header
#include "api_config.h"
#include "util/inireader.hpp"
#include <sodium.h>
#include <loguru.hpp>
#include <fstream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <cstdlib>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#include <direct.h>
#include <sys/types.h>
#include <sys/stat.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#ifdef __APPLE__
#include <net/if_dl.h>
#include <IOKit/IOKitLib.h>
#else  // Linux
#include <linux/if_packet.h>
#endif
#endif

namespace lsl {
namespace security {

// Platform wrapper for mkdir (avoids repeated #ifdef blocks)
static int make_dir(const char* p) {
#ifdef _WIN32
    return _mkdir(p);
#else
    return mkdir(p, 0700);
#endif
}

// Check if path exists and is a directory
static bool is_directory(const char* p) {
#ifdef _WIN32
    struct _stat st;
    return _stat(p, &st) == 0 && (st.st_mode & _S_IFDIR);
#else
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

// Recursively create directory and all parent components with mode 0700 (owner-only).
// Replaces system("mkdir -p") to avoid shell injection.
static bool create_directories(const std::string& path) {
    if (path.empty()) return false;
    if (make_dir(path.c_str()) == 0) return true;
    if (errno == EEXIST) return is_directory(path.c_str());
    if (errno != ENOENT) return false;
    // Parent doesn't exist; find it and create recursively
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return false;
    if (!create_directories(path.substr(0, pos))) return false;
    return make_dir(path.c_str()) == 0 || (errno == EEXIST && is_directory(path.c_str()));
}

// === Utility Functions ===

const char* security_result_string(SecurityResult result) {
    switch (result) {
        case SecurityResult::SUCCESS: return "Success";
        case SecurityResult::NOT_INITIALIZED: return "Security not initialized";
        case SecurityResult::INITIALIZATION_FAILED: return "Security initialization failed";
        case SecurityResult::INVALID_KEY: return "Invalid key";
        case SecurityResult::INVALID_SIGNATURE: return "Invalid signature";
        case SecurityResult::ENCRYPTION_FAILED: return "Encryption failed";
        case SecurityResult::DECRYPTION_FAILED: return "Decryption failed";
        case SecurityResult::AUTHENTICATION_FAILED: return "Authentication failed";
        case SecurityResult::REPLAY_DETECTED: return "Replay attack detected";
        case SecurityResult::CONFIG_NOT_FOUND: return "Configuration file not found";
        case SecurityResult::CONFIG_PARSE_ERROR: return "Configuration parse error";
        case SecurityResult::KEY_GENERATION_FAILED: return "Key generation failed";
        case SecurityResult::SECURITY_MISMATCH: return "Security configuration mismatch";
        case SecurityResult::KEY_LOCKED: return "Private key is encrypted and requires passphrase";
        case SecurityResult::INVALID_PASSPHRASE: return "Invalid passphrase";
        case SecurityResult::PASSPHRASE_REQUIRED: return "Operation requires unlocking the key first";
        case SecurityResult::TOKEN_NOT_FOUND: return "Session token file not found";
        case SecurityResult::TOKEN_INVALID: return "Session token is corrupted or expired";
        case SecurityResult::DEVICE_MISMATCH: return "Token was created on a different device";
        default: return "Unknown error";
    }
}

std::string base64_encode(const uint8_t* data, size_t len) {
    if (len == 0 || data == nullptr) return "";

    // Calculate output size (with null terminator)
    size_t encoded_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string result(encoded_len - 1, '\0');

    sodium_bin2base64(&result[0], encoded_len, data, len, sodium_base64_VARIANT_ORIGINAL);
    return result;
}

bool base64_decode(const std::string& encoded, std::vector<uint8_t>& decoded) {
    if (encoded.empty()) return false;

    // Allocate maximum possible size
    decoded.resize(encoded.size());
    size_t decoded_len = 0;

    int ret = sodium_base642bin(
        decoded.data(), decoded.size(),
        encoded.c_str(), encoded.size(),
        nullptr, &decoded_len, nullptr,
        sodium_base64_VARIANT_ORIGINAL
    );

    if (ret != 0) {
        decoded.clear();
        return false;
    }

    decoded.resize(decoded_len);
    return true;
}

void secure_zero(void* data, size_t len) {
    sodium_memzero(data, len);
}

// === NonceTracker Implementation ===

bool NonceTracker::check_and_update(uint64_t nonce) {
    // Nonce must be greater than 0 (0 is reserved)
    if (nonce == 0) return false;

    // If this is the first nonce, accept it
    if (last_nonce_ == 0) {
        last_nonce_ = nonce;
        window_base_ = nonce;
        window_bitmap_ = 1;
        return true;
    }

    // If nonce is ahead of window, slide the window forward
    if (nonce > last_nonce_) {
        uint64_t shift = nonce - last_nonce_;
        if (shift >= WINDOW_SIZE) {
            // New nonce is way ahead, reset window
            window_bitmap_ = 1;
            window_base_ = nonce;
        } else {
            // Shift the window
            window_bitmap_ <<= shift;
            window_bitmap_ |= 1;
        }
        last_nonce_ = nonce;
        return true;
    }

    // Nonce is within or before the window
    uint64_t diff = last_nonce_ - nonce;
    if (diff >= WINDOW_SIZE) {
        // Too old, reject
        LOG_F(WARNING, "Replay detected: nonce %llu is too old (last: %llu)",
              (unsigned long long)nonce, (unsigned long long)last_nonce_);
        return false;
    }

    // Check if already seen
    uint64_t mask = 1ULL << diff;
    if (window_bitmap_ & mask) {
        LOG_F(WARNING, "Replay detected: nonce %llu already used",
              (unsigned long long)nonce);
        return false;
    }

    // Mark as seen
    window_bitmap_ |= mask;
    return true;
}

void NonceTracker::reset() {
    last_nonce_ = 0;
    window_base_ = 0;
    window_bitmap_ = 0;
}

// === LSLSecurity Implementation ===

LSLSecurity& LSLSecurity::instance() {
    static LSLSecurity instance;
    return instance;
}

LSLSecurity::LSLSecurity()
    : initialized_(false)
    , enabled_(false)
    , credentials_loaded_(false)
    , key_locked_(false)
    , has_encrypted_key_(false)
    , session_key_lifetime_(3600)
    , token_expiry_(-1)
    , device_id_cached_(false) {
    public_key_.fill(0);
    secret_key_.fill(0);
    x25519_public_key_.fill(0);
    x25519_secret_key_.fill(0);
    cached_device_id_.fill(0);
}

LSLSecurity::~LSLSecurity() {
    // Securely zero all sensitive data
    secure_zero(secret_key_.data(), secret_key_.size());
    secure_zero(x25519_secret_key_.data(), x25519_secret_key_.size());
}

SecurityResult LSLSecurity::initialize() {
    static std::once_flag init_flag;
    SecurityResult result = SecurityResult::SUCCESS;

    std::call_once(init_flag, [this, &result]() {
        if (sodium_init() < 0) {
            LOG_F(ERROR, "Failed to initialize libsodium");
            result = SecurityResult::INITIALIZATION_FAILED;
            return;
        }

        initialized_ = true;
        LOG_F(INFO, "LSL Security: libsodium initialized successfully");

        // Try to load credentials from config
        SecurityResult load_result = load_credentials();
        if (load_result == SecurityResult::SUCCESS) {
            enabled_ = true;
            LOG_F(INFO, "LSL Security: credentials loaded, security enabled");
        } else {
            LOG_F(INFO, "LSL Security: no credentials found, security disabled");
        }
    });

    return result;
}

bool LSLSecurity::is_enabled() const {
    return initialized_ && enabled_ && credentials_loaded_;
}

bool LSLSecurity::is_initialized() const {
    return initialized_;
}

SecurityResult LSLSecurity::generate_keypair(
    std::array<uint8_t, PUBLIC_KEY_SIZE>& public_key,
    std::array<uint8_t, SECRET_KEY_SIZE>& secret_key) {

    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    if (crypto_sign_keypair(public_key.data(), secret_key.data()) != 0) {
        LOG_F(ERROR, "Failed to generate Ed25519 keypair");
        return SecurityResult::KEY_GENERATION_FAILED;
    }

    return SecurityResult::SUCCESS;
}

std::string LSLSecurity::get_default_config_path() {
    std::string homedir;

    // NOLINTBEGIN(concurrency-mt-unsafe)
    if (auto* home = getenv("HOME"))
        homedir = home;
    else if (auto* home = getenv("USERPROFILE"))
        homedir = home;
    else if (getenv("HOMEDRIVE") && getenv("HOMEPATH"))
        homedir = std::string(getenv("HOMEDRIVE")) + getenv("HOMEPATH");
    else
        homedir = ".";
    // NOLINTEND(concurrency-mt-unsafe)

    return homedir + "/.lsl_api/lsl_api.cfg";
}

SecurityResult LSLSecurity::generate_and_save_keypair(
    const std::string& config_path, bool force, const std::string& passphrase) {

    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    std::string path = config_path.empty() ? get_default_config_path() : config_path;

    // Check if file exists and has keys
    if (!force) {
        std::ifstream check(path);
        if (check.good()) {
            std::string line;
            while (std::getline(check, line)) {
                if (line.find("private_key") != std::string::npos ||
                    line.find("encrypted_private_key") != std::string::npos) {
                    LOG_F(WARNING, "Keys already exist in %s. Use --force to overwrite.", path.c_str());
                    return SecurityResult::CONFIG_PARSE_ERROR;
                }
            }
        }
    }

    // Generate new keypair
    std::array<uint8_t, PUBLIC_KEY_SIZE> pk;
    std::array<uint8_t, SECRET_KEY_SIZE> sk;
    SecurityResult result = generate_keypair(pk, sk);
    if (result != SecurityResult::SUCCESS) {
        return result;
    }

    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream timestamp;
    timestamp << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");

    // Create directory if needed
    size_t last_slash = path.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        std::string dir = path.substr(0, last_slash);
        if (!create_directories(dir)) {
            LOG_F(ERROR, "Failed to create directory %s: %s", dir.c_str(), strerror(errno));
            secure_zero(sk.data(), sk.size());
            return SecurityResult::CONFIG_PARSE_ERROR;
        }
    }

    // Read existing config or create new
    std::string existing_content;
    {
        std::ifstream existing(path);
        if (existing.good()) {
            std::stringstream buffer;
            buffer << existing.rdbuf();
            existing_content = buffer.str();
        }
    }

    // Remove existing [security] section if present
    size_t sec_start = existing_content.find("[security]");
    if (sec_start != std::string::npos) {
        size_t sec_end = existing_content.find('[', sec_start + 1);
        if (sec_end == std::string::npos) sec_end = existing_content.length();
        existing_content.erase(sec_start, sec_end - sec_start);
    }

    // Append new security section
    std::ofstream outfile(path);
    if (!outfile.good()) {
        LOG_F(ERROR, "Failed to open config file for writing: %s", path.c_str());
        secure_zero(sk.data(), sk.size());
        return SecurityResult::CONFIG_PARSE_ERROR;
    }

    outfile << existing_content;
    if (!existing_content.empty() && existing_content.back() != '\n') {
        outfile << "\n";
    }

    outfile << "[security]\n";
    outfile << "enabled = true\n";

    // If passphrase provided, encrypt the private key
    if (!passphrase.empty()) {
        std::vector<uint8_t> encrypted_key;
        result = encrypt_private_key(sk, passphrase, encrypted_key);
        if (result != SecurityResult::SUCCESS) {
            secure_zero(sk.data(), sk.size());
            return result;
        }
        outfile << "encrypted_private_key = " << base64_encode(encrypted_key.data(), encrypted_key.size()) << "\n";
        secure_zero(encrypted_key.data(), encrypted_key.size());
        LOG_F(INFO, "Private key encrypted with passphrase protection (two-factor authentication enabled)");
    } else {
        outfile << "private_key = " << base64_encode(sk.data(), sk.size()) << "\n";
    }

    outfile << "key_created = " << timestamp.str() << "\n";
    outfile << "session_key_lifetime = 3600\n";
    outfile << "\n";

    outfile.close();
    if (outfile.fail()) {
        LOG_F(ERROR, "Failed to write config file %s: I/O error on close", path.c_str());
        secure_zero(sk.data(), sk.size());
        return SecurityResult::CONFIG_PARSE_ERROR;
    }

    // Set restrictive permissions (owner read/write only) since file contains private key
#ifndef _WIN32
    if (chmod(path.c_str(), 0600) != 0) {
        LOG_F(ERROR, "Failed to set permissions on %s: %s. "
              "Private key file may be readable by other users!",
              path.c_str(), strerror(errno));
        secure_zero(sk.data(), sk.size());
        return SecurityResult::CONFIG_PARSE_ERROR;
    }
#endif

    // Zero out the secret key from stack
    secure_zero(sk.data(), sk.size());

    LOG_F(INFO, "Generated new keypair, saved to %s", path.c_str());
    LOG_F(INFO, "Public key fingerprint: %s", compute_fingerprint(pk).c_str());

    return SecurityResult::SUCCESS;
}

SecurityResult LSLSecurity::load_credentials() {
    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    // Search for config files in order
    std::vector<std::string> config_paths;

    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    if (auto* cfgpath = getenv("LSLAPICFG")) {
        config_paths.emplace_back(cfgpath);
    }
    config_paths.emplace_back("lsl_api.cfg");
    config_paths.push_back(get_default_config_path());
    config_paths.emplace_back("/etc/lsl_api/lsl_api.cfg");

    for (const auto& path : config_paths) {
        std::ifstream infile(path);
        if (!infile.good()) continue;

        INI config;
        try {
            config.load(infile);
        } catch (...) {
            continue;
        }

        std::string enabled_str = config.get("security.enabled", "false");
        if (enabled_str != "true" && enabled_str != "1") {
            continue;
        }

        // Load optional fields first
        key_created_ = config.get("security.key_created", "");
        session_key_lifetime_ = config.get("security.session_key_lifetime", 3600);

        // Check for encrypted private key first (passphrase-protected)
        std::string encrypted_key_b64 = config.get("security.encrypted_private_key", "");
        if (!encrypted_key_b64.empty()) {
            // Decode encrypted key
            if (!base64_decode(encrypted_key_b64, encrypted_key_data_) ||
                encrypted_key_data_.size() != ENCRYPTED_KEY_SIZE) {
                LOG_F(ERROR, "Invalid encrypted_private_key format in %s", path.c_str());
                encrypted_key_data_.clear();
                continue;
            }

            credentials_loaded_ = true;
            key_locked_ = true;
            has_encrypted_key_ = true;  // Remember this is a passphrase-protected key
            enabled_ = false;  // Not enabled until unlocked

            LOG_F(INFO, "Found passphrase-protected key in %s", path.c_str());

            // Check for LSL_KEY_PASSPHRASE environment variable for auto-unlock
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            if (auto* passphrase_env = getenv("LSL_KEY_PASSPHRASE")) {
                LOG_F(INFO, "Attempting auto-unlock using LSL_KEY_PASSPHRASE environment variable");
                SecurityResult unlock_result = unlock(passphrase_env);
                if (unlock_result == SecurityResult::SUCCESS) {
                    LOG_F(INFO, "Auto-unlock successful via environment variable");
                    // Security warning: environment variables are visible to other processes
                    LOG_F(WARNING, "SECURITY: Passphrase loaded from LSL_KEY_PASSPHRASE environment variable.");
                    LOG_F(WARNING, "          Environment variables are visible to other processes on this system.");
                    LOG_F(WARNING, "          For better security, use device-bound session tokens instead:");
                    LOG_F(WARNING, "            lsl-config --remember-device --passphrase");
                    return SecurityResult::SUCCESS;
                } else {
                    LOG_F(WARNING, "Auto-unlock via env var failed: %s", security_result_string(unlock_result));
                }
            }

            // Try device-bound session token for auto-unlock
            SecurityResult token_result = try_auto_unlock();
            if (token_result == SecurityResult::SUCCESS) {
                return SecurityResult::SUCCESS;
            } else if (token_result != SecurityResult::TOKEN_NOT_FOUND) {
                // Log non-trivial failures (not just "no token exists")
                LOG_F(INFO, "Session token auto-unlock: %s", security_result_string(token_result));
            }

            return SecurityResult::KEY_LOCKED;
        }

        // Check for plaintext private key (no passphrase)
        std::string private_key_b64 = config.get("security.private_key", "");
        if (private_key_b64.empty()) {
            LOG_F(WARNING, "Security enabled but no private_key in %s", path.c_str());
            continue;
        }

        // Decode private key
        std::vector<uint8_t> sk_vec;
        if (!base64_decode(private_key_b64, sk_vec) || sk_vec.size() != SECRET_KEY_SIZE) {
            LOG_F(ERROR, "Invalid private_key format in %s", path.c_str());
            continue;
        }

        // Copy to internal storage
        std::copy(sk_vec.begin(), sk_vec.end(), secret_key_.begin());
        secure_zero(sk_vec.data(), sk_vec.size());

        // Extract public key from secret key (Ed25519 secret key contains public key)
        std::copy(secret_key_.begin() + 32, secret_key_.end(), public_key_.begin());

        // Convert Ed25519 keys to X25519 for key exchange
        SecurityResult convert_result = convert_ed25519_to_x25519();
        if (convert_result != SecurityResult::SUCCESS) {
            LOG_F(ERROR, "Failed to convert keys for key exchange");
            return convert_result;
        }

        credentials_loaded_ = true;
        key_locked_ = false;
        enabled_ = true;

        LOG_F(INFO, "Loaded security credentials from %s", path.c_str());
        LOG_F(INFO, "Public key fingerprint: %s", compute_fingerprint(public_key_).c_str());

        return SecurityResult::SUCCESS;
    }

    return SecurityResult::CONFIG_NOT_FOUND;
}

SecurityResult LSLSecurity::convert_ed25519_to_x25519() {
    // Convert Ed25519 public key to X25519
    if (crypto_sign_ed25519_pk_to_curve25519(
            x25519_public_key_.data(), public_key_.data()) != 0) {
        return SecurityResult::INVALID_KEY;
    }

    // Convert Ed25519 secret key to X25519
    if (crypto_sign_ed25519_sk_to_curve25519(
            x25519_secret_key_.data(), secret_key_.data()) != 0) {
        return SecurityResult::INVALID_KEY;
    }

    return SecurityResult::SUCCESS;
}

// === Passphrase Protection ===

SecurityResult LSLSecurity::encrypt_private_key(
    const std::array<uint8_t, SECRET_KEY_SIZE>& secret_key,
    const std::string& passphrase,
    std::vector<uint8_t>& encrypted_key) {

    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    if (passphrase.empty()) {
        return SecurityResult::INVALID_PASSPHRASE;
    }

    // Allocate output: salt + nonce + ciphertext + tag
    encrypted_key.resize(ENCRYPTED_KEY_SIZE);
    uint8_t* salt = encrypted_key.data();
    uint8_t* nonce = salt + PASSPHRASE_SALT_SIZE;
    uint8_t* ciphertext = nonce + NONCE_SIZE;

    // Generate random salt and nonce
    randombytes_buf(salt, PASSPHRASE_SALT_SIZE);
    randombytes_buf(nonce, NONCE_SIZE);

    // Derive encryption key from passphrase using Argon2id
    std::array<uint8_t, SESSION_KEY_SIZE> derived_key;
    if (crypto_pwhash(
            derived_key.data(), derived_key.size(),
            passphrase.c_str(), passphrase.length(),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        LOG_F(ERROR, "Failed to derive key from passphrase (out of memory?)");
        return SecurityResult::ENCRYPTION_FAILED;
    }

    // Encrypt the secret key using ChaCha20-Poly1305
    unsigned long long ciphertext_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext, &ciphertext_len,
            secret_key.data(), secret_key.size(),
            nullptr, 0,  // no additional data
            nullptr,     // unused secret nonce
            nonce,
            derived_key.data()) != 0) {
        secure_zero(derived_key.data(), derived_key.size());
        return SecurityResult::ENCRYPTION_FAILED;
    }

    secure_zero(derived_key.data(), derived_key.size());
    LOG_F(INFO, "Private key encrypted with passphrase");
    return SecurityResult::SUCCESS;
}

SecurityResult LSLSecurity::decrypt_private_key(
    const std::vector<uint8_t>& encrypted_key,
    const std::string& passphrase,
    std::array<uint8_t, SECRET_KEY_SIZE>& secret_key) {

    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    if (encrypted_key.size() != ENCRYPTED_KEY_SIZE) {
        LOG_F(ERROR, "Invalid encrypted key size: %zu (expected %zu)",
              encrypted_key.size(), ENCRYPTED_KEY_SIZE);
        return SecurityResult::INVALID_KEY;
    }

    if (passphrase.empty()) {
        return SecurityResult::INVALID_PASSPHRASE;
    }

    const uint8_t* salt = encrypted_key.data();
    const uint8_t* nonce = salt + PASSPHRASE_SALT_SIZE;
    const uint8_t* ciphertext = nonce + NONCE_SIZE;
    size_t ciphertext_len = SECRET_KEY_SIZE + AUTH_TAG_SIZE;

    // Derive decryption key from passphrase using Argon2id
    std::array<uint8_t, SESSION_KEY_SIZE> derived_key;
    if (crypto_pwhash(
            derived_key.data(), derived_key.size(),
            passphrase.c_str(), passphrase.length(),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        LOG_F(ERROR, "Failed to derive key from passphrase");
        return SecurityResult::DECRYPTION_FAILED;
    }

    // Decrypt the secret key
    unsigned long long plaintext_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            secret_key.data(), &plaintext_len,
            nullptr,  // unused secret nonce
            ciphertext, ciphertext_len,
            nullptr, 0,  // no additional data
            nonce,
            derived_key.data()) != 0) {
        secure_zero(derived_key.data(), derived_key.size());
        LOG_F(WARNING, "Failed to decrypt private key: invalid passphrase");
        return SecurityResult::INVALID_PASSPHRASE;
    }

    secure_zero(derived_key.data(), derived_key.size());
    return SecurityResult::SUCCESS;
}

bool LSLSecurity::is_locked() const {
    return key_locked_;
}

bool LSLSecurity::has_encrypted_key() const {
    return has_encrypted_key_;
}

SecurityResult LSLSecurity::unlock(const std::string& passphrase) {
    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    if (!key_locked_) {
        // Already unlocked or not encrypted
        return SecurityResult::SUCCESS;
    }

    if (encrypted_key_data_.empty()) {
        LOG_F(ERROR, "No encrypted key data available");
        return SecurityResult::INVALID_KEY;
    }

    // Decrypt the private key
    SecurityResult result = decrypt_private_key(encrypted_key_data_, passphrase, secret_key_);
    if (result != SecurityResult::SUCCESS) {
        return result;
    }

    // Extract public key from secret key (Ed25519 secret key contains public key)
    std::copy(secret_key_.begin() + 32, secret_key_.end(), public_key_.begin());

    // Convert to X25519 for key exchange
    result = convert_ed25519_to_x25519();
    if (result != SecurityResult::SUCCESS) {
        secure_zero(secret_key_.data(), secret_key_.size());
        return result;
    }

    // Clear encrypted key data and update state
    secure_zero(encrypted_key_data_.data(), encrypted_key_data_.size());
    encrypted_key_data_.clear();

    key_locked_ = false;
    enabled_ = true;

    LOG_F(INFO, "Private key unlocked successfully");
    LOG_F(INFO, "Public key fingerprint: %s", compute_fingerprint(public_key_).c_str());

    return SecurityResult::SUCCESS;
}

const std::array<uint8_t, PUBLIC_KEY_SIZE>& LSLSecurity::get_public_key() const {
    return public_key_;
}

std::string LSLSecurity::compute_fingerprint(
    const std::array<uint8_t, PUBLIC_KEY_SIZE>& public_key) {

    uint8_t hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof(hash), public_key.data(), public_key.size(), nullptr, 0);

    std::stringstream ss;
    ss << "BLAKE2b:";
    for (size_t i = 0; i < 8; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    }
    ss << "...";

    return ss.str();
}

const std::string& LSLSecurity::get_key_created() const {
    return key_created_;
}

uint32_t LSLSecurity::get_session_key_lifetime() const {
    return session_key_lifetime_;
}

SecurityResult LSLSecurity::derive_session_key(
    const std::array<uint8_t, PUBLIC_KEY_SIZE>& peer_public_key,
    std::array<uint8_t, SESSION_KEY_SIZE>& session_key,
    bool is_initiator) {

    if (!initialized_ || !credentials_loaded_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    // Convert peer's Ed25519 public key to X25519
    std::array<uint8_t, 32> peer_x25519;
    if (crypto_sign_ed25519_pk_to_curve25519(peer_x25519.data(), peer_public_key.data()) != 0) {
        return SecurityResult::INVALID_KEY;
    }

    // X25519 key agreement
    std::array<uint8_t, crypto_scalarmult_BYTES> shared_secret;
    if (crypto_scalarmult(shared_secret.data(), x25519_secret_key_.data(), peer_x25519.data()) != 0) {
        return SecurityResult::INVALID_KEY;
    }

    // Derive session key from shared secret and both public keys
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, SESSION_KEY_SIZE);
    crypto_generichash_update(&state, shared_secret.data(), shared_secret.size());
    crypto_generichash_update(&state, (const uint8_t*)HKDF_CONTEXT, sizeof(HKDF_CONTEXT) - 1);

    // Order public keys consistently (smaller first) so both parties derive same key
    if (memcmp(public_key_.data(), peer_public_key.data(), PUBLIC_KEY_SIZE) < 0) {
        crypto_generichash_update(&state, public_key_.data(), PUBLIC_KEY_SIZE);
        crypto_generichash_update(&state, peer_public_key.data(), PUBLIC_KEY_SIZE);
    } else {
        crypto_generichash_update(&state, peer_public_key.data(), PUBLIC_KEY_SIZE);
        crypto_generichash_update(&state, public_key_.data(), PUBLIC_KEY_SIZE);
    }

    crypto_generichash_final(&state, session_key.data(), SESSION_KEY_SIZE);

    // Zero shared secret
    secure_zero(shared_secret.data(), shared_secret.size());
    secure_zero(peer_x25519.data(), peer_x25519.size());

    return SecurityResult::SUCCESS;
}

SecurityResult LSLSecurity::encrypt(
    uint8_t* data,
    size_t data_len,
    uint64_t nonce,
    const std::array<uint8_t, SESSION_KEY_SIZE>& session_key,
    size_t& ciphertext_len) {

    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    // Expand 64-bit nonce to 96-bit (12 bytes) as required by ChaCha20-Poly1305 IETF
    std::array<uint8_t, NONCE_SIZE> nonce_bytes = {0};
    memcpy(nonce_bytes.data(), &nonce, sizeof(nonce));

    unsigned long long actual_ciphertext_len = 0;

    int ret = crypto_aead_chacha20poly1305_ietf_encrypt(
        data,                      // output ciphertext (in place)
        &actual_ciphertext_len,
        data,                      // input plaintext
        data_len,
        nullptr, 0,                // no additional authenticated data
        nullptr,                   // unused (secret nonce)
        nonce_bytes.data(),
        session_key.data()
    );

    if (ret != 0) {
        LOG_F(ERROR, "Encryption failed");
        return SecurityResult::ENCRYPTION_FAILED;
    }

    ciphertext_len = static_cast<size_t>(actual_ciphertext_len);
    return SecurityResult::SUCCESS;
}

SecurityResult LSLSecurity::decrypt(
    uint8_t* data,
    size_t ciphertext_len,
    uint64_t nonce,
    const std::array<uint8_t, SESSION_KEY_SIZE>& session_key,
    size_t& plaintext_len) {

    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    if (ciphertext_len < AUTH_TAG_SIZE) {
        return SecurityResult::DECRYPTION_FAILED;
    }

    // Expand nonce
    std::array<uint8_t, NONCE_SIZE> nonce_bytes = {0};
    memcpy(nonce_bytes.data(), &nonce, sizeof(nonce));

    unsigned long long actual_plaintext_len = 0;

    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
        data,                      // output plaintext (in place)
        &actual_plaintext_len,
        nullptr,                   // unused (secret nonce)
        data,                      // input ciphertext
        ciphertext_len,
        nullptr, 0,                // no additional authenticated data
        nonce_bytes.data(),
        session_key.data()
    );

    if (ret != 0) {
        LOG_F(WARNING, "Decryption failed: authentication error");
        return SecurityResult::AUTHENTICATION_FAILED;
    }

    plaintext_len = static_cast<size_t>(actual_plaintext_len);
    return SecurityResult::SUCCESS;
}

SecurityResult LSLSecurity::sign(
    const uint8_t* message,
    size_t message_len,
    std::array<uint8_t, SIGNATURE_SIZE>& signature) {

    if (!initialized_ || !credentials_loaded_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    if (crypto_sign_detached(
            signature.data(), nullptr,
            message, message_len,
            secret_key_.data()) != 0) {
        return SecurityResult::ENCRYPTION_FAILED;
    }

    return SecurityResult::SUCCESS;
}

SecurityResult LSLSecurity::verify(
    const uint8_t* message,
    size_t message_len,
    const std::array<uint8_t, SIGNATURE_SIZE>& signature,
    const std::array<uint8_t, PUBLIC_KEY_SIZE>& public_key) {

    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    if (crypto_sign_verify_detached(
            signature.data(),
            message, message_len,
            public_key.data()) != 0) {
        return SecurityResult::INVALID_SIGNATURE;
    }

    return SecurityResult::SUCCESS;
}

// === Device-Bound Session Token Implementation ===

std::string LSLSecurity::get_default_token_path() {
    std::string homedir;

    // NOLINTBEGIN(concurrency-mt-unsafe)
    if (auto* home = getenv("HOME"))
        homedir = home;
    else if (auto* home = getenv("USERPROFILE"))
        homedir = home;
    // NOLINTEND(concurrency-mt-unsafe)

    if (homedir.empty()) {
        homedir = ".";
    }

#ifdef _WIN32
    return homedir + "\\.lsl_api\\session_token";
#else
    return homedir + "/.lsl_api/session_token";
#endif
}

// Platform-specific helper to get primary MAC address
static std::string get_primary_mac() {
#ifdef _WIN32
    // Windows implementation
    IP_ADAPTER_INFO adapters[16];
    DWORD buflen = sizeof(adapters);

    if (GetAdaptersInfo(adapters, &buflen) == ERROR_SUCCESS) {
        // Find first non-loopback adapter
        for (PIP_ADAPTER_INFO adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->AddressLength == 6) {
                char mac[18];
                snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                    adapter->Address[0], adapter->Address[1],
                    adapter->Address[2], adapter->Address[3],
                    adapter->Address[4], adapter->Address[5]);
                return mac;
            }
        }
    }
    return "";

#elif defined(__APPLE__)
    // macOS implementation using getifaddrs
    struct ifaddrs* iflist = nullptr;
    if (getifaddrs(&iflist) != 0) return "";

    std::string result;
    for (struct ifaddrs* ifa = iflist; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;

        // Skip loopback
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        struct sockaddr_dl* sdl = (struct sockaddr_dl*)ifa->ifa_addr;
        if (sdl->sdl_alen == 6) {
            unsigned char* mac = (unsigned char*)LLADDR(sdl);
            char buf[18];
            snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            result = buf;
            break;  // Use first non-loopback interface
        }
    }

    freeifaddrs(iflist);
    return result;

#else  // Linux
    // Linux implementation using getifaddrs
    struct ifaddrs* iflist = nullptr;
    if (getifaddrs(&iflist) != 0) return "";

    std::string result;
    for (struct ifaddrs* ifa = iflist; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;

        // Skip loopback
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        struct sockaddr_ll* sll = (struct sockaddr_ll*)ifa->ifa_addr;
        if (sll->sll_halen == 6) {
            char buf[18];
            snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2],
                sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
            result = buf;
            break;
        }
    }

    freeifaddrs(iflist);
    return result;
#endif
}

// Platform-specific helper to get machine ID
static std::string get_machine_id() {
#ifdef _WIN32
    // Windows: use MachineGuid from registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD buflen = sizeof(buffer);
        if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr,
                (LPBYTE)buffer, &buflen) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::string(buffer);
        }
        RegCloseKey(hKey);
    }
    return "";

#elif defined(__APPLE__)
    // macOS: use IOKit to get hardware UUID
    io_service_t platformExpert = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));

    if (platformExpert) {
        CFStringRef uuid = (CFStringRef)IORegistryEntryCreateCFProperty(
            platformExpert, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);

        if (uuid) {
            char buffer[256];
            if (CFStringGetCString(uuid, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
                CFRelease(uuid);
                IOObjectRelease(platformExpert);
                return std::string(buffer);
            }
            CFRelease(uuid);
        }
        IOObjectRelease(platformExpert);
    }
    return "";

#else  // Linux
    // Linux: use /etc/machine-id or /var/lib/dbus/machine-id
    std::ifstream f("/etc/machine-id");
    if (!f.is_open()) {
        f.open("/var/lib/dbus/machine-id");
    }
    if (f.is_open()) {
        std::string id;
        std::getline(f, id);
        return id;
    }
    return "";
#endif
}

SecurityResult LSLSecurity::compute_device_id(std::array<uint8_t, DEVICE_ID_SIZE>& device_id) {
    // Get hostname
    char hostname[256] = {0};
#ifdef _WIN32
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
#else
    gethostname(hostname, sizeof(hostname) - 1);
#endif

    // Get MAC address
    std::string mac = get_primary_mac();

    // Get machine ID
    std::string machine_id = get_machine_id();

    // Concatenate: hostname || MAC || machine-id
    std::string combined = std::string(hostname) + "|" + mac + "|" + machine_id;

    // Hash with SHA256
    crypto_hash_sha256(device_id.data(),
        reinterpret_cast<const unsigned char*>(combined.c_str()),
        combined.length());

    LOG_F(INFO, "Device ID computed from: hostname=%s, MAC=%s, machine-id=%s",
        hostname, mac.c_str(), machine_id.empty() ? "(none)" : "(present)");

    return SecurityResult::SUCCESS;
}

std::string LSLSecurity::get_device_id_string() {
    std::array<uint8_t, DEVICE_ID_SIZE> device_id;
    if (compute_device_id(device_id) != SecurityResult::SUCCESS) {
        return "";
    }

    // Convert to hex string
    std::stringstream ss;
    for (size_t i = 0; i < device_id.size(); ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)device_id[i];
    }
    return ss.str();
}

bool LSLSecurity::has_device_token() const {
    std::ifstream f(get_default_token_path());
    return f.good();
}

int64_t LSLSecurity::get_token_expiry() const {
    return token_expiry_;
}

bool LSLSecurity::is_token_expired() const {
    if (token_expiry_ < 0) return false;  // No token
    if (token_expiry_ == 0) return false;  // Never expires

    auto now = std::chrono::system_clock::now();
    int64_t now_ts = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    return now_ts > token_expiry_;
}

SecurityResult LSLSecurity::remember_device(const std::string& passphrase, uint32_t expiry_days) {
    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    // Verify passphrase is correct by checking we can unlock
    if (key_locked_ || !encrypted_key_data_.empty()) {
        std::array<uint8_t, SECRET_KEY_SIZE> test_sk;
        SecurityResult dec_result = decrypt_private_key(encrypted_key_data_, passphrase, test_sk);
        if (dec_result != SecurityResult::SUCCESS) {
            return SecurityResult::INVALID_PASSPHRASE;
        }
        secure_zero(test_sk.data(), test_sk.size());
    }

    // Compute device ID
    std::array<uint8_t, DEVICE_ID_SIZE> device_id;
    compute_device_id(device_id);

    // We need to store the passphrase itself (encrypted), not a hash
    // because Argon2id needs the raw passphrase to derive the key
    // Pad passphrase to fixed size for consistent ciphertext length
    constexpr size_t MAX_PASSPHRASE_LEN = 256;
    std::vector<uint8_t> passphrase_padded(MAX_PASSPHRASE_LEN, 0);
    size_t passphrase_len = std::min(passphrase.length(), MAX_PASSPHRASE_LEN - 1);
    memcpy(passphrase_padded.data(), passphrase.c_str(), passphrase_len);
    // Store length in first byte (after shifting data)
    // Actually, use last byte for length
    passphrase_padded[MAX_PASSPHRASE_LEN - 1] = static_cast<uint8_t>(passphrase_len);

    // Generate salt and nonce
    std::array<uint8_t, PASSPHRASE_SALT_SIZE> salt;
    std::array<uint8_t, NONCE_SIZE> nonce;
    randombytes_buf(salt.data(), salt.size());
    randombytes_buf(nonce.data(), nonce.size());

    // Derive encryption key from device ID + salt
    std::array<uint8_t, SESSION_KEY_SIZE> derived_key;
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, SESSION_KEY_SIZE);
    crypto_generichash_update(&state, device_id.data(), device_id.size());
    crypto_generichash_update(&state, salt.data(), salt.size());
    crypto_generichash_final(&state, derived_key.data(), SESSION_KEY_SIZE);

    // Encrypt the padded passphrase
    std::vector<uint8_t> ciphertext(MAX_PASSPHRASE_LEN + AUTH_TAG_SIZE);
    unsigned long long ciphertext_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            passphrase_padded.data(), MAX_PASSPHRASE_LEN,
            nullptr, 0,
            nullptr,
            nonce.data(),
            derived_key.data()) != 0) {
        secure_zero(passphrase_padded.data(), passphrase_padded.size());
        secure_zero(derived_key.data(), derived_key.size());
        return SecurityResult::ENCRYPTION_FAILED;
    }

    secure_zero(passphrase_padded.data(), passphrase_padded.size());
    secure_zero(derived_key.data(), derived_key.size());

    // Calculate expiry timestamp
    int64_t expiry_ts = 0;
    if (expiry_days > 0) {
        auto now = std::chrono::system_clock::now();
        auto expiry = now + std::chrono::hours(24 * expiry_days);
        expiry_ts = std::chrono::duration_cast<std::chrono::seconds>(
            expiry.time_since_epoch()).count();
    }

    // Build token: device_id + salt + nonce + encrypted_hash + expiry
    std::vector<uint8_t> token;
    token.insert(token.end(), device_id.begin(), device_id.end());
    token.insert(token.end(), salt.begin(), salt.end());
    token.insert(token.end(), nonce.begin(), nonce.end());
    token.insert(token.end(), ciphertext.begin(), ciphertext.end());

    // Append expiry (8 bytes, little-endian)
    for (int i = 0; i < 8; ++i) {
        token.push_back(static_cast<uint8_t>((expiry_ts >> (i * 8)) & 0xFF));
    }

    // Write to file
    std::string token_path = get_default_token_path();

    // Create directory if needed
    size_t last_slash = token_path.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        std::string dir = token_path.substr(0, last_slash);
        if (!create_directories(dir)) {
            LOG_F(ERROR, "Failed to create directory %s: %s", dir.c_str(), strerror(errno));
            return SecurityResult::CONFIG_PARSE_ERROR;
        }
    }

    std::ofstream f(token_path, std::ios::binary);
    if (!f.good()) {
        LOG_F(ERROR, "Failed to create session token file: %s", token_path.c_str());
        return SecurityResult::CONFIG_PARSE_ERROR;
    }

    f.write(reinterpret_cast<const char*>(token.data()), token.size());
    f.close();

    // Set restrictive permissions (owner read/write only)
#ifndef _WIN32
    if (chmod(token_path.c_str(), 0600) != 0) {
        LOG_F(ERROR, "Failed to set permissions on token file %s: %s",
              token_path.c_str(), strerror(errno));
        return SecurityResult::CONFIG_PARSE_ERROR;
    }
#endif

    token_expiry_ = expiry_ts;
    LOG_F(INFO, "Session token created: %s (expires: %s)",
        token_path.c_str(), expiry_ts == 0 ? "never" : "in days");

    return SecurityResult::SUCCESS;
}

SecurityResult LSLSecurity::forget_device() {
    std::string token_path = get_default_token_path();

    if (std::remove(token_path.c_str()) == 0) {
        LOG_F(INFO, "Session token removed: %s", token_path.c_str());
    }

    token_expiry_ = -1;
    return SecurityResult::SUCCESS;
}

SecurityResult LSLSecurity::try_auto_unlock() {
    if (!initialized_) {
        return SecurityResult::NOT_INITIALIZED;
    }

    if (!key_locked_) {
        return SecurityResult::SUCCESS;  // Already unlocked
    }

    std::string token_path = get_default_token_path();
    std::ifstream f(token_path, std::ios::binary);
    if (!f.good()) {
        return SecurityResult::TOKEN_NOT_FOUND;
    }

    // Read token
    std::vector<uint8_t> token((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    f.close();

    // Expected size: device_id(32) + salt(16) + nonce(12) + encrypted_passphrase(256+16) + expiry(8)
    size_t expected_size = DEVICE_ID_SIZE + PASSPHRASE_SALT_SIZE + NONCE_SIZE + MAX_PASSPHRASE_LEN + AUTH_TAG_SIZE + 8;
    if (token.size() != expected_size) {
        LOG_F(WARNING, "Session token has invalid size: %zu (expected %zu)",
            token.size(), expected_size);
        return SecurityResult::TOKEN_INVALID;
    }

    // Parse token
    const uint8_t* stored_device_id = token.data();
    const uint8_t* salt = stored_device_id + DEVICE_ID_SIZE;
    const uint8_t* nonce = salt + PASSPHRASE_SALT_SIZE;
    const uint8_t* ciphertext = nonce + NONCE_SIZE;
    const uint8_t* expiry_bytes = ciphertext + MAX_PASSPHRASE_LEN + AUTH_TAG_SIZE;

    // Read expiry
    int64_t expiry_ts = 0;
    for (int i = 0; i < 8; ++i) {
        expiry_ts |= static_cast<int64_t>(expiry_bytes[i]) << (i * 8);
    }
    token_expiry_ = expiry_ts;

    // Check expiry
    if (expiry_ts > 0) {
        auto now = std::chrono::system_clock::now();
        int64_t now_ts = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        if (now_ts > expiry_ts) {
            LOG_F(WARNING, "Session token has expired");
            return SecurityResult::TOKEN_INVALID;
        }
    }

    // Compute current device ID
    std::array<uint8_t, DEVICE_ID_SIZE> current_device_id;
    compute_device_id(current_device_id);

    // Verify device ID matches
    if (memcmp(stored_device_id, current_device_id.data(), DEVICE_ID_SIZE) != 0) {
        LOG_F(WARNING, "Session token device ID mismatch - token was created on different device");
        return SecurityResult::DEVICE_MISMATCH;
    }

    // Derive decryption key from device ID + salt
    std::array<uint8_t, SESSION_KEY_SIZE> derived_key;
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, SESSION_KEY_SIZE);
    crypto_generichash_update(&state, current_device_id.data(), current_device_id.size());
    crypto_generichash_update(&state, salt, PASSPHRASE_SALT_SIZE);
    crypto_generichash_final(&state, derived_key.data(), SESSION_KEY_SIZE);

    // Decrypt padded passphrase
    std::vector<uint8_t> passphrase_padded(MAX_PASSPHRASE_LEN);
    unsigned long long plaintext_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            passphrase_padded.data(), &plaintext_len,
            nullptr,
            ciphertext, MAX_PASSPHRASE_LEN + AUTH_TAG_SIZE,
            nullptr, 0,
            nonce,
            derived_key.data()) != 0) {
        secure_zero(derived_key.data(), derived_key.size());
        LOG_F(WARNING, "Session token decryption failed");
        return SecurityResult::TOKEN_INVALID;
    }

    secure_zero(derived_key.data(), derived_key.size());

    // Extract passphrase length from last byte and recover passphrase
    size_t passphrase_len = passphrase_padded[MAX_PASSPHRASE_LEN - 1];
    if (passphrase_len >= MAX_PASSPHRASE_LEN) {
        secure_zero(passphrase_padded.data(), passphrase_padded.size());
        LOG_F(WARNING, "Session token has invalid passphrase length");
        return SecurityResult::TOKEN_INVALID;
    }

    std::string passphrase(reinterpret_cast<char*>(passphrase_padded.data()), passphrase_len);
    secure_zero(passphrase_padded.data(), passphrase_padded.size());

    // Now use the passphrase to unlock the key
    SecurityResult unlock_result = unlock(passphrase);
    secure_zero(&passphrase[0], passphrase.size());

    if (unlock_result == SecurityResult::SUCCESS) {
        LOG_F(INFO, "Auto-unlock successful using device session token");
    } else {
        LOG_F(WARNING, "Auto-unlock failed: %s", security_result_string(unlock_result));
    }

    return unlock_result;
}

} // namespace security
} // namespace lsl

#endif // LSL_SECURITY_ENABLED
