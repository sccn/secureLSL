// Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

/**
 * @file lsl_security.h
 * @brief LSL Security Layer - Ed25519 authentication and ChaCha20-Poly1305 encryption
 *
 * This header provides the public API for the LSL security layer, which implements
 * transparent encryption and authentication for Lab Streaming Layer communications.
 *
 * Security Model:
 * - Ed25519 for device identity and signatures
 * - X25519 + HKDF for session key derivation
 * - ChaCha20-Poly1305 for authenticated encryption
 * - Unified security: all-secure or all-insecure network
 *
 * @copyright 2025-2026 The Regents of the University of California
 */

#ifndef LSL_SECURITY_H
#define LSL_SECURITY_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <array>

// API visibility macros (same pattern as lsl/common.h)
#ifdef _WIN32
#ifdef LIBLSL_EXPORTS
#define LSL_SECURITY_API __declspec(dllexport)
#else
#define LSL_SECURITY_API __declspec(dllimport)
#endif
#elif __GNUC__ >= 4 || defined(__clang__)
#define LSL_SECURITY_API __attribute__((visibility("default")))
#else
#define LSL_SECURITY_API
#endif

#ifdef LSL_SECURITY_ENABLED

namespace lsl {
namespace security {

/// Size of Ed25519 public key in bytes
constexpr size_t PUBLIC_KEY_SIZE = 32;

/// Size of Ed25519 secret key in bytes
constexpr size_t SECRET_KEY_SIZE = 64;

/// Size of Ed25519 signature in bytes
constexpr size_t SIGNATURE_SIZE = 64;

/// Size of X25519 shared secret in bytes
constexpr size_t SHARED_SECRET_SIZE = 32;

/// Size of session key in bytes (ChaCha20-Poly1305)
constexpr size_t SESSION_KEY_SIZE = 32;

/// Size of nonce in bytes (ChaCha20-Poly1305 IETF)
constexpr size_t NONCE_SIZE = 12;

/// Size of authentication tag in bytes
constexpr size_t AUTH_TAG_SIZE = 16;

/// Size of salt for passphrase-based key derivation (Argon2id)
constexpr size_t PASSPHRASE_SALT_SIZE = 16;

/// Size of encrypted private key (salt + nonce + ciphertext + tag)
constexpr size_t ENCRYPTED_KEY_SIZE = PASSPHRASE_SALT_SIZE + NONCE_SIZE + SECRET_KEY_SIZE + AUTH_TAG_SIZE;

/// Size of device ID hash (SHA256)
constexpr size_t DEVICE_ID_SIZE = 32;

/// Maximum passphrase length for session token storage
constexpr size_t MAX_PASSPHRASE_LEN = 256;

/// Size of session token (device_id + salt + nonce + encrypted_passphrase + tag + expiry)
constexpr size_t SESSION_TOKEN_SIZE = DEVICE_ID_SIZE + PASSPHRASE_SALT_SIZE + NONCE_SIZE + MAX_PASSPHRASE_LEN + AUTH_TAG_SIZE + 8;

/// Result codes for security operations
enum class SecurityResult {
    SUCCESS = 0,
    NOT_INITIALIZED,
    INITIALIZATION_FAILED,
    INVALID_KEY,
    INVALID_SIGNATURE,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    AUTHENTICATION_FAILED,
    REPLAY_DETECTED,
    CONFIG_NOT_FOUND,
    CONFIG_PARSE_ERROR,
    KEY_GENERATION_FAILED,
    SECURITY_MISMATCH,
    KEY_LOCKED,              ///< Private key is encrypted and requires passphrase
    INVALID_PASSPHRASE,      ///< Passphrase verification failed
    PASSPHRASE_REQUIRED,     ///< Operation requires unlocking first
    TOKEN_NOT_FOUND,         ///< Session token file does not exist
    TOKEN_INVALID,           ///< Session token is corrupted or expired
    DEVICE_MISMATCH          ///< Token was created on a different device
};

/// Convert security result to human-readable string
LSL_SECURITY_API const char* security_result_string(SecurityResult result);

/**
 * @brief Main security class for LSL encryption/authentication
 *
 * This class provides all cryptographic operations needed for secure LSL
 * communication. It uses the singleton pattern and is initialized automatically
 * when security is enabled in the configuration.
 */
class LSL_SECURITY_API LSLSecurity {
public:
    /// Get the singleton instance
    static LSLSecurity& instance();

    /**
     * @brief Initialize the security subsystem
     * @return SUCCESS if libsodium initialized correctly
     *
     * This is called automatically during library initialization.
     * Subsequent calls are safe and return immediately.
     */
    SecurityResult initialize();

    /**
     * @brief Check if security is enabled in configuration
     * @return true if security is enabled and credentials are loaded
     */
    bool is_enabled() const;

    /**
     * @brief Check if security subsystem is initialized
     * @return true if libsodium is initialized
     */
    bool is_initialized() const;

    // === Key Management ===

    /**
     * @brief Generate a new Ed25519 keypair
     * @param[out] public_key 32-byte public key
     * @param[out] secret_key 64-byte secret key
     * @return SUCCESS if key generation succeeded
     */
    SecurityResult generate_keypair(
        std::array<uint8_t, PUBLIC_KEY_SIZE>& public_key,
        std::array<uint8_t, SECRET_KEY_SIZE>& secret_key);

    /**
     * @brief Generate keypair and save to configuration file
     * @param config_path Path to configuration file (empty = default location)
     * @param force Overwrite existing keys if true
     * @param passphrase Optional passphrase to encrypt the private key (empty = no encryption)
     * @return SUCCESS if keys generated and saved
     *
     * If a passphrase is provided, the private key will be encrypted using
     * Argon2id key derivation and ChaCha20-Poly1305 encryption. The key must
     * be unlocked using unlock() before it can be used.
     */
    SecurityResult generate_and_save_keypair(
        const std::string& config_path = "",
        bool force = false,
        const std::string& passphrase = "");

    /**
     * @brief Load credentials from configuration
     * @return SUCCESS if credentials loaded, KEY_LOCKED if key is encrypted
     *
     * If the private key is encrypted with a passphrase, this will return
     * KEY_LOCKED. Call unlock() with the passphrase to decrypt the key.
     */
    SecurityResult load_credentials();

    /**
     * @brief Check if private key is encrypted and locked
     * @return true if key is encrypted and requires unlock()
     */
    bool is_locked() const;

    /**
     * @brief Check if the configuration uses an encrypted (passphrase-protected) key
     * @return true if the key is/was passphrase-protected (even if currently unlocked)
     */
    bool has_encrypted_key() const;

    /**
     * @brief Unlock a passphrase-protected private key
     * @param passphrase The passphrase to decrypt the key
     * @return SUCCESS if key was unlocked, INVALID_PASSPHRASE if wrong passphrase
     *
     * This decrypts the private key using the provided passphrase.
     * After successful unlock, is_locked() returns false and is_enabled() returns true.
     */
    SecurityResult unlock(const std::string& passphrase);

    // === Device-Bound Session Tokens ===

    /**
     * @brief Create a device-bound session token for auto-unlock
     * @param passphrase The passphrase to remember
     * @param expiry_days Number of days until token expires (0 = never)
     * @return SUCCESS if token was created and saved
     *
     * Creates a session token that allows auto-unlock on this device only.
     * The token is bound to this device's hardware identifiers (hostname, MAC, machine-id).
     * Copying the token to another device will not work.
     *
     * Security model:
     * - Token = Encrypt(passphrase_hash, key=DeviceID)
     * - DeviceID = SHA256(hostname || MAC || machine-id)
     * - Token is useless on different hardware
     */
    SecurityResult remember_device(const std::string& passphrase, uint32_t expiry_days = 0);

    /**
     * @brief Remove the device session token
     * @return SUCCESS if token was removed or didn't exist
     *
     * After calling this, the passphrase will be required on next startup.
     */
    SecurityResult forget_device();

    /**
     * @brief Check if a device session token exists
     * @return true if a session token file exists (may be expired or invalid)
     */
    bool has_device_token() const;

    /**
     * @brief Try to auto-unlock using device session token
     * @return SUCCESS if unlocked, TOKEN_NOT_FOUND/TOKEN_INVALID/DEVICE_MISMATCH otherwise
     *
     * This is called automatically during load_credentials() if a token exists.
     * It can also be called manually to retry auto-unlock.
     */
    SecurityResult try_auto_unlock();

    /**
     * @brief Get the default session token file path
     * @return Path to ~/.lsl_api/session_token or equivalent
     */
    static std::string get_default_token_path();

    /**
     * @brief Compute this device's unique identifier
     * @param[out] device_id 32-byte SHA256 hash of device identifiers
     * @return SUCCESS if device ID was computed
     *
     * DeviceID = SHA256(hostname || primary_MAC || machine-id)
     */
    static SecurityResult compute_device_id(std::array<uint8_t, DEVICE_ID_SIZE>& device_id);

    /**
     * @brief Get this device's unique identifier as hex string
     * @return Hex-encoded device ID or empty string on error
     */
    static std::string get_device_id_string();

    /**
     * @brief Get token expiry timestamp
     * @return Unix timestamp when token expires, 0 if never expires, -1 if no token
     */
    int64_t get_token_expiry() const;

    /**
     * @brief Check if token is expired
     * @return true if token exists but is expired
     */
    bool is_token_expired() const;

    /**
     * @brief Get this device's public key
     * @return 32-byte public key or empty if not loaded
     */
    const std::array<uint8_t, PUBLIC_KEY_SIZE>& get_public_key() const;

    /**
     * @brief Compute BLAKE2b fingerprint of a public key
     * @param public_key The public key to fingerprint
     * @return Hex-encoded fingerprint string (BLAKE2b:xxxx...)
     */
    static std::string compute_fingerprint(
        const std::array<uint8_t, PUBLIC_KEY_SIZE>& public_key);

    // === Session Key Derivation ===

    /**
     * @brief Derive a session key from peer's public key
     * @param peer_public_key Peer's Ed25519 public key
     * @param[out] session_key Derived 32-byte session key
     * @param is_initiator true if we initiated the connection
     * @return SUCCESS if key derived
     *
     * Uses X25519 key agreement with HKDF to derive a symmetric session key.
     * The is_initiator flag ensures both parties derive the same key.
     */
    SecurityResult derive_session_key(
        const std::array<uint8_t, PUBLIC_KEY_SIZE>& peer_public_key,
        std::array<uint8_t, SESSION_KEY_SIZE>& session_key,
        bool is_initiator);

    // === Encryption/Decryption ===

    /**
     * @brief Encrypt data in place using ChaCha20-Poly1305
     * @param[in,out] data Data buffer (must have AUTH_TAG_SIZE extra bytes)
     * @param data_len Length of plaintext
     * @param nonce Unique 64-bit nonce (will be expanded to 12 bytes)
     * @param session_key 32-byte session key
     * @param[out] ciphertext_len Length of ciphertext (data_len + AUTH_TAG_SIZE)
     * @return SUCCESS if encryption succeeded
     *
     * The output ciphertext is data_len + AUTH_TAG_SIZE bytes.
     * The nonce MUST be unique for each encryption with the same key.
     */
    SecurityResult encrypt(
        uint8_t* data,
        size_t data_len,
        uint64_t nonce,
        const std::array<uint8_t, SESSION_KEY_SIZE>& session_key,
        size_t& ciphertext_len);

    /**
     * @brief Decrypt data in place using ChaCha20-Poly1305
     * @param[in,out] data Ciphertext buffer
     * @param ciphertext_len Length of ciphertext (including auth tag)
     * @param nonce Nonce used during encryption
     * @param session_key 32-byte session key
     * @param[out] plaintext_len Length of decrypted plaintext
     * @return SUCCESS if decryption and authentication succeeded
     */
    SecurityResult decrypt(
        uint8_t* data,
        size_t ciphertext_len,
        uint64_t nonce,
        const std::array<uint8_t, SESSION_KEY_SIZE>& session_key,
        size_t& plaintext_len);

    // === Signatures ===

    /**
     * @brief Sign a message using this device's secret key
     * @param message Message to sign
     * @param message_len Length of message
     * @param[out] signature 64-byte signature
     * @return SUCCESS if signing succeeded
     */
    SecurityResult sign(
        const uint8_t* message,
        size_t message_len,
        std::array<uint8_t, SIGNATURE_SIZE>& signature);

    /**
     * @brief Verify a signature
     * @param message Signed message
     * @param message_len Length of message
     * @param signature 64-byte signature to verify
     * @param public_key Signer's public key
     * @return SUCCESS if signature is valid
     */
    SecurityResult verify(
        const uint8_t* message,
        size_t message_len,
        const std::array<uint8_t, SIGNATURE_SIZE>& signature,
        const std::array<uint8_t, PUBLIC_KEY_SIZE>& public_key);

    // === Configuration ===

    /**
     * @brief Get the default configuration file path
     * @return Path to ~/.lsl_api/lsl_api.cfg or equivalent
     */
    static std::string get_default_config_path();

    /**
     * @brief Get key creation timestamp
     * @return ISO 8601 timestamp string or empty if not set
     */
    const std::string& get_key_created() const;

    /**
     * @brief Get session key lifetime in seconds
     * @return Lifetime in seconds (default 3600)
     */
    uint32_t get_session_key_lifetime() const;

    // Prevent copying
    LSLSecurity(const LSLSecurity&) = delete;
    LSLSecurity& operator=(const LSLSecurity&) = delete;

private:
    LSLSecurity();
    ~LSLSecurity();

    bool initialized_;
    bool enabled_;
    bool credentials_loaded_;
    bool key_locked_;  ///< True if key is encrypted and not yet unlocked
    bool has_encrypted_key_;  ///< True if config uses encrypted key (persists after unlock)

    std::array<uint8_t, PUBLIC_KEY_SIZE> public_key_;
    std::array<uint8_t, SECRET_KEY_SIZE> secret_key_;

    // X25519 keys derived from Ed25519 keys
    std::array<uint8_t, 32> x25519_public_key_;
    std::array<uint8_t, 32> x25519_secret_key_;

    // Encrypted key data (when passphrase-protected)
    std::vector<uint8_t> encrypted_key_data_;

    std::string key_created_;
    uint32_t session_key_lifetime_;

    // Session token data
    int64_t token_expiry_;  ///< Unix timestamp when token expires, 0 = never, -1 = no token
    std::array<uint8_t, DEVICE_ID_SIZE> cached_device_id_;
    bool device_id_cached_;

    // Internal helper to convert Ed25519 keys to X25519
    SecurityResult convert_ed25519_to_x25519();

    // Internal helper to encrypt private key with passphrase
    SecurityResult encrypt_private_key(
        const std::array<uint8_t, SECRET_KEY_SIZE>& secret_key,
        const std::string& passphrase,
        std::vector<uint8_t>& encrypted_key);

    // Internal helper to decrypt private key with passphrase
    SecurityResult decrypt_private_key(
        const std::vector<uint8_t>& encrypted_key,
        const std::string& passphrase,
        std::array<uint8_t, SECRET_KEY_SIZE>& secret_key);
};

// === Utility Functions ===

/**
 * @brief Encode binary data to base64
 * @param data Binary data
 * @param len Length of data
 * @return Base64-encoded string
 */
LSL_SECURITY_API std::string base64_encode(const uint8_t* data, size_t len);

/**
 * @brief Decode base64 string to binary
 * @param encoded Base64-encoded string
 * @param[out] decoded Output buffer
 * @return true if decoding succeeded
 */
LSL_SECURITY_API bool base64_decode(const std::string& encoded, std::vector<uint8_t>& decoded);

/**
 * @brief Securely zero memory
 * @param data Pointer to memory
 * @param len Length of memory to zero
 *
 * This function ensures memory is zeroed even with compiler optimizations.
 */
LSL_SECURITY_API void secure_zero(void* data, size_t len);

} // namespace security
} // namespace lsl

#endif // LSL_SECURITY_ENABLED

#endif // LSL_SECURITY_H
