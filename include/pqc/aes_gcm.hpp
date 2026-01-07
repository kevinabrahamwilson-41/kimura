// aes_gcm.hpp - Production-grade AES-256-GCM header-only library
#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <vector>
#include <span>
#include <expected>
#include <string>
#include <memory>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>

class AesGcmError {
public:
    enum class Code {
        RandFailed, KeyDeriveFailed, ContextFailed, EncryptFailed, 
        DecryptFailed, InvalidInput, HashFailed
    };
    explicit AesGcmError(Code code) : code_(code) {}
    Code code() const { return code_; }
private:
    Code code_;
};

struct CipherCtx {
    EVP_CIPHER_CTX* ctx;
    CipherCtx() : ctx(EVP_CIPHER_CTX_new()) {}
    ~CipherCtx() { if (ctx) EVP_CIPHER_CTX_free(ctx); }
    CipherCtx(const CipherCtx&) = delete;
    CipherCtx& operator=(const CipherCtx&) = delete;
    explicit operator bool() const { return ctx != nullptr; }
};

// ==================== KEY DERIVATION ====================
std::expected<std::vector<std::uint8_t>, AesGcmError> derive_key_pbkdf2(
    std::string_view password, 
    std::span<const std::uint8_t> salt,
    int iterations = 100000);

std::expected<std::vector<std::uint8_t>, AesGcmError> derive_key_hkdf(
    std::span<const std::uint8_t> secret,
    std::span<const std::uint8_t> salt,
    std::string_view info = "");

// ==================== RANDOM GENERATION ====================
std::expected<std::vector<std::uint8_t>, AesGcmError> generate_key();     // 32-byte AES-256
std::expected<std::vector<std::uint8_t>, AesGcmError> generate_nonce();   // 12-byte GCM IV
std::expected<std::vector<std::uint8_t>, AesGcmError> generate_salt();    // 16-byte PBKDF2 salt

// ==================== CORE ENCRYPTION ====================
std::expected<std::vector<std::uint8_t>, AesGcmError> aes256_gcm_encrypt(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> plaintext,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad = std::span<const std::uint8_t>());

std::expected<std::vector<std::uint8_t>, AesGcmError> aes256_gcm_decrypt(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> ciphertext_tag,  // ciphertext + 16-byte tag
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad = std::span<const std::uint8_t>());

// ==================== HKDF + AES-GCM COMBO ====================
std::expected<std::vector<std::uint8_t>, AesGcmError> hkdf_aes256_gcm_encrypt(
    std::span<const std::uint8_t> secret,           // ML-KEM shared_secret (32 bytes)
    std::span<const std::uint8_t> plaintext,
    std::span<const std::uint8_t> aad = {});        // Returns: nonce(12) + ciphertext + tag(16)

std::expected<std::vector<std::uint8_t>, AesGcmError> hkdf_aes256_gcm_decrypt(
    std::span<const std::uint8_t> secret,           // ML-KEM shared_secret (32 bytes)  
    std::span<const std::uint8_t> encrypted_data);  // nonce(12) + ciphertext + tag(16)

// ==================== HEX UTILITIES ====================
std::string to_hex(const std::vector<std::uint8_t>& data);
std::expected<std::vector<std::uint8_t>, AesGcmError> from_hex(std::string_view hex);

// ==================== CONSTANTS ====================
inline constexpr size_t AES256_KEY_SIZE = 32;
inline constexpr size_t GCM_NONCE_SIZE = 12;
inline constexpr size_t GCM_TAG_SIZE = 16;
inline constexpr size_t PBKDF2_SALT_SIZE = 16;
inline constexpr size_t HKDF_SALT_SIZE = 32;
