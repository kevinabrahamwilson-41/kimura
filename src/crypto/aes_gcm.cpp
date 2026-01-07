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
#include <iostream>

class AesGcmError {
public:
    enum class Code {
        RandFailed, KeyDeriveFailed, ContextFailed, EncryptFailed, DecryptFailed, InvalidInput, HashFailed
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
    int iterations = 100000) {
    
    if (salt.size() < 16) {
        return std::unexpected{AesGcmError{AesGcmError::Code::InvalidInput}};
    }
    
    std::vector<std::uint8_t> key(32); // AES-256
    if (PKCS5_PBKDF2_HMAC(password.data(), password.size(),
                         salt.data(), salt.size(),
                         iterations, EVP_sha256(),
                         key.size(), key.data()) != 1) {
        return std::unexpected{AesGcmError{AesGcmError::Code::KeyDeriveFailed}};
    }
    return key;
}

// ==================== RANDOM GENERATION ====================
std::expected<std::vector<std::uint8_t>, AesGcmError> generate_key() {
    std::vector<std::uint8_t> key(32);
    if (RAND_bytes(key.data(), key.size()) != 1) {
        return std::unexpected{AesGcmError{AesGcmError::Code::RandFailed}};
    }
    return key;
}

std::expected<std::vector<std::uint8_t>, AesGcmError> generate_nonce() {
    std::vector<std::uint8_t> nonce(12);
    if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
        return std::unexpected{AesGcmError{AesGcmError::Code::RandFailed}};
    }
    return nonce;
}

std::expected<std::vector<std::uint8_t>, AesGcmError> generate_salt() {
    std::vector<std::uint8_t> salt(16);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        return std::unexpected{AesGcmError{AesGcmError::Code::RandFailed}};
    }
    return salt;
}

// ==================== CORE ENCRYPTION ====================
std::expected<std::vector<std::uint8_t>, AesGcmError> aes256_gcm_encrypt(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> plaintext,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad = std::span<const std::uint8_t>()) {
    
    if (key.size() != 32 || nonce.size() != 12 || plaintext.empty()) {
        return std::unexpected{AesGcmError{AesGcmError::Code::InvalidInput}};
    }
    
    CipherCtx ctx;
    if (!ctx) return std::unexpected{AesGcmError{AesGcmError::Code::ContextFailed}};
    
    std::vector<std::uint8_t> ciphertext(plaintext.size());
    std::vector<std::uint8_t> tag(16);
    int len = 0, final_len = 0;
    
    // Initialize + AAD (if provided)
    if ((EVP_EncryptInit_ex(ctx.ctx, EVP_aes_256_gcm(), nullptr, 
                           key.data(), nonce.data()) != 1) ||
        (!aad.empty() && (EVP_EncryptUpdate(ctx.ctx, nullptr, &len, aad.data(), aad.size()) != 1))) {
        return std::unexpected{AesGcmError{AesGcmError::Code::EncryptFailed}};
    }
    
    if (EVP_EncryptUpdate(ctx.ctx, ciphertext.data(), &len, 
                         plaintext.data(), plaintext.size()) != 1 ||
        EVP_EncryptFinal_ex(ctx.ctx, ciphertext.data() + len, &final_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        return std::unexpected{AesGcmError{AesGcmError::Code::EncryptFailed}};
    }
    
    ciphertext.resize(len + final_len);
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return ciphertext;
}

// ==================== CORE DECRYPTION ====================
std::expected<std::vector<std::uint8_t>, AesGcmError> aes256_gcm_decrypt(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> ciphertext_tag,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad = std::span<const std::uint8_t>()) {
    
    if (key.size() != 32 || nonce.size() != 12 || ciphertext_tag.size() < 16) {
        return std::unexpected{AesGcmError{AesGcmError::Code::InvalidInput}};
    }
    
    std::span<const std::uint8_t> ciphertext{ciphertext_tag.data(), ciphertext_tag.size() - 16};
    std::span<const std::uint8_t> tag = ciphertext_tag.subspan(ciphertext_tag.size() - 16);
    
    CipherCtx ctx;
    if (!ctx) return std::unexpected{AesGcmError{AesGcmError::Code::ContextFailed}};
    
    std::vector<std::uint8_t> plaintext(ciphertext.size());
    int len = 0, final_len = 0;
    
    if (EVP_DecryptInit_ex(ctx.ctx, EVP_aes_256_gcm(), nullptr,
                          key.data(), nonce.data()) != 1 ||
        (!aad.empty() && EVP_DecryptUpdate(ctx.ctx, nullptr, &len, aad.data(), aad.size()) != 1) ||
        EVP_DecryptUpdate(ctx.ctx, plaintext.data(), &len,
                         ciphertext.data(), ciphertext.size()) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_GCM_SET_TAG, 16, 
                           const_cast<std::uint8_t*>(tag.data())) != 1 ||
        EVP_DecryptFinal_ex(ctx.ctx, plaintext.data() + len, &final_len) != 1) {
        return std::unexpected{AesGcmError{AesGcmError::Code::DecryptFailed}};
    }
    
    plaintext.resize(len + final_len);
    return plaintext;
}

// ==================== HEX UTILITIES ====================
std::string to_hex(const std::vector<std::uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto byte : data) {
        ss << std::setw(2) << static_cast<unsigned>(byte);
    }
    return ss.str();
}

std::expected<std::vector<std::uint8_t>, AesGcmError> from_hex(std::string_view hex) {
    std::vector<std::uint8_t> data((hex.size() + 1) / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string_view byte_str = hex.substr(i, 2);  // FIXED: string_view instead of string
        try {
            data[i / 2] = static_cast<std::uint8_t>(std::stoi(std::string(byte_str), nullptr, 16));
        } catch (...) {
            return std::unexpected{AesGcmError{AesGcmError::Code::InvalidInput}};
        }
    }
    return data;
}

int main() {
    // Generate all crypto materials
    auto salt_res = generate_salt();
    if (!salt_res) return 1;
    
    std::string password = "my_secure_password123";
    auto key_res = derive_key_pbkdf2(password, salt_res.value());
    if (!key_res) return 1;
    
    auto nonce_res = generate_nonce();
    if (!nonce_res) return 1;
    
    std::string message = "Top secret production data";
    std::vector<std::uint8_t> plaintext(message.begin(), message.end());
    
    // ENCRYPT - stores in memory
    std::vector<std::uint8_t> ciphertext_tag;
    auto ct_res = aes256_gcm_encrypt(key_res.value(), plaintext, nonce_res.value());
    if (!ct_res) return 1;
    ciphertext_tag = std::move(ct_res.value());  // Zero-copy move
    
    // DECRYPT - stores in memory  
    std::vector<std::uint8_t> decrypted_plaintext;
    auto pt_res = aes256_gcm_decrypt(key_res.value(), ciphertext_tag, nonce_res.value());
    if (!pt_res) return 1;
    decrypted_plaintext = std::move(pt_res.value());  // Zero-copy move
    
    // In production: use these vectors directly
    // - ciphertext_tag: encrypted data + 16-byte auth tag (ready to write to file/network)
    // - key_res.value(): 32-byte AES-256 key (keep secret!)
    // - nonce_res.value(): 12-byte nonce/IV (safe to transmit)
    // - salt_res.value(): 16-byte salt (safe to transmit)
    
    return 0;  // Silent success
}

/* To compile and run (requires OpenSSL development libraries):
g++ -std=c++23 -Wall -Wextra -O2 ./src/crypto/aes_gcm.cpp $(pkg-config --libs openssl) -o aes_gcm && ./aes_gcm
*/
