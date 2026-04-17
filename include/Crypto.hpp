#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <openssl/evp.h>

// Distinct type so callers can tell GCM tag failure apart from framing/key errors,
// which continue to throw std::runtime_error.
class TamperDetectedException : public std::runtime_error
{
public:
    explicit TamperDetectedException(const std::string &what) : std::runtime_error(what) {}
};

class Crypto
{
private:
    EVP_CIPHER_CTX *m_encryptCtx;
    EVP_CIPHER_CTX *m_decryptCtx;

public:
    Crypto();
    ~Crypto();

    static constexpr size_t KEY_SIZE = 32;     // 256 bits
    static constexpr size_t GCM_IV_SIZE = 12;  // 96 bits (recommended for GCM)
    static constexpr size_t GCM_TAG_SIZE = 16; // 128 bits

    std::vector<uint8_t> encrypt(std::vector<uint8_t> &&plaintext,
                                 const std::vector<uint8_t> &key,
                                 const std::vector<uint8_t> &iv);

    // Throws TamperDetectedException on GCM tag failure; std::runtime_error otherwise.
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &encryptedData,
                                 const std::vector<uint8_t> &key,
                                 const std::vector<uint8_t> &iv);
};

#endif