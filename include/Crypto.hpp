#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <openssl/evp.h>

// Distinct from std::runtime_error so callers can react to tag failure specifically.
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

    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t GCM_IV_SIZE = 12;
    static constexpr size_t GCM_TAG_SIZE = 16;

    std::vector<uint8_t> encrypt(std::vector<uint8_t> &&plaintext,
                                 const std::vector<uint8_t> &key);
    void encrypt(const uint8_t *plaintext, size_t plaintextLen,
                 const std::vector<uint8_t> &key,
                 std::vector<uint8_t> &out);

    // Throws TamperDetectedException on tag failure; std::runtime_error on everything else.
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &encryptedData,
                                 const std::vector<uint8_t> &key);
};

#endif