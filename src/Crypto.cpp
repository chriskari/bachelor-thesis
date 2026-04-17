#include "Crypto.hpp"
#include "ByteOrder.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>

Crypto::Crypto()
{
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    m_encryptCtx = EVP_CIPHER_CTX_new();
    if (!m_encryptCtx)
    {
        throw std::runtime_error("Failed to create encryption context");
    }

    m_decryptCtx = EVP_CIPHER_CTX_new();
    if (!m_decryptCtx)
    {
        EVP_CIPHER_CTX_free(m_encryptCtx);
        throw std::runtime_error("Failed to create decryption context");
    }
}

Crypto::~Crypto()
{
    if (m_encryptCtx)
    {
        EVP_CIPHER_CTX_free(m_encryptCtx);
    }
    if (m_decryptCtx)
    {
        EVP_CIPHER_CTX_free(m_decryptCtx);
    }
    EVP_cleanup();
}

// Wire format (little-endian): [u32 dataSize][ciphertext, dataSize bytes][tag, GCM_TAG_SIZE bytes]
std::vector<uint8_t> Crypto::encrypt(std::vector<uint8_t> &&plaintext,
                                     const std::vector<uint8_t> &key,
                                     const std::vector<uint8_t> &iv)
{
    if (plaintext.empty())
        return {};
    if (key.size() != KEY_SIZE)
        throw std::runtime_error("Invalid key size");
    if (iv.size() != GCM_IV_SIZE)
        throw std::runtime_error("Invalid IV size");

    EVP_CIPHER_CTX_reset(m_encryptCtx);

    if (EVP_EncryptInit_ex(m_encryptCtx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1)
    {
        throw std::runtime_error("Failed to initialize encryption");
    }

    const size_t sizeFieldSize = sizeof(uint32_t);
    const size_t ciphertextSize = plaintext.size();
    const size_t totalSize = sizeFieldSize + ciphertextSize + GCM_TAG_SIZE;

    std::vector<uint8_t> result(totalSize);

    byteorder::writeLE32(result.data(), static_cast<uint32_t>(ciphertextSize));

    int encryptedLen = 0;
    if (EVP_EncryptUpdate(m_encryptCtx, result.data() + sizeFieldSize, &encryptedLen,
                          plaintext.data(), plaintext.size()) != 1)
    {
        throw std::runtime_error("Failed during encryption update");
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(m_encryptCtx, result.data() + sizeFieldSize + encryptedLen, &finalLen) != 1)
    {
        throw std::runtime_error("Failed to finalize encryption");
    }

    // For GCM, encryptedLen + finalLen should equal plaintext.size()
    if (encryptedLen + finalLen != static_cast<int>(plaintext.size()))
    {
        throw std::runtime_error("Unexpected encryption output size");
    }

    if (EVP_CIPHER_CTX_ctrl(m_encryptCtx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE,
                            result.data() + sizeFieldSize + ciphertextSize) != 1)
    {
        throw std::runtime_error("Failed to get authentication tag");
    }

    return result;
}

std::vector<uint8_t> Crypto::decrypt(const std::vector<uint8_t> &encryptedData,
                                     const std::vector<uint8_t> &key,
                                     const std::vector<uint8_t> &iv)
{
    if (encryptedData.empty())
    {
        return std::vector<uint8_t>();
    }

    if (key.size() != KEY_SIZE)
    {
        throw std::runtime_error("Invalid key size. Expected 32 bytes for AES-256");
    }

    if (iv.size() != GCM_IV_SIZE)
    {
        throw std::runtime_error("Invalid IV size. Expected 12 bytes for GCM");
    }

    if (encryptedData.size() < sizeof(uint32_t))
    {
        throw std::runtime_error("Encrypted data too small - missing data size");
    }

    uint32_t dataSize = byteorder::readLE32(encryptedData.data());
    size_t position = sizeof(uint32_t);

    if (position + dataSize > encryptedData.size())
    {
        throw std::runtime_error("Encrypted data too small - missing complete data");
    }

    const uint8_t *ciphertextPtr = encryptedData.data() + position;
    position += dataSize;

    if (position + GCM_TAG_SIZE > encryptedData.size())
    {
        throw std::runtime_error("Encrypted data too small - missing authentication tag");
    }

    // OpenSSL takes a non-const pointer for the tag; we copy into a local buffer.
    std::vector<uint8_t> tag(GCM_TAG_SIZE);
    std::memcpy(tag.data(), encryptedData.data() + position, GCM_TAG_SIZE);

    EVP_CIPHER_CTX_reset(m_decryptCtx);

    if (EVP_DecryptInit_ex(m_decryptCtx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1)
    {
        throw std::runtime_error("Failed to initialize decryption");
    }

    if (EVP_CIPHER_CTX_ctrl(m_decryptCtx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag.data()) != 1)
    {
        throw std::runtime_error("Failed to set authentication tag");
    }

    std::vector<uint8_t> decryptedData(dataSize);
    int decryptedLen = 0;

    if (EVP_DecryptUpdate(m_decryptCtx, decryptedData.data(), &decryptedLen,
                          ciphertextPtr, dataSize) != 1)
    {
        throw std::runtime_error("Failed during decryption update");
    }

    int finalLen = 0;
    int ret = EVP_DecryptFinal_ex(m_decryptCtx, decryptedData.data() + decryptedLen, &finalLen);

    if (ret != 1)
    {
        throw TamperDetectedException("AES-GCM authentication tag verification failed");
    }

    decryptedData.resize(decryptedLen + finalLen);
    return decryptedData;
}
