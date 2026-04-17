#include "Crypto.hpp"
#include "ByteOrder.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>

Crypto::Crypto()
{
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

// Wire format (little-endian): [u32 dataSize][iv, GCM_IV_SIZE bytes][ciphertext, dataSize bytes][tag, GCM_TAG_SIZE bytes]
// A fresh random IV is generated per call via RAND_bytes and embedded in the output — never reuse an IV under the same key.
void Crypto::encrypt(const uint8_t *plaintext, size_t plaintextLen,
                     const std::vector<uint8_t> &key,
                     std::vector<uint8_t> &out)
{
    out.clear();

    if (plaintextLen == 0)
        return;
    if (key.size() != KEY_SIZE)
        throw std::runtime_error("Invalid key size");

    const size_t sizeFieldSize = sizeof(uint32_t);
    const size_t ciphertextSize = plaintextLen;
    const size_t totalSize = sizeFieldSize + GCM_IV_SIZE + ciphertextSize + GCM_TAG_SIZE;

    out.resize(totalSize);

    byteorder::writeLE32(out.data(), static_cast<uint32_t>(ciphertextSize));

    uint8_t *ivPtr = out.data() + sizeFieldSize;
    if (RAND_bytes(ivPtr, GCM_IV_SIZE) != 1)
    {
        throw std::runtime_error("Failed to generate random IV");
    }

    EVP_CIPHER_CTX_reset(m_encryptCtx);

    if (EVP_EncryptInit_ex(m_encryptCtx, EVP_aes_256_gcm(), nullptr, key.data(), ivPtr) != 1)
    {
        throw std::runtime_error("Failed to initialize encryption");
    }

    const size_t ciphertextOffset = sizeFieldSize + GCM_IV_SIZE;

    int encryptedLen = 0;
    if (EVP_EncryptUpdate(m_encryptCtx, out.data() + ciphertextOffset, &encryptedLen,
                          plaintext, plaintextLen) != 1)
    {
        throw std::runtime_error("Failed during encryption update");
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(m_encryptCtx, out.data() + ciphertextOffset + encryptedLen, &finalLen) != 1)
    {
        throw std::runtime_error("Failed to finalize encryption");
    }

    if (encryptedLen + finalLen != static_cast<int>(plaintextLen))
    {
        throw std::runtime_error("Unexpected encryption output size");
    }

    if (EVP_CIPHER_CTX_ctrl(m_encryptCtx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE,
                            out.data() + ciphertextOffset + ciphertextSize) != 1)
    {
        throw std::runtime_error("Failed to get authentication tag");
    }
}

std::vector<uint8_t> Crypto::encrypt(std::vector<uint8_t> &&plaintext,
                                     const std::vector<uint8_t> &key)
{
    std::vector<uint8_t> out;
    encrypt(plaintext.data(), plaintext.size(), key, out);
    return out;
}

std::vector<uint8_t> Crypto::decrypt(const std::vector<uint8_t> &encryptedData,
                                     const std::vector<uint8_t> &key)
{
    if (encryptedData.empty())
    {
        return std::vector<uint8_t>();
    }

    if (key.size() != KEY_SIZE)
    {
        throw std::runtime_error("Invalid key size. Expected 32 bytes for AES-256");
    }

    if (encryptedData.size() < sizeof(uint32_t) + GCM_IV_SIZE)
    {
        throw std::runtime_error("Encrypted data too small - missing size field or IV");
    }

    uint32_t dataSize = byteorder::readLE32(encryptedData.data());
    size_t position = sizeof(uint32_t);

    const uint8_t *ivPtr = encryptedData.data() + position;
    position += GCM_IV_SIZE;

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

    // EVP_CIPHER_CTX_ctrl takes a non-const pointer, so we copy the tag out.
    std::vector<uint8_t> tag(GCM_TAG_SIZE);
    std::memcpy(tag.data(), encryptedData.data() + position, GCM_TAG_SIZE);

    EVP_CIPHER_CTX_reset(m_decryptCtx);

    if (EVP_DecryptInit_ex(m_decryptCtx, EVP_aes_256_gcm(), nullptr, key.data(), ivPtr) != 1)
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
