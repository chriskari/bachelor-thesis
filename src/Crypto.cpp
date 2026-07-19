#include "Crypto.hpp"
#include "ByteOrder.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>

Crypto::Crypto()
{
    // No OpenSSL_add_all_algorithms()/EVP_cleanup(): both are deprecated
    // no-ops since OpenSSL 1.1, and EVP_cleanup() on 1.0 tore down GLOBAL
    // algorithm tables while other Crypto instances were still live.
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
}

std::vector<uint8_t> Crypto::buildAad(uint64_t seqnum,
                                      const uint8_t *targetName,
                                      size_t targetNameLen)
{
    if (targetNameLen > 0xFFFFu)
    {
        throw std::runtime_error("Target name too long for AAD (max 65535 bytes)");
    }

    std::vector<uint8_t> aad(SEQNUM_SIZE + sizeof(uint16_t) + targetNameLen);
    byteorder::writeLE64(aad.data(), seqnum);
    byteorder::writeLE16(aad.data() + SEQNUM_SIZE, static_cast<uint16_t>(targetNameLen));
    if (targetNameLen > 0)
    {
        std::memcpy(aad.data() + SEQNUM_SIZE + sizeof(uint16_t), targetName, targetNameLen);
    }
    return aad;
}

bool Crypto::peekSeqnum(const uint8_t *encryptedData, size_t encryptedLen, uint64_t &outSeqnum)
{
    if (encryptedLen < sizeof(uint32_t) + SEQNUM_SIZE)
        return false;
    outSeqnum = byteorder::readLE64(encryptedData + sizeof(uint32_t));
    return true;
}

bool Crypto::peekSeqnum(const std::vector<uint8_t> &encryptedData, uint64_t &outSeqnum)
{
    return peekSeqnum(encryptedData.data(), encryptedData.size(), outSeqnum);
}

// Wire format (little-endian):
//   [u32 dataSize][u64 seqnum][iv GCM_IV_SIZE][ciphertext dataSize][tag GCM_TAG_SIZE]
// Fresh random IV per call; seqnum + target name are bound into the GCM AAD.
void Crypto::encrypt(const uint8_t *plaintext, size_t plaintextLen,
                     const std::vector<uint8_t> &key,
                     std::vector<uint8_t> &out,
                     uint64_t seqnum,
                     const uint8_t *targetName, size_t targetNameLen)
{
    out.clear();

    if (plaintextLen == 0)
        return;
    if (key.size() != KEY_SIZE)
        throw std::runtime_error("Invalid key size");

    const size_t sizeFieldSize = sizeof(uint32_t);
    const size_t ciphertextSize = plaintextLen;
    const size_t totalSize = sizeFieldSize + SEQNUM_SIZE + GCM_IV_SIZE + ciphertextSize + GCM_TAG_SIZE;

    out.resize(totalSize);

    byteorder::writeLE32(out.data(), static_cast<uint32_t>(ciphertextSize));
    byteorder::writeLE64(out.data() + sizeFieldSize, seqnum);

    uint8_t *ivPtr = out.data() + sizeFieldSize + SEQNUM_SIZE;
    if (RAND_bytes(ivPtr, GCM_IV_SIZE) != 1)
    {
        throw std::runtime_error("Failed to generate random IV");
    }

    try
    {
        // Bind cipher + key only when the key changed; otherwise the per-call
        // init sets just the fresh IV and skips the AES-256 key schedule.
        if (m_encryptKeyCache != key)
        {
            if (EVP_EncryptInit_ex(m_encryptCtx, EVP_aes_256_gcm(), nullptr, key.data(),
                                   nullptr) != 1)
            {
                throw std::runtime_error("Failed to initialize encryption key");
            }
            m_encryptKeyCache = key;
        }
        if (EVP_EncryptInit_ex(m_encryptCtx, nullptr, nullptr, nullptr, ivPtr) != 1)
        {
            throw std::runtime_error("Failed to initialize encryption");
        }

        const auto aad = buildAad(seqnum, targetName, targetNameLen);
        int aadOut = 0;
        if (EVP_EncryptUpdate(m_encryptCtx, nullptr, &aadOut, aad.data(),
                              static_cast<int>(aad.size())) != 1)
        {
            throw std::runtime_error("Failed to feed AAD into encryption");
        }

        const size_t ciphertextOffset = sizeFieldSize + SEQNUM_SIZE + GCM_IV_SIZE;

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
    catch (...)
    {
        // Context state is undefined after a failure; force a full re-init.
        m_encryptKeyCache.clear();
        EVP_CIPHER_CTX_reset(m_encryptCtx);
        throw;
    }
}

void Crypto::encrypt(const uint8_t *plaintext, size_t plaintextLen,
                     const std::vector<uint8_t> &key,
                     std::vector<uint8_t> &out)
{
    encrypt(plaintext, plaintextLen, key, out, /*seqnum=*/0, nullptr, 0);
}

std::vector<uint8_t> Crypto::encrypt(std::vector<uint8_t> &&plaintext,
                                     const std::vector<uint8_t> &key)
{
    std::vector<uint8_t> out;
    encrypt(plaintext.data(), plaintext.size(), key, out);
    return out;
}

std::vector<uint8_t> Crypto::decrypt(const std::vector<uint8_t> &encryptedData,
                                     const std::vector<uint8_t> &key,
                                     const uint8_t *targetName, size_t targetNameLen)
{
    return decrypt(encryptedData.data(), encryptedData.size(), key, targetName, targetNameLen);
}

std::vector<uint8_t> Crypto::decrypt(const uint8_t *encryptedData, size_t encryptedLen,
                                     const std::vector<uint8_t> &key,
                                     const uint8_t *targetName, size_t targetNameLen)
{
    if (encryptedLen == 0)
    {
        return std::vector<uint8_t>();
    }

    if (key.size() != KEY_SIZE)
    {
        throw std::runtime_error("Invalid key size. Expected 32 bytes for AES-256");
    }

    const size_t headerSize = sizeof(uint32_t) + SEQNUM_SIZE + GCM_IV_SIZE;
    if (encryptedLen < headerSize)
    {
        throw std::runtime_error("Encrypted data too small - missing header");
    }

    uint32_t dataSize = byteorder::readLE32(encryptedData);
    size_t position = sizeof(uint32_t);

    uint64_t seqnum = byteorder::readLE64(encryptedData + position);
    position += SEQNUM_SIZE;

    const uint8_t *ivPtr = encryptedData + position;
    position += GCM_IV_SIZE;

    if (position + dataSize > encryptedLen)
    {
        throw std::runtime_error("Encrypted data too small - missing complete data");
    }

    const uint8_t *ciphertextPtr = encryptedData + position;
    position += dataSize;

    if (position + GCM_TAG_SIZE > encryptedLen)
    {
        throw std::runtime_error("Encrypted data too small - missing authentication tag");
    }

    // EVP_CIPHER_CTX_ctrl takes a non-const pointer, so we copy the tag out.
    std::vector<uint8_t> tag(GCM_TAG_SIZE);
    std::memcpy(tag.data(), encryptedData + position, GCM_TAG_SIZE);

    try
    {
        if (m_decryptKeyCache != key)
        {
            if (EVP_DecryptInit_ex(m_decryptCtx, EVP_aes_256_gcm(), nullptr, key.data(),
                                   nullptr) != 1)
            {
                throw std::runtime_error("Failed to initialize decryption key");
            }
            m_decryptKeyCache = key;
        }
        if (EVP_DecryptInit_ex(m_decryptCtx, nullptr, nullptr, nullptr, ivPtr) != 1)
        {
            throw std::runtime_error("Failed to initialize decryption");
        }

        if (EVP_CIPHER_CTX_ctrl(m_decryptCtx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag.data()) != 1)
        {
            throw std::runtime_error("Failed to set authentication tag");
        }

        const auto aad = buildAad(seqnum, targetName, targetNameLen);
        int aadOut = 0;
        if (EVP_DecryptUpdate(m_decryptCtx, nullptr, &aadOut, aad.data(),
                              static_cast<int>(aad.size())) != 1)
        {
            throw std::runtime_error("Failed to feed AAD into decryption");
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
    catch (...)
    {
        // Includes tag failures: GCM leaves the context mid-operation, so
        // force a full re-init before the next use.
        m_decryptKeyCache.clear();
        EVP_CIPHER_CTX_reset(m_decryptCtx);
        throw;
    }
}

std::vector<uint8_t> Crypto::decrypt(const std::vector<uint8_t> &encryptedData,
                                     const std::vector<uint8_t> &key)
{
    return decrypt(encryptedData, key, nullptr, 0);
}
