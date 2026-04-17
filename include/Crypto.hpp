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
    static constexpr size_t SEQNUM_SIZE = 8;

    // Convenience overloads: seqnum=0 and empty target name (no tamper binding).
    std::vector<uint8_t> encrypt(std::vector<uint8_t> &&plaintext,
                                 const std::vector<uint8_t> &key);
    void encrypt(const uint8_t *plaintext, size_t plaintextLen,
                 const std::vector<uint8_t> &key,
                 std::vector<uint8_t> &out);

    void encrypt(const uint8_t *plaintext, size_t plaintextLen,
                 const std::vector<uint8_t> &key,
                 std::vector<uint8_t> &out,
                 uint64_t seqnum,
                 const uint8_t *targetName, size_t targetNameLen);

    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &encryptedData,
                                 const std::vector<uint8_t> &key);

    // Reads seqnum from the blob header and reconstructs AAD from seqnum + targetName.
    // Throws TamperDetectedException on any tag mismatch.
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &encryptedData,
                                 const std::vector<uint8_t> &key,
                                 const uint8_t *targetName, size_t targetNameLen);

    static bool peekSeqnum(const uint8_t *encryptedData, size_t encryptedLen,
                           uint64_t &outSeqnum);
    static bool peekSeqnum(const std::vector<uint8_t> &encryptedData,
                           uint64_t &outSeqnum);

    static std::vector<uint8_t> buildAad(uint64_t seqnum,
                                         const uint8_t *targetName,
                                         size_t targetNameLen);
};

#endif
