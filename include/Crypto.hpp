#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <memory>

class Crypto
{
public:
    Crypto();
    ~Crypto();

    static constexpr size_t KEY_SIZE = 32;     // 256 bits
    static constexpr size_t GCM_IV_SIZE = 12;  // 96 bits (recommended for GCM)
    static constexpr size_t GCM_TAG_SIZE = 16; // 128 bits

    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &compressedData,
                                 const std::vector<uint8_t> &key,
                                 const std::vector<uint8_t> &iv);

    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &encryptedData,
                                 const std::vector<uint8_t> &key,
                                 const std::vector<uint8_t> &iv);
};

#endif