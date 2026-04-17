#ifndef COMPRESSION_HPP
#define COMPRESSION_HPP

#include "LogEntry.hpp"
#include <vector>
#include <cstdint>
#include <zlib.h>

// Holds persistent deflate/inflate z_streams; not thread-safe. One instance per writer thread.
class Compression
{
public:
    // Zip-bomb guard for decompress.
    static constexpr size_t DEFAULT_MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024;

    Compression();
    ~Compression();

    Compression(const Compression &) = delete;
    Compression &operator=(const Compression &) = delete;
    Compression(Compression &&) = delete;
    Compression &operator=(Compression &&) = delete;

    std::vector<uint8_t> compress(std::vector<uint8_t> &&data, int level = Z_DEFAULT_COMPRESSION);
    void compress(const uint8_t *data, size_t size, std::vector<uint8_t> &out,
                  int level = Z_DEFAULT_COMPRESSION);

    std::vector<uint8_t> decompress(std::vector<uint8_t> &&compressedData,
                                    size_t maxDecompressedSize = DEFAULT_MAX_DECOMPRESSED_SIZE);
    void decompress(const uint8_t *data, size_t size, std::vector<uint8_t> &out,
                    size_t maxDecompressedSize = DEFAULT_MAX_DECOMPRESSED_SIZE);

private:
    z_stream m_deflateStream{};
    z_stream m_inflateStream{};
    int m_deflateLevel = 0; // 0 = uninitialized; otherwise the level bound to m_deflateStream
    bool m_inflateInitialized = false;
};

#endif
