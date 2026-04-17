#ifndef COMPRESSION_HPP
#define COMPRESSION_HPP

#include "LogEntry.hpp"
#include <vector>
#include <cstdint>
#include <zlib.h>

class Compression
{
public:
    // Zip-bomb guard: decompress throws if output would exceed this. Matches the default
    // maxSegmentSize so legitimate inputs fit comfortably.
    static constexpr size_t DEFAULT_MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024;

    static std::vector<uint8_t> compress(std::vector<uint8_t> &&data, int level = Z_DEFAULT_COMPRESSION);

    static std::vector<uint8_t> decompress(std::vector<uint8_t> &&compressedData,
                                           size_t maxDecompressedSize = DEFAULT_MAX_DECOMPRESSED_SIZE);
};

#endif