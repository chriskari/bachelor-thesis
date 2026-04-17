#ifndef COMPRESSION_HPP
#define COMPRESSION_HPP

#include "LogEntry.hpp"
#include <vector>
#include <cstdint>
#include <zlib.h>

class Compression
{
public:
    // Cap on decompressed output to defeat zip-bomb inputs. 100 MiB is 5× the largest
    // segment payload we expect in practice and matches maxSegmentSize default.
    static constexpr size_t DEFAULT_MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024;

    static std::vector<uint8_t> compress(std::vector<uint8_t> &&data, int level = Z_DEFAULT_COMPRESSION);

    static std::vector<uint8_t> decompress(std::vector<uint8_t> &&compressedData,
                                           size_t maxDecompressedSize = DEFAULT_MAX_DECOMPRESSED_SIZE);
};

#endif