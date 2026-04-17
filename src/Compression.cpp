#include "Compression.hpp"
#include <stdexcept>
#include <cstring>
#include <iostream>

Compression::Compression() = default;

Compression::~Compression()
{
    if (m_deflateLevel != 0)
    {
        deflateEnd(&m_deflateStream);
    }
    if (m_inflateInitialized)
    {
        inflateEnd(&m_inflateStream);
    }
}

void Compression::compress(const uint8_t *data, size_t size, std::vector<uint8_t> &out, int level)
{
    out.clear();

    if (size == 0)
    {
        return;
    }

    // Level changes force a full re-init because zlib's internal buffers are sized by it;
    // same-level calls take the cheap deflateReset path.
    if (m_deflateLevel != level)
    {
        if (m_deflateLevel != 0)
        {
            deflateEnd(&m_deflateStream);
            m_deflateLevel = 0;
        }
        std::memset(&m_deflateStream, 0, sizeof(m_deflateStream));
        if (deflateInit(&m_deflateStream, level) != Z_OK)
        {
            throw std::runtime_error("Failed to initialize zlib deflate");
        }
        m_deflateLevel = level;
    }
    else
    {
        if (deflateReset(&m_deflateStream) != Z_OK)
        {
            deflateEnd(&m_deflateStream);
            m_deflateLevel = 0;
            throw std::runtime_error("Failed to reset zlib deflate");
        }
    }

    m_deflateStream.next_in = const_cast<Bytef *>(data);
    m_deflateStream.avail_in = size;

    int ret;
    char outbuffer[32768];

    do
    {
        m_deflateStream.next_out = reinterpret_cast<Bytef *>(outbuffer);
        m_deflateStream.avail_out = sizeof(outbuffer);

        ret = deflate(&m_deflateStream, Z_FINISH);

        if (out.size() < m_deflateStream.total_out)
        {
            out.insert(out.end(),
                       outbuffer,
                       outbuffer + (m_deflateStream.total_out - out.size()));
        }
    } while (ret == Z_OK);

    if (ret != Z_STREAM_END)
    {
        // Abandon the stream; the next call will rebuild it.
        deflateEnd(&m_deflateStream);
        m_deflateLevel = 0;
        throw std::runtime_error("Exception during zlib compression");
    }
}

std::vector<uint8_t> Compression::compress(std::vector<uint8_t> &&data, int level)
{
    std::vector<uint8_t> out;
    compress(data.data(), data.size(), out, level);
    return out;
}

void Compression::decompress(const uint8_t *data, size_t size, std::vector<uint8_t> &out,
                              size_t maxDecompressedSize)
{
    out.clear();

    if (size == 0)
    {
        return;
    }

    if (!m_inflateInitialized)
    {
        std::memset(&m_inflateStream, 0, sizeof(m_inflateStream));
        if (inflateInit(&m_inflateStream) != Z_OK)
        {
            throw std::runtime_error("Failed to initialize zlib inflate");
        }
        m_inflateInitialized = true;
    }
    else
    {
        if (inflateReset(&m_inflateStream) != Z_OK)
        {
            inflateEnd(&m_inflateStream);
            m_inflateInitialized = false;
            throw std::runtime_error("Failed to reset zlib inflate");
        }
    }

    m_inflateStream.next_in = const_cast<Bytef *>(data);
    m_inflateStream.avail_in = size;

    int ret;
    char outbuffer[32768];

    do
    {
        m_inflateStream.next_out = reinterpret_cast<Bytef *>(outbuffer);
        m_inflateStream.avail_out = sizeof(outbuffer);

        ret = inflate(&m_inflateStream, Z_NO_FLUSH);

        if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
        {
            inflateEnd(&m_inflateStream);
            m_inflateInitialized = false;
            throw std::runtime_error("Exception during zlib decompression");
        }

        if (m_inflateStream.total_out > maxDecompressedSize)
        {
            inflateEnd(&m_inflateStream);
            m_inflateInitialized = false;
            throw std::runtime_error("Decompressed data exceeds maxDecompressedSize");
        }

        if (out.size() < m_inflateStream.total_out)
        {
            out.insert(out.end(),
                       outbuffer,
                       outbuffer + (m_inflateStream.total_out - out.size()));
        }
    } while (ret == Z_OK);

    if (ret != Z_STREAM_END)
    {
        inflateEnd(&m_inflateStream);
        m_inflateInitialized = false;
        throw std::runtime_error("Exception during zlib decompression");
    }
}

std::vector<uint8_t> Compression::decompress(std::vector<uint8_t> &&compressedData,
                                             size_t maxDecompressedSize)
{
    std::vector<uint8_t> out;
    decompress(compressedData.data(), compressedData.size(), out, maxDecompressedSize);
    return out;
}
