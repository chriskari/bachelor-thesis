#ifndef BYTE_ORDER_HPP
#define BYTE_ORDER_HPP

#include <cstdint>

// Little-endian byte helpers so the on-disk wire format is host-independent.
namespace byteorder
{
inline void writeLE16(uint8_t *dst, uint16_t v) noexcept
{
    dst[0] = static_cast<uint8_t>(v);
    dst[1] = static_cast<uint8_t>(v >> 8);
}

inline uint16_t readLE16(const uint8_t *src) noexcept
{
    return static_cast<uint16_t>(src[0]) |
           (static_cast<uint16_t>(src[1]) << 8);
}

inline void writeLE32(uint8_t *dst, uint32_t v) noexcept
{
    dst[0] = static_cast<uint8_t>(v);
    dst[1] = static_cast<uint8_t>(v >> 8);
    dst[2] = static_cast<uint8_t>(v >> 16);
    dst[3] = static_cast<uint8_t>(v >> 24);
}

inline uint32_t readLE32(const uint8_t *src) noexcept
{
    return static_cast<uint32_t>(src[0]) |
           (static_cast<uint32_t>(src[1]) << 8) |
           (static_cast<uint32_t>(src[2]) << 16) |
           (static_cast<uint32_t>(src[3]) << 24);
}

inline void writeLE64(uint8_t *dst, uint64_t v) noexcept
{
    dst[0] = static_cast<uint8_t>(v);
    dst[1] = static_cast<uint8_t>(v >> 8);
    dst[2] = static_cast<uint8_t>(v >> 16);
    dst[3] = static_cast<uint8_t>(v >> 24);
    dst[4] = static_cast<uint8_t>(v >> 32);
    dst[5] = static_cast<uint8_t>(v >> 40);
    dst[6] = static_cast<uint8_t>(v >> 48);
    dst[7] = static_cast<uint8_t>(v >> 56);
}

inline uint64_t readLE64(const uint8_t *src) noexcept
{
    return static_cast<uint64_t>(src[0]) |
           (static_cast<uint64_t>(src[1]) << 8) |
           (static_cast<uint64_t>(src[2]) << 16) |
           (static_cast<uint64_t>(src[3]) << 24) |
           (static_cast<uint64_t>(src[4]) << 32) |
           (static_cast<uint64_t>(src[5]) << 40) |
           (static_cast<uint64_t>(src[6]) << 48) |
           (static_cast<uint64_t>(src[7]) << 56);
}
} // namespace byteorder

#endif
