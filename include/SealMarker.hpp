#ifndef SEAL_MARKER_HPP
#define SEAL_MARKER_HPP

#include <cstddef>
#include <cstdint>

// Plaintext of the per-target seal batch written on clean shutdown. Its seqnum
// equals the count of data batches for that target, so the exporter can detect
// tail truncation. The embedded control bytes ensure this can't collide with
// a LogEntry::serializeBatch prefix.
namespace seal_marker
{
inline constexpr uint8_t MAGIC[] = {
    'S', 'E', 'A', 'L', 0x00, 0x01, 'G', 'D', 'P', 'R'};
inline constexpr size_t MAGIC_LEN = sizeof(MAGIC);
} // namespace seal_marker

#endif
