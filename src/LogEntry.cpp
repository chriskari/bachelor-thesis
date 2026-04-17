#include "LogEntry.hpp"
#include "ByteOrder.hpp"
#include <cstring>
#include <stdexcept>
#include <iostream>

namespace
{
inline void appendLE32(std::vector<uint8_t> &v, uint32_t x)
{
    uint8_t buf[4];
    byteorder::writeLE32(buf, x);
    v.insert(v.end(), buf, buf + 4);
}

inline void appendLE64(std::vector<uint8_t> &v, uint64_t x)
{
    uint8_t buf[8];
    byteorder::writeLE64(buf, x);
    v.insert(v.end(), buf, buf + 8);
}
} // namespace

LogEntry::LogEntry()
    : m_actionType(ActionType::CREATE),
      m_dataLocation(""),
      m_dataControllerId(""),
      m_dataProcessorId(""),
      m_dataSubjectId(""),
      m_timestamp(std::chrono::system_clock::now()),
      m_payload() {}

LogEntry::LogEntry(ActionType actionType,
                   std::string dataLocation,
                   std::string dataControllerId,
                   std::string dataProcessorId,
                   std::string dataSubjectId,
                   std::vector<uint8_t> payload)
    : m_actionType(actionType),
      m_dataLocation(std::move(dataLocation)),
      m_dataControllerId(std::move(dataControllerId)),
      m_dataProcessorId(std::move(dataProcessorId)),
      m_dataSubjectId(std::move(dataSubjectId)),
      m_timestamp(std::chrono::system_clock::now()),
      m_payload(std::move(payload))
{
}

// Wire format (little-endian, byte-order independent):
//   actionType:  u32
//   dataLocation, dataControllerId, dataProcessorId, dataSubjectId: each u32 length + bytes
//   timestamp:   u64 (ms since epoch)
//   payloadSize: u32
//   payload:     payloadSize bytes
// On x86_64 this produces the same bytes as the previous memcpy-based format; differences
// only show up on big-endian hosts, which previously couldn't read files written on
// little-endian hosts.

std::vector<uint8_t> LogEntry::serialize() &&
{
    size_t totalSize =
        sizeof(uint32_t) +                             // ActionType
        sizeof(uint32_t) + m_dataLocation.size() +     // Size + data location
        sizeof(uint32_t) + m_dataControllerId.size() + // Size + data controller ID
        sizeof(uint32_t) + m_dataProcessorId.size() +  // Size + data processor ID
        sizeof(uint32_t) + m_dataSubjectId.size() +    // Size + data subject ID
        sizeof(uint64_t) +                             // Timestamp
        sizeof(uint32_t) + m_payload.size();           // Size + payload data

    std::vector<uint8_t> result;
    result.reserve(totalSize);

    appendLE32(result, static_cast<uint32_t>(m_actionType));

    appendStringToVector(result, std::move(m_dataLocation));
    appendStringToVector(result, std::move(m_dataControllerId));
    appendStringToVector(result, std::move(m_dataProcessorId));
    appendStringToVector(result, std::move(m_dataSubjectId));

    int64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                            m_timestamp.time_since_epoch())
                            .count();
    appendLE64(result, static_cast<uint64_t>(timestamp));

    appendLE32(result, static_cast<uint32_t>(m_payload.size()));
    if (!m_payload.empty())
    {
        result.insert(result.end(),
                      std::make_move_iterator(m_payload.begin()),
                      std::make_move_iterator(m_payload.end()));
    }

    return result;
}

std::vector<uint8_t> LogEntry::serialize() const &
{
    size_t totalSize =
        sizeof(uint32_t) +                             // ActionType
        sizeof(uint32_t) + m_dataLocation.size() +     // Size + data location
        sizeof(uint32_t) + m_dataControllerId.size() + // Size + data controller  ID
        sizeof(uint32_t) + m_dataProcessorId.size() +  // Size + data processor  ID
        sizeof(uint32_t) + m_dataSubjectId.size() +    // Size + data subject ID
        sizeof(uint64_t) +                             // Timestamp
        sizeof(uint32_t) + m_payload.size();           // Size + payload data

    std::vector<uint8_t> result;
    result.reserve(totalSize);

    appendLE32(result, static_cast<uint32_t>(m_actionType));

    appendStringToVector(result, m_dataLocation);
    appendStringToVector(result, m_dataControllerId);
    appendStringToVector(result, m_dataProcessorId);
    appendStringToVector(result, m_dataSubjectId);

    int64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                            m_timestamp.time_since_epoch())
                            .count();
    appendLE64(result, static_cast<uint64_t>(timestamp));

    appendLE32(result, static_cast<uint32_t>(m_payload.size()));
    if (!m_payload.empty())
    {
        appendToVector(result, m_payload.data(), m_payload.size());
    }

    return result;
}

bool LogEntry::deserialize(std::vector<uint8_t> &&data)
{
    try
    {
        size_t offset = 0;

        if (data.size() < sizeof(uint32_t))
            return false;

        uint32_t actionType = byteorder::readLE32(data.data() + offset);
        offset += sizeof(uint32_t);
        m_actionType = static_cast<ActionType>(actionType);

        if (!extractStringFromVector(data, offset, m_dataLocation))
            return false;
        if (!extractStringFromVector(data, offset, m_dataControllerId))
            return false;
        if (!extractStringFromVector(data, offset, m_dataProcessorId))
            return false;
        if (!extractStringFromVector(data, offset, m_dataSubjectId))
            return false;

        if (offset + sizeof(uint64_t) > data.size())
            return false;

        int64_t timestamp = static_cast<int64_t>(byteorder::readLE64(data.data() + offset));
        offset += sizeof(uint64_t);
        m_timestamp = std::chrono::system_clock::time_point(std::chrono::milliseconds(timestamp));

        if (offset + sizeof(uint32_t) > data.size())
            return false;

        uint32_t payloadSize = byteorder::readLE32(data.data() + offset);
        offset += sizeof(uint32_t);

        if (payloadSize > MAX_PAYLOAD_SIZE)
            return false;

        if (offset + payloadSize > data.size())
            return false;

        if (payloadSize > 0)
        {
            m_payload.clear();
            m_payload.reserve(payloadSize);

            auto start_it = data.begin() + offset;
            auto end_it = start_it + payloadSize;
            m_payload.assign(std::make_move_iterator(start_it),
                             std::make_move_iterator(end_it));
            offset += payloadSize;
        }
        else
        {
            m_payload.clear();
        }

        return true;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

std::vector<uint8_t> LogEntry::serializeBatch(std::vector<LogEntry> &&entries)
{
    if (entries.empty())
    {
        std::vector<uint8_t> batchData(sizeof(uint32_t));
        byteorder::writeLE32(batchData.data(), 0);
        return batchData;
    }

    size_t estimatedSize = sizeof(uint32_t);
    for (const auto &entry : entries)
    {
        estimatedSize += sizeof(uint32_t) +     // Entry size field
                         sizeof(uint32_t) +     // ActionType
                         3 * sizeof(uint32_t) + // 3 string length fields
                         entry.getDataLocation().size() +
                         entry.getDataControllerId().size() +
                         entry.getDataProcessorId().size() +
                         entry.getDataSubjectId().size() +
                         sizeof(uint64_t) + // Timestamp
                         sizeof(uint32_t) + // Payload size
                         entry.getPayload().size();
    }

    std::vector<uint8_t> batchData;
    batchData.reserve(estimatedSize);

    appendLE32(batchData, static_cast<uint32_t>(entries.size()));

    for (auto &entry : entries)
    {
        std::vector<uint8_t> entryData = std::move(entry).serialize();
        appendLE32(batchData, static_cast<uint32_t>(entryData.size()));
        batchData.insert(batchData.end(),
                         std::make_move_iterator(entryData.begin()),
                         std::make_move_iterator(entryData.end()));
    }

    return batchData;
}

std::vector<LogEntry> LogEntry::deserializeBatch(std::vector<uint8_t> &&batchData)
{
    std::vector<LogEntry> entries;

    try
    {
        if (batchData.size() < sizeof(uint32_t))
        {
            throw std::runtime_error("Batch data too small to contain entry count");
        }

        uint32_t numEntries = byteorder::readLE32(batchData.data());
        entries.reserve(numEntries);

        size_t position = sizeof(uint32_t);

        for (uint32_t i = 0; i < numEntries; ++i)
        {
            if (position + sizeof(uint32_t) > batchData.size())
            {
                throw std::runtime_error("Unexpected end of batch data");
            }

            uint32_t entrySize = byteorder::readLE32(batchData.data() + position);
            position += sizeof(uint32_t);

            if (entrySize > MAX_ENTRY_SIZE)
            {
                throw std::runtime_error("Entry size exceeds MAX_ENTRY_SIZE");
            }

            if (position + entrySize > batchData.size())
            {
                throw std::runtime_error("Unexpected end of batch data");
            }

            std::vector<uint8_t> entryData;
            entryData.reserve(entrySize);

            auto start_it = batchData.begin() + position;
            auto end_it = start_it + entrySize;
            entryData.assign(std::make_move_iterator(start_it),
                             std::make_move_iterator(end_it));
            position += entrySize;

            LogEntry entry;
            if (entry.deserialize(std::move(entryData)))
            {
                entries.emplace_back(std::move(entry));
            }
            else
            {
                throw std::runtime_error("Failed to deserialize log entry");
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error deserializing log batch: " << e.what() << std::endl;
    }

    return entries;
}

void LogEntry::appendToVector(std::vector<uint8_t> &vec, const void *data, size_t size) const
{
    const uint8_t *bytes = static_cast<const uint8_t *>(data);
    vec.insert(vec.end(), bytes, bytes + size);
}

void LogEntry::appendStringToVector(std::vector<uint8_t> &vec, const std::string &str) const
{
    appendLE32(vec, static_cast<uint32_t>(str.size()));
    if (!str.empty())
    {
        appendToVector(vec, str.data(), str.size());
    }
}

void LogEntry::appendStringToVector(std::vector<uint8_t> &vec, std::string &&str)
{
    appendLE32(vec, static_cast<uint32_t>(str.size()));
    if (!str.empty())
    {
        vec.insert(vec.end(), str.begin(), str.end());
    }
}

bool LogEntry::extractStringFromVector(std::vector<uint8_t> &vec, size_t &offset, std::string &str)
{
    if (offset + sizeof(uint32_t) > vec.size())
        return false;

    uint32_t length = byteorder::readLE32(vec.data() + offset);
    offset += sizeof(uint32_t);

    if (length > MAX_STRING_SIZE)
        return false;

    if (offset + length > vec.size())
        return false;

    str.assign(reinterpret_cast<const char *>(vec.data() + offset), length);
    offset += length;

    return true;
}
