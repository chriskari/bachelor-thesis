#ifndef LOG_ENTRY_HPP
#define LOG_ENTRY_HPP

#include <string>
#include <chrono>
#include <vector>
#include <memory>
#include <cstdint>

class LogEntry
{
public:
    // Caps on deserialized sizes; reject inputs larger than these instead of allocating.
    static constexpr size_t MAX_STRING_SIZE = 1 * 1024 * 1024;
    static constexpr size_t MAX_PAYLOAD_SIZE = 16 * 1024 * 1024;
    static constexpr size_t MAX_ENTRY_SIZE = 32 * 1024 * 1024;

    enum class ActionType
    {
        CREATE,
        READ,
        UPDATE,
        DELETE,
    };

    LogEntry();

    LogEntry(ActionType actionType,
             std::string dataLocation,
             std::string dataControllerId,
             std::string dataProcessorId,
             std::string dataSubjectId,
             std::vector<uint8_t> payload = std::vector<uint8_t>());

    std::vector<uint8_t> serialize() &&;
    std::vector<uint8_t> serialize() const &;
    // Append into a caller-owned buffer; no heap allocation if `out` has enough capacity.
    void serialize(std::vector<uint8_t> &out) &&;
    void serialize(std::vector<uint8_t> &out) const &;
    size_t serializedSize() const;
    bool deserialize(std::vector<uint8_t> &&data);

    static std::vector<uint8_t> serializeBatch(std::vector<LogEntry> &&entries);
    // Overwrites `out`.
    static void serializeBatch(std::vector<LogEntry> &&entries, std::vector<uint8_t> &out);
    static std::vector<LogEntry> deserializeBatch(std::vector<uint8_t> &&batchData);

    ActionType getActionType() const { return m_actionType; }
    std::string getDataLocation() const { return m_dataLocation; }
    std::string getDataControllerId() const { return m_dataControllerId; }
    std::string getDataProcessorId() const { return m_dataProcessorId; }
    std::string getDataSubjectId() const { return m_dataSubjectId; }
    std::chrono::system_clock::time_point getTimestamp() const { return m_timestamp; }
    const std::vector<uint8_t> &getPayload() const { return m_payload; }

private:
    void appendToVector(std::vector<uint8_t> &vec, const void *data, size_t size) const;
    void appendStringToVector(std::vector<uint8_t> &vec, const std::string &str) const;
    void appendStringToVector(std::vector<uint8_t> &vec, std::string &&str);
    bool extractStringFromVector(std::vector<uint8_t> &vec, size_t &offset, std::string &str);

    ActionType m_actionType;
    std::string m_dataLocation;
    std::string m_dataControllerId;
    std::string m_dataProcessorId;
    std::string m_dataSubjectId;
    std::chrono::system_clock::time_point m_timestamp;
    std::vector<uint8_t> m_payload;
};

#endif