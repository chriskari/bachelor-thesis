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
    // Deserialization sanity caps — reject malformed inputs before allocating. These are
    // deliberately generous relative to the GDPR log entries this system produces.
    static constexpr size_t MAX_STRING_SIZE = 1 * 1024 * 1024;   // 1 MiB per string field
    static constexpr size_t MAX_PAYLOAD_SIZE = 16 * 1024 * 1024; // 16 MiB per payload
    static constexpr size_t MAX_ENTRY_SIZE = 32 * 1024 * 1024;   // 32 MiB per serialized entry

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
    bool deserialize(std::vector<uint8_t> &&data);

    static std::vector<uint8_t> serializeBatch(std::vector<LogEntry> &&entries);
    static std::vector<LogEntry> deserializeBatch(std::vector<uint8_t> &&batchData);

    ActionType getActionType() const { return m_actionType; }
    std::string getDataLocation() const { return m_dataLocation; }
    std::string getDataControllerId() const { return m_dataControllerId; }
    std::string getDataProcessorId() const { return m_dataProcessorId; }
    std::string getDataSubjectId() const { return m_dataSubjectId; }
    std::chrono::system_clock::time_point getTimestamp() const { return m_timestamp; }
    const std::vector<uint8_t> &getPayload() const { return m_payload; }

private:
    // Helper methods for binary serialization
    void appendToVector(std::vector<uint8_t> &vec, const void *data, size_t size) const;
    void appendStringToVector(std::vector<uint8_t> &vec, const std::string &str) const;
    void appendStringToVector(std::vector<uint8_t> &vec, std::string &&str);
    bool extractStringFromVector(std::vector<uint8_t> &vec, size_t &offset, std::string &str);

    ActionType m_actionType;                           // Type of GDPR operation
    std::string m_dataLocation;                        // Location of the data being operated on
    std::string m_dataControllerId;                    // ID of the entity controlling the data
    std::string m_dataProcessorId;                     // ID of the entity performing the operation
    std::string m_dataSubjectId;                       // ID of the data subject
    std::chrono::system_clock::time_point m_timestamp; // When the operation occurred
    std::vector<uint8_t> m_payload;                    // optional extra bytes
};

#endif