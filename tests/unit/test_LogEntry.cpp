#include <gtest/gtest.h>
#include "LogEntry.hpp"
#include <vector>
#include <iostream>
#include <chrono>
#include <cstring>
#include <limits>

// Test default constructor
TEST(LogEntryTest1, DefaultConstructor_InitializesCorrectly)
{
    LogEntry entry;

    EXPECT_EQ(entry.getActionType(), LogEntry::ActionType::CREATE);
    EXPECT_EQ(entry.getDataLocation(), "");
    EXPECT_EQ(entry.getDataControllerId(), "");
    EXPECT_EQ(entry.getDataProcessorId(), "");
    EXPECT_EQ(entry.getDataSubjectId(), "");
    EXPECT_EQ(entry.getPayload().size(), 0);

    auto now = std::chrono::system_clock::now();
    EXPECT_NEAR(std::chrono::system_clock::to_time_t(entry.getTimestamp()),
                std::chrono::system_clock::to_time_t(now), 1);
}

// Test parameterized constructor
TEST(LogEntryTest2, ParameterizedConstructor_SetsFieldsCorrectly)
{
    std::vector<uint8_t> testPayload(128, 0xAA); // 128 bytes of 0xAA
    LogEntry entry(LogEntry::ActionType::UPDATE, "database/users", "controller123", "processor789", "subject456", testPayload);

    EXPECT_EQ(entry.getActionType(), LogEntry::ActionType::UPDATE);
    EXPECT_EQ(entry.getDataLocation(), "database/users");
    EXPECT_EQ(entry.getDataControllerId(), "controller123");
    EXPECT_EQ(entry.getDataProcessorId(), "processor789");
    EXPECT_EQ(entry.getDataSubjectId(), "subject456");
    EXPECT_EQ(entry.getPayload().size(), testPayload.size());

    // Check content matches
    const auto &payload = entry.getPayload();
    bool contentMatches = true;
    for (size_t i = 0; i < payload.size(); ++i)
    {
        if (payload[i] != testPayload[i])
        {
            contentMatches = false;
            break;
        }
    }
    EXPECT_TRUE(contentMatches);

    auto now = std::chrono::system_clock::now();
    EXPECT_NEAR(std::chrono::system_clock::to_time_t(entry.getTimestamp()),
                std::chrono::system_clock::to_time_t(now), 1);
}

// Test serialization and deserialization with empty payload
TEST(LogEntryTest4, SerializationDeserialization_WorksCorrectly)
{
    LogEntry entry(LogEntry::ActionType::READ, "storage/files", "controllerABC", "processorDEF", "subjectXYZ");

    std::vector<uint8_t> serializedData = entry.serialize();
    LogEntry newEntry;
    bool success = newEntry.deserialize(std::move(serializedData));

    EXPECT_TRUE(success);
    EXPECT_EQ(newEntry.getActionType(), LogEntry::ActionType::READ);
    EXPECT_EQ(newEntry.getDataLocation(), "storage/files");
    EXPECT_EQ(newEntry.getDataControllerId(), "controllerABC");
    EXPECT_EQ(newEntry.getDataProcessorId(), "processorDEF");
    EXPECT_EQ(newEntry.getDataSubjectId(), "subjectXYZ");
    EXPECT_EQ(newEntry.getPayload().size(), 0); // Payload should still be empty

    std::vector<uint8_t> serializedData2 = entry.serialize();
    success = newEntry.deserialize(std::move(serializedData2));

    EXPECT_TRUE(success);

    EXPECT_EQ(newEntry.getActionType(), LogEntry::ActionType::READ);
    EXPECT_EQ(newEntry.getDataLocation(), "storage/files");
    EXPECT_EQ(newEntry.getDataControllerId(), "controllerABC");
    EXPECT_EQ(newEntry.getDataSubjectId(), "subjectXYZ");
    EXPECT_NEAR(std::chrono::system_clock::to_time_t(newEntry.getTimestamp()),
                std::chrono::system_clock::to_time_t(entry.getTimestamp()), 1);
}

// Test serialization and deserialization with payload
TEST(LogEntryTest4A, SerializationDeserializationWithPayload_WorksCorrectly)
{
    // Create test payload
    std::vector<uint8_t> testPayload(64);
    for (size_t i = 0; i < testPayload.size(); ++i)
    {
        testPayload[i] = static_cast<uint8_t>(i & 0xFF);
    }

    LogEntry entry(LogEntry::ActionType::READ, "storage/files", "controllerABC", "processorDEF", "subjectXYZ", testPayload);

    // Serialize and deserialize
    std::vector<uint8_t> serializedData = entry.serialize();
    LogEntry newEntry;
    bool success = newEntry.deserialize(std::move(serializedData));

    // Verify deserialization worked
    EXPECT_TRUE(success);
    EXPECT_EQ(newEntry.getActionType(), LogEntry::ActionType::READ);
    EXPECT_EQ(newEntry.getDataLocation(), "storage/files");
    EXPECT_EQ(newEntry.getDataControllerId(), "controllerABC");
    EXPECT_EQ(newEntry.getDataProcessorId(), "processorDEF");
    EXPECT_EQ(newEntry.getDataSubjectId(), "subjectXYZ");

    // Verify payload
    EXPECT_EQ(newEntry.getPayload().size(), testPayload.size());

    // Check payload content
    const auto &recoveredPayload = newEntry.getPayload();
    bool payloadMatches = true;
    for (size_t i = 0; i < testPayload.size(); ++i)
    {
        if (recoveredPayload[i] != testPayload[i])
        {
            payloadMatches = false;
            break;
        }
    }
    EXPECT_TRUE(payloadMatches);
}

// Test batch serialization and deserialization with payloads
TEST(LogEntryTest5, BatchSerializationDeserialization_WorksCorrectly)
{
    // Create a batch of log entries
    std::vector<LogEntry> originalEntries;

    // Entry with no payload
    originalEntries.push_back(LogEntry(LogEntry::ActionType::CREATE, "db/users", "controller1", "processor1", "subject1"));

    // Entry with small payload
    std::vector<uint8_t> payload2(16, 0x22); // 16 bytes of 0x22
    originalEntries.push_back(LogEntry(LogEntry::ActionType::READ, "files/documents", "controller2", "processor2", "subject2", payload2));

    // Entry with medium payload
    std::vector<uint8_t> payload3(128, 0x33); // 128 bytes of 0x33
    originalEntries.push_back(LogEntry(LogEntry::ActionType::UPDATE, "cache/profiles", "controller3", "processor3", "subject3", payload3));

    // Entry with large payload
    std::vector<uint8_t> payload4(1024, 0x44); // 1024 bytes of 0x44
    originalEntries.push_back(LogEntry(LogEntry::ActionType::DELETE, "archive/logs", "controller4", "processor4", "subject4", payload4));

    // Serialize the batch
    std::vector<uint8_t> batchData = LogEntry::serializeBatch(std::move(originalEntries));

    // Check that the batch has reasonable size
    EXPECT_GT(batchData.size(), sizeof(uint32_t)); // At least space for entry count

    // Deserialize the batch
    std::vector<LogEntry> recoveredEntries = LogEntry::deserializeBatch(std::move(batchData));

    // Verify the number of entries
    EXPECT_EQ(recoveredEntries.size(), originalEntries.size());

    // Verify each entry's data
    for (size_t i = 0; i < originalEntries.size() && i < recoveredEntries.size(); ++i)
    {
        EXPECT_EQ(recoveredEntries[i].getActionType(), originalEntries[i].getActionType());
        EXPECT_EQ(recoveredEntries[i].getDataLocation(), originalEntries[i].getDataLocation());
        EXPECT_EQ(recoveredEntries[i].getDataControllerId(), originalEntries[i].getDataControllerId());
        EXPECT_EQ(recoveredEntries[i].getDataProcessorId(), originalEntries[i].getDataProcessorId());
        EXPECT_EQ(recoveredEntries[i].getDataSubjectId(), originalEntries[i].getDataSubjectId());

        // Verify payload size
        EXPECT_EQ(recoveredEntries[i].getPayload().size(), originalEntries[i].getPayload().size());

        // Check payload content if it's not empty
        if (!originalEntries[i].getPayload().empty())
        {
            const auto &originalPayload = originalEntries[i].getPayload();
            const auto &recoveredPayload = recoveredEntries[i].getPayload();

            bool payloadMatches = true;
            for (size_t j = 0; j < originalPayload.size(); ++j)
            {
                if (recoveredPayload[j] != originalPayload[j])
                {
                    payloadMatches = false;
                    break;
                }
            }
            EXPECT_TRUE(payloadMatches) << "Payload mismatch at entry " << i;
        }

        // Compare timestamps (allowing 1 second difference for potential precision issues)
        EXPECT_NEAR(
            std::chrono::system_clock::to_time_t(recoveredEntries[i].getTimestamp()),
            std::chrono::system_clock::to_time_t(originalEntries[i].getTimestamp()),
            1);
    }
}

// Regression: a malformed batch with a huge entrySize must be rejected cleanly
// (deserializeBatch returns an empty vector) instead of attempting a 4 GB allocation.
TEST(LogEntryRegression, DeserializeBatchRejectsOversizedEntry)
{
    // numEntries=1, entrySize=UINT32_MAX — exceeds MAX_ENTRY_SIZE.
    std::vector<uint8_t> malformed(sizeof(uint32_t) + sizeof(uint32_t), 0);
    uint32_t numEntries = 1;
    uint32_t entrySize = std::numeric_limits<uint32_t>::max();
    std::memcpy(malformed.data(), &numEntries, sizeof(numEntries));
    std::memcpy(malformed.data() + sizeof(numEntries), &entrySize, sizeof(entrySize));

    auto recovered = LogEntry::deserializeBatch(std::move(malformed));
    EXPECT_TRUE(recovered.empty()) << "Oversized entry must not produce a LogEntry";
}

// Regression: a single LogEntry with a huge declared payloadSize must cause
// deserialize to return false, not allocate gigabytes.
TEST(LogEntryRegression, DeserializeRejectsOversizedPayload)
{
    // Build a buffer with:
    //   actionType (int), 4× empty strings (each uint32 length = 0),
    //   timestamp (int64), payloadSize = MAX_PAYLOAD_SIZE + 1
    std::vector<uint8_t> buf;
    int actionType = static_cast<int>(LogEntry::ActionType::CREATE);
    buf.insert(buf.end(),
               reinterpret_cast<uint8_t *>(&actionType),
               reinterpret_cast<uint8_t *>(&actionType) + sizeof(actionType));
    for (int i = 0; i < 4; ++i)
    {
        uint32_t zero = 0;
        buf.insert(buf.end(),
                   reinterpret_cast<uint8_t *>(&zero),
                   reinterpret_cast<uint8_t *>(&zero) + sizeof(zero));
    }
    int64_t ts = 0;
    buf.insert(buf.end(),
               reinterpret_cast<uint8_t *>(&ts),
               reinterpret_cast<uint8_t *>(&ts) + sizeof(ts));
    uint32_t bigSize = static_cast<uint32_t>(LogEntry::MAX_PAYLOAD_SIZE) + 1;
    buf.insert(buf.end(),
               reinterpret_cast<uint8_t *>(&bigSize),
               reinterpret_cast<uint8_t *>(&bigSize) + sizeof(bigSize));

    LogEntry entry;
    EXPECT_FALSE(entry.deserialize(std::move(buf)));
}