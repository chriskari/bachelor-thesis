#include <gtest/gtest.h>
#include "LogEntry.hpp"
#include <vector>
#include <iostream>
#include <chrono>
#include <optional>

// Test default constructor
TEST(LogEntryTest1, DefaultConstructor_InitializesCorrectly)
{
    LogEntry entry;

    EXPECT_EQ(entry.getActionType(), LogEntry::ActionType::CREATE);
    EXPECT_EQ(entry.getDataLocation(), "");
    EXPECT_EQ(entry.getUserId(), "");
    EXPECT_EQ(entry.getDataSubjectId(), "");
    EXPECT_FALSE(entry.getTargetFilename().has_value());

    auto now = std::chrono::system_clock::now();
    EXPECT_NEAR(
        std::chrono::system_clock::to_time_t(entry.getTimestamp()),
        std::chrono::system_clock::to_time_t(now),
        1);
}

// Test parameterized constructor without filename
TEST(LogEntryTest2, ParameterizedConstructor_SetsFieldsCorrectly)
{
    LogEntry entry(
        LogEntry::ActionType::UPDATE,
        "database/users",
        "user123",
        "subject456");

    EXPECT_EQ(entry.getActionType(), LogEntry::ActionType::UPDATE);
    EXPECT_EQ(entry.getDataLocation(), "database/users");
    EXPECT_EQ(entry.getUserId(), "user123");
    EXPECT_EQ(entry.getDataSubjectId(), "subject456");
    EXPECT_FALSE(entry.getTargetFilename().has_value());

    auto now = std::chrono::system_clock::now();
    EXPECT_NEAR(
        std::chrono::system_clock::to_time_t(entry.getTimestamp()),
        std::chrono::system_clock::to_time_t(now),
        1);
}

// Test parameterized constructor with filename
TEST(LogEntryTest3, ParameterizedConstructor_WithFilename_SetsFilenameCorrectly)
{
    LogEntry entry(
        LogEntry::ActionType::CREATE,
        "db/table",
        "userABC",
        "subjectXYZ",
        std::optional<std::string>("audit.log"));

    EXPECT_EQ(entry.getActionType(), LogEntry::ActionType::CREATE);
    EXPECT_EQ(entry.getDataLocation(), "db/table");
    EXPECT_EQ(entry.getUserId(), "userABC");
    EXPECT_EQ(entry.getDataSubjectId(), "subjectXYZ");
    ASSERT_TRUE(entry.getTargetFilename().has_value());
    EXPECT_EQ(entry.getTargetFilename().value(), "audit.log");
}

// Test setter methods
TEST(LogEntryTest4, Setters_UpdateFieldsCorrectly)
{
    LogEntry entry;

    entry.setActionType(LogEntry::ActionType::DELETE);
    entry.setDataLocation("server/logs");
    entry.setUserId("admin");
    entry.setDataSubjectId("subject789");
    entry.setTargetFilename(std::optional<std::string>("privacy.log"));

    EXPECT_EQ(entry.getActionType(), LogEntry::ActionType::DELETE);
    EXPECT_EQ(entry.getDataLocation(), "server/logs");
    EXPECT_EQ(entry.getUserId(), "admin");
    EXPECT_EQ(entry.getDataSubjectId(), "subject789");
    ASSERT_TRUE(entry.getTargetFilename().has_value());
    EXPECT_EQ(entry.getTargetFilename().value(), "privacy.log");
}

// Test serialization and deserialization without filename
TEST(LogEntryTest5, SerializationDeserialization_WithoutFilename_WorksCorrectly)
{
    LogEntry entry(
        LogEntry::ActionType::READ,
        "storage/files",
        "userABC",
        "subjectXYZ");

    std::vector<uint8_t> serializedData = entry.serialize();
    LogEntry newEntry;
    bool success = newEntry.deserialize(serializedData);

    EXPECT_TRUE(success);
    EXPECT_EQ(newEntry.getActionType(), LogEntry::ActionType::READ);
    EXPECT_EQ(newEntry.getDataLocation(), "storage/files");
    EXPECT_EQ(newEntry.getUserId(), "userABC");
    EXPECT_EQ(newEntry.getDataSubjectId(), "subjectXYZ");
    EXPECT_FALSE(newEntry.getTargetFilename().has_value());
    EXPECT_NEAR(
        std::chrono::system_clock::to_time_t(newEntry.getTimestamp()),
        std::chrono::system_clock::to_time_t(entry.getTimestamp()),
        1);
}

// Test serialization and deserialization with filename
TEST(LogEntryTest6, SerializationDeserialization_WithFilename_WorksCorrectly)
{
    LogEntry entry(
        LogEntry::ActionType::DELETE,
        "bucket/objects",
        "userXYZ",
        "subject123",
        std::optional<std::string>("custom.log"));

    std::vector<uint8_t> serializedData = entry.serialize();
    LogEntry newEntry;
    bool success = newEntry.deserialize(serializedData);

    EXPECT_TRUE(success);
    EXPECT_EQ(newEntry.getActionType(), LogEntry::ActionType::DELETE);
    EXPECT_EQ(newEntry.getDataLocation(), "bucket/objects");
    EXPECT_EQ(newEntry.getUserId(), "userXYZ");
    EXPECT_EQ(newEntry.getDataSubjectId(), "subject123");
    ASSERT_TRUE(newEntry.getTargetFilename().has_value());
    EXPECT_EQ(newEntry.getTargetFilename().value(), "custom.log");
    EXPECT_NEAR(
        std::chrono::system_clock::to_time_t(newEntry.getTimestamp()),
        std::chrono::system_clock::to_time_t(entry.getTimestamp()),
        1);
}

// Test action type conversion functions
TEST(LogEntryTest7, ActionTypeConversion_ValidAndInvalidCases)
{
    EXPECT_EQ(actionTypeToString(LogEntry::ActionType::CREATE), "CREATE");
    EXPECT_EQ(actionTypeToString(LogEntry::ActionType::READ), "READ");
    EXPECT_EQ(actionTypeToString(LogEntry::ActionType::UPDATE), "UPDATE");
    EXPECT_EQ(actionTypeToString(LogEntry::ActionType::DELETE), "DELETE");

    EXPECT_THROW(actionTypeToString(static_cast<LogEntry::ActionType>(99)), std::invalid_argument);
}