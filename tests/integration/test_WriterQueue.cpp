#include <gtest/gtest.h>
#include "Writer.hpp"
#include "LockFreeQueue.hpp"
#include "SegmentedStorage.hpp"
#include <chrono>
#include <thread>
#include <vector>
#include <filesystem>

class WriterIntegrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Create a temporary directory for test log segments
        testDir = "test_logs";
        std::filesystem::create_directories(testDir);
        logQueue = std::make_unique<LockFreeQueue>(1024);

        // Create a SegmentedStorage instance with reduced sizes for testing
        storage = std::make_shared<SegmentedStorage>(
            testDir,
            "test_logsegment",
            1024 * 1024, // Maximum segment size (1 MB for testing)
            1024         // Buffer size (1 KB for testing)
        );

        writer = std::make_unique<Writer>(*logQueue, storage);
    }

    void TearDown() override
    {
        if (writer)
        {
            writer->stop();
        }
        std::filesystem::remove_all(testDir);
    }

    std::unique_ptr<LockFreeQueue> logQueue;
    std::unique_ptr<Writer> writer;
    std::shared_ptr<SegmentedStorage> storage;
    std::string testDir;

    QueueItem createTestItem(int id)
    {
        QueueItem item;
        item.entry = LogEntry(
            LogEntry::ActionType::UPDATE,
            "location" + std::to_string(id),
            "user" + std::to_string(id),
            "subject" + std::to_string(id % 10));
        return item;
    }
};

// Test basic processing functionality
TEST_F(WriterIntegrationTest, BasicWriteOperation)
{
    const int NUM_ENTRIES = 500;
    for (int i = 0; i < NUM_ENTRIES; ++i)
    {
        ASSERT_TRUE(logQueue->enqueueBlocking(createTestItem(i), std::chrono::milliseconds(100)))
            << "Failed to enqueue entry " << i;
    }

    EXPECT_EQ(logQueue->size(), 500);

    writer->start();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    writer->stop();

    EXPECT_EQ(logQueue->size(), 0) << "Not all entries were processed";
}

// Test concurrent writing and processing
TEST_F(WriterIntegrationTest, ConcurrentWriteAndProcess)
{
    const int NUM_ENTRIES = 1000;
    const int NUM_PRODUCERS = 4;

    // Function to simulate producers adding log entries
    auto producer = [this](int start, int count)
    {
        for (int i = start; i < start + count; ++i)
        {
            // Introduce a small delay to simulate variability
            std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 10));
            logQueue->enqueueBlocking(createTestItem(i), std::chrono::milliseconds(500));
        }
    };

    writer->start();

    std::vector<std::thread> producerThreads;
    for (int i = 0; i < NUM_PRODUCERS; ++i)
    {
        producerThreads.emplace_back(producer, i * (NUM_ENTRIES / NUM_PRODUCERS),
                                     NUM_ENTRIES / NUM_PRODUCERS);
    }

    // Wait for all producer threads to finish
    for (auto &t : producerThreads)
    {
        t.join();
    }

    // Allow some time for the writer to process the entries
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    writer->stop();

    EXPECT_EQ(logQueue->size(), 0) << "Not all entries were processed";
}