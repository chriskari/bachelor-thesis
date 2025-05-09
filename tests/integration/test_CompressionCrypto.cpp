#include <gtest/gtest.h>
#include "Compression.hpp"
#include "Crypto.hpp"
#include "LogEntry.hpp"
#include <vector>
#include <string>
#include <memory>

class CompressionCryptoTest : public ::testing::Test
{
protected:
    Crypto crypto;

    void SetUp() override
    {
        // Create sample log entries for testing
        entry1 = LogEntry(LogEntry::ActionType::CREATE, "/data/records/1", "user123", "subject456");
        entry2 = LogEntry(LogEntry::ActionType::READ, "/data/records/2", "admin789", "subject456");
        entry3 = LogEntry(LogEntry::ActionType::UPDATE, "/data/records/3", "user123", "subject789");

        // Create encryption key and IV
        key = std::vector<uint8_t>(32, 0x42);      // Fixed key for reproducibility
        wrongKey = std::vector<uint8_t>(32, 0x24); // Different key for testing
        dummyIV = std::vector<uint8_t>(12, 0x24);  // Fixed IV for reproducibility
    }

    // Helper function to compare two LogEntry objects
    bool LogEntriesEqual(const LogEntry &a, const LogEntry &b)
    {
        return a.serialize() == b.serialize();
    }

    // Helper function to serialize a batch of log entries
    std::vector<std::vector<uint8_t>> serializeBatch(const std::vector<LogEntry> &entries)
    {
        std::vector<std::vector<uint8_t>> serializedEntries;
        for (const auto &entry : entries)
        {
            serializedEntries.push_back(entry.serialize());
        }
        return serializedEntries;
    }

    LogEntry entry1, entry2, entry3;
    std::vector<uint8_t> key;
    std::vector<uint8_t> wrongKey;
    std::vector<uint8_t> dummyIV;
};

// Batch processing - original -> compress -> encrypt -> decrypt -> decompress -> recovered
TEST_F(CompressionCryptoTest, BatchProcessing)
{
    std::vector<LogEntry> batch = {entry1, entry2, entry3};

    // Serialize the batch first
    std::vector<std::vector<uint8_t>> serializedBatch = serializeBatch(batch);

    // Compress the serialized batch
    std::vector<uint8_t> compressed = Compression::compressBatch(serializedBatch);
    ASSERT_GT(compressed.size(), 0);

    std::vector<uint8_t> encrypted = crypto.encrypt(compressed, key, dummyIV);
    ASSERT_GT(encrypted.size(), 0);
    EXPECT_NE(encrypted, compressed);

    std::vector<uint8_t> decrypted = crypto.decrypt(encrypted, key, dummyIV);
    ASSERT_GT(decrypted.size(), 0);
    EXPECT_EQ(decrypted, compressed);

    std::vector<LogEntry> recovered = Compression::decompressBatch(decrypted);
    ASSERT_EQ(batch.size(), recovered.size());

    for (size_t i = 0; i < batch.size(); i++)
    {
        EXPECT_TRUE(LogEntriesEqual(batch[i], recovered[i]))
            << "Entries at index " << i << " don't match";
    }

    // Test with empty batch
    std::vector<LogEntry> emptyBatch;
    std::vector<std::vector<uint8_t>> emptySerializedBatch = serializeBatch(emptyBatch);
    std::vector<uint8_t> emptyCompressed = Compression::compressBatch(emptySerializedBatch);
    std::vector<uint8_t> emptyEncrypted = crypto.encrypt(emptyCompressed, key, dummyIV);
    std::vector<uint8_t> emptyDecrypted = crypto.decrypt(emptyEncrypted, key, dummyIV);
    std::vector<LogEntry> emptyRecovered = Compression::decompressBatch(emptyDecrypted);
    EXPECT_TRUE(emptyRecovered.empty());

    // Test with single entry batch
    std::vector<LogEntry> singleBatch = {entry1};
    std::vector<std::vector<uint8_t>> singleSerializedBatch = serializeBatch(singleBatch);
    std::vector<uint8_t> singleCompressed = Compression::compressBatch(singleSerializedBatch);
    std::vector<uint8_t> singleEncrypted = crypto.encrypt(singleCompressed, key, dummyIV);
    std::vector<uint8_t> singleDecrypted = crypto.decrypt(singleEncrypted, key, dummyIV);
    std::vector<LogEntry> singleRecovered = Compression::decompressBatch(singleDecrypted);
    ASSERT_EQ(1, singleRecovered.size());
    EXPECT_TRUE(LogEntriesEqual(entry1, singleRecovered[0]));
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}