#include <gtest/gtest.h>
#include "ByteOrder.hpp"
#include "Compression.hpp"
#include "Config.hpp"
#include "Crypto.hpp"
#include "LogEntry.hpp"
#include "LoggingManager.hpp"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

// End-to-end round-trip: producers → LoggingManager → disk → decrypt → decompress →
// deserialize. Reads segment files manually because LoggingManager::exportLogs is a stub
// on this branch. Uses the same hardcoded placeholder key/IV that Writer currently uses
// (see [src/Writer.cpp]); real key management is out of scope for this hardening pass.

namespace
{
constexpr uint8_t kPlaceholderKeyByte = 0x42;
constexpr uint8_t kPlaceholderIVByte = 0x24;

std::vector<uint8_t> readFile(const std::string &path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        return {};
    auto size = f.tellg();
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    f.seekg(0);
    f.read(reinterpret_cast<char *>(buf.data()), size);
    return buf;
}

// Split a segment file into the concatenated encrypted blobs Writer produced.
// Format per blob: [u32 ciphertextSize][ciphertext][GCM_TAG_SIZE bytes tag].
std::vector<std::vector<uint8_t>> splitSegmentIntoBlobs(const std::vector<uint8_t> &segment)
{
    std::vector<std::vector<uint8_t>> blobs;
    size_t pos = 0;
    while (pos + sizeof(uint32_t) <= segment.size())
    {
        uint32_t ciphertextSize = byteorder::readLE32(segment.data() + pos);
        size_t blobSize = sizeof(uint32_t) + ciphertextSize + Crypto::GCM_TAG_SIZE;
        if (pos + blobSize > segment.size())
            break; // truncated trailer — shouldn't happen after clean stop()
        blobs.emplace_back(segment.begin() + pos, segment.begin() + pos + blobSize);
        pos += blobSize;
    }
    return blobs;
}

std::vector<LogEntry> decryptSegmentToEntries(const std::vector<uint8_t> &segment)
{
    Crypto crypto;
    std::vector<uint8_t> key(Crypto::KEY_SIZE, kPlaceholderKeyByte);
    std::vector<uint8_t> iv(Crypto::GCM_IV_SIZE, kPlaceholderIVByte);

    std::vector<LogEntry> out;
    for (auto &blob : splitSegmentIntoBlobs(segment))
    {
        auto plaintext = crypto.decrypt(blob, key, iv);
        auto decompressed = Compression::decompress(std::move(plaintext));
        auto entries = LogEntry::deserializeBatch(std::move(decompressed));
        for (auto &e : entries)
            out.emplace_back(std::move(e));
    }
    return out;
}

std::vector<std::string> listSegments(const std::string &dir, const std::string &baseFilename)
{
    std::vector<std::string> files;
    for (const auto &entry : std::filesystem::directory_iterator(dir))
    {
        if (entry.is_regular_file())
        {
            std::string name = entry.path().filename().string();
            if (name.find(baseFilename) == 0 && name.rfind(".log") != std::string::npos)
                files.push_back(entry.path().string());
        }
    }
    std::sort(files.begin(), files.end());
    return files;
}
} // namespace

class RoundTripTest : public ::testing::Test
{
protected:
    std::string testDir;

    void SetUp() override
    {
        testDir = "./test_roundtrip_" +
                  std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        std::filesystem::remove_all(testDir);
    }

    void TearDown() override
    {
        std::filesystem::remove_all(testDir);
    }

    LoggingConfig makeConfig()
    {
        LoggingConfig cfg;
        cfg.basePath = testDir;
        cfg.baseFilename = "rt";
        cfg.queueCapacity = 4096;
        cfg.maxExplicitProducers = 8;
        cfg.numWriterThreads = 2;
        cfg.batchSize = 32;
        cfg.useEncryption = true;
        cfg.compressionLevel = 6;
        cfg.appendTimeout = std::chrono::milliseconds(5000);
        cfg.maxSegmentSize = 8 * 1024; // small, to force rotation
        return cfg;
    }
};

TEST_F(RoundTripTest, ProducesRecoverableEntries)
{
    const int numProducers = 3;
    const int entriesPerProducer = 200;
    const int totalExpected = numProducers * entriesPerProducer;

    {
        LoggingManager mgr(makeConfig());
        ASSERT_TRUE(mgr.start());

        std::vector<std::thread> producers;
        for (int p = 0; p < numProducers; ++p)
        {
            producers.emplace_back([&, p]()
                                   {
                auto token = mgr.createProducerToken();
                for (int i = 0; i < entriesPerProducer; ++i)
                {
                    LogEntry entry(
                        LogEntry::ActionType::READ,
                        "loc_" + std::to_string(p) + "_" + std::to_string(i),
                        "ctrl_" + std::to_string(p),
                        "proc_" + std::to_string(p),
                        "subj_" + std::to_string(i));
                    ASSERT_TRUE(mgr.append(std::move(entry), token));
                } });
        }
        for (auto &t : producers)
            t.join();
        ASSERT_TRUE(mgr.stop());
    }

    // Read back all segments and count entries.
    auto files = listSegments(testDir, "rt");
    ASSERT_FALSE(files.empty()) << "Expected at least one segment";

    std::vector<LogEntry> recovered;
    for (const auto &f : files)
    {
        auto segment = readFile(f);
        auto entries = decryptSegmentToEntries(segment);
        for (auto &e : entries)
            recovered.emplace_back(std::move(e));
    }

    EXPECT_EQ(static_cast<int>(recovered.size()), totalExpected)
        << "Round-trip lost or duplicated entries";

    // Spot-check a few fields. We can't rely on order (multiple writers, multiple files),
    // so we verify every recovered entry has a well-formed location/controller pair.
    for (const auto &e : recovered)
    {
        EXPECT_EQ(e.getActionType(), LogEntry::ActionType::READ);
        EXPECT_EQ(e.getDataLocation().rfind("loc_", 0), 0u);
        EXPECT_EQ(e.getDataControllerId().rfind("ctrl_", 0), 0u);
    }
}

// Regression: a single flipped byte in a persisted segment must cause decrypt to throw
// TamperDetectedException, not silently return empty plaintext.
TEST_F(RoundTripTest, TamperingInSegmentIsDetected)
{
    {
        LoggingManager mgr(makeConfig());
        ASSERT_TRUE(mgr.start());
        auto token = mgr.createProducerToken();
        for (int i = 0; i < 50; ++i)
        {
            LogEntry entry(LogEntry::ActionType::CREATE,
                           "loc_" + std::to_string(i),
                           "ctrl", "proc", "subj");
            ASSERT_TRUE(mgr.append(std::move(entry), token));
        }
        ASSERT_TRUE(mgr.stop());
    }

    auto files = listSegments(testDir, "rt");
    ASSERT_FALSE(files.empty());

    // Corrupt a byte in the first blob's ciphertext region (offset ~10: past the 4-byte
    // size field, inside the encrypted payload).
    auto segment = readFile(files[0]);
    ASSERT_GT(segment.size(), 32u);
    segment[10] ^= 0xFF;

    EXPECT_THROW(decryptSegmentToEntries(segment), TamperDetectedException);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
