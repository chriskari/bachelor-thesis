#include <gtest/gtest.h>
#include "ByteOrder.hpp"
#include "Config.hpp"
#include "Crypto.hpp"
#include "LogEntry.hpp"
#include "LoggingManager.hpp"
#include "PlaceholderCryptoMaterial.hpp"
#include "SealMarker.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

// Each test writes a real log, mutates the segment bytes on disk to simulate
// an attacker, and checks the exporter's response.

namespace
{
struct BlobSpan
{
    size_t offset;
    size_t size;
};

std::vector<uint8_t> readSegment(const std::string &path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    EXPECT_TRUE(f);
    auto size = f.tellg();
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    f.seekg(0);
    f.read(reinterpret_cast<char *>(buf.data()), size);
    return buf;
}

void writeSegment(const std::string &path, const std::vector<uint8_t> &data)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(f);
    f.write(reinterpret_cast<const char *>(data.data()),
            static_cast<std::streamsize>(data.size()));
}

std::vector<BlobSpan> scanBlobs(const std::vector<uint8_t> &segment)
{
    std::vector<BlobSpan> spans;
    size_t pos = 0;
    while (pos + sizeof(uint32_t) <= segment.size())
    {
        uint32_t ciphertextSize = byteorder::readLE32(segment.data() + pos);
        size_t blobSize = sizeof(uint32_t) + Crypto::SEQNUM_SIZE + Crypto::GCM_IV_SIZE +
                          ciphertextSize + Crypto::GCM_TAG_SIZE;
        if (pos + blobSize > segment.size())
            break;
        spans.push_back({pos, blobSize});
        pos += blobSize;
    }
    return spans;
}

std::vector<std::string> listLogFiles(const std::string &dir)
{
    std::vector<std::string> files;
    for (const auto &entry : std::filesystem::directory_iterator(dir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
            files.push_back(entry.path().string());
    }
    std::sort(files.begin(), files.end());
    return files;
}

size_t countLines(const std::string &path)
{
    std::ifstream f(path);
    if (!f)
        return 0;
    size_t n = 0;
    std::string line;
    while (std::getline(f, line))
        if (!line.empty())
            ++n;
    return n;
}
} // namespace

class TamperSeqnumTest : public ::testing::Test
{
protected:
    std::string testDir;
    std::string outputPath;

    void SetUp() override
    {
        auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        testDir = "./test_tamper_seqnum_" + suffix;
        outputPath = testDir + "/export.ndjson";
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
        cfg.baseFilename = "ts";
        cfg.queueCapacity = 4096;
        cfg.maxExplicitProducers = 8;
        cfg.numWriterThreads = 2;
        // One entry per batch so each LogEntry maps 1:1 to a blob.
        cfg.batchSize = 1;
        cfg.useEncryption = true;
        cfg.compressionLevel = 1;
        cfg.appendTimeout = std::chrono::milliseconds(5000);
        cfg.maxSegmentSize = 64 * 1024;
        return cfg;
    }

    void writeEntries(LoggingManager &mgr, int count)
    {
        auto token = mgr.createProducerToken();
        for (int i = 0; i < count; ++i)
        {
            LogEntry entry(LogEntry::ActionType::CREATE,
                           "loc_" + std::to_string(i), "c", "p", "s");
            ASSERT_TRUE(mgr.append(std::move(entry), token));
        }
    }
};

TEST_F(TamperSeqnumTest, DeletedBatchDetected)
{
    LoggingManager mgr(makeConfig());
    ASSERT_TRUE(mgr.start());
    writeEntries(mgr, 5);
    ASSERT_TRUE(mgr.stop());

    auto segments = listLogFiles(testDir);
    ASSERT_EQ(segments.size(), 1u);

    auto segment = readSegment(segments[0]);
    auto spans = scanBlobs(segment);
    ASSERT_GE(spans.size(), 4u); // data batches + seal

    std::vector<uint8_t> tampered;
    tampered.insert(tampered.end(), segment.begin(), segment.begin() + spans[1].offset);
    tampered.insert(tampered.end(),
                    segment.begin() + spans[1].offset + spans[1].size,
                    segment.end());
    writeSegment(segments[0], tampered);

    EXPECT_FALSE(mgr.exportLogs(outputPath));
    EXPECT_FALSE(std::filesystem::exists(outputPath));
}

TEST_F(TamperSeqnumTest, DuplicateBatchDetected)
{
    LoggingManager mgr(makeConfig());
    ASSERT_TRUE(mgr.start());
    writeEntries(mgr, 4);
    ASSERT_TRUE(mgr.stop());

    auto segments = listLogFiles(testDir);
    ASSERT_EQ(segments.size(), 1u);

    auto segment = readSegment(segments[0]);
    auto spans = scanBlobs(segment);
    ASSERT_GE(spans.size(), 3u);

    std::vector<uint8_t> tampered = segment;
    tampered.insert(tampered.end(),
                    segment.begin() + spans[0].offset,
                    segment.begin() + spans[0].offset + spans[0].size);
    writeSegment(segments[0], tampered);

    EXPECT_FALSE(mgr.exportLogs(outputPath));
    EXPECT_FALSE(std::filesystem::exists(outputPath));
}

TEST_F(TamperSeqnumTest, MovedBatchToDifferentTargetRejected)
{
    LoggingManager mgr(makeConfig());
    ASSERT_TRUE(mgr.start());

    auto token = mgr.createProducerToken();
    for (int i = 0; i < 3; ++i)
    {
        LogEntry entry(LogEntry::ActionType::CREATE,
                       "A_" + std::to_string(i), "c", "p", "s");
        ASSERT_TRUE(mgr.append(std::move(entry), token, std::string("fileA")));
    }
    for (int i = 0; i < 3; ++i)
    {
        LogEntry entry(LogEntry::ActionType::CREATE,
                       "B_" + std::to_string(i), "c", "p", "s");
        ASSERT_TRUE(mgr.append(std::move(entry), token, std::string("fileB")));
    }
    ASSERT_TRUE(mgr.stop());

    auto allSegments = listLogFiles(testDir);
    std::string segA, segB;
    for (const auto &s : allSegments)
    {
        if (s.find("/fileA_") != std::string::npos)
            segA = s;
        if (s.find("/fileB_") != std::string::npos)
            segB = s;
    }
    ASSERT_FALSE(segA.empty());
    ASSERT_FALSE(segB.empty());

    auto segAdata = readSegment(segA);
    auto spansA = scanBlobs(segAdata);
    ASSERT_GE(spansA.size(), 2u);

    auto segBdata = readSegment(segB);
    segBdata.insert(segBdata.end(),
                    segAdata.begin() + spansA[0].offset,
                    segAdata.begin() + spansA[0].offset + spansA[0].size);
    writeSegment(segB, segBdata);

    EXPECT_FALSE(mgr.exportLogs(outputPath));
    EXPECT_FALSE(std::filesystem::exists(outputPath));
}

TEST_F(TamperSeqnumTest, ReorderedBatchesEmittedInOrder)
{
    // Single writer so entry-index == seqnum deterministically. With multiple
    // consumers ConcurrentQueue doesn't guarantee strict FIFO across them.
    LoggingConfig cfg = makeConfig();
    cfg.numWriterThreads = 1;

    LoggingManager mgr(cfg);
    ASSERT_TRUE(mgr.start());
    writeEntries(mgr, 5);
    ASSERT_TRUE(mgr.stop());

    auto segments = listLogFiles(testDir);
    ASSERT_EQ(segments.size(), 1u);

    auto segment = readSegment(segments[0]);
    auto spans = scanBlobs(segment);
    ASSERT_GE(spans.size(), 4u);

    // Swap blobs 1 and 2 on disk; the exporter should still emit in seqnum order.
    std::vector<uint8_t> blob1(segment.begin() + spans[1].offset,
                               segment.begin() + spans[1].offset + spans[1].size);
    std::vector<uint8_t> blob2(segment.begin() + spans[2].offset,
                               segment.begin() + spans[2].offset + spans[2].size);
    std::vector<uint8_t> tampered;
    tampered.insert(tampered.end(), segment.begin(),
                    segment.begin() + spans[1].offset);
    tampered.insert(tampered.end(), blob2.begin(), blob2.end());
    tampered.insert(tampered.end(), blob1.begin(), blob1.end());
    tampered.insert(tampered.end(),
                    segment.begin() + spans[2].offset + spans[2].size,
                    segment.end());
    writeSegment(segments[0], tampered);

    EXPECT_TRUE(mgr.exportLogs(outputPath));
    ASSERT_TRUE(std::filesystem::exists(outputPath));
    EXPECT_EQ(countLines(outputPath), 5u);

    std::ifstream f(outputPath);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line))
    {
        if (!line.empty())
            lines.push_back(line);
    }
    ASSERT_EQ(lines.size(), 5u);
    for (int i = 0; i < 5; ++i)
    {
        std::string expected = "\"dataLocation\":\"loc_" + std::to_string(i) + "\"";
        EXPECT_NE(lines[i].find(expected), std::string::npos)
            << "Line " << i << " did not contain " << expected << ": " << lines[i];
    }
}

TEST_F(TamperSeqnumTest, TruncatedTailDetected)
{
    LoggingManager mgr(makeConfig());
    ASSERT_TRUE(mgr.start());
    writeEntries(mgr, 5);
    ASSERT_TRUE(mgr.stop());

    auto segments = listLogFiles(testDir);
    ASSERT_EQ(segments.size(), 1u);

    auto segment = readSegment(segments[0]);
    auto spans = scanBlobs(segment);
    ASSERT_GE(spans.size(), 6u); // 5 data + 1 seal

    // Drop the two trailing data batches but keep the seal, so the seal's count
    // (5) contradicts the data batches actually present (3).
    const size_t sealSpanIdx = spans.size() - 1;
    const size_t removeA = sealSpanIdx - 1;
    const size_t removeB = sealSpanIdx - 2;

    std::vector<uint8_t> tampered;
    for (size_t i = 0; i < spans.size(); ++i)
    {
        if (i == removeA || i == removeB)
            continue;
        tampered.insert(tampered.end(),
                        segment.begin() + spans[i].offset,
                        segment.begin() + spans[i].offset + spans[i].size);
    }
    writeSegment(segments[0], tampered);

    EXPECT_FALSE(mgr.exportLogs(outputPath));
    EXPECT_FALSE(std::filesystem::exists(outputPath));
}

TEST_F(TamperSeqnumTest, ParallelWritersContiguousSeqnums)
{
    LoggingConfig cfg = makeConfig();
    cfg.numWriterThreads = 8;
    cfg.batchSize = 16;
    cfg.maxSegmentSize = 1024 * 1024;

    const int numProducers = 8;
    const int entriesPerProducer = 125;
    const int totalExpected = numProducers * entriesPerProducer;

    LoggingManager mgr(cfg);
    ASSERT_TRUE(mgr.start());

    std::vector<std::thread> producers;
    for (int p = 0; p < numProducers; ++p)
    {
        producers.emplace_back([&, p]()
                               {
            auto token = mgr.createProducerToken();
            for (int i = 0; i < entriesPerProducer; ++i)
            {
                LogEntry entry(LogEntry::ActionType::UPDATE,
                               "p" + std::to_string(p) + "_i" + std::to_string(i),
                               "c", "p", "s");
                ASSERT_TRUE(mgr.append(std::move(entry), token));
            } });
    }
    for (auto &t : producers)
        t.join();

    ASSERT_TRUE(mgr.stop());

    ASSERT_TRUE(mgr.exportLogs(outputPath));
    EXPECT_EQ(countLines(outputPath), static_cast<size_t>(totalExpected));

    // Export success already implies contiguous seqnums; also assert every
    // distinct producer/index pair is unique to catch duplicate-plus-missing bugs.
    std::ifstream f(outputPath);
    std::unordered_set<std::string> seen;
    std::string line;
    const std::string needle = "\"dataLocation\":\"";
    while (std::getline(f, line))
    {
        if (line.empty())
            continue;
        auto pos = line.find(needle);
        ASSERT_NE(pos, std::string::npos) << line;
        pos += needle.size();
        auto end = line.find('"', pos);
        ASSERT_NE(end, std::string::npos) << line;
        auto loc = line.substr(pos, end - pos);
        auto inserted = seen.insert(std::move(loc));
        EXPECT_TRUE(inserted.second)
            << "Duplicate dataLocation in export: " << *inserted.first;
    }
    EXPECT_EQ(seen.size(), static_cast<size_t>(totalExpected));
}

TEST_F(TamperSeqnumTest, RoundTripAcrossRotation)
{
    LoggingConfig cfg = makeConfig();
    cfg.numWriterThreads = 1;
    cfg.maxSegmentSize = 512; // small enough to rotate

    const int numEntries = 20;

    LoggingManager mgr(cfg);
    ASSERT_TRUE(mgr.start());
    writeEntries(mgr, numEntries);
    ASSERT_TRUE(mgr.stop());

    auto segments = listLogFiles(testDir);
    ASSERT_GE(segments.size(), 2u)
        << "test requires at least 2 segments to exercise rotation";

    ASSERT_TRUE(mgr.exportLogs(outputPath));
    EXPECT_EQ(countLines(outputPath), static_cast<size_t>(numEntries));
}

TEST_F(TamperSeqnumTest, DeletedBatchInNonFirstSegmentDetected)
{
    LoggingConfig cfg = makeConfig();
    cfg.numWriterThreads = 1;
    cfg.maxSegmentSize = 512;

    LoggingManager mgr(cfg);
    ASSERT_TRUE(mgr.start());
    writeEntries(mgr, 20);
    ASSERT_TRUE(mgr.stop());

    auto segments = listLogFiles(testDir);
    ASSERT_GE(segments.size(), 2u);

    // Prefer a middle segment so we're clearly removing a data batch, not the seal.
    std::string targetSegment;
    for (size_t i = 1; i + 1 < segments.size(); ++i)
    {
        auto seg = readSegment(segments[i]);
        if (!scanBlobs(seg).empty())
        {
            targetSegment = segments[i];
            break;
        }
    }
    if (targetSegment.empty())
        targetSegment = segments[1];

    auto segment = readSegment(targetSegment);
    auto spans = scanBlobs(segment);
    ASSERT_GE(spans.size(), 2u);

    std::vector<uint8_t> tampered;
    tampered.insert(tampered.end(), segment.begin(), segment.begin() + spans[0].offset);
    tampered.insert(tampered.end(),
                    segment.begin() + spans[0].offset + spans[0].size,
                    segment.end());
    writeSegment(targetSegment, tampered);

    EXPECT_FALSE(mgr.exportLogs(outputPath));
    EXPECT_FALSE(std::filesystem::exists(outputPath));
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
