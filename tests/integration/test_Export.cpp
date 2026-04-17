#include <gtest/gtest.h>
#include "Config.hpp"
#include "LogEntry.hpp"
#include "LoggingManager.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace
{
std::vector<std::string> readLines(const std::string &path)
{
    std::vector<std::string> lines;
    std::ifstream f(path);
    if (!f)
        return lines;
    std::string line;
    while (std::getline(f, line))
    {
        if (!line.empty())
            lines.push_back(line);
    }
    return lines;
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

// Minimal extractor for the NDJSON shape this exporter emits: every field is a
// JSON string with no internal backslash escapes in our test data. The search
// looks for  "<field>":"<value>"  and returns <value>.
std::string extractStringField(const std::string &line, const std::string &field)
{
    std::string key = "\"" + field + "\":\"";
    auto pos = line.find(key);
    if (pos == std::string::npos)
        return "<MISSING:" + field + ">";
    pos += key.size();
    auto end = line.find('"', pos);
    if (end == std::string::npos)
        return "<UNTERMINATED:" + field + ">";
    return line.substr(pos, end - pos);
}

std::vector<uint8_t> base64Decode(const std::string &s)
{
    if (s.empty())
        return {};
    // Our encoder always emits padded, 4-aligned base64 via EVP_EncodeBlock.
    std::vector<uint8_t> out((s.size() / 4) * 3);
    int written = EVP_DecodeBlock(out.data(),
                                  reinterpret_cast<const unsigned char *>(s.data()),
                                  static_cast<int>(s.size()));
    if (written < 0)
        return {};
    size_t pad = 0;
    if (s.size() >= 1 && s.back() == '=')
        ++pad;
    if (s.size() >= 2 && s[s.size() - 2] == '=')
        ++pad;
    out.resize(static_cast<size_t>(written) - pad);
    return out;
}

// Tuple of identifying fields (timestamp excluded because LogEntry stamps it
// internally at construction; we verify timestamps separately by range).
using EntryKey = std::tuple<std::string, std::string, std::string,
                            std::string, std::string, std::vector<uint8_t>>;

const char *actionTypeName(LogEntry::ActionType t)
{
    switch (t)
    {
    case LogEntry::ActionType::CREATE:
        return "CREATE";
    case LogEntry::ActionType::READ:
        return "READ";
    case LogEntry::ActionType::UPDATE:
        return "UPDATE";
    case LogEntry::ActionType::DELETE:
        return "DELETE";
    }
    return "UNKNOWN";
}

EntryKey keyOf(const LogEntry &e)
{
    return EntryKey(actionTypeName(e.getActionType()),
                    e.getDataLocation(),
                    e.getDataControllerId(),
                    e.getDataProcessorId(),
                    e.getDataSubjectId(),
                    e.getPayload());
}

EntryKey keyFromLine(const std::string &line)
{
    return EntryKey(extractStringField(line, "actionType"),
                    extractStringField(line, "dataLocation"),
                    extractStringField(line, "dataControllerId"),
                    extractStringField(line, "dataProcessorId"),
                    extractStringField(line, "dataSubjectId"),
                    base64Decode(extractStringField(line, "payload")));
}
} // namespace

class ExportTest : public ::testing::Test
{
protected:
    std::string testDir;
    std::string outputPath;

    void SetUp() override
    {
        auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        testDir = "./test_export_" + suffix;
        outputPath = testDir + "/export.ndjson";
        std::filesystem::remove_all(testDir);
    }

    void TearDown() override
    {
        std::filesystem::remove_all(testDir);
    }

    LoggingConfig makeConfig(bool useEncryption = true)
    {
        LoggingConfig cfg;
        cfg.basePath = testDir;
        cfg.baseFilename = "exp";
        cfg.queueCapacity = 4096;
        cfg.maxExplicitProducers = 8;
        cfg.numWriterThreads = 2;
        cfg.batchSize = 32;
        cfg.useEncryption = useEncryption;
        cfg.compressionLevel = 6;
        cfg.appendTimeout = std::chrono::milliseconds(5000);
        cfg.maxSegmentSize = 16 * 1024;
        return cfg;
    }
};

TEST_F(ExportTest, RoundTripViaExport)
{
    const int numEntries = 120;
    std::multiset<EntryKey> expected;
    auto testStart = std::chrono::system_clock::now();

    {
        LoggingManager mgr(makeConfig());
        ASSERT_TRUE(mgr.start());
        auto token = mgr.createProducerToken();
        for (int i = 0; i < numEntries; ++i)
        {
            LogEntry entry(LogEntry::ActionType::READ,
                           "loc_" + std::to_string(i),
                           "ctrl_" + std::to_string(i % 2),
                           "proc_" + std::to_string(i % 3),
                           "subj_" + std::to_string(i % 4));
            expected.insert(keyOf(entry));
            ASSERT_TRUE(mgr.append(std::move(entry), token));
        }
        ASSERT_TRUE(mgr.stop());
        ASSERT_TRUE(mgr.exportLogs(outputPath));
    }
    auto testEnd = std::chrono::system_clock::now();

    auto lines = readLines(outputPath);
    ASSERT_EQ(static_cast<int>(lines.size()), numEntries);

    std::multiset<EntryKey> actual;
    for (const auto &line : lines)
    {
        actual.insert(keyFromLine(line));
        // Every timestamp is RFC 3339 UTC and falls within the test window.
        const std::string ts = extractStringField(line, "timestamp");
        EXPECT_EQ(ts.size(), 24u) << ts;
        EXPECT_EQ(ts.back(), 'Z') << ts;
        EXPECT_EQ(ts[4], '-') << ts;
        EXPECT_EQ(ts[7], '-') << ts;
        EXPECT_EQ(ts[10], 'T') << ts;
        EXPECT_EQ(ts[13], ':') << ts;
        EXPECT_EQ(ts[16], ':') << ts;
        EXPECT_EQ(ts[19], '.') << ts;
    }
    EXPECT_EQ(actual, expected);

    // Year check: both test_start and test_end must share a year with every
    // exported timestamp. (Tight range comparison would require parsing the
    // string back, which this suite deliberately keeps simple.)
    auto yearOf = [](std::chrono::system_clock::time_point tp)
    {
        std::time_t t = std::chrono::system_clock::to_time_t(tp);
        std::tm tm{};
        gmtime_r(&t, &tm);
        return tm.tm_year + 1900;
    };
    int startYear = yearOf(testStart);
    int endYear = yearOf(testEnd);
    for (const auto &line : lines)
    {
        int lineYear = std::stoi(extractStringField(line, "timestamp").substr(0, 4));
        EXPECT_GE(lineYear, startYear);
        EXPECT_LE(lineYear, endYear);
    }
}

// Byte-exact round-trip for payloads of assorted sizes and byte values,
// including values that stress base64 padding (0, 1, 2 mod 3 lengths) and
// edge bytes (0x00, 0xFF).
TEST_F(ExportTest, PayloadBytesSurviveRoundTrip)
{
    std::vector<std::vector<uint8_t>> payloads = {
        {},
        {0x00},
        {0xFF},
        {0x00, 0x01, 0x02},           // 3-aligned
        {0xDE, 0xAD, 0xBE, 0xEF},     // 1 mod 3
        {0x01, 0x02, 0x03, 0x04, 0x05}, // 2 mod 3
        {'h', 'e', 'l', 'l', 'o'},
    };
    // Add a 1KB pseudo-random buffer so the test also exercises larger payloads.
    std::vector<uint8_t> big(1024);
    for (size_t i = 0; i < big.size(); ++i)
        big[i] = static_cast<uint8_t>((i * 31 + 7) & 0xFF);
    payloads.push_back(std::move(big));

    std::multiset<EntryKey> expected;
    {
        LoggingManager mgr(makeConfig());
        ASSERT_TRUE(mgr.start());
        auto token = mgr.createProducerToken();
        for (size_t i = 0; i < payloads.size(); ++i)
        {
            LogEntry entry(LogEntry::ActionType::UPDATE,
                           "loc_" + std::to_string(i),
                           "ctrl", "proc", "subj",
                           payloads[i]);
            expected.insert(keyOf(entry));
            ASSERT_TRUE(mgr.append(std::move(entry), token));
        }
        ASSERT_TRUE(mgr.stop());
        ASSERT_TRUE(mgr.exportLogs(outputPath));
    }

    auto lines = readLines(outputPath);
    ASSERT_EQ(lines.size(), payloads.size());

    std::multiset<EntryKey> actual;
    for (const auto &line : lines)
        actual.insert(keyFromLine(line));
    EXPECT_EQ(actual, expected);
}

TEST_F(ExportTest, TimeRangeFilter)
{
    std::chrono::system_clock::time_point cutoff;
    const int before = 20;
    const int after = 30;
    std::multiset<EntryKey> expectedAfter;

    {
        LoggingManager mgr(makeConfig());
        ASSERT_TRUE(mgr.start());
        auto token = mgr.createProducerToken();
        for (int i = 0; i < before; ++i)
        {
            LogEntry entry(LogEntry::ActionType::CREATE,
                           "early_" + std::to_string(i), "c", "p", "s");
            ASSERT_TRUE(mgr.append(std::move(entry), token));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        cutoff = std::chrono::system_clock::now();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        for (int i = 0; i < after; ++i)
        {
            LogEntry entry(LogEntry::ActionType::CREATE,
                           "late_" + std::to_string(i), "c", "p", "s");
            expectedAfter.insert(keyOf(entry));
            ASSERT_TRUE(mgr.append(std::move(entry), token));
        }
        ASSERT_TRUE(mgr.stop());
        ASSERT_TRUE(mgr.exportLogs(outputPath, cutoff));
    }

    auto lines = readLines(outputPath);
    ASSERT_EQ(static_cast<int>(lines.size()), after);

    std::multiset<EntryKey> actual;
    for (const auto &line : lines)
        actual.insert(keyFromLine(line));
    EXPECT_EQ(actual, expectedAfter);
}

TEST_F(ExportTest, SubjectIdFilter)
{
    const int perSubject = 15;
    std::multiset<EntryKey> expectedBob;

    {
        LoggingManager mgr(makeConfig());
        ASSERT_TRUE(mgr.start());
        auto token = mgr.createProducerToken();
        for (const auto *subj : {"alice", "bob", "carol"})
        {
            for (int i = 0; i < perSubject; ++i)
            {
                LogEntry entry(LogEntry::ActionType::UPDATE,
                               "loc_" + std::to_string(i), "c", "p", subj);
                if (std::string(subj) == "bob")
                    expectedBob.insert(keyOf(entry));
                ASSERT_TRUE(mgr.append(std::move(entry), token));
            }
        }
        ASSERT_TRUE(mgr.stop());
        ASSERT_TRUE(mgr.exportLogs(outputPath,
                                   std::chrono::system_clock::time_point(),
                                   std::chrono::system_clock::time_point(),
                                   std::string("bob")));
    }

    auto lines = readLines(outputPath);
    ASSERT_EQ(static_cast<int>(lines.size()), perSubject);

    std::multiset<EntryKey> actual;
    for (const auto &line : lines)
        actual.insert(keyFromLine(line));
    EXPECT_EQ(actual, expectedBob);
}

TEST_F(ExportTest, TamperingAborts)
{
    {
        LoggingManager mgr(makeConfig());
        ASSERT_TRUE(mgr.start());
        auto token = mgr.createProducerToken();
        for (int i = 0; i < 50; ++i)
        {
            LogEntry entry(LogEntry::ActionType::CREATE,
                           "loc_" + std::to_string(i), "c", "p", "s");
            ASSERT_TRUE(mgr.append(std::move(entry), token));
        }
        ASSERT_TRUE(mgr.stop());

        auto segments = listLogFiles(testDir);
        ASSERT_FALSE(segments.empty());
        std::vector<char> content;
        {
            std::ifstream in(segments[0], std::ios::binary);
            content.assign(std::istreambuf_iterator<char>(in),
                           std::istreambuf_iterator<char>());
        }
        ASSERT_GT(content.size(), 32u);
        content[10] ^= 0xFF;
        {
            std::ofstream out(segments[0], std::ios::binary | std::ios::trunc);
            out.write(content.data(), static_cast<std::streamsize>(content.size()));
        }

        EXPECT_FALSE(mgr.exportLogs(outputPath));
    }

    EXPECT_FALSE(std::filesystem::exists(outputPath));
}

TEST_F(ExportTest, RejectsWhileRunning)
{
    LoggingManager mgr(makeConfig());
    ASSERT_TRUE(mgr.start());

    EXPECT_FALSE(mgr.exportLogs(outputPath));
    EXPECT_FALSE(std::filesystem::exists(outputPath));

    ASSERT_TRUE(mgr.stop());
}

TEST_F(ExportTest, RejectsWithEncryptionDisabled)
{
    LoggingManager mgr(makeConfig(/*useEncryption=*/false));
    ASSERT_TRUE(mgr.start());
    auto token = mgr.createProducerToken();
    for (int i = 0; i < 10; ++i)
    {
        LogEntry entry(LogEntry::ActionType::READ, "loc", "c", "p", "s");
        ASSERT_TRUE(mgr.append(std::move(entry), token));
    }
    ASSERT_TRUE(mgr.stop());

    EXPECT_FALSE(mgr.exportLogs(outputPath));
    EXPECT_FALSE(std::filesystem::exists(outputPath));
}
