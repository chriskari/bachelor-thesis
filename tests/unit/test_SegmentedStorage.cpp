#include <gtest/gtest.h>
#include "SegmentedStorage.hpp"
#include <thread>
#include <vector>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <random>
#include <algorithm>
#include <chrono>

class SegmentedStorageTest : public ::testing::Test
{
protected:
    std::string testPath;
    std::string baseFilename;

    void SetUp() override
    {
        testPath = "./test_storage_";
        baseFilename = "test_file";

        if (std::filesystem::exists(testPath))
        {
            std::filesystem::remove_all(testPath);
        }
    }

    std::string getCurrentTimestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_time_t), "%Y%m%d%H%M%S");
        return ss.str();
    }

    std::vector<uint8_t> generateRandomData(size_t size)
    {
        std::vector<uint8_t> data(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);

        std::generate(data.begin(), data.end(), [&]()
                      { return distrib(gen); });
        return data;
    }

    std::vector<std::string> getSegmentFiles(const std::string &basePath, const std::string &baseFilename)
    {
        std::vector<std::string> files;
        for (const auto &entry : std::filesystem::directory_iterator(basePath))
        {
            std::string filename = entry.path().filename().string();
            if (filename.find(baseFilename) == 0 && filename.find(".log") != std::string::npos)
            {
                files.push_back(entry.path().string());
            }
        }
        std::sort(files.begin(), files.end());
        return files;
    }

    size_t getFileSize(const std::string &filepath)
    {
        std::ifstream file(filepath, std::ios::binary | std::ios::ate);
        if (!file.is_open())
        {
            return 0;
        }
        return file.tellg();
    }

    std::vector<uint8_t> readFile(const std::string &filepath)
    {
        std::ifstream file(filepath, std::ios::binary | std::ios::ate);
        if (!file.is_open())
        {
            return {};
        }

        size_t fileSize = file.tellg();
        std::vector<uint8_t> buffer(fileSize);

        file.seekg(0);
        file.read(reinterpret_cast<char *>(buffer.data()), fileSize);

        return buffer;
    }
};

// Test basic writing functionality
TEST_F(SegmentedStorageTest, BasicWriteTest)
{
    SegmentedStorage storage(testPath, baseFilename);

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    // Keep a copy for verification
    std::vector<uint8_t> dataCopy = data;
    size_t bytesWritten = storage.write(std::move(data));

    ASSERT_EQ(bytesWritten, dataCopy.size());

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_EQ(files.size(), 1) << "Only one file should be created";

    auto fileContents = readFile(files[0]);
    ASSERT_EQ(fileContents.size(), dataCopy.size());
    ASSERT_TRUE(std::equal(dataCopy.begin(), dataCopy.end(), fileContents.begin()));
}

// Test segment rotation based on size limit
TEST_F(SegmentedStorageTest, SegmentRotationTest)
{
    size_t maxSegmentSize = 1024;
    SegmentedStorage storage(testPath, baseFilename, maxSegmentSize);

    std::vector<uint8_t> data1 = generateRandomData(maxSegmentSize - 100);
    std::vector<uint8_t> data1Copy = data1; // Copy for verification
    size_t bytesWritten1 = storage.write(std::move(data1));
    ASSERT_EQ(bytesWritten1, data1Copy.size());

    std::vector<uint8_t> data2 = generateRandomData(200);
    std::vector<uint8_t> data2Copy = data2; // Copy for verification
    size_t bytesWritten2 = storage.write(std::move(data2));
    ASSERT_EQ(bytesWritten2, data2Copy.size());

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_EQ(files.size(), 2) << "Two files should be created due to rotation";

    auto file1Contents = readFile(files[0]);
    ASSERT_EQ(file1Contents.size(), data1Copy.size());
    ASSERT_TRUE(std::equal(data1Copy.begin(), data1Copy.end(), file1Contents.begin()));

    auto file2Contents = readFile(files[1]);
    ASSERT_EQ(file2Contents.size(), data2Copy.size());
    ASSERT_TRUE(std::equal(data2Copy.begin(), data2Copy.end(), file2Contents.begin()));
}

// Test writing to a specific file
TEST_F(SegmentedStorageTest, WriteToSpecificFileTest)
{
    SegmentedStorage storage(testPath, baseFilename);

    std::string customFilename = "custom_file";
    std::vector<uint8_t> data = {'C', 'u', 's', 't', 'o', 'm', ' ', 'F', 'i', 'l', 'e'};
    std::vector<uint8_t> dataCopy = data; // Copy for verification
    size_t bytesWritten = storage.writeToFile(customFilename, std::move(data));
    ASSERT_EQ(bytesWritten, dataCopy.size());

    storage.flush();

    auto files = getSegmentFiles(testPath, customFilename);
    ASSERT_EQ(files.size(), 1) << "One custom file should be created";

    auto fileContents = readFile(files[0]);
    ASSERT_EQ(fileContents.size(), dataCopy.size());
    ASSERT_TRUE(std::equal(dataCopy.begin(), dataCopy.end(), fileContents.begin()));
}

// Test concurrent writing to the same file
TEST_F(SegmentedStorageTest, ConcurrentWriteTest)
{
    SegmentedStorage storage(testPath, baseFilename);

    size_t numThreads = 10;
    size_t dataSize = 1000;
    size_t totalSize = numThreads * dataSize;

    std::vector<std::thread> threads;
    std::vector<std::vector<uint8_t>> dataBlocks;
    dataBlocks.reserve(numThreads);

    for (size_t i = 0; i < numThreads; i++)
    {
        dataBlocks.push_back(generateRandomData(dataSize));
        threads.emplace_back([&storage, &dataBlocks, i]()
                             { storage.write(std::move(dataBlocks[i])); });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_EQ(files.size(), 1) << "Only one file should be created";

    size_t fileSize = getFileSize(files[0]);
    ASSERT_EQ(fileSize, totalSize) << "File size should match total written data";
}

// Test concurrent writing with rotation
TEST_F(SegmentedStorageTest, ConcurrentWriteWithRotationTest)
{
    size_t maxSegmentSize = 5000;
    SegmentedStorage storage(testPath, baseFilename, maxSegmentSize);

    size_t numThreads = 20;
    size_t dataSize = 1000;

    std::vector<std::thread> threads;
    std::vector<std::vector<uint8_t>> dataBlocks;
    // Reserve so push_back doesn't reallocate while worker threads hold refs to elements.
    dataBlocks.reserve(numThreads);

    for (size_t i = 0; i < numThreads; i++)
    {
        dataBlocks.push_back(generateRandomData(dataSize));
        threads.emplace_back([&storage, &dataBlocks, i]()
                             { storage.write(std::move(dataBlocks[i])); });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_GT(files.size(), 1) << "Multiple files should be created due to rotation";

    size_t totalFileSize = 0;
    for (const auto &file : files)
    {
        totalFileSize += getFileSize(file);
    }

    ASSERT_EQ(totalFileSize, numThreads * dataSize) << "Total file sizes should match total written data";
}

// Test flush functionality
TEST_F(SegmentedStorageTest, FlushTest)
{
    SegmentedStorage storage(testPath, baseFilename);

    std::vector<uint8_t> data = generateRandomData(1000);
    std::vector<uint8_t> dataCopy = data; // Copy for verification
    storage.write(std::move(data));

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_EQ(files.size(), 1);

    auto fileContents = readFile(files[0]);
    ASSERT_EQ(fileContents.size(), dataCopy.size());
    ASSERT_TRUE(std::equal(dataCopy.begin(), dataCopy.end(), fileContents.begin()));
}

// Test multiple segment files with the same base path
TEST_F(SegmentedStorageTest, MultipleSegmentFilesTest)
{
    SegmentedStorage storage(testPath, baseFilename);

    std::string file1 = "file1";
    std::string file2 = "file2";
    std::string file3 = "file3";

    std::vector<uint8_t> data1 = {'F', 'i', 'l', 'e', '1'};
    std::vector<uint8_t> data2 = {'F', 'i', 'l', 'e', '2'};
    std::vector<uint8_t> data3 = {'F', 'i', 'l', 'e', '3'};
    std::vector<uint8_t> data1Copy = data1; // Copies for verification
    std::vector<uint8_t> data2Copy = data2;
    std::vector<uint8_t> data3Copy = data3;

    storage.writeToFile(file1, std::move(data1));
    storage.writeToFile(file2, std::move(data2));
    storage.writeToFile(file3, std::move(data3));

    storage.flush();

    ASSERT_EQ(getSegmentFiles(testPath, file1).size(), 1);
    ASSERT_EQ(getSegmentFiles(testPath, file2).size(), 1);
    ASSERT_EQ(getSegmentFiles(testPath, file3).size(), 1);

    auto files1 = getSegmentFiles(testPath, file1);
    auto files2 = getSegmentFiles(testPath, file2);
    auto files3 = getSegmentFiles(testPath, file3);

    auto content1 = readFile(files1[0]);
    auto content2 = readFile(files2[0]);
    auto content3 = readFile(files3[0]);

    ASSERT_TRUE(std::equal(data1Copy.begin(), data1Copy.end(), content1.begin()));
    ASSERT_TRUE(std::equal(data2Copy.begin(), data2Copy.end(), content2.begin()));
    ASSERT_TRUE(std::equal(data3Copy.begin(), data3Copy.end(), content3.begin()));
}

// Test large files
TEST_F(SegmentedStorageTest, LargeFileTest)
{
    SegmentedStorage storage(testPath, baseFilename);

    size_t dataSize = 5 * 1024 * 1024;
    std::vector<uint8_t> largeData = generateRandomData(dataSize);
    size_t bytesWritten = storage.write(std::move(largeData));
    ASSERT_EQ(bytesWritten, dataSize);

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_EQ(files.size(), 1);

    size_t fileSize = getFileSize(files[0]);
    ASSERT_EQ(fileSize, dataSize);
}

// Test destructor closes files properly
TEST_F(SegmentedStorageTest, DestructorTest)
{
    {
        SegmentedStorage storage(testPath, baseFilename);
        std::vector<uint8_t> data = {'T', 'e', 's', 't'};
        std::vector<uint8_t> dataCopy = data; // Copy for verification
        storage.write(std::move(data));
        storage.flush();
    }

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_EQ(files.size(), 1);

    auto fileContents = readFile(files[0]);
    ASSERT_EQ(fileContents.size(), 4);
    ASSERT_EQ(fileContents[0], 'T');
    ASSERT_EQ(fileContents[1], 'e');
    ASSERT_EQ(fileContents[2], 's');
    ASSERT_EQ(fileContents[3], 't');
}

// Test exact rotation boundary case
TEST_F(SegmentedStorageTest, ExactRotationBoundaryTest)
{
    size_t maxSegmentSize = 1000;
    SegmentedStorage storage(testPath, baseFilename, maxSegmentSize);

    std::vector<uint8_t> data1 = generateRandomData(maxSegmentSize);
    std::vector<uint8_t> data1Copy = data1; // Copy for verification
    size_t bytesWritten1 = storage.write(std::move(data1));
    ASSERT_EQ(bytesWritten1, data1Copy.size());

    std::vector<uint8_t> data2 = {42};
    std::vector<uint8_t> data2Copy = data2; // Copy for verification
    size_t bytesWritten2 = storage.write(std::move(data2));
    ASSERT_EQ(bytesWritten2, data2Copy.size());

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_EQ(files.size(), 2) << "Two files should be created with exact boundary";

    ASSERT_EQ(getFileSize(files[0]), maxSegmentSize);
    ASSERT_EQ(getFileSize(files[1]), 1);
}

// Test concurrent writing with realistic thread count at rotation boundaries
TEST_F(SegmentedStorageTest, RealisticConcurrencyRotationTest)
{
    size_t maxSegmentSize = 1000;
    SegmentedStorage storage(testPath, baseFilename, maxSegmentSize);

    size_t numThreads = 8;
    size_t dataSize = 200;

    std::vector<std::thread> threads;
    std::vector<std::vector<uint8_t>> dataBlocks;
    dataBlocks.reserve(numThreads);

    for (size_t i = 0; i < numThreads; i++)
    {
        dataBlocks.push_back(generateRandomData(dataSize));
        threads.emplace_back([&storage, &dataBlocks, i]()
                             { storage.write(std::move(dataBlocks[i])); });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_GT(files.size(), 1) << "Multiple files should be created due to rotation";

    size_t totalFileSize = 0;
    for (const auto &file : files)
    {
        totalFileSize += getFileSize(file);
    }

    ASSERT_EQ(totalFileSize, numThreads * dataSize) << "Total file sizes should match total written data";
}

// Test rotation with realistic thread count writing near segment boundary
TEST_F(SegmentedStorageTest, RealisticRotationBoundaryTest)
{
    size_t maxSegmentSize = 1000;
    SegmentedStorage storage(testPath, baseFilename, maxSegmentSize);

    size_t numThreads = 6;
    size_t dataSize = maxSegmentSize - 50;

    std::vector<std::thread> threads;
    std::vector<std::vector<uint8_t>> dataBlocks;

    for (size_t i = 0; i < numThreads; i++)
    {
        dataBlocks.push_back(generateRandomData(dataSize));
    }

    for (size_t i = 0; i < numThreads; i++)
    {
        threads.emplace_back([&storage, &dataBlocks, i]()
                             { storage.write(std::move(dataBlocks[i])); });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_GT(files.size(), 1) << "Multiple files should be created due to rotation";

    size_t totalFileSize = 0;
    for (const auto &file : files)
    {
        totalFileSize += getFileSize(file);
    }

    ASSERT_EQ(totalFileSize, numThreads * dataSize) << "Total file sizes should match total written data";
}

// Test writing zero bytes
TEST_F(SegmentedStorageTest, ZeroByteWriteTest)
{
    SegmentedStorage storage(testPath, baseFilename);

    std::vector<uint8_t> emptyData;
    size_t bytesWritten = storage.write(std::move(emptyData));

    ASSERT_EQ(bytesWritten, 0) << "Zero bytes should be written for empty data";

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_EQ(files.size(), 1) << "One file should still be created";
    ASSERT_EQ(getFileSize(files[0]), 0) << "File should be empty";
}

// Test concurrent writes to different files
TEST_F(SegmentedStorageTest, ConcurrentMultiFileWriteTest)
{
    SegmentedStorage storage(testPath, baseFilename);

    size_t numFiles = 10;
    size_t threadsPerFile = 5;
    size_t dataSize = 100;

    std::vector<std::thread> threads;
    std::vector<std::string> filenames;
    std::vector<std::vector<uint8_t>> dataBlocks;

    for (size_t i = 0; i < numFiles; i++)
    {
        filenames.push_back("file_" + std::to_string(i));
    }

    for (size_t i = 0; i < numFiles * threadsPerFile; i++)
    {
        dataBlocks.push_back(generateRandomData(dataSize));
    }

    for (size_t i = 0; i < numFiles; i++)
    {
        for (size_t j = 0; j < threadsPerFile; j++)
        {
            size_t dataIndex = i * threadsPerFile + j;
            threads.emplace_back([&storage, &filenames, &dataBlocks, i, dataIndex]()
                                 { storage.writeToFile(filenames[i], std::move(dataBlocks[dataIndex])); });
        }
    }

    for (auto &t : threads)
    {
        t.join();
    }

    storage.flush();

    for (const auto &filename : filenames)
    {
        auto files = getSegmentFiles(testPath, filename);
        ASSERT_EQ(files.size(), 1) << "One file should be created per filename";

        size_t fileSize = getFileSize(files[0]);
        ASSERT_EQ(fileSize, threadsPerFile * dataSize) << "Each file should contain data from all its threads";
    }
}

// Test rapid succession of writes near rotation boundary
TEST_F(SegmentedStorageTest, RapidWritesNearRotationTest)
{
    size_t maxSegmentSize = 1000;
    SegmentedStorage storage(testPath, baseFilename, maxSegmentSize);

    std::vector<uint8_t> initialData = generateRandomData(maxSegmentSize - 100);
    size_t initialSize = initialData.size();
    storage.write(std::move(initialData));

    size_t numWrites = 20;
    size_t smallChunkSize = 10;

    std::vector<std::vector<uint8_t>> dataChunks;
    for (size_t i = 0; i < numWrites; i++)
    {
        dataChunks.push_back(generateRandomData(smallChunkSize));
    }

    for (auto &chunk : dataChunks)
    {
        storage.write(std::move(chunk));
    }

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_GE(files.size(), 2) << "At least two files should be created due to rotation";

    size_t totalFileSize = 0;
    for (const auto &file : files)
    {
        totalFileSize += getFileSize(file);
    }

    size_t expectedTotalSize = initialSize + (numWrites * smallChunkSize);
    ASSERT_EQ(totalFileSize, expectedTotalSize) << "Total file sizes should match total written data";
}

// Test with extremely small segment size to force frequent rotations
TEST_F(SegmentedStorageTest, FrequentRotationTest)
{
    size_t maxSegmentSize = 50;
    SegmentedStorage storage(testPath, baseFilename, maxSegmentSize);

    size_t numWrites = 20;
    size_t dataSize = 30;

    std::vector<std::vector<uint8_t>> dataBlocks;
    for (size_t i = 0; i < numWrites; i++)
    {
        dataBlocks.push_back(generateRandomData(dataSize));
        storage.write(std::move(dataBlocks[i]));
    }

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_GE(files.size(), numWrites / 2) << "Many files should be created due to frequent rotation";

    size_t totalFileSize = 0;
    for (const auto &file : files)
    {
        totalFileSize += getFileSize(file);
        ASSERT_LE(getFileSize(file), maxSegmentSize);
    }

    ASSERT_EQ(totalFileSize, numWrites * dataSize) << "Total file sizes should match total written data";
}

// Test recovery after write failure
TEST_F(SegmentedStorageTest, WriteErrorRecoveryTest)
{
    SegmentedStorage storage(testPath, baseFilename);

    std::vector<uint8_t> data1 = {'I', 'n', 'i', 't', 'i', 'a', 'l'};
    std::vector<uint8_t> data1Copy = data1; // Copy for verification
    storage.write(std::move(data1));

    std::vector<uint8_t> data2 = {'R', 'e', 'c', 'o', 'v', 'e', 'r', 'y'};
    std::vector<uint8_t> data2Copy = data2; // Copy for verification
    storage.write(std::move(data2));

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_EQ(files.size(), 1);

    auto fileContents = readFile(files[0]);
    ASSERT_EQ(fileContents.size(), data1Copy.size() + data2Copy.size());

    for (size_t i = 0; i < data1Copy.size(); i++)
    {
        ASSERT_EQ(fileContents[i], data1Copy[i]);
    }

    for (size_t i = 0; i < data2Copy.size(); i++)
    {
        ASSERT_EQ(fileContents[data1Copy.size() + i], data2Copy[i]);
    }
}

// Test boundary case for multiple segments
TEST_F(SegmentedStorageTest, MultiSegmentBoundaryTest)
{
    size_t maxSegmentSize = 100;
    SegmentedStorage storage(testPath, baseFilename, maxSegmentSize);

    for (int i = 0; i < 3; i++)
    {
        auto data = generateRandomData(maxSegmentSize);
        storage.write(std::move(data));
    }

    storage.flush();

    auto files = getSegmentFiles(testPath, baseFilename);
    ASSERT_EQ(files.size(), 3) << "Should have exactly 3 segments";

    for (const auto &file : files)
    {
        ASSERT_EQ(getFileSize(file), maxSegmentSize);
    }
}

// maxOpenFiles=2 forces constant eviction while six filenames cycle — pre-fix this
// could close an fd mid-pwrite (EBADF) or lose data.
TEST_F(SegmentedStorageTest, LRUEvictionUnderConcurrentWrites)
{
    const size_t maxOpenFiles = 2;
    SegmentedStorage storage(testPath, baseFilename,
                             /*maxSegmentSize*/ 1024 * 1024,
                             /*maxAttempts*/ 5,
                             /*baseRetryDelay*/ std::chrono::milliseconds(1),
                             maxOpenFiles);

    const size_t numFilenames = 6;
    const size_t writesPerFilename = 200;
    const size_t dataSize = 64;

    std::vector<std::thread> threads;
    for (size_t i = 0; i < numFilenames; i++)
    {
        threads.emplace_back([&, i]()
                             {
            for (size_t j = 0; j < writesPerFilename; j++)
            {
                auto data = generateRandomData(dataSize);
                storage.writeToFile("evict_file_" + std::to_string(i), std::move(data));
            } });
    }

    for (auto &t : threads)
        t.join();

    storage.flush();

    // Each filename's segments must contain exactly writesPerFilename * dataSize bytes.
    for (size_t i = 0; i < numFilenames; i++)
    {
        auto files = getSegmentFiles(testPath, "evict_file_" + std::to_string(i));
        size_t total = 0;
        for (const auto &f : files)
            total += getFileSize(f);
        EXPECT_EQ(total, writesPerFilename * dataSize)
            << "evict_file_" << i << ": data lost under LRU pressure";
    }
}

// A rotation whose openWithRetry fails must not leave the cache holding a broken entry
// — pre-fix, writeToFile would spin forever refetching an fd=-1 entry.
TEST_F(SegmentedStorageTest, RotationOpenFailureRecovers)
{
    if (::geteuid() == 0)
    {
        GTEST_SKIP() << "Cannot simulate open failure while running as root";
    }

    const size_t maxSegmentSize = 100;
    SegmentedStorage storage(testPath, baseFilename, maxSegmentSize,
                             /*maxAttempts*/ 2,
                             /*baseRetryDelay*/ std::chrono::milliseconds(1));

    // Restore perms on scope exit so TearDown can delete the directory even on failure.
    struct PermRestorer
    {
        std::string path;
        ~PermRestorer()
        {
            std::error_code ec;
            std::filesystem::permissions(
                path,
                std::filesystem::perms::owner_all |
                    std::filesystem::perms::group_read |
                    std::filesystem::perms::others_read,
                std::filesystem::perm_options::replace, ec);
        }
    } restorer{testPath};

    ASSERT_EQ(storage.write(std::vector<uint8_t>(80, 'A')), 80u);

    // Remove write permission on the base dir so the next rotation's open fails.
    std::filesystem::permissions(
        testPath,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_exec,
        std::filesystem::perm_options::replace);

    EXPECT_THROW(storage.write(std::vector<uint8_t>(80, 'B')), std::runtime_error);

    // After restoring perms, the storage should recover via cache invalidation.
    std::filesystem::permissions(
        testPath,
        std::filesystem::perms::owner_all |
            std::filesystem::perms::group_read |
            std::filesystem::perms::others_read,
        std::filesystem::perm_options::replace);

    EXPECT_NO_THROW(storage.write(std::vector<uint8_t>(80, 'C')));
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}