#include "BenchmarkUtils.hpp"
#include "LoggingSystem.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <future>
#include <optional>
#include <iomanip>
#include <filesystem>

struct BenchmarkResult
{
    double elapsedSeconds;
    double throughputEntries;
    double throughputGiB;
    int fileCount;
    double writeAmplification;
};

int countLogFiles(const std::string &basePath)
{
    int count = 0;
    for (const auto &entry : std::filesystem::directory_iterator(basePath))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            count++;
        }
    }
    return count;
}

BenchmarkResult runFileRotationBenchmark(
    const LoggingConfig &baseConfig,
    int maxSegmentSizeKB,
    int numProducerThreads,
    int entriesPerProducer,
    int numSpecificFiles,
    int producerBatchSize,
    int payloadSize)
{
    std::string logDir = "./logs/rotation_" + std::to_string(maxSegmentSizeKB) + "kb";

    cleanupLogDirectory(logDir);

    LoggingConfig config = baseConfig;
    config.basePath = logDir;
    config.maxSegmentSize = maxSegmentSizeKB * 1024; // Convert KB to bytes

    std::cout << "Generating batches with pre-determined destinations for all threads...";
    std::vector<BatchWithDestination> batches = generateBatches(entriesPerProducer, numSpecificFiles, producerBatchSize, payloadSize);
    std::cout << " Done." << std::endl;

    size_t totalDataSizeBytes = calculateTotalDataSize(batches, numProducerThreads);
    double totalDataSizeGiB = static_cast<double>(totalDataSizeBytes) / (1024 * 1024 * 1024);

    std::cout << "Total data to be written: " << totalDataSizeBytes << " bytes ("
              << totalDataSizeGiB << " GiB)" << std::endl;

    LoggingSystem loggingSystem(config);
    loggingSystem.start();
    auto startTime = std::chrono::high_resolution_clock::now();

    std::vector<std::future<void>> futures;
    for (int i = 0; i < numProducerThreads; i++)
    {
        futures.push_back(std::async(
            std::launch::async,
            appendLogEntries,
            std::ref(loggingSystem),
            std::ref(batches)));
    }

    for (auto &future : futures)
    {
        future.wait();
    }

    loggingSystem.stop();
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = endTime - startTime;

    size_t finalStorageSize = calculateDirectorySize(logDir);
    double writeAmplification = static_cast<double>(finalStorageSize) / totalDataSizeBytes;

    double elapsedSeconds = elapsed.count();
    const size_t totalEntries = numProducerThreads * entriesPerProducer;
    double throughputEntries = totalEntries / elapsedSeconds;
    double throughputGiB = totalDataSizeGiB / elapsedSeconds;
    int fileCount = countLogFiles(logDir);

    cleanupLogDirectory(logDir);

    return BenchmarkResult{
        elapsedSeconds,
        throughputEntries,
        throughputGiB,
        fileCount,
        writeAmplification};
}

void runFileRotationComparison(
    const LoggingConfig &baseConfig,
    const std::vector<int> &segmentSizesKB,
    int numProducerThreads,
    int entriesPerProducer,
    int numSpecificFiles,
    int producerBatchSize,
    int payloadSize)
{
    std::vector<BenchmarkResult> results;

    for (int segmentSize : segmentSizesKB)
    {
        BenchmarkResult result = runFileRotationBenchmark(
            baseConfig,
            segmentSize,
            numProducerThreads,
            entriesPerProducer,
            numSpecificFiles,
            producerBatchSize,
            payloadSize);

        results.push_back(result);

        // Add a small delay between runs
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    std::cout << "\n========================== FILE ROTATION BENCHMARK SUMMARY ==========================" << std::endl;
    std::cout << std::left << std::setw(20) << "Segment Size (KB)"
              << std::setw(15) << "Time (sec)"
              << std::setw(25) << "Throughput (entries/s)"
              << std::setw(25) << "Throughput (GiB/s)"
              << std::setw(20) << "Log Files Created"
              << std::setw(20) << "Write Amplification"
              << std::setw(20) << "Relative Performance" << std::endl;
    std::cout << "------------------------------------------------------------------------------------------------" << std::endl;

    // Use the first segment size as the baseline for relative performance
    double baselineThroughput = results[0].throughputEntries;

    for (size_t i = 0; i < segmentSizesKB.size(); i++)
    {
        double relativePerf = results[i].throughputEntries / baselineThroughput;
        std::cout << std::left << std::setw(20) << segmentSizesKB[i]
                  << std::setw(15) << std::fixed << std::setprecision(2) << results[i].elapsedSeconds
                  << std::setw(25) << std::fixed << std::setprecision(2) << results[i].throughputEntries
                  << std::setw(25) << std::fixed << std::setprecision(3) << results[i].throughputGiB
                  << std::setw(20) << results[i].fileCount
                  << std::setw(20) << std::fixed << std::setprecision(4) << results[i].writeAmplification
                  << std::setw(20) << std::fixed << std::setprecision(2) << relativePerf << std::endl;
    }
    std::cout << "================================================================================================" << std::endl;
}

int main()
{
    // system parameters
    LoggingConfig baseConfig;
    baseConfig.baseFilename = "default";
    baseConfig.maxAttempts = 5;
    baseConfig.baseRetryDelay = std::chrono::milliseconds(1);
    baseConfig.queueCapacity = 3000000;
    baseConfig.maxExplicitProducers = 32;
    baseConfig.batchSize = 8400;
    baseConfig.numWriterThreads = 12;
    baseConfig.appendTimeout = std::chrono::minutes(2);
    baseConfig.useEncryption = true;
    baseConfig.useCompression = true;
    // benchmark parameters
    const int numSpecificFiles = 0;
    const int producerBatchSize = 1000;
    const int numProducers = 32;
    const int entriesPerProducer = 3000000;
    const int payloadSize = 2048;

    std::vector<int> segmentSizesKB = {100, 500, 1000, 2500, 5000, 10000, 20000};

    runFileRotationComparison(
        baseConfig,
        segmentSizesKB,
        numProducers,
        entriesPerProducer,
        numSpecificFiles,
        producerBatchSize,
        payloadSize);

    return 0;
}