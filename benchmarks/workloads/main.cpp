#include "BenchmarkUtils.hpp"
#include "LoggingManager.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <future>
#include <optional>
#include <filesystem>
#include <numeric>

int main()
{
    // system parameters
    LoggingConfig config;
    config.basePath = "./logs";
    config.baseFilename = "default";
    config.maxSegmentSize = 50 * 1024 * 1024; // 50 MB
    config.maxAttempts = 5;
    config.baseRetryDelay = std::chrono::milliseconds(1);
    config.queueCapacity = 3000000;
    config.maxExplicitProducers = 96;
    config.batchSize = 8192;
    config.numWriterThreads = 96;
    config.appendTimeout = std::chrono::minutes(2);
    config.useEncryption = true;
    config.useCompression = true;
    config.maxOpenFiles = 512;
    // benchmark parameters
    const int numSpecificFiles = 1024;
    const int producerBatchSize = 4096;
    const int numProducers = 96;
    const int entriesPerProducer = 800000;
    const int payloadSize = 4096;

    cleanupLogDirectory(config.basePath);

    std::cout << "Generating batches with pre-determined destinations...";
    std::vector<BatchWithDestination> batches = generateBatches(entriesPerProducer, numSpecificFiles, producerBatchSize, payloadSize);
    std::cout << " Done." << std::endl;
    size_t totalDataSizeBytes = calculateTotalDataSize(batches, numProducers);
    double totalDataSizeGiB = static_cast<double>(totalDataSizeBytes) / (1024 * 1024 * 1024);
    std::cout << "Total data to be written: " << totalDataSizeBytes << " bytes (" << totalDataSizeGiB << " GiB)" << std::endl;

    LoggingManager loggingManager(config);
    loggingManager.start();
    auto startTime = std::chrono::high_resolution_clock::now();

    std::vector<std::future<void>> futures;
    for (int i = 0; i < numProducers; i++)
    {
        futures.push_back(std::async(
            std::launch::async,
            appendLogEntries,
            std::ref(loggingManager),
            std::ref(batches)));
    }

    for (auto &future : futures)
    {
        future.wait();
    }

    loggingManager.stop();
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = endTime - startTime;

    size_t finalStorageSize = calculateDirectorySize(config.basePath);
    double finalStorageSizeGiB = static_cast<double>(finalStorageSize) / (1024 * 1024 * 1024);
    double writeAmplification = static_cast<double>(finalStorageSize) / totalDataSizeBytes;

    double elapsedSeconds = elapsed.count();
    const size_t totalEntries = numProducers * entriesPerProducer;
    double entriesThroughput = totalEntries / elapsedSeconds;
    double dataThroughputGiB = totalDataSizeGiB / elapsedSeconds;
    double averageEntrySize = static_cast<double>(totalDataSizeBytes) / totalEntries;

    cleanupLogDirectory(config.basePath);

    std::cout << "============== Benchmark Results ==============" << std::endl;
    std::cout << "Execution time: " << elapsedSeconds << " seconds" << std::endl;
    std::cout << "Total entries appended: " << totalEntries << std::endl;
    std::cout << "Average entry size: " << averageEntrySize << " bytes" << std::endl;
    std::cout << "Total data written: " << totalDataSizeGiB << " GiB" << std::endl;
    std::cout << "Final storage size: " << finalStorageSizeGiB << " GiB" << std::endl;
    std::cout << "Write amplification: " << writeAmplification << " (ratio)" << std::endl;
    std::cout << "Throughput (entries): " << entriesThroughput << " entries/second" << std::endl;
    std::cout << "Throughput (data): " << dataThroughputGiB << " GiB/second" << std::endl;
    std::cout << "===============================================" << std::endl;

    return 0;
}