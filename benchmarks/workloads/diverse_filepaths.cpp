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
    double writeAmplification;
};

BenchmarkResult runFilepathDiversityBenchmark(const LoggingConfig &config, int numSpecificFiles, int numProducerThreads,
                                              int entriesPerProducer, int producerBatchSize, int payloadSize)
{
    LoggingConfig runConfig = config;
    runConfig.basePath = "./logs/files_" + std::to_string(numSpecificFiles);

    cleanupLogDirectory(runConfig.basePath);

    std::cout << "Generating batches with " << numSpecificFiles << " specific files for all threads...";
    std::vector<BatchWithDestination> batches = generateBatches(entriesPerProducer, numSpecificFiles, producerBatchSize, payloadSize);
    std::cout << " Done." << std::endl;
    size_t totalDataSizeBytes = calculateTotalDataSize(batches, numProducerThreads);
    double totalDataSizeGiB = static_cast<double>(totalDataSizeBytes) / (1024 * 1024 * 1024);
    std::cout << "Total data to be written: " << totalDataSizeBytes << " bytes ("
              << totalDataSizeGiB << " GiB)" << std::endl;

    LoggingSystem loggingSystem(runConfig);
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

    size_t finalStorageSize = calculateDirectorySize(runConfig.basePath);
    double writeAmplification = static_cast<double>(finalStorageSize) / totalDataSizeBytes;

    double elapsedSeconds = elapsed.count();
    const size_t totalEntries = numProducerThreads * entriesPerProducer;
    double throughputEntries = totalEntries / elapsedSeconds;
    double throughputGiB = totalDataSizeGiB / elapsedSeconds;

    cleanupLogDirectory(runConfig.basePath);

    return BenchmarkResult{
        elapsedSeconds,
        throughputEntries,
        throughputGiB,
        writeAmplification};
}

void runFilepathDiversityComparison(const LoggingConfig &config, const std::vector<int> &numFilesVariants,
                                    int numProducerThreads, int entriesPerProducer, int producerBatchSize, int payloadSize)
{
    std::vector<BenchmarkResult> results;
    std::vector<std::string> descriptions;

    for (int fileCount : numFilesVariants)
    {
        if (fileCount == 0)
        {
            descriptions.push_back("Default file only");
        }
        else if (fileCount == 1)
        {
            descriptions.push_back("1 specific file");
        }
        else
        {
            descriptions.push_back(std::to_string(fileCount) + " specific files");
        }
    }

    for (size_t i = 0; i < numFilesVariants.size(); i++)
    {
        int fileCount = numFilesVariants[i];
        std::cout << "\nRunning benchmark with " << descriptions[i] << "..." << std::endl;

        BenchmarkResult result = runFilepathDiversityBenchmark(
            config,
            fileCount,
            numProducerThreads, entriesPerProducer, producerBatchSize, payloadSize);

        results.push_back(result);

        // Add a small delay between runs
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    std::cout << "\n=========== FILEPATH DIVERSITY BENCHMARK SUMMARY ===========" << std::endl;
    std::cout << std::left << std::setw(30) << "Configuration"
              << std::setw(15) << "Time (sec)"
              << std::setw(25) << "Throughput (entries/s)"
              << std::setw(25) << "Throughput (GiB/s)"
              << std::setw(20) << "Write Amplification"
              << std::setw(20) << "Relative Performance" << std::endl;
    std::cout << "------------------------------------------------------------------------------" << std::endl;

    // Calculate base throughput for relative performance
    double baseThroughputEntries = results[0].throughputEntries;

    for (size_t i = 0; i < numFilesVariants.size(); i++)
    {
        double relativePerf = results[i].throughputEntries / baseThroughputEntries;
        std::cout << std::left << std::setw(30) << descriptions[i]
                  << std::setw(15) << std::fixed << std::setprecision(2) << results[i].elapsedSeconds
                  << std::setw(25) << std::fixed << std::setprecision(2) << results[i].throughputEntries
                  << std::setw(25) << std::fixed << std::setprecision(3) << results[i].throughputGiB
                  << std::setw(20) << std::fixed << std::setprecision(4) << results[i].writeAmplification
                  << std::setw(20) << std::fixed << std::setprecision(2) << relativePerf << std::endl;
    }
    std::cout << "==============================================================================" << std::endl;
}

int main()
{
    // system parameters
    LoggingConfig config;
    config.baseFilename = "default";
    config.maxSegmentSize = 50 * 1024 * 1024; // 50 MB
    config.maxAttempts = 10;
    config.baseRetryDelay = std::chrono::milliseconds(2);
    config.queueCapacity = 3000000;
    config.maxExplicitProducers = 25;
    config.batchSize = 8400;
    config.numWriterThreads = 32;
    config.appendTimeout = std::chrono::minutes(2);
    config.useEncryption = true;
    config.useCompression = true;
    // benchmark parameters
    const int numProducers = 25;
    const int entriesPerProducer = 1000000;
    const int producerBatchSize = 50;
    const int payloadSize = 2048;

    std::vector<int> numFilesVariants = {0, 10, 50, 100, 250, 500, 1000, 5000};

    runFilepathDiversityComparison(config,
                                   numFilesVariants,
                                   numProducers,
                                   entriesPerProducer,
                                   producerBatchSize,
                                   payloadSize);

    return 0;
}