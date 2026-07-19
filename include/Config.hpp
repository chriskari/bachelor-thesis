#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <chrono>

struct LoggingConfig
{
    // api
    std::chrono::milliseconds appendTimeout = std::chrono::milliseconds(30000);
    // queue
    size_t queueCapacity = 8192;
    size_t maxExplicitProducers = 16;
    // writers
    size_t batchSize = 100;
    size_t numWriterThreads = 2;
    bool useEncryption = true;
    // 0 disables compression; 1-9 are zlib levels. Default 3: the level sweep
    // (benchmarks/findings/compression_level_sweep.cpp) measured 2x the
    // ingest throughput of level 9 at an equal compression ratio; levels
    // above 3 buy <1% ratio on this workload class.
    int compressionLevel = 3;
    // segmented storage
    std::string basePath = "./logs";
    std::string baseFilename = "default";
    size_t maxSegmentSize = 100 * 1024 * 1024;
    size_t maxAttempts = 10;
    std::chrono::milliseconds baseRetryDelay = std::chrono::milliseconds(1);
    size_t maxOpenFiles = 512;
};

#endif