#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <chrono>

struct LoggingConfig
{
    std::string basePath = "./logs";
    std::string baseFilename = "gdpr_audit";
    size_t maxSegmentSize = 100 * 1024 * 1024; // 100 MB
    size_t bufferSize = 64 * 1024;             // 64 KB
    size_t queueCapacity = 8192;
    size_t batchSize = 100;
    size_t numWriterThreads = 2;
    std::chrono::milliseconds appendTimeout = std::chrono::milliseconds(30000);
};

#endif
