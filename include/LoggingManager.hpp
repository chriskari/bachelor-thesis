#ifndef LOGGING_SYSTEM_HPP
#define LOGGING_SYSTEM_HPP

#include "Config.hpp"
#include "Logger.hpp"
#include "BufferQueue.hpp"
#include "SegmentedStorage.hpp"
#include "Writer.hpp"
#include "LogEntry.hpp"
#include <memory>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
#include <string>
#include <optional>

class LoggingManager
{
public:
    explicit LoggingManager(const LoggingConfig &config);
    ~LoggingManager();

    bool start();
    bool stop();

    BufferQueue::ProducerToken createProducerToken();
    bool append(LogEntry entry,
                BufferQueue::ProducerToken &token,
                const std::optional<std::string> &filename = std::nullopt);
    bool appendBatch(std::vector<LogEntry> entries,
                     BufferQueue::ProducerToken &token,
                     const std::optional<std::string> &filename = std::nullopt);

    bool exportLogs(const std::string &outputPath,
                    std::chrono::system_clock::time_point fromTimestamp = std::chrono::system_clock::time_point(),
                    std::chrono::system_clock::time_point toTimestamp = std::chrono::system_clock::time_point(),
                    const std::optional<std::string> &dataSubjectId = std::nullopt);

private:
    std::shared_ptr<BufferQueue> m_queue;
    std::shared_ptr<SegmentedStorage> m_storage;
    std::vector<std::unique_ptr<Writer>> m_writers;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_acceptingEntries{false};
    // Producers past the accepting-check that haven't finished enqueuing yet; stop()
    // drains this to zero before flushing.
    std::atomic<size_t> m_inflightAppends{0};
    std::mutex m_systemMutex;

    size_t m_numWriterThreads;
    size_t m_batchSize;
    bool m_useEncryption;
    int m_compressionLevel;
    std::string m_basePath;
    std::string m_baseFilename;
};

#endif