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
                    std::chrono::system_clock::time_point toTimestamp = std::chrono::system_clock::time_point());

private:
    std::shared_ptr<BufferQueue> m_queue;           // Thread-safe queue for queue items
    std::shared_ptr<SegmentedStorage> m_storage;    // Manages append-only log segments
    std::vector<std::unique_ptr<Writer>> m_writers; // Multiple writer threads
    std::atomic<bool> m_running{false};             // System running state
    std::atomic<bool> m_acceptingEntries{false};    // Controls whether new entries are accepted
    std::atomic<size_t> m_inflightAppends{0};       // Producers currently past the accepting-check
    std::mutex m_systemMutex;                       // For system-wide operations

    size_t m_numWriterThreads; // Number of writer threads
    size_t m_batchSize;        // Batch size for writers
    bool m_useEncryption;
    int m_compressionLevel;
};

#endif