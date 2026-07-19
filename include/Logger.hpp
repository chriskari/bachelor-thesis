#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "LogEntry.hpp"
#include "BufferQueue.hpp"
#include "QueueItem.hpp"
#include <string>
#include <chrono>
#include <memory>
#include <vector>
#include <functional>
#include <optional>

class Logger
{
public:
    static Logger &getInstance();

    bool initialize(std::shared_ptr<BufferQueue> queue,
                    std::chrono::milliseconds appendTimeout = std::chrono::milliseconds::max());
    // Idempotent variant for restart paths: succeeds if uninitialized OR
    // already bound to the same queue (refreshing the timeout); fails only if
    // a different queue owns the singleton.
    bool ensureInitialized(std::shared_ptr<BufferQueue> queue,
                           std::chrono::milliseconds appendTimeout);

    BufferQueue::ProducerToken createProducerToken();
    bool append(LogEntry entry,
                BufferQueue::ProducerToken &token,
                const std::optional<std::string> &filename = std::nullopt);
    bool appendBatch(std::vector<LogEntry> entries,
                     BufferQueue::ProducerToken &token,
                     const std::optional<std::string> &filename = std::nullopt);

    bool reset();
    // Releases the singleton only if it is bound to `queue`; lets a
    // LoggingManager release on destruction without clobbering a successor.
    bool resetIf(const std::shared_ptr<BufferQueue> &queue);

    ~Logger();

private:
    Logger();
    Logger(const Logger &) = delete;
    Logger &operator=(const Logger &) = delete;

    // Readers snapshot m_logQueue under this lock and then use the snapshot unlocked,
    // so reset() can null the member without racing an in-flight enqueue.
    mutable std::mutex m_stateMutex;
    std::shared_ptr<BufferQueue> m_logQueue;
    std::chrono::milliseconds m_appendTimeout;
    bool m_initialized;

    void reportError(const std::string &message);
};

#endif
