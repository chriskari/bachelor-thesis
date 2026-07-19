#include "Logger.hpp"
#include "QueueItem.hpp"
#include "SegmentedStorage.hpp"
#include <iostream>
#include <mutex>

Logger &Logger::getInstance()
{
    // Meyers singleton: magic statics are thread-safe since C++11, so no
    // mutex is taken on this per-append hot path.
    static Logger instance;
    return instance;
}

Logger::Logger()
    : m_logQueue(nullptr),
      m_appendTimeout(std::chrono::milliseconds::max()),
      m_initialized(false)
{
}

Logger::~Logger()
{
    if (m_initialized)
    {
        reset();
    }
}

bool Logger::initialize(std::shared_ptr<BufferQueue> queue,
                        std::chrono::milliseconds appendTimeout)
{
    std::lock_guard<std::mutex> lock(m_stateMutex);
    if (m_initialized)
    {
        reportError("Logger already initialized");
        return false;
    }

    if (!queue)
    {
        reportError("Cannot initialize with a null queue");
        return false;
    }

    m_logQueue = std::move(queue);
    m_appendTimeout = appendTimeout;
    m_initialized = true;

    return true;
}

bool Logger::ensureInitialized(std::shared_ptr<BufferQueue> queue,
                               std::chrono::milliseconds appendTimeout)
{
    std::lock_guard<std::mutex> lock(m_stateMutex);
    if (!queue)
    {
        reportError("Cannot initialize with a null queue");
        return false;
    }
    if (m_initialized)
    {
        if (m_logQueue != queue)
        {
            reportError("Logger already owned by a different queue");
            return false;
        }
        m_appendTimeout = appendTimeout;
        return true;
    }

    m_logQueue = std::move(queue);
    m_appendTimeout = appendTimeout;
    m_initialized = true;
    return true;
}

BufferQueue::ProducerToken Logger::createProducerToken()
{
    std::shared_ptr<BufferQueue> queue;
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        if (!m_initialized)
        {
            reportError("Logger not initialized");
            throw std::runtime_error("Logger not initialized");
        }
        queue = m_logQueue;
    }
    return queue->createProducerToken();
}

bool Logger::append(LogEntry entry,
                    BufferQueue::ProducerToken &token,
                    const std::optional<std::string> &filename)
{
    if (filename && !SegmentedStorage::isValidTargetFilename(*filename))
    {
        reportError("Rejected invalid target filename: " + *filename);
        return false;
    }

    std::shared_ptr<BufferQueue> queue;
    std::chrono::milliseconds timeout;
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        if (!m_initialized)
        {
            reportError("Logger not initialized");
            return false;
        }
        queue = m_logQueue;
        timeout = m_appendTimeout;
    }

    QueueItem item{std::move(entry), filename};
    return queue->enqueueBlocking(std::move(item), token, timeout);
}

bool Logger::appendBatch(std::vector<LogEntry> entries,
                         BufferQueue::ProducerToken &token,
                         const std::optional<std::string> &filename)
{
    if (filename && !SegmentedStorage::isValidTargetFilename(*filename))
    {
        reportError("Rejected invalid target filename: " + *filename);
        return false;
    }

    std::shared_ptr<BufferQueue> queue;
    std::chrono::milliseconds timeout;
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        if (!m_initialized)
        {
            reportError("Logger not initialized");
            return false;
        }
        queue = m_logQueue;
        timeout = m_appendTimeout;
    }

    if (entries.empty())
    {
        return true;
    }

    std::vector<QueueItem> batch;
    batch.reserve(entries.size());
    for (auto &entry : entries)
    {
        batch.emplace_back(std::move(entry), filename);
    }
    return queue->enqueueBatchBlocking(std::move(batch), token, timeout);
}

bool Logger::reset()
{
    std::lock_guard<std::mutex> lock(m_stateMutex);
    if (!m_initialized)
    {
        return false;
    }

    m_initialized = false;
    m_logQueue.reset();

    return true;
}

bool Logger::resetIf(const std::shared_ptr<BufferQueue> &queue)
{
    std::lock_guard<std::mutex> lock(m_stateMutex);
    if (!m_initialized || m_logQueue != queue)
    {
        return false;
    }

    m_initialized = false;
    m_logQueue.reset();

    return true;
}

void Logger::reportError(const std::string &message)
{
    std::cerr << "Logger Error: " << message << std::endl;
}
