#include "LoggingManager.hpp"
#include "Crypto.hpp"
#include "Compression.hpp"
#include <iostream>
#include <filesystem>

LoggingManager::LoggingManager(const LoggingConfig &config)
    : m_numWriterThreads(config.numWriterThreads),
      m_batchSize(config.batchSize),
      m_useEncryption(config.useEncryption),
      m_compressionLevel(config.compressionLevel)
{
    // Zero/false are valid for useEncryption and compressionLevel, so they aren't checked.
    if (config.queueCapacity == 0)
        throw std::invalid_argument("LoggingConfig: queueCapacity must be > 0");
    if (config.numWriterThreads == 0)
        throw std::invalid_argument("LoggingConfig: numWriterThreads must be > 0");
    if (config.batchSize == 0)
        throw std::invalid_argument("LoggingConfig: batchSize must be > 0");
    if (config.maxSegmentSize == 0)
        throw std::invalid_argument("LoggingConfig: maxSegmentSize must be > 0");
    if (config.maxOpenFiles == 0)
        throw std::invalid_argument("LoggingConfig: maxOpenFiles must be > 0");
    if (config.maxAttempts == 0)
        throw std::invalid_argument("LoggingConfig: maxAttempts must be > 0");

    if (!std::filesystem::create_directories(config.basePath) &&
        !std::filesystem::exists(config.basePath))
    {
        throw std::runtime_error("Failed to create log directory: " + config.basePath);
    }

    m_queue = std::make_shared<BufferQueue>(config.queueCapacity, config.maxExplicitProducers);
    m_storage = std::make_shared<SegmentedStorage>(
        config.basePath, config.baseFilename,
        config.maxSegmentSize,
        config.maxAttempts,
        config.baseRetryDelay,
        config.maxOpenFiles);

    Logger::getInstance().initialize(m_queue, config.appendTimeout);

    m_writers.reserve(m_numWriterThreads);
}

LoggingManager::~LoggingManager()
{
    stop();
}

bool LoggingManager::start()
{
    std::lock_guard<std::mutex> lock(m_systemMutex);

    if (m_running.load(std::memory_order_acquire))
    {
        std::cerr << "LoggingSystem: Already running" << std::endl;
        return false;
    }

    m_running.store(true, std::memory_order_release);
    m_acceptingEntries.store(true, std::memory_order_release);

    for (size_t i = 0; i < m_numWriterThreads; ++i)
    {
        auto writer = std::make_unique<Writer>(*m_queue, m_storage, m_batchSize, m_useEncryption, m_compressionLevel);
        writer->start();
        m_writers.push_back(std::move(writer));
    }

    std::cout << "LoggingSystem: Started " << m_numWriterThreads << " writer threads";
    std::cout << " (Encryption: " << (m_useEncryption ? "Enabled" : "Disabled");
    std::cout << ", Compression: " << (m_compressionLevel != 0 ? "Enabled" : "Disabled") << ")" << std::endl;
    return true;
}

bool LoggingManager::stop()
{
    std::lock_guard<std::mutex> lock(m_systemMutex);

    if (!m_running.load(std::memory_order_acquire))
    {
        return false;
    }

    m_acceptingEntries.store(false, std::memory_order_release);

    // Drain producers already past the accepting-check so no entry lands after flush().
    // Pairs with the increment-then-check ordering in InflightGuard below.
    while (m_inflightAppends.load(std::memory_order_acquire) > 0)
    {
        std::this_thread::yield();
    }

    if (m_queue)
    {
        std::cout << "LoggingSystem: Waiting for queue to empty..." << std::endl;
        m_queue->flush();
    }

    for (auto &writer : m_writers)
    {
        writer->stop();
    }
    m_writers.clear();

    if (m_storage)
    {
        m_storage->flush();
    }

    m_running.store(false, std::memory_order_release);

    Logger::getInstance().reset();

    std::cout << "LoggingSystem: Stopped" << std::endl;
    return true;
}

BufferQueue::ProducerToken LoggingManager::createProducerToken()
{
    return Logger::getInstance().createProducerToken();
}

namespace
{
// Construct BEFORE reading m_acceptingEntries so stop() can safely drain.
struct InflightGuard
{
    std::atomic<size_t> &counter;
    explicit InflightGuard(std::atomic<size_t> &c) : counter(c)
    {
        counter.fetch_add(1, std::memory_order_acq_rel);
    }
    ~InflightGuard()
    {
        counter.fetch_sub(1, std::memory_order_acq_rel);
    }
    InflightGuard(const InflightGuard &) = delete;
    InflightGuard &operator=(const InflightGuard &) = delete;
};
} // namespace

bool LoggingManager::append(LogEntry entry,
                            BufferQueue::ProducerToken &token,
                            const std::optional<std::string> &filename)
{
    InflightGuard guard(m_inflightAppends);
    if (!m_acceptingEntries.load(std::memory_order_acquire))
    {
        std::cerr << "LoggingSystem: Not accepting entries" << std::endl;
        return false;
    }

    return Logger::getInstance().append(std::move(entry), token, filename);
}

bool LoggingManager::appendBatch(std::vector<LogEntry> entries,
                                 BufferQueue::ProducerToken &token,
                                 const std::optional<std::string> &filename)
{
    InflightGuard guard(m_inflightAppends);
    if (!m_acceptingEntries.load(std::memory_order_acquire))
    {
        std::cerr << "LoggingSystem: Not accepting entries" << std::endl;
        return false;
    }

    return Logger::getInstance().appendBatch(std::move(entries), token, filename);
}

bool LoggingManager::exportLogs(
    const std::string &outputPath,
    std::chrono::system_clock::time_point fromTimestamp,
    std::chrono::system_clock::time_point toTimestamp)
{
    std::cerr << "LoggingSystem: Export logs not fully implemented" << std::endl;
    return false;
}