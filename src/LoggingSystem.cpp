#include "LoggingSystem.hpp"
#include "Crypto.hpp"
#include "Compression.hpp"
#include <iostream>
#include <filesystem>

LoggingSystem::LoggingSystem(const LoggingConfig &config)
    : m_numWriterThreads(config.numWriterThreads),
      m_batchSize(config.batchSize),
      m_useEncryption(config.useEncryption),
      m_useCompression(config.useCompression)
{
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

    LoggingAPI::getInstance().initialize(m_queue, config.appendTimeout);

    m_writers.reserve(m_numWriterThreads);
}

LoggingSystem::~LoggingSystem()
{
    stop();
}

bool LoggingSystem::start()
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
        auto writer = std::make_unique<Writer>(*m_queue, m_storage, m_batchSize, m_useEncryption, m_useCompression);
        writer->start();
        m_writers.push_back(std::move(writer));
    }

    std::cout << "LoggingSystem: Started " << m_numWriterThreads << " writer threads";
    std::cout << " (Encryption: " << (m_useEncryption ? "Enabled" : "Disabled");
    std::cout << ", Compression: " << (m_useCompression ? "Enabled" : "Disabled") << ")" << std::endl;
    return true;
}

bool LoggingSystem::stop()
{
    std::lock_guard<std::mutex> lock(m_systemMutex);

    if (!m_running.load(std::memory_order_acquire))
    {
        return false;
    }

    m_acceptingEntries.store(false, std::memory_order_release);

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

    // Flush storage to ensure all data is written
    if (m_storage)
    {
        m_storage->flush();
    }

    m_running.store(false, std::memory_order_release);

    LoggingAPI::getInstance().reset();

    std::cout << "LoggingSystem: Stopped" << std::endl;
    return true;
}

BufferQueue::ProducerToken LoggingSystem::createProducerToken()
{
    return LoggingAPI::getInstance().createProducerToken();
}

bool LoggingSystem::append(LogEntry entry,
                           BufferQueue::ProducerToken &token,
                           const std::optional<std::string> &filename)
{
    if (!m_acceptingEntries.load(std::memory_order_acquire))
    {
        std::cerr << "LoggingSystem: Not accepting entries" << std::endl;
        return false;
    }

    return LoggingAPI::getInstance().append(std::move(entry), token, filename);
}

bool LoggingSystem::appendBatch(std::vector<LogEntry> entries,
                                BufferQueue::ProducerToken &token,
                                const std::optional<std::string> &filename)
{
    if (!m_acceptingEntries.load(std::memory_order_acquire))
    {
        std::cerr << "LoggingSystem: Not accepting entries" << std::endl;
        return false;
    }

    return LoggingAPI::getInstance().appendBatch(std::move(entries), token, filename);
}

bool LoggingSystem::exportLogs(
    const std::string &outputPath,
    std::chrono::system_clock::time_point fromTimestamp,
    std::chrono::system_clock::time_point toTimestamp)
{
    // This is a placeholder implementation for log export
    // A complete solution would:
    // 1. Read the encrypted segments from storage
    // 2. Decrypt and decompress them
    // 3. Filter by timestamp if requested
    // 4. Write to the output path

    std::cerr << "LoggingSystem: Export logs not fully implemented" << std::endl;
    return false;
}