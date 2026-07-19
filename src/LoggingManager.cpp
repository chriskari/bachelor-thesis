#include "LoggingManager.hpp"
#include "Crypto.hpp"
#include "Compression.hpp"
#include "LogExporter.hpp"
#include "PlaceholderCryptoMaterial.hpp"
#include "SealMarker.hpp"
#include <iostream>
#include <filesystem>
#include <vector>

LoggingManager::LoggingManager(const LoggingConfig &config)
    : m_numWriterThreads(config.numWriterThreads),
      m_batchSize(config.batchSize),
      m_useEncryption(config.useEncryption),
      m_compressionLevel(config.compressionLevel),
      m_basePath(config.basePath),
      m_baseFilename(config.baseFilename),
      m_appendTimeout(config.appendTimeout)
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
    m_seqnumAllocator = std::make_shared<SeqnumAllocator>();

    // Continue per-target seqnums after whatever earlier runs left on disk;
    // restarting them at 0 would duplicate seqnums and make export abort.
    if (m_useEncryption)
    {
        m_recoveredStates = LogExporter::recoverTargetStates(m_basePath, m_compressionLevel);
        for (const auto &[target, state] : m_recoveredStates)
        {
            m_seqnumAllocator->seed(target, state.count);
        }
    }

    // A second concurrent manager must fail loudly here — otherwise its
    // appends would silently route into the first manager's queue and storage.
    if (!Logger::getInstance().initialize(m_queue, config.appendTimeout))
    {
        throw std::runtime_error(
            "LoggingManager: Logger singleton is already owned by another instance");
    }

    m_writers.reserve(m_numWriterThreads);
}

LoggingManager::~LoggingManager()
{
    stop();
    // Release the singleton even if this manager was never started (stop()
    // only resets it on a running->stopped transition).
    Logger::getInstance().resetIf(m_queue);
}

bool LoggingManager::start()
{
    std::lock_guard<std::mutex> lock(m_systemMutex);

    if (m_running.load(std::memory_order_acquire))
    {
        std::cerr << "LoggingSystem: Already running" << std::endl;
        return false;
    }

    // Re-acquire the Logger singleton: a previous stop() released it.
    if (!Logger::getInstance().ensureInitialized(m_queue, m_appendTimeout))
    {
        std::cerr << "LoggingSystem: Logger singleton is owned by another instance"
                  << std::endl;
        return false;
    }

    m_running.store(true, std::memory_order_release);
    m_acceptingEntries.store(true, std::memory_order_release);

    for (size_t i = 0; i < m_numWriterThreads; ++i)
    {
        auto writer = std::make_unique<Writer>(*m_queue, m_storage,
                                               m_batchSize,
                                               m_useEncryption, m_compressionLevel,
                                               m_seqnumAllocator, m_baseFilename);
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
    // Sleep instead of yield: a producer may be parked inside its append
    // timeout, and spinning a core for that long helps nobody.
    while (m_inflightAppends.load(std::memory_order_acquire) > 0)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
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

    // Seal each target with a batch at seqnum == count, giving the exporter a
    // high-water-mark for tail-truncation detection.
    if (m_useEncryption && m_seqnumAllocator && m_storage)
    {
        try
        {
            Crypto crypto;
            Compression compression;
            const std::vector<uint8_t> key(Crypto::KEY_SIZE, placeholder_crypto::KEY_BYTE);

            for (const auto &[target, count] : m_seqnumAllocator->snapshot())
            {
                if (count == 0)
                    continue;

                // Nothing appended for this target since the seal found at
                // startup — rewriting an identical seal adds nothing.
                auto recovered = m_recoveredStates.find(target);
                if (recovered != m_recoveredStates.end() && recovered->second.sealed &&
                    recovered->second.count == count)
                    continue;

                std::vector<uint8_t> plaintext(seal_marker::MAGIC,
                                               seal_marker::MAGIC + seal_marker::MAGIC_LEN);
                std::vector<uint8_t> scratch;
                std::vector<uint8_t> *current = &plaintext;
                std::vector<uint8_t> *other = &scratch;

                if (m_compressionLevel > 0)
                {
                    compression.compress(current->data(), current->size(),
                                         *other, m_compressionLevel);
                    std::swap(current, other);
                }

                std::vector<uint8_t> encrypted;
                crypto.encrypt(current->data(), current->size(), key, encrypted,
                               /*seqnum=*/count,
                               reinterpret_cast<const uint8_t *>(target.data()),
                               target.size());
                m_storage->writeToFile(target, encrypted.data(), encrypted.size());
                m_recoveredStates[target] = RecoveredTargetState{count, true};
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "LoggingSystem: failed to write seal batch: " << e.what()
                      << std::endl;
        }
    }

    if (m_storage)
    {
        m_storage->flush();
    }

    m_running.store(false, std::memory_order_release);

    Logger::getInstance().resetIf(m_queue);

    std::cout << "LoggingSystem: Stopped" << std::endl;
    return true;
}

BufferQueue::ProducerToken LoggingManager::createProducerToken()
{
    return m_queue->createProducerToken();
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

// Append hot path: goes to m_queue directly instead of through the Logger
// singleton — m_queue is immutable for the manager's lifetime, so no lock or
// state snapshot is needed per call.
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
    if (filename && !SegmentedStorage::isValidTargetFilename(*filename))
    {
        std::cerr << "LoggingSystem: Rejected invalid target filename: " << *filename
                  << std::endl;
        return false;
    }

    QueueItem item{std::move(entry), filename};
    return m_queue->enqueueBlocking(std::move(item), token, m_appendTimeout);
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
    if (filename && !SegmentedStorage::isValidTargetFilename(*filename))
    {
        std::cerr << "LoggingSystem: Rejected invalid target filename: " << *filename
                  << std::endl;
        return false;
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
    return m_queue->enqueueBatchBlocking(std::move(batch), token, m_appendTimeout);
}

bool LoggingManager::exportLogs(
    const std::string &outputPath,
    std::chrono::system_clock::time_point fromTimestamp,
    std::chrono::system_clock::time_point toTimestamp,
    const std::optional<std::string> &dataSubjectId)
{
    if (m_running.load(std::memory_order_acquire))
    {
        std::cerr << "LoggingSystem: exportLogs requires the system to be stopped first"
                  << std::endl;
        return false;
    }

    ExportFilter filter;
    filter.from = fromTimestamp;
    filter.to = toTimestamp;
    filter.subjectId = dataSubjectId;

    // Cap = largest batch plaintext this configuration can legally write.
    const size_t maxBatchPlaintext =
        m_batchSize * (LogEntry::MAX_ENTRY_SIZE + sizeof(uint32_t)) + sizeof(uint32_t);
    LogExporter exporter(m_basePath, m_useEncryption, m_compressionLevel, maxBatchPlaintext);
    return exporter.exportToNDJSON(outputPath, filter);
}