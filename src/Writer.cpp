#include "Writer.hpp"
#include "Crypto.hpp"
#include "Compression.hpp"
#include "PlaceholderCryptoMaterial.hpp"
#include <iostream>
#include <chrono>
#include <optional>
#include <string>
#include <unordered_map>

Writer::Writer(BufferQueue &queue,
               std::shared_ptr<SegmentedStorage> storage,
               size_t batchSize,
               bool useEncryption,
               int compressionLevel,
               std::shared_ptr<SeqnumAllocator> seqnumAllocator,
               std::string baseFilename)
    : m_queue(queue),
      m_storage(std::move(storage)),
      m_seqnumAllocator(seqnumAllocator ? std::move(seqnumAllocator)
                                        : std::make_shared<SeqnumAllocator>()),
      m_baseFilename(std::move(baseFilename)),
      m_batchSize(batchSize),
      m_useEncryption(useEncryption),
      m_compressionLevel(compressionLevel),
      m_consumerToken(queue.createConsumerToken())
{
}

Writer::~Writer()
{
    stop();
}

void Writer::start()
{
    if (m_running.exchange(true))
    {
        return;
    }

    m_writerThread.reset(new std::thread(&Writer::processLogEntries, this));
}

void Writer::stop()
{
    if (m_running.exchange(false))
    {
        if (m_writerThread && m_writerThread->joinable())
        {
            m_writerThread->join();
        }
    }
}

bool Writer::isRunning() const
{
    return m_running.load();
}

void Writer::processLogEntries()
{
    std::vector<QueueItem> batch;

    Crypto crypto;
    Compression compression;
    std::vector<uint8_t> encryptionKey(crypto.KEY_SIZE, placeholder_crypto::KEY_BYTE);

    // Reused across loop iterations so clear() keeps the underlying allocations.
    std::unordered_map<std::optional<std::string>, std::vector<LogEntry>> groupedEntries;
    std::vector<uint8_t> scratchA;
    std::vector<uint8_t> scratchB;

    // Per-writer handles skip the storage's global LRU mutex on every batch;
    // stale handles (evicted/rotated entries) refresh themselves inside write().
    std::unordered_map<std::string, SegmentedStorage::WriteHandle> writeHandles;
    auto handleFor = [&](const std::string &target) -> SegmentedStorage::WriteHandle &
    {
        auto it = writeHandles.find(target);
        if (it == writeHandles.end())
        {
            it = writeHandles.emplace(target, m_storage->createWriteHandle(target)).first;
        }
        return it->second;
    };

    while (m_running)
    {
        // Semaphore wait: wakes immediately when an entry is enqueued; the
        // timeout only bounds how often m_running is rechecked for shutdown.
        size_t entriesDequeued =
            m_queue.waitDequeueBatch(batch, m_batchSize, m_consumerToken,
                                     std::chrono::milliseconds(10));
        if (entriesDequeued == 0)
        {
            continue;
        }

        groupedEntries.clear();
        for (auto &item : batch)
        {
            groupedEntries[item.targetFilename].emplace_back(std::move(item.entry));
        }

        for (auto &[targetFilename, entries] : groupedEntries)
        {
            const size_t groupSize = entries.size();
            try
            {
                // Must match what the exporter parses from the segment filename,
                // otherwise AAD reconstruction fails the tag check.
                const std::string &resolvedTarget =
                    targetFilename ? *targetFilename : m_baseFilename;

                LogEntry::serializeBatch(std::move(entries), scratchA);
                std::vector<uint8_t> *current = &scratchA;
                std::vector<uint8_t> *other = &scratchB;

                if (m_compressionLevel > 0)
                {
                    compression.compress(current->data(), current->size(), *other, m_compressionLevel);
                    std::swap(current, other);
                }
                if (m_useEncryption)
                {
                    const uint64_t seqnum = m_seqnumAllocator->next(resolvedTarget);
                    crypto.encrypt(current->data(), current->size(), encryptionKey, *other,
                                   seqnum,
                                   reinterpret_cast<const uint8_t *>(resolvedTarget.data()),
                                   resolvedTarget.size());
                    std::swap(current, other);
                }

                // Write via a cached handle. The default target uses the
                // storage's base filename (which may differ from the AAD
                // fallback m_baseFilename in stand-alone unit-test setups).
                const std::string &writeTarget =
                    targetFilename ? *targetFilename : m_storage->baseFilename();
                m_storage->write(handleFor(writeTarget), current->data(), current->size());
            }
            catch (const std::exception &e)
            {
                // Drop the failing group; keep the thread alive for subsequent batches.
                m_droppedEntries.fetch_add(groupSize, std::memory_order_acq_rel);
                std::cerr << "Writer: dropped " << groupSize << " entries from "
                          << (targetFilename ? *targetFilename : std::string("<default>"))
                          << ": " << e.what() << std::endl;
            }
        }

        batch.clear();
    }
}
