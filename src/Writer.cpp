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
               int compressionLevel)
    : m_queue(queue),
      m_storage(std::move(storage)),
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

    while (m_running)
    {
        size_t entriesDequeued = m_queue.tryDequeueBatch(batch, m_batchSize, m_consumerToken);
        if (entriesDequeued == 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
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
                    crypto.encrypt(current->data(), current->size(), encryptionKey, *other);
                    std::swap(current, other);
                }

                if (targetFilename)
                {
                    m_storage->writeToFile(*targetFilename, current->data(), current->size());
                }
                else
                {
                    m_storage->write(current->data(), current->size());
                }
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