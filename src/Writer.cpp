#include "Writer.hpp"
#include "Crypto.hpp"
#include "Compression.hpp"
#include <iostream>
#include <chrono>
#include <map>

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
    std::vector<uint8_t> encryptionKey(crypto.KEY_SIZE, 0x42); // dummy key
    std::vector<uint8_t> dummyIV(crypto.GCM_IV_SIZE, 0x24);    // dummy IV

    while (m_running)
    {
        size_t entriesDequeued = m_queue.tryDequeueBatch(batch, m_batchSize, m_consumerToken);
        if (entriesDequeued == 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        std::map<std::optional<std::string>, std::vector<LogEntry>> groupedEntries;
        for (auto &item : batch)
        {
            groupedEntries[item.targetFilename].emplace_back(std::move(item.entry));
        }

        for (auto &[targetFilename, entries] : groupedEntries)
        {
            const size_t groupSize = entries.size();
            try
            {
                std::vector<uint8_t> processedData = LogEntry::serializeBatch(std::move(entries));

                // Apply compression if enabled
                if (m_compressionLevel > 0)
                {
                    processedData = Compression::compress(std::move(processedData), m_compressionLevel);
                }
                // Apply encryption if enabled
                if (m_useEncryption)
                {
                    processedData = crypto.encrypt(std::move(processedData), encryptionKey, dummyIV);
                }

                if (targetFilename)
                {
                    m_storage->writeToFile(*targetFilename, std::move(processedData));
                }
                else
                {
                    m_storage->write(std::move(processedData));
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