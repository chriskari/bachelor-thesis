#include "Writer.hpp"
#include <iostream>
#include <chrono>
#include "Crypto.hpp"
#include "Compression.hpp"

Writer::Writer(LockFreeQueue &logQueue,
               std::shared_ptr<SegmentedStorage> storage,
               size_t batchSize)
    : m_logQueue(logQueue),
      m_storage(storage),
      m_batchSize(batchSize) {}

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

    m_writerThread = std::make_unique<std::thread>(&Writer::processLogEntries, this);
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
    std::vector<LogEntry> batch;
    batch.reserve(m_batchSize);

    Crypto crypto;
    std::vector<uint8_t> encryptionKey(32, 0x42); // dummy key

    while (m_running)
    {
        // Try to dequeue a batch of log entries
        size_t entriesDequeued = m_logQueue.dequeueBatch(batch, m_batchSize);

        if (entriesDequeued > 0)
        {
            std::vector<uint8_t> compressedData = Compression::compressBatch(batch);
            std::vector<uint8_t> encryptedData = crypto.encrypt(compressedData, encryptionKey);

            size_t bytesWritten = m_storage->write(encryptedData);

            // Clear the batch for next iteration
            batch.clear();
        }
        else
        {
            // If no entries, wait a bit to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    // Ensure any remaining data is flushed when stopping
    m_storage->flush();
}