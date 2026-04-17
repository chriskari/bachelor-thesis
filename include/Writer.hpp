#ifndef WRITER_HPP
#define WRITER_HPP

#include <thread>
#include <atomic>
#include <memory>
#include <vector>
#include "QueueItem.hpp"
#include "BufferQueue.hpp"
#include "SegmentedStorage.hpp"

class Writer
{
public:
    explicit Writer(BufferQueue &queue,
                    std::shared_ptr<SegmentedStorage> storage,
                    size_t batchSize = 100,
                    bool useEncryption = true,
                    int m_compressionLevel = 9);

    ~Writer();

    void start();
    void stop();
    bool isRunning() const;

    // Count of log entries dropped by this writer because their batch failed during
    // serialization, compression, encryption, or write. Bumped when processLogEntries
    // catches an exception and discards the offending batch to keep the thread alive.
    size_t droppedEntries() const { return m_droppedEntries.load(std::memory_order_acquire); }

private:
    void processLogEntries();

    BufferQueue &m_queue;
    std::shared_ptr<SegmentedStorage> m_storage;
    std::unique_ptr<std::thread> m_writerThread;
    std::atomic<bool> m_running{false};
    std::atomic<size_t> m_droppedEntries{0};
    const size_t m_batchSize;
    const bool m_useEncryption;
    const int m_compressionLevel;

    BufferQueue::ConsumerToken m_consumerToken;
};
#endif