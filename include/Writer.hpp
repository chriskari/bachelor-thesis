#ifndef WRITER_HPP
#define WRITER_HPP

#include <thread>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include "QueueItem.hpp"
#include "BufferQueue.hpp"
#include "SegmentedStorage.hpp"
#include "SeqnumAllocator.hpp"

class Writer
{
public:
    // seqnumAllocator and baseFilename default so unit tests can build a stand-alone
    // Writer; a null allocator is replaced with a private (unshared) one.
    explicit Writer(BufferQueue &queue,
                    std::shared_ptr<SegmentedStorage> storage,
                    size_t batchSize = 100,
                    bool useEncryption = true,
                    int m_compressionLevel = 9,
                    std::shared_ptr<SeqnumAllocator> seqnumAllocator = nullptr,
                    std::string baseFilename = "");

    ~Writer();

    void start();
    void stop();
    bool isRunning() const;

    // Entries dropped by the pipeline (serialize/compress/encrypt/write threw).
    size_t droppedEntries() const { return m_droppedEntries.load(std::memory_order_acquire); }

private:
    void processLogEntries();

    BufferQueue &m_queue;
    std::shared_ptr<SegmentedStorage> m_storage;
    std::shared_ptr<SeqnumAllocator> m_seqnumAllocator;
    std::string m_baseFilename;
    std::unique_ptr<std::thread> m_writerThread;
    std::atomic<bool> m_running{false};
    std::atomic<size_t> m_droppedEntries{0};
    const size_t m_batchSize;
    const bool m_useEncryption;
    const int m_compressionLevel;

    BufferQueue::ConsumerToken m_consumerToken;
};
#endif
