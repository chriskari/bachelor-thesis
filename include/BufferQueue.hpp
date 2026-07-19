#ifndef BUFFER_QUEUE_HPP
#define BUFFER_QUEUE_HPP

#include "QueueItem.hpp"
#include "blockingconcurrentqueue.h"
#include <atomic>
#include <vector>
#include <memory>
#include <condition_variable>
#include <chrono>

class BufferQueue
{
public:
    using ProducerToken = moodycamel::ProducerToken;
    using ConsumerToken = moodycamel::ConsumerToken;

private:
    // Blocking variant so consumers can wait on a semaphore instead of
    // sleep-polling; producers still use the non-blocking try_* API.
    moodycamel::BlockingConcurrentQueue<QueueItem> m_queue;

public:
    explicit BufferQueue(size_t capacity, size_t maxExplicitProducers);

    ProducerToken createProducerToken() { return ProducerToken(m_queue); }
    ConsumerToken createConsumerToken() { return ConsumerToken(m_queue); }

    bool enqueueBlocking(QueueItem item,
                         ProducerToken &token,
                         std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
    bool enqueueBatchBlocking(std::vector<QueueItem> items,
                              ProducerToken &token,
                              std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
    bool tryDequeue(QueueItem &item, ConsumerToken &token);
    size_t tryDequeueBatch(std::vector<QueueItem> &items, size_t maxItems, ConsumerToken &token);
    // Blocks on the queue's semaphore until at least one item is available (or
    // `timeout` elapses), then dequeues up to maxItems. Returns the number
    // dequeued (0 on timeout). Wakes immediately on enqueue — no poll interval.
    size_t waitDequeueBatch(std::vector<QueueItem> &items, size_t maxItems, ConsumerToken &token,
                            std::chrono::milliseconds timeout);
    bool flush();
    size_t size() const;

    // delete copy/move
    BufferQueue(const BufferQueue &) = delete;
    BufferQueue &operator=(const BufferQueue &) = delete;
    BufferQueue(BufferQueue &&) = delete;
    BufferQueue &operator=(BufferQueue &&) = delete;

private:
    bool enqueue(QueueItem item, ProducerToken &token);
    bool enqueueBatch(std::vector<QueueItem> items, ProducerToken &token);
};

#endif
