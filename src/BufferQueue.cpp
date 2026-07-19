#include "BufferQueue.hpp"
#include <algorithm>
#include <thread>
#include <iostream>
#include <chrono>
#include <cmath>

namespace
{
// milliseconds::max() converted to a finer duration (as duration comparison
// operators do) overflows and wraps negative, so it must never reach a
// duration comparison. Treat it as "no deadline" explicitly instead.
constexpr bool isInfinite(std::chrono::milliseconds timeout)
{
    return timeout == std::chrono::milliseconds::max();
}
} // namespace

BufferQueue::BufferQueue(size_t capacity, size_t maxExplicitProducers)
    : m_queue(capacity, maxExplicitProducers, 0)
{
}

bool BufferQueue::enqueue(QueueItem item, ProducerToken &token)
{
    return m_queue.try_enqueue(token, std::move(item));
}

bool BufferQueue::enqueueBlocking(QueueItem item, ProducerToken &token, std::chrono::milliseconds timeout)
{
    auto start = std::chrono::steady_clock::now();
    int backoffMs = 1;
    const int maxBackoffMs = 100;

    // moodycamel's try_enqueue leaves the source untouched on capacity failure, so the
    // same `item` can be re-moved on each retry.
    while (true)
    {
        if (m_queue.try_enqueue(token, std::move(item)))
        {
            return true;
        }

        auto elapsed = std::chrono::steady_clock::now() - start;
        if (!isInfinite(timeout) && elapsed >= timeout)
        {
            return false;
        }

        int sleepTime = backoffMs;

        // Don't sleep past the remaining timeout.
        if (!isInfinite(timeout))
        {
            auto remainingTime = timeout - elapsed;
            if (remainingTime <= std::chrono::milliseconds(sleepTime))
            {
                sleepTime = std::max(1, static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(remainingTime).count()));
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
        backoffMs = std::min(backoffMs * 2, maxBackoffMs);
    }
}

bool BufferQueue::enqueueBatch(std::vector<QueueItem> items, ProducerToken &token)
{
    return m_queue.try_enqueue_bulk(token, std::make_move_iterator(items.begin()), items.size());
}

bool BufferQueue::enqueueBatchBlocking(std::vector<QueueItem> items, ProducerToken &token,
                                       std::chrono::milliseconds timeout)
{
    auto start = std::chrono::steady_clock::now();
    int backoffMs = 1;
    const int maxBackoffMs = 100;
    int emptyFailures = 0;

    // try_enqueue_bulk is all-or-nothing on capacity failure: no slot is constructed
    // and the iterator is not advanced, so items stay intact for retry.
    while (true)
    {
        if (m_queue.try_enqueue_bulk(token,
                                     std::make_move_iterator(items.begin()),
                                     items.size()))
        {
            return true;
        }

        // A bulk enqueue that repeatedly fails against an EMPTY queue cannot
        // fit at all (the batch exceeds the block pool available to this
        // producer), so waiting for consumers cannot help — fail fast instead
        // of spinning for the full timeout. Three consecutive checks guard
        // against the transient window where a concurrent drain has emptied
        // the queue but its blocks are not yet recycled.
        if (m_queue.size_approx() == 0)
        {
            if (++emptyFailures >= 3)
            {
                return false;
            }
            std::this_thread::yield();
            continue;
        }
        emptyFailures = 0;

        auto elapsed = std::chrono::steady_clock::now() - start;
        if (!isInfinite(timeout) && elapsed >= timeout)
        {
            return false;
        }

        int sleepTime = backoffMs;

        if (!isInfinite(timeout))
        {
            auto remainingTime = timeout - elapsed;
            if (remainingTime <= std::chrono::milliseconds(sleepTime))
            {
                sleepTime = std::max(1, static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(remainingTime).count()));
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
        backoffMs = std::min(backoffMs * 2, maxBackoffMs);
    }
}

bool BufferQueue::tryDequeue(QueueItem &item, ConsumerToken &token)
{
    if (m_queue.try_dequeue(token, item))
    {
        return true;
    }
    return false;
}

size_t BufferQueue::tryDequeueBatch(std::vector<QueueItem> &items, size_t maxItems, ConsumerToken &token)
{
    items.clear();
    items.resize(maxItems);

    size_t dequeued = m_queue.try_dequeue_bulk(token, items.begin(), maxItems);
    items.resize(dequeued);

    return dequeued;
}

size_t BufferQueue::waitDequeueBatch(std::vector<QueueItem> &items, size_t maxItems,
                                     ConsumerToken &token, std::chrono::milliseconds timeout)
{
    items.clear();
    items.resize(maxItems);

    size_t dequeued = m_queue.wait_dequeue_bulk_timed(token, items.begin(), maxItems, timeout);
    items.resize(dequeued);

    return dequeued;
}

bool BufferQueue::flush()
{
    // Check before sleeping: an already-empty queue must not pay any wait.
    while (m_queue.size_approx() != 0)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    return true;
}

size_t BufferQueue::size() const
{
    return m_queue.size_approx();
}
