#ifndef SEGMENTED_STORAGE_HPP
#define SEGMENTED_STORAGE_HPP

#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>
#include <cstdint>
#include <unordered_map>
#include <fcntl.h>  // for open flags
#include <unistd.h> // for close, pwrite, fsync
#include <chrono>
#include <thread>
#include <stdexcept>
#include <list>

class SegmentedStorage
{
public:
    SegmentedStorage(const std::string &basePath,
                     const std::string &baseFilename,
                     size_t maxSegmentSize = 100 * 1024 * 1024, // 100 MB default
                     size_t maxAttempts = 5,
                     std::chrono::milliseconds baseRetryDelay = std::chrono::milliseconds(1),
                     size_t maxOpenFiles = 512);

    ~SegmentedStorage();

    size_t write(std::vector<uint8_t> &&data);
    size_t write(const uint8_t *data, size_t size);
    size_t writeToFile(const std::string &filename, std::vector<uint8_t> &&data);
    // Pointer/size overload so the caller keeps ownership of the buffer.
    size_t writeToFile(const std::string &filename, const uint8_t *data, size_t size);
    void flush();

private:
    std::string m_basePath;
    std::string m_baseFilename;
    size_t m_maxSegmentSize;
    size_t m_maxAttempts;
    std::chrono::milliseconds m_baseRetryDelay;
    size_t m_maxOpenFiles;

    struct CacheEntry
    {
        int fd{-1};
        std::atomic<size_t> segmentIndex{0};
        std::atomic<size_t> currentOffset{0};
        // Bumped by rotateSegment; writers compare their pre-reservation value to detect
        // that their reserved offset points at a closed segment and must be discarded.
        std::atomic<size_t> generation{0};
        std::string currentSegmentPath;
        mutable std::shared_mutex fileMutex; // shared for pwrite, exclusive for rotate/flush
    };

    class LRUCache
    {
    public:
        LRUCache(size_t capacity, SegmentedStorage *parent) : m_capacity(capacity), m_parent(parent) {}

        std::shared_ptr<CacheEntry> get(const std::string &filename);
        void flush(const std::string &filename);
        void flushAll();
        void closeAll();
        // Drop the cache reference without touching the fd. Callers that have already
        // closed the fd (partial rotation) use this so the next get() rebuilds state.
        void invalidate(const std::string &filename);

    private:
        size_t m_capacity;
        SegmentedStorage *m_parent;

        std::list<std::string> m_lruList;
        struct CacheData
        {
            std::shared_ptr<CacheEntry> entry;
            std::list<std::string>::iterator lruIt;
        };
        std::unordered_map<std::string, CacheData> m_cache;
        mutable std::mutex m_mutex;

        void evictLRU();
        std::shared_ptr<CacheEntry> reconstructState(const std::string &filename);
    };

    LRUCache m_cache;

    std::string rotateSegment(const std::string &filename, std::shared_ptr<CacheEntry> entry);
    std::string generateSegmentPath(const std::string &filename, size_t segmentIndex) const;
    size_t getFileSize(const std::string &path) const;
    size_t findLatestSegmentIndex(const std::string &filename) const;

    template <typename Func>
    auto retryWithBackoff(Func &&f)
    {
        for (size_t attempt = 1;; ++attempt)
        {
            try
            {
                return f();
            }
            catch (const std::runtime_error &)
            {
                if (attempt >= m_maxAttempts)
                    throw;
                auto delay = m_baseRetryDelay * (1 << (attempt - 1));
                std::this_thread::sleep_for(delay);
            }
        }
    }

    int openWithRetry(const char *path, int flags, mode_t mode)
    {
        return retryWithBackoff([&]()
                                {
            int fd = ::open(path, flags, mode);
            if (fd < 0) throw std::runtime_error("open failed");
            return fd; });
    }

    size_t pwriteFull(int fd, const uint8_t *buf, size_t count, off_t offset)
    {
        size_t total = 0;
        while (total < count)
        {
            ssize_t written = ::pwrite(fd, buf + total, count - total, offset + total);
            if (written < 0)
            {
                if (errno == EINTR)
                    continue;
                throw std::runtime_error("pwrite failed");
            }
            total += written;
        }
        return total;
    }

    void fsyncRetry(int fd)
    {
        retryWithBackoff([&]()
                         {
            if (::fsync(fd) < 0) throw std::runtime_error("fsync failed");
            return 0; });
    }
};

#endif