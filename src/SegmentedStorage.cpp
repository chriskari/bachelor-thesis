#include "SegmentedStorage.hpp"
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <sys/stat.h>

SegmentedStorage::SegmentedStorage(const std::string &basePath,
                                   const std::string &baseFilename,
                                   size_t maxSegmentSize,
                                   size_t maxAttempts,
                                   std::chrono::milliseconds baseRetryDelay,
                                   size_t maxOpenFiles)
    : m_basePath(basePath),
      m_baseFilename(baseFilename),
      m_maxSegmentSize(maxSegmentSize),
      m_maxAttempts(maxAttempts),
      m_baseRetryDelay(baseRetryDelay),
      m_maxOpenFiles(maxOpenFiles),
      m_cache(maxOpenFiles, this)
{
    std::filesystem::create_directories(m_basePath);
    // Pre-warm the cache with the base filename
    m_cache.get(m_baseFilename);
}

SegmentedStorage::~SegmentedStorage()
{
    m_cache.closeAll();
}

// LRUCache methods
std::shared_ptr<SegmentedStorage::CacheEntry> SegmentedStorage::LRUCache::get(const std::string &filename)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_cache.find(filename);
    if (it != m_cache.end())
    {
        // Found in cache, move to front (most recently used)
        m_lruList.erase(it->second.lruIt);
        m_lruList.push_front(filename);
        it->second.lruIt = m_lruList.begin();
        return it->second.entry;
    }

    // Not in cache, need to reconstruct state
    auto entry = reconstructState(filename);

    // Check if we need to evict
    if (m_cache.size() >= m_capacity)
    {
        evictLRU();
    }

    // Add to cache
    m_lruList.push_front(filename);
    m_cache[filename] = {entry, m_lruList.begin()};

    return entry;
}

void SegmentedStorage::LRUCache::evictLRU()
{
    // Called with m_mutex already locked.
    // Lock ordering invariant: m_mutex may be held while acquiring a fileMutex, but never
    // the reverse. Callers of LRUCache::get() must not hold any fileMutex.
    if (m_lruList.empty())
        return;

    const std::string &lru_filename = m_lruList.back();
    auto it = m_cache.find(lru_filename);
    if (it != m_cache.end())
    {
        // Writers hold shared_lock(fileMutex) while calling pwriteFull; take exclusive
        // lock here so we never close an fd that is currently being written. Mark fd = -1
        // inside the lock so any later reader inside shared_lock observes the closed state.
        auto entry = it->second.entry;
        {
            std::unique_lock<std::shared_mutex> fileLock(entry->fileMutex);
            int fd = entry->fd;
            entry->fd = -1;
            if (fd >= 0)
            {
                try
                {
                    m_parent->fsyncRetry(fd);
                }
                catch (...)
                {
                    // Best-effort fsync on eviction; still close to avoid fd leak.
                }
                ::close(fd);
            }
        }
        m_cache.erase(it);
    }
    m_lruList.pop_back();
}

std::shared_ptr<SegmentedStorage::CacheEntry> SegmentedStorage::LRUCache::reconstructState(const std::string &filename)
{
    // Called with m_mutex already locked
    auto entry = std::make_shared<CacheEntry>();

    // Find the latest segment index for this filename
    size_t latestIndex = m_parent->findLatestSegmentIndex(filename);
    entry->segmentIndex.store(latestIndex, std::memory_order_release);

    // Generate the path for the current segment
    std::string segmentPath = m_parent->generateSegmentPath(filename, latestIndex);
    entry->currentSegmentPath = segmentPath;

    // Open the file and get its current size
    entry->fd = m_parent->openWithRetry(segmentPath.c_str(), O_CREAT | O_RDWR | O_APPEND, 0644);

    // Get the current file size to set as the offset
    size_t fileSize = m_parent->getFileSize(segmentPath);
    entry->currentOffset.store(fileSize, std::memory_order_release);

    return entry;
}

void SegmentedStorage::LRUCache::flush(const std::string &filename)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_cache.find(filename);
    if (it != m_cache.end() && it->second.entry->fd >= 0)
    {
        m_parent->fsyncRetry(it->second.entry->fd);
    }
}

void SegmentedStorage::LRUCache::flushAll()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto &pair : m_cache)
    {
        if (pair.second.entry->fd >= 0)
        {
            m_parent->fsyncRetry(pair.second.entry->fd);
        }
    }
}

void SegmentedStorage::LRUCache::closeAll()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto &pair : m_cache)
    {
        auto entry = pair.second.entry;
        std::unique_lock<std::shared_mutex> fileLock(entry->fileMutex);
        int fd = entry->fd;
        entry->fd = -1;
        if (fd >= 0)
        {
            try
            {
                m_parent->fsyncRetry(fd);
            }
            catch (...)
            {
                // Best-effort fsync on shutdown; still close to avoid fd leak.
            }
            ::close(fd);
        }
    }
    m_cache.clear();
    m_lruList.clear();
}

size_t SegmentedStorage::findLatestSegmentIndex(const std::string &filename) const
{
    size_t maxIndex = 0;
    std::string pattern = filename + "_";

    try
    {
        for (const auto &entry : std::filesystem::directory_iterator(m_basePath))
        {
            if (entry.is_regular_file())
            {
                std::string name = entry.path().filename().string();
                if (name.find(pattern) == 0)
                {
                    // Extract the index from filename format: filename_YYYYMMDD_HHMMSS_NNNNNN.log
                    size_t lastUnderscore = name.find_last_of('_');
                    if (lastUnderscore != std::string::npos)
                    {
                        size_t dotPos = name.find('.', lastUnderscore);
                        if (dotPos != std::string::npos)
                        {
                            std::string indexStr = name.substr(lastUnderscore + 1, dotPos - lastUnderscore - 1);
                            try
                            {
                                size_t index = std::stoull(indexStr);
                                maxIndex = std::max(maxIndex, index);
                            }
                            catch (...)
                            {
                                // Ignore files that don't match the expected format
                            }
                        }
                    }
                }
            }
        }
    }
    catch (const std::filesystem::filesystem_error &)
    {
        // If directory doesn't exist or other filesystem error, return 0
    }

    return maxIndex;
}

size_t SegmentedStorage::getFileSize(const std::string &path) const
{
    struct stat st;
    if (::stat(path.c_str(), &st) == 0)
    {
        return static_cast<size_t>(st.st_size);
    }
    return 0;
}

size_t SegmentedStorage::write(std::vector<uint8_t> &&data)
{
    return writeToFile(m_baseFilename, std::move(data));
}

size_t SegmentedStorage::writeToFile(const std::string &filename, std::vector<uint8_t> &&data)
{
    size_t size = data.size();
    if (size == 0)
        return 0;

    std::shared_ptr<CacheEntry> entry = m_cache.get(filename);
    size_t writeOffset;

    // Reserve and write under shared_lock so rotation (which requires unique_lock) cannot
    // happen between fetch_add and pwrite. Performing fetch_add outside the lock would
    // allow a rotation to sneak in: the abandoned reservation on the closed segment
    // leaves a gap that a later writer at a higher offset turns into a sparse hole — data
    // on disk becomes non-contiguous, breaking read-back of the raw concatenated blobs.
    while (true)
    {
        size_t genBefore = entry->generation.load(std::memory_order_acquire);
        size_t currentOffset = entry->currentOffset.load(std::memory_order_acquire);

        if (currentOffset + size > m_maxSegmentSize)
        {
            std::unique_lock<std::shared_mutex> rotLock(entry->fileMutex);
            // Only rotate if we still observe the pre-overflow generation. If another
            // thread already rotated, just retry the outer loop with fresh state.
            if (entry->generation.load(std::memory_order_acquire) == genBefore &&
                entry->currentOffset.load(std::memory_order_acquire) + size > m_maxSegmentSize)
            {
                rotateSegment(filename, entry);
            }
            continue;
        }

        std::shared_lock<std::shared_mutex> writeLock(entry->fileMutex);
        if (entry->fd < 0)
        {
            // Entry was evicted from the LRU cache. Re-fetch (which reopens the file)
            // and retry. Release the shared_lock first so m_cache.get() can safely take
            // its own internal mutex.
            writeLock.unlock();
            entry = m_cache.get(filename);
            continue;
        }
        if (entry->generation.load(std::memory_order_acquire) != genBefore)
        {
            continue;
        }

        writeOffset = entry->currentOffset.fetch_add(size, std::memory_order_acq_rel);
        if (writeOffset + size > m_maxSegmentSize)
        {
            // Another shared_lock holder crossed the boundary. Our fetch_add bumped the
            // counter past max but we don't write — no sparse hole results because we
            // never pwrite at this offset. Retry: the next iteration will see offset>max
            // and route through the rotation branch.
            continue;
        }

        pwriteFull(entry->fd, data.data(), size, static_cast<off_t>(writeOffset));
        break;
    }

    return size;
}

void SegmentedStorage::flush()
{
    m_cache.flushAll();
}

std::string SegmentedStorage::rotateSegment(const std::string &filename, std::shared_ptr<CacheEntry> entry)
{
    // exclusive lock assumed by the caller (writeToFile)

    // Close the old file descriptor
    if (entry->fd >= 0)
    {
        fsyncRetry(entry->fd);
        ::close(entry->fd);
        entry->fd = -1;
    }

    size_t newIndex = entry->segmentIndex.fetch_add(1, std::memory_order_acq_rel) + 1;
    entry->currentOffset.store(0, std::memory_order_release);
    std::string newPath = generateSegmentPath(filename, newIndex);

    // Update the entry's path and open the new file
    entry->currentSegmentPath = newPath;
    entry->fd = openWithRetry(newPath.c_str(), O_CREAT | O_RDWR | O_APPEND, 0644);

    // Bump generation LAST. Readers using acquire semantics on generation will, upon seeing
    // the new value, also observe the reset offset and new fd (release ordering via the
    // preceding stores). Writers holding a stale genBefore will detect the mismatch and retry.
    entry->generation.fetch_add(1, std::memory_order_acq_rel);

    return newPath;
}

std::string SegmentedStorage::generateSegmentPath(const std::string &filename, size_t segmentIndex) const
{
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm time_info;

    // Linux-specific thread-safe version of localtime
    localtime_r(&now_time_t, &time_info);

    std::stringstream ss;
    ss << m_basePath << "/";
    ss << filename << "_";
    ss << std::put_time(&time_info, "%Y%m%d_%H%M%S") << "_";
    ss << std::setw(6) << std::setfill('0') << segmentIndex << ".log";
    return ss.str();
}