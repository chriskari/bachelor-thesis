#ifndef SEQNUM_ALLOCATOR_HPP
#define SEQNUM_ALLOCATOR_HPP

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// Per-target monotonic counter. Only the first call for a target holds the
// map mutex; subsequent calls are a lock-free fetch_add on the per-target atomic.
class SeqnumAllocator
{
public:
    uint64_t next(const std::string &target);

    uint64_t peek(const std::string &target) const;

    // (target, count) pairs where count is the number of seqnums already issued.
    std::vector<std::pair<std::string, uint64_t>> snapshot() const;

private:
    mutable std::mutex m_mapMutex;
    std::unordered_map<std::string, std::unique_ptr<std::atomic<uint64_t>>> m_counters;
};

#endif
