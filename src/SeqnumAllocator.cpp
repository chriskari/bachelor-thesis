#include "SeqnumAllocator.hpp"

uint64_t SeqnumAllocator::next(const std::string &target)
{
    std::atomic<uint64_t> *counter;
    {
        std::lock_guard<std::mutex> lock(m_mapMutex);
        auto it = m_counters.find(target);
        if (it == m_counters.end())
        {
            it = m_counters.emplace(target,
                                    std::make_unique<std::atomic<uint64_t>>(0)).first;
        }
        counter = it->second.get();
    }
    return counter->fetch_add(1, std::memory_order_relaxed);
}

uint64_t SeqnumAllocator::peek(const std::string &target) const
{
    std::lock_guard<std::mutex> lock(m_mapMutex);
    auto it = m_counters.find(target);
    if (it == m_counters.end())
        return 0;
    return it->second->load(std::memory_order_relaxed);
}

std::vector<std::pair<std::string, uint64_t>> SeqnumAllocator::snapshot() const
{
    std::vector<std::pair<std::string, uint64_t>> out;
    std::lock_guard<std::mutex> lock(m_mapMutex);
    out.reserve(m_counters.size());
    for (const auto &[target, counter] : m_counters)
    {
        out.emplace_back(target, counter->load(std::memory_order_relaxed));
    }
    return out;
}
