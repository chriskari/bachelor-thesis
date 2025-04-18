#include "LoggingAPI.hpp"
#include <iostream>

// Initialize static members
std::unique_ptr<LoggingAPI> LoggingAPI::s_instance = nullptr;
std::mutex LoggingAPI::s_instanceMutex;

LoggingAPI &LoggingAPI::getInstance()
{
    std::lock_guard<std::mutex> lock(s_instanceMutex);
    if (s_instance == nullptr)
    {
        s_instance.reset(new LoggingAPI());
    }
    return *s_instance;
}

LoggingAPI::LoggingAPI()
    : m_initialized(false),
      m_appendTimeout(std::chrono::milliseconds::max())
{
}

LoggingAPI::~LoggingAPI()
{
    if (m_initialized)
    {
        reset();
    }
}

bool LoggingAPI::initialize(std::shared_ptr<LockFreeQueue> queue, std::chrono::milliseconds appendTimeout)
{
    std::unique_lock<std::shared_mutex> lock(m_apiMutex);

    if (m_initialized)
    {
        reportError("LoggingAPI already initialized");
        return false;
    }

    if (!queue)
    {
        reportError("Cannot initialize with a null queue");
        return false;
    }

    m_logQueue = queue;
    m_appendTimeout = appendTimeout;
    m_initialized = true;

    return true;
}

bool LoggingAPI::append(const LogEntry &entry)
{
    std::shared_lock<std::shared_mutex> lock(m_apiMutex);

    if (!m_initialized)
    {
        reportError("LoggingAPI not initialized");
        return false;
    }

    LogEntry entryCopy = entry;
    return m_logQueue->enqueueBlocking(entryCopy, m_appendTimeout);
}

bool LoggingAPI::appendBatch(const std::vector<LogEntry> &entries)
{
    std::shared_lock<std::shared_mutex> lock(m_apiMutex);

    if (!m_initialized)
    {
        reportError("LoggingAPI not initialized");
        return false;
    }

    if (entries.empty())
    {
        return true;
    }

    std::vector<LogEntry> entriesCopy(entries);
    return m_logQueue->enqueueBatchBlocking(entriesCopy, m_appendTimeout);
}

bool LoggingAPI::reset()
{
    std::unique_lock<std::shared_mutex> lock(m_apiMutex);

    if (!m_initialized)
    {
        return false;
    }

    // Reset state
    m_initialized = false;
    m_logQueue.reset();

    return true;
}

bool LoggingAPI::exportLogs(
    const std::string &outputPath,
    std::chrono::system_clock::time_point fromTimestamp,
    std::chrono::system_clock::time_point toTimestamp)
{
    std::shared_lock<std::shared_mutex> lock(m_apiMutex);

    if (!m_initialized)
    {
        reportError("LoggingAPI not initialized");
        return false;
    }

    // This functionality would typically be handled by a separate component,
    // such as a log storage or retrieval system
    reportError("Export logs functionality not implemented in LoggingAPI");
    return false;
}

void LoggingAPI::reportError(const std::string &message)
{
    std::cerr << "LoggingAPI Error: " << message << std::endl;
}