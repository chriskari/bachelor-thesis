#ifndef LOGGING_API_HPP
#define LOGGING_API_HPP

#include "LogEntry.hpp"
#include "LockFreeBuffer.hpp"
#include <string>
#include <chrono>
#include <memory>
#include <vector>
#include <mutex>
#include <functional>

class LoggingAPI
{
    friend class LoggingAPITest;

public:
    static LoggingAPI &getInstance();

    bool initialize(std::shared_ptr<LockFreeQueue> queue);

    bool append(const LogEntry &entry);

    bool append(LogEntry::ActionType actionType,
                const std::string &dataLocation,
                const std::string &userId,
                const std::string &dataSubjectId);

    // Shutdown the logging system gracefully
    // waitForCompletion: Whether to wait for all pending entries to be written
    bool shutdown(bool waitForCompletion = true);

    bool exportLogs(const std::string &outputPath,
                    std::chrono::system_clock::time_point fromTimestamp = std::chrono::system_clock::time_point(),
                    std::chrono::system_clock::time_point toTimestamp = std::chrono::system_clock::time_point());

    ~LoggingAPI();

private:
    LoggingAPI();
    LoggingAPI(const LoggingAPI &) = delete;
    LoggingAPI &operator=(const LoggingAPI &) = delete;
    // Singleton instance
    static std::unique_ptr<LoggingAPI> s_instance;
    static std::mutex s_instanceMutex;

    std::shared_ptr<LockFreeQueue> m_logQueue;

    // State tracking
    bool m_initialized;
    std::mutex m_apiMutex;

    // Helper to report errors
    void reportError(const std::string &message);
};

#endif