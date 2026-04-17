#ifndef LOG_EXPORTER_HPP
#define LOG_EXPORTER_HPP

#include "LogEntry.hpp"
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Filter applied per entry during export. Epoch-value time points mean
// "unbounded on that side"; subjectId == nullopt means "no subject filter".
struct ExportFilter
{
    std::chrono::system_clock::time_point from{};
    std::chrono::system_clock::time_point to{};
    std::optional<std::string> subjectId;
};

class LogExporter
{
public:
    LogExporter(std::string basePath, bool useEncryption, int compressionLevel);

    // Walks all *.log segment files under basePath, reverses the Writer
    // pipeline (decrypt -> [decompress] -> deserialize), applies `filter`,
    // and writes NDJSON (one entry per line) to `outputPath`.
    //
    // Returns false and removes any partial output file if:
    //   - useEncryption was false at construction (unframed format unsupported)
    //   - a segment blob fails AES-GCM tag verification (tamper)
    //   - any I/O or parse error occurs
    bool exportToNDJSON(const std::string &outputPath, const ExportFilter &filter);

private:
    std::string m_basePath;
    bool m_useEncryption;
    int m_compressionLevel;
};

#endif
