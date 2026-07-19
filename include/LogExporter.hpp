#ifndef LOG_EXPORTER_HPP
#define LOG_EXPORTER_HPP

#include "LogEntry.hpp"
#include <chrono>
#include <cstdint>
#include <map>
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

// Per-target state recovered from an existing log directory at startup:
// how many data batches are on disk (`count`, the next seqnum to issue) and
// whether a seal at exactly that count exists (last run shut down cleanly
// and nothing was appended since).
struct RecoveredTargetState
{
    uint64_t count = 0;
    bool sealed = false;
};

class LogExporter
{
public:
    // maxDecompressedSize bounds a single batch's plaintext during export.
    // Batch plaintext is AES-GCM-authenticated before it reaches inflate, so
    // this is a sanity bound, not a zip-bomb defense — it must be at least
    // the writer's largest legal batch (batchSize * MAX_ENTRY_SIZE), or
    // honest logs fail to export.
    LogExporter(std::string basePath, bool useEncryption, int compressionLevel,
                size_t maxDecompressedSize = DEFAULT_MAX_BATCH_PLAINTEXT);

    static constexpr size_t DEFAULT_MAX_BATCH_PLAINTEXT =
        100 * (LogEntry::MAX_ENTRY_SIZE + sizeof(uint32_t)) + sizeof(uint32_t);

    // Streams over blob headers in all segments under basePath (decrypting
    // only tiny max-seqnum candidates to tell seal from data) so a restarted
    // LoggingManager can continue per-target seqnums instead of reissuing
    // them from 0 — which would make every later export abort on duplicates.
    static std::map<std::string, RecoveredTargetState> recoverTargetStates(
        const std::string &basePath, int compressionLevel);

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
    size_t m_maxDecompressedSize;
};

#endif
