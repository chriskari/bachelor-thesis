#include "LogExporter.hpp"
#include "ByteOrder.hpp"
#include "Compression.hpp"
#include "Crypto.hpp"
#include "PlaceholderCryptoMaterial.hpp"
#include "SealMarker.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <utility>

namespace
{
bool isSealPlaintext(const std::vector<uint8_t> &plaintext)
{
    if (plaintext.size() != seal_marker::MAGIC_LEN)
        return false;
    return std::memcmp(plaintext.data(), seal_marker::MAGIC, seal_marker::MAGIC_LEN) == 0;
}

const char *actionTypeName(LogEntry::ActionType t)
{
    switch (t)
    {
    case LogEntry::ActionType::CREATE:
        return "CREATE";
    case LogEntry::ActionType::READ:
        return "READ";
    case LogEntry::ActionType::UPDATE:
        return "UPDATE";
    case LogEntry::ActionType::DELETE:
        return "DELETE";
    }
    return "UNKNOWN";
}

void appendJsonEscaped(std::string &out, const std::string &s)
{
    out.push_back('"');
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':
            out.append("\\\"");
            break;
        case '\\':
            out.append("\\\\");
            break;
        case '\b':
            out.append("\\b");
            break;
        case '\f':
            out.append("\\f");
            break;
        case '\n':
            out.append("\\n");
            break;
        case '\r':
            out.append("\\r");
            break;
        case '\t':
            out.append("\\t");
            break;
        default:
            if (c < 0x20)
            {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out.append(buf);
            }
            else
            {
                out.push_back(static_cast<char>(c));
            }
        }
    }
    out.push_back('"');
}

std::string base64Encode(const std::vector<uint8_t> &data)
{
    if (data.empty())
        return {};
    const size_t outLen = 4 * ((data.size() + 2) / 3);
    std::string out(outLen, '\0');
    int written = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&out[0]),
                                  data.data(),
                                  static_cast<int>(data.size()));
    if (written < 0)
        return {};
    out.resize(static_cast<size_t>(written));
    return out;
}

std::string formatRfc3339Utc(std::chrono::system_clock::time_point tp)
{
    using namespace std::chrono;
    const auto ms = duration_cast<milliseconds>(tp.time_since_epoch()).count();
    std::time_t secs = static_cast<std::time_t>(ms / 1000);
    int millis = static_cast<int>(ms % 1000);
    if (millis < 0)
    {
        // Handles pre-epoch time_points: round toward -inf for seconds.
        secs -= 1;
        millis += 1000;
    }
    std::tm tm{};
    gmtime_r(&secs, &tm);
    char buf[32];
    std::snprintf(buf, sizeof(buf),
                  "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, millis);
    return std::string(buf);
}

std::vector<uint8_t> readFile(const std::string &path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        return {};
    auto size = f.tellg();
    if (size <= 0)
        return {};
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    f.seekg(0);
    f.read(reinterpret_cast<char *>(buf.data()), size);
    return buf;
}

// (offset, size) views into a loaded segment — no per-blob copy; decryption
// reads the blob in place via Crypto's pointer/length overload.
struct BlobSpan
{
    size_t offset;
    size_t size;
};

std::vector<BlobSpan> splitSegmentIntoBlobSpans(const std::vector<uint8_t> &segment)
{
    std::vector<BlobSpan> spans;
    size_t pos = 0;
    while (pos + sizeof(uint32_t) <= segment.size())
    {
        uint32_t ciphertextSize = byteorder::readLE32(segment.data() + pos);
        size_t blobSize = sizeof(uint32_t) + Crypto::SEQNUM_SIZE + Crypto::GCM_IV_SIZE +
                          ciphertextSize + Crypto::GCM_TAG_SIZE;
        if (pos + blobSize > segment.size())
            break;
        spans.push_back({pos, blobSize});
        pos += blobSize;
    }
    return spans;
}

// Filename layout "<target>_YYYYMMDD_HHMMSS_NNNNNN.log" — strip the three trailing
// underscore-separated fields to recover the target name used for AAD binding.
std::string parseTargetFromSegmentPath(const std::string &path)
{
    std::filesystem::path p(path);
    std::string stem = p.stem().string();
    for (int i = 0; i < 3; ++i)
    {
        auto pos = stem.rfind('_');
        if (pos == std::string::npos)
            return stem;
        stem.resize(pos);
    }
    return stem;
}

std::vector<std::string> listSegments(const std::string &dir)
{
    std::vector<std::string> files;
    if (!std::filesystem::exists(dir))
        return files;
    for (const auto &entry : std::filesystem::directory_iterator(dir))
    {
        if (!entry.is_regular_file())
            continue;
        if (entry.path().extension() == ".log")
            files.push_back(entry.path().string());
    }
    std::sort(files.begin(), files.end());
    return files;
}

bool passesFilter(const LogEntry &e, const ExportFilter &filter)
{
    const auto unset = std::chrono::system_clock::time_point{};
    if (filter.from != unset && e.getTimestamp() < filter.from)
        return false;
    if (filter.to != unset && e.getTimestamp() > filter.to)
        return false;
    if (filter.subjectId && e.getDataSubjectId() != *filter.subjectId)
        return false;
    return true;
}

void writeNdjsonLine(std::ostream &out, const LogEntry &e)
{
    std::string line;
    line.reserve(256 + e.getPayload().size() * 2);
    line.append("{\"actionType\":\"");
    line.append(actionTypeName(e.getActionType()));
    line.append("\",\"dataLocation\":");
    appendJsonEscaped(line, e.getDataLocation());
    line.append(",\"dataControllerId\":");
    appendJsonEscaped(line, e.getDataControllerId());
    line.append(",\"dataProcessorId\":");
    appendJsonEscaped(line, e.getDataProcessorId());
    line.append(",\"dataSubjectId\":");
    appendJsonEscaped(line, e.getDataSubjectId());
    line.append(",\"timestamp\":\"");
    line.append(formatRfc3339Utc(e.getTimestamp()));
    line.append("\",\"payload\":\"");
    line.append(base64Encode(e.getPayload()));
    line.append("\"}\n");
    out.write(line.data(), static_cast<std::streamsize>(line.size()));
}

struct DecodedBatch
{
    uint64_t seqnum;
    std::vector<LogEntry> entries;
    std::string segmentPath;
    size_t blobOffset;
};

struct TargetState
{
    std::vector<DecodedBatch> batches;
    // One entry per seal blob. Multiple seals are legitimate since each run
    // over the same directory writes one on clean shutdown; only the newest
    // (highest) seal can attest the current tail.
    std::vector<uint64_t> sealSeqnums;
};

// Header of one blob inside a segment, discovered without reading the payload.
struct BlobHeaderInfo
{
    size_t offset;
    size_t size;
    uint64_t seqnum;
};

// Walks the blob chain of a segment reading only the [u32 size][u64 seqnum]
// headers and seeking over payloads, so startup recovery does not load whole
// segments. Stops at a torn trailing blob.
std::vector<BlobHeaderInfo> scanSegmentBlobHeaders(const std::string &path)
{
    std::vector<BlobHeaderInfo> out;
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        return out;
    const size_t fileSize = static_cast<size_t>(f.tellg());
    const size_t headerSize = sizeof(uint32_t) + Crypto::SEQNUM_SIZE;
    uint8_t header[sizeof(uint32_t) + Crypto::SEQNUM_SIZE];
    size_t pos = 0;
    while (pos + headerSize <= fileSize)
    {
        f.seekg(static_cast<std::streamoff>(pos));
        f.read(reinterpret_cast<char *>(header), static_cast<std::streamsize>(headerSize));
        if (!f)
            break;
        const uint32_t ciphertextSize = byteorder::readLE32(header);
        const uint64_t seqnum = byteorder::readLE64(header + sizeof(uint32_t));
        const size_t blobSize = sizeof(uint32_t) + Crypto::SEQNUM_SIZE + Crypto::GCM_IV_SIZE +
                                ciphertextSize + Crypto::GCM_TAG_SIZE;
        if (pos + blobSize > fileSize)
            break;
        out.push_back({pos, blobSize, seqnum});
        pos += blobSize;
    }
    return out;
}

std::vector<uint8_t> readFileRange(const std::string &path, size_t offset, size_t size)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};
    f.seekg(static_cast<std::streamoff>(offset));
    std::vector<uint8_t> buf(size);
    f.read(reinterpret_cast<char *>(buf.data()), static_cast<std::streamsize>(size));
    if (!f)
        return {};
    return buf;
}
} // namespace

LogExporter::LogExporter(std::string basePath, bool useEncryption, int compressionLevel,
                         size_t maxDecompressedSize)
    : m_basePath(std::move(basePath)),
      m_useEncryption(useEncryption),
      m_compressionLevel(compressionLevel),
      m_maxDecompressedSize(maxDecompressedSize)
{
}

std::map<std::string, RecoveredTargetState> LogExporter::recoverTargetStates(
    const std::string &basePath, int compressionLevel)
{
    // A seal blob is tiny (10-byte plaintext); anything bigger than this is
    // certainly a data batch and needs no decryption to classify.
    constexpr size_t SEAL_CANDIDATE_MAX_BLOB_SIZE = 4096;
    // Classification only ever inflates seal-sized plaintexts; a data batch
    // hitting this cap is classified as data via the catch below.
    constexpr size_t CLASSIFY_MAX_DECOMPRESSED = 1024 * 1024;

    struct Candidate
    {
        std::string segmentPath;
        size_t offset;
        size_t size;
    };
    struct Scan
    {
        bool any = false;
        uint64_t maxSeqnum = 0;
        std::vector<Candidate> maxSeqnumBlobs;
    };

    std::map<std::string, Scan> scans;
    for (const auto &segmentPath : listSegments(basePath))
    {
        const std::string target = parseTargetFromSegmentPath(segmentPath);
        Scan &scan = scans[target];
        for (const auto &blob : scanSegmentBlobHeaders(segmentPath))
        {
            if (!scan.any || blob.seqnum > scan.maxSeqnum)
            {
                scan.any = true;
                scan.maxSeqnum = blob.seqnum;
                scan.maxSeqnumBlobs.clear();
            }
            if (blob.seqnum == scan.maxSeqnum)
            {
                scan.maxSeqnumBlobs.push_back({segmentPath, blob.offset, blob.size});
            }
        }
    }

    std::map<std::string, RecoveredTargetState> out;
    if (scans.empty())
        return out;

    Crypto crypto;
    Compression compression;
    const std::vector<uint8_t> key(Crypto::KEY_SIZE, placeholder_crypto::KEY_BYTE);

    for (const auto &[target, scan] : scans)
    {
        if (!scan.any)
            continue;

        // The max seqnum S is ambiguous on its own: a clean run ends with a
        // seal AT S (count = S), a crashed run ends with a data batch at S
        // (count = S + 1). Both can coexist after crash-after-clean-run, so
        // classify every blob carrying S.
        bool sawData = false;
        bool sawSeal = false;
        for (const auto &candidate : scan.maxSeqnumBlobs)
        {
            if (candidate.size > SEAL_CANDIDATE_MAX_BLOB_SIZE)
            {
                sawData = true;
                continue;
            }
            try
            {
                auto blobBytes = readFileRange(candidate.segmentPath, candidate.offset,
                                               candidate.size);
                auto plaintext = crypto.decrypt(blobBytes, key,
                                                reinterpret_cast<const uint8_t *>(target.data()),
                                                target.size());
                std::vector<uint8_t> serialized =
                    compressionLevel > 0
                        ? compression.decompress(std::move(plaintext),
                                                 CLASSIFY_MAX_DECOMPRESSED)
                        : std::move(plaintext);
                if (isSealPlaintext(serialized))
                    sawSeal = true;
                else
                    sawData = true;
            }
            catch (const std::exception &e)
            {
                // Unreadable counts as data: continuing one seqnum past it can
                // never reuse a number, whereas assuming "seal" could.
                std::cerr << "LogExporter: recovery could not classify blob in "
                          << candidate.segmentPath << " at offset " << candidate.offset
                          << " (" << e.what() << "); treating as data" << std::endl;
                sawData = true;
            }
        }

        RecoveredTargetState state;
        state.count = sawData ? scan.maxSeqnum + 1 : scan.maxSeqnum;
        state.sealed = sawSeal && !sawData;
        out[target] = state;
    }
    return out;
}

bool LogExporter::exportToNDJSON(const std::string &outputPath, const ExportFilter &filter)
{
    if (!m_useEncryption)
    {
        std::cerr << "LogExporter: useEncryption=false is not supported — "
                     "the on-disk format lacks per-batch framing without encryption."
                  << std::endl;
        return false;
    }

    std::ofstream out(outputPath, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        std::cerr << "LogExporter: failed to open output path: " << outputPath << std::endl;
        return false;
    }

    auto abortAndCleanup = [&](const std::string &reason)
    {
        out.close();
        std::error_code ec;
        std::filesystem::remove(outputPath, ec);
        std::cerr << "LogExporter: " << reason << std::endl;
    };

    Crypto crypto;
    Compression compression;
    const std::vector<uint8_t> key(Crypto::KEY_SIZE, placeholder_crypto::KEY_BYTE);

    std::map<std::string, TargetState> perTarget;

    for (const auto &segmentPath : listSegments(m_basePath))
    {
        auto segment = readFile(segmentPath);
        if (segment.empty())
            continue;

        const std::string target = parseTargetFromSegmentPath(segmentPath);
        TargetState &state = perTarget[target];

        for (const auto &blob : splitSegmentIntoBlobSpans(segment))
        {
            const uint8_t *blobPtr = segment.data() + blob.offset;
            uint64_t seqnum = 0;
            if (!Crypto::peekSeqnum(blobPtr, blob.size, seqnum))
            {
                std::ostringstream msg;
                msg << "malformed blob (too small for header) in " << segmentPath
                    << " at offset " << blob.offset;
                abortAndCleanup(msg.str());
                return false;
            }

            std::vector<uint8_t> plaintext;
            try
            {
                plaintext = crypto.decrypt(blobPtr, blob.size, key,
                                           reinterpret_cast<const uint8_t *>(target.data()),
                                           target.size());
            }
            catch (const TamperDetectedException &e)
            {
                std::ostringstream msg;
                msg << "tamper detected in " << segmentPath
                    << " at offset " << blob.offset
                    << " (seqnum " << seqnum << ", target '" << target << "'): "
                    << e.what();
                abortAndCleanup(msg.str());
                return false;
            }
            catch (const std::exception &e)
            {
                std::ostringstream msg;
                msg << "decryption failed in " << segmentPath
                    << " at offset " << blob.offset << ": " << e.what();
                abortAndCleanup(msg.str());
                return false;
            }

            std::vector<uint8_t> serialized;
            if (m_compressionLevel > 0)
            {
                try
                {
                    serialized = compression.decompress(std::move(plaintext),
                                                        m_maxDecompressedSize);
                }
                catch (const std::exception &e)
                {
                    std::ostringstream msg;
                    msg << "decompression failed in " << segmentPath
                        << " at offset " << blob.offset << ": " << e.what();
                    abortAndCleanup(msg.str());
                    return false;
                }
            }
            else
            {
                serialized = std::move(plaintext);
            }

            if (isSealPlaintext(serialized))
            {
                state.sealSeqnums.push_back(seqnum);
                continue;
            }

            std::vector<LogEntry> entries;
            try
            {
                entries = LogEntry::deserializeBatch(std::move(serialized));
            }
            catch (const std::exception &e)
            {
                std::ostringstream msg;
                msg << "deserialization failed in " << segmentPath
                    << " at offset " << blob.offset << ": " << e.what();
                abortAndCleanup(msg.str());
                return false;
            }

            state.batches.push_back(DecodedBatch{seqnum, std::move(entries),
                                                 segmentPath, blob.offset});
        }
    }

    for (auto &[target, state] : perTarget)
    {
        auto &batches = state.batches;
        std::sort(batches.begin(), batches.end(),
                  [](const DecodedBatch &a, const DecodedBatch &b)
                  { return a.seqnum < b.seqnum; });

        for (size_t i = 0; i < batches.size(); ++i)
        {
            const uint64_t expected = static_cast<uint64_t>(i);
            if (batches[i].seqnum != expected)
            {
                std::ostringstream msg;
                if (i + 1 < batches.size() && batches[i + 1].seqnum == batches[i].seqnum)
                {
                    msg << "duplicate seqnum " << batches[i].seqnum
                        << " for target '" << target << "'";
                }
                else
                {
                    msg << "seqnum gap for target '" << target
                        << "': expected " << expected
                        << ", got " << batches[i].seqnum;
                }
                abortAndCleanup(msg.str());
                return false;
            }
        }

        // Seal semantics with multi-run logs: every seal marks a clean
        // shutdown boundary (seqnum == data-batch count at that shutdown).
        // Any seal above the present count proves truncation; a tail beyond
        // the newest seal (crash, or no seal at all) cannot be attested.
        auto &seals = state.sealSeqnums;
        std::sort(seals.begin(), seals.end());
        seals.erase(std::unique(seals.begin(), seals.end()), seals.end());

        const uint64_t dataCount = static_cast<uint64_t>(batches.size());
        for (uint64_t sealSeqnum : seals)
        {
            if (sealSeqnum > dataCount)
            {
                std::ostringstream msg;
                msg << "target '" << target << "' truncated: seal reports "
                    << sealSeqnum << " batches but "
                    << dataCount << " present";
                abortAndCleanup(msg.str());
                return false;
            }
        }

        if (seals.empty() || seals.back() != dataCount)
        {
            // Missing/stale final seal = crash before shutdown (or an attacker
            // dropped it). Tail-truncation of the unsealed part is
            // undetectable; partial export continues.
            std::cerr << "LogExporter: warning — no final seal for target '"
                      << target << "' (tail truncation beyond "
                      << (seals.empty() ? 0 : seals.back())
                      << " batches cannot be detected)" << std::endl;
        }

        for (const auto &batch : batches)
        {
            for (const auto &e : batch.entries)
            {
                if (passesFilter(e, filter))
                    writeNdjsonLine(out, e);
            }
        }
    }

    out.flush();
    if (!out)
    {
        abortAndCleanup("output stream in bad state after write");
        return false;
    }
    return true;
}
