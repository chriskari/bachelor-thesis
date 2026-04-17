#include "LogExporter.hpp"
#include "ByteOrder.hpp"
#include "Compression.hpp"
#include "Crypto.hpp"
#include "PlaceholderCryptoMaterial.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <utility>

namespace
{
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

// Returns the list of [u32 size][ciphertext][GCM_TAG] blob spans. Each element
// is a pair of (byteOffsetInSegment, blobBytes) so we can report the offset on
// tamper.
struct Blob
{
    size_t offset;
    std::vector<uint8_t> bytes;
};

std::vector<Blob> splitSegmentIntoBlobs(const std::vector<uint8_t> &segment)
{
    std::vector<Blob> blobs;
    size_t pos = 0;
    while (pos + sizeof(uint32_t) <= segment.size())
    {
        uint32_t ciphertextSize = byteorder::readLE32(segment.data() + pos);
        size_t blobSize = sizeof(uint32_t) + ciphertextSize + Crypto::GCM_TAG_SIZE;
        if (pos + blobSize > segment.size())
            break;
        blobs.push_back({pos, std::vector<uint8_t>(segment.begin() + pos,
                                                   segment.begin() + pos + blobSize)});
        pos += blobSize;
    }
    return blobs;
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
} // namespace

LogExporter::LogExporter(std::string basePath, bool useEncryption, int compressionLevel)
    : m_basePath(std::move(basePath)),
      m_useEncryption(useEncryption),
      m_compressionLevel(compressionLevel)
{
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
    const std::vector<uint8_t> iv(Crypto::GCM_IV_SIZE, placeholder_crypto::IV_BYTE);

    for (const auto &segmentPath : listSegments(m_basePath))
    {
        auto segment = readFile(segmentPath);
        if (segment.empty())
            continue;

        for (const auto &blob : splitSegmentIntoBlobs(segment))
        {
            std::vector<uint8_t> plaintext;
            try
            {
                plaintext = crypto.decrypt(blob.bytes, key, iv);
            }
            catch (const TamperDetectedException &e)
            {
                std::ostringstream msg;
                msg << "tamper detected in " << segmentPath
                    << " at offset " << blob.offset << ": " << e.what();
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
                    serialized = compression.decompress(std::move(plaintext));
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

            for (const auto &e : entries)
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
