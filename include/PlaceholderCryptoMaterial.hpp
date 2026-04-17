#ifndef PLACEHOLDER_CRYPTO_MATERIAL_HPP
#define PLACEHOLDER_CRYPTO_MATERIAL_HPP

#include <cstdint>

// Placeholder AES-256-GCM key used by Writer when encrypting, and by
// LogExporter / round-trip tests when decrypting. Key management is out of
// scope for this codebase (see README "Security Scope and Limitations") — a
// production deployment must source the key from a KMS. Centralized here so
// writer and reader paths cannot drift. IVs are generated freshly per batch
// inside Crypto::encrypt via RAND_bytes and embedded in the ciphertext wire
// format, so no placeholder IV is needed.
namespace placeholder_crypto
{
constexpr uint8_t KEY_BYTE = 0x42;
} // namespace placeholder_crypto

#endif
