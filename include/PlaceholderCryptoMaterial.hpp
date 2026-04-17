#ifndef PLACEHOLDER_CRYPTO_MATERIAL_HPP
#define PLACEHOLDER_CRYPTO_MATERIAL_HPP

#include <cstdint>

// Placeholder AES-256-GCM key and IV used by Writer when encrypting, and by
// LogExporter / round-trip tests when decrypting. Key management is out of
// scope for this codebase (see README "Security Scope and Limitations") — a
// production deployment must source the key from a KMS and use a fresh IV per
// batch. Centralized here so writer and reader paths cannot drift.
namespace placeholder_crypto
{
constexpr uint8_t KEY_BYTE = 0x42;
constexpr uint8_t IV_BYTE = 0x24;
} // namespace placeholder_crypto

#endif
