// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "path_authority/export.hpp"

namespace path_authority {

// Digest scheme: SHA-256 over the deterministic canonical encoding of the
// semantic content named by the digest. The scheme version is carried
// separately (kDigestSchemeVersion) because it is a compatibility surface.
class PATH_AUTHORITY_API Digest {
 public:
  static constexpr std::size_t kBytes = 32;
  static constexpr std::size_t kHexLength = 64;

  constexpr Digest() noexcept = default;

  static Digest of(std::span<const std::byte> bytes) noexcept;
  static Digest of(std::string_view text) noexcept;
  static std::optional<Digest> from_hex(std::string_view hex) noexcept;
  static Digest from_bytes(std::array<std::byte, kBytes> bytes) noexcept;

  std::string hex() const;
  std::string short_hex(std::size_t chars) const;

  const std::array<std::byte, kBytes>& bytes() const noexcept { return bytes_; }
  bool is_zero() const noexcept;

  friend bool operator==(const Digest&, const Digest&) noexcept = default;
  friend std::strong_ordering operator<=>(const Digest&, const Digest&) noexcept = default;

 private:
  std::array<std::byte, kBytes> bytes_{};
};

// SHA-256 primitive. Exposed because the wire protocol, persistence layer and
// semantic digests all depend on one audited implementation.
PATH_AUTHORITY_API Digest sha256(std::span<const std::byte> bytes) noexcept;

}  // namespace path_authority
