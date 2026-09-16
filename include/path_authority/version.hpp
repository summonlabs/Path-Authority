// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "path_authority/export.hpp"

namespace path_authority {

inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;

// Independently versioned compatibility surfaces. These are deliberately not
// tied to the package version.
inline constexpr std::uint32_t kPersistenceFormatVersion = 1;
inline constexpr std::uint32_t kCanonicalEncodingVersion = 1;
inline constexpr std::uint32_t kDigestSchemeVersion = 1;
inline constexpr std::uint16_t kWireProtocolVersion = 1;
inline constexpr std::uint32_t kRuleSetVersion = 1;

// Deterministic display strings derived from the constants above.
PATH_AUTHORITY_API std::string_view library_name() noexcept;
PATH_AUTHORITY_API std::string_view version_string() noexcept;
PATH_AUTHORITY_API std::string version_report();

}  // namespace path_authority
