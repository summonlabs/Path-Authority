// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "path_authority/export.hpp"
#include "path_authority/runtime.hpp"

namespace path_authority {

// Versioned, integrity-checked, deterministically encoded durable state.
// Layout:
//   magic           8 bytes  "PATHAUTH"
//   format version  u32      kPersistenceFormatVersion
//   payload bytes   u64      bounded by Limits::max_store_bytes
//   payload         canonical encoding of DurableState
//   sha256          32 bytes over magic+version+length+payload
class PATH_AUTHORITY_API PersistenceError : public std::runtime_error {
 public:
  explicit PersistenceError(const std::string& what) : std::runtime_error(what) {}
};

struct PATH_AUTHORITY_API PersistenceInfo {
  bool readable = false;
  std::uint32_t format_version = 0;
  std::size_t image_bytes = 0;
  std::size_t payload_bytes = 0;
  std::size_t record_count = 0;
  CoordinatorEpoch epoch;
  PolicyGeneration policy;
  std::size_t constraint_sets = 0;
  std::size_t revoked = 0;
  std::size_t authorizing = 0;
  Digest image_digest;
  std::string problem;
};

// Canonical, bounded, integrity-checked codec.
PATH_AUTHORITY_API std::vector<std::byte> encode_durable_state(const DurableState& state,
                                                              const Limits& limits);
PATH_AUTHORITY_API DurableState decode_durable_state(std::span<const std::byte> image,
                                                     const Limits& limits);

// Atomic replacement: the image is written to a unique temporary file in the
// destination directory, flushed, then moved over the destination. A failed
// write never leaves a partial image at the destination path.
PATH_AUTHORITY_API void write_store(const DurableState& state,
                                    const std::filesystem::path& path,
                                    const Limits& limits);
PATH_AUTHORITY_API DurableState read_store(const std::filesystem::path& path,
                                           const Limits& limits);

// Never throws. Reports the shape of an image, or the reason it is rejected.
PATH_AUTHORITY_API PersistenceInfo inspect_store(const std::filesystem::path& path,
                                                 const Limits& limits);

}  // namespace path_authority
