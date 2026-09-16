// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>

#include "path_authority/export.hpp"

namespace path_authority {

// Every bound below is enforced by the subsystem named in its comment. A limit
// that is not enforced by a named path is a defect, not a configuration knob.
struct PATH_AUTHORITY_API Limits {
  // Structure validation and decoding (path.cpp, canonical.cpp).
  std::uint32_t max_hops = 64;                    // hops in one candidate path
  std::uint32_t max_id_length = 128;              // bytes in one element identity
  std::uint32_t max_metadata_bytes = 4096;        // bytes in one free-form field

  // Constraint model (constraints.cpp).
  std::uint32_t max_constraints = 256;            // capability + domain constraints per set
  std::uint32_t max_capability_values = 64;       // values inside one requirement leaf
  std::uint32_t max_requirement_nodes = 128;      // nodes per requirement expression
  std::uint32_t max_requirement_depth = 8;        // nesting depth per requirement expression
  std::uint32_t max_failure_domain_refs = 128;    // failure-domain constraints per set
  std::uint32_t max_nesting_depth = 4;            // logical path -> underlying path depth

  // Runtime (runtime.cpp).
  std::uint32_t max_paths = 1000000;              // path records retained
  std::uint32_t max_batch = 4096;                 // paths per batch evaluation
  std::uint32_t max_history = 32;                 // history entries retained per path
  std::uint32_t max_explanation_entries = 64;     // violations retained per result
  std::uint32_t max_dependencies_per_path = 4096; // distinct evidence dependencies
  std::uint32_t max_outstanding_attempts = 1048576;  // attempt ids tracked process-wide
  std::uint32_t max_publishers = 4096;            // publisher incarnations tracked

  // Persistence and wire (persistence.cpp, wire.cpp).
  std::uint32_t max_frame_bytes = 1048576;        // one protocol frame
  std::uint32_t max_store_bytes = 1073741824;     // persisted image
  std::uint32_t max_store_records = 1000000;      // records in one image

  static constexpr Limits defaults() noexcept { return Limits{}; }
  bool valid() const noexcept;
  std::string describe() const;
};

}  // namespace path_authority
