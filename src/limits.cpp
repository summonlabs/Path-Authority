// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/limits.hpp"

#include <string>

namespace path_authority {

bool Limits::valid() const noexcept {
  // Every bound is enforced somewhere by name; a zero bound would silently
  // disable its subsystem, so it is rejected at construction instead.
  return max_hops > 1 && max_id_length > 0 && max_metadata_bytes > 0 && max_constraints > 0 &&
         max_capability_values > 0 && max_requirement_nodes > 0 && max_requirement_depth > 0 &&
         max_failure_domain_refs > 0 && max_nesting_depth > 0 && max_paths > 0 && max_batch > 0 &&
         max_history > 0 && max_explanation_entries > 0 && max_dependencies_per_path > 0 &&
         max_outstanding_attempts > 0 && max_publishers > 0 && max_frame_bytes > 0 &&
         max_store_bytes > 0 && max_store_records > 0;
}

std::string Limits::describe() const {
  std::string text;
  const auto line = [&text](const char* name, std::uint64_t value) {
    text += std::string(name) + "=" + std::to_string(value) + "\n";
  };
  line("max_hops", max_hops);
  line("max_id_length", max_id_length);
  line("max_metadata_bytes", max_metadata_bytes);
  line("max_constraints", max_constraints);
  line("max_capability_values", max_capability_values);
  line("max_requirement_nodes", max_requirement_nodes);
  line("max_requirement_depth", max_requirement_depth);
  line("max_failure_domain_refs", max_failure_domain_refs);
  line("max_nesting_depth", max_nesting_depth);
  line("max_paths", max_paths);
  line("max_batch", max_batch);
  line("max_history", max_history);
  line("max_explanation_entries", max_explanation_entries);
  line("max_dependencies_per_path", max_dependencies_per_path);
  line("max_outstanding_attempts", max_outstanding_attempts);
  line("max_publishers", max_publishers);
  line("max_frame_bytes", max_frame_bytes);
  line("max_store_bytes", max_store_bytes);
  line("max_store_records", max_store_records);
  return text;
}

}  // namespace path_authority
