// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "path_authority/authority.hpp"
#include "path_authority/export.hpp"
#include "path_authority/persistence.hpp"
#include "path_authority/snapshot.hpp"
#include "path_authority/wire.hpp"

namespace path_authority {

// Minimal deterministic JSON writer used by the CLI and the examples. Object
// members are emitted in insertion order, which callers keep stable so output
// is byte-for-byte reproducible.
class PATH_AUTHORITY_API JsonWriter {
 public:
  JsonWriter& begin_object();
  JsonWriter& end_object();
  JsonWriter& begin_array();
  JsonWriter& end_array();
  JsonWriter& key(std::string_view name);
  JsonWriter& string(std::string_view value);
  JsonWriter& number(std::uint64_t value);
  JsonWriter& number(std::int64_t value);
  JsonWriter& boolean(bool value);
  JsonWriter& null_value();
  JsonWriter& member(std::string_view name, std::string_view value);
  JsonWriter& member(std::string_view name, std::uint64_t value);
  JsonWriter& member(std::string_view name, bool value);
  JsonWriter& member_string_array(std::string_view name, const std::vector<std::string>& values);

  const std::string& str() const noexcept { return out_; }

 private:
  void separate();
  void indent();
  std::string out_;
  int depth_ = 0;
  bool need_comma_ = false;
};

PATH_AUTHORITY_API std::string to_json(const EvaluationResult& result);
PATH_AUTHORITY_API std::string to_json(const AuthoritySnapshot& snapshot);
PATH_AUTHORITY_API std::string to_json(const AuthorityDiff& diff);
PATH_AUTHORITY_API std::string to_json(const EvidenceVector& evidence);
PATH_AUTHORITY_API std::string to_json(const PathDefinition& path);
PATH_AUTHORITY_API std::string to_json(const InvalidationReport& report);
PATH_AUTHORITY_API std::string to_json(const PersistenceInfo& info);
PATH_AUTHORITY_API std::string to_json(const DurableState& state);
PATH_AUTHORITY_API std::string to_json(const WorkerInfo& worker);
PATH_AUTHORITY_API std::string to_json(const std::vector<WorkerInfo>& workers);

}  // namespace path_authority
