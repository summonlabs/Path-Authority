// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/json.hpp"

#include <string>
#include <utility>

#include "path_authority/version.hpp"

namespace path_authority {
namespace {

void escape_into(std::string& out, std::string_view value) {
  for (char c : value) {
    const unsigned char raw = static_cast<unsigned char>(c);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (raw < 0x20) {
          static const char* kHex = "0123456789abcdef";
          out += "\\u00";
          out += kHex[(raw >> 4) & 0x0f];
          out += kHex[raw & 0x0f];
        } else {
          out += c;
        }
        break;
    }
  }
}

}  // namespace

void JsonWriter::separate() {
  if (need_comma_) {
    out_ += ",";
  }
  need_comma_ = false;
}

void JsonWriter::indent() {
  out_.append(static_cast<std::size_t>(depth_) * 2, ' ');
}

JsonWriter& JsonWriter::begin_object() {
  separate();
  out_ += "{";
  need_comma_ = false;
  ++depth_;
  return *this;
}

JsonWriter& JsonWriter::end_object() {
  --depth_;
  out_ += "}";
  need_comma_ = true;
  return *this;
}

JsonWriter& JsonWriter::begin_array() {
  separate();
  out_ += "[";
  need_comma_ = false;
  return *this;
}

JsonWriter& JsonWriter::end_array() {
  out_ += "]";
  need_comma_ = true;
  return *this;
}

JsonWriter& JsonWriter::key(std::string_view name) {
  separate();
  out_ += '"';
  escape_into(out_, name);
  out_ += "\":";
  need_comma_ = false;
  return *this;
}

JsonWriter& JsonWriter::string(std::string_view value) {
  separate();
  out_ += '"';
  escape_into(out_, value);
  out_ += '"';
  need_comma_ = true;
  return *this;
}

JsonWriter& JsonWriter::number(std::uint64_t value) {
  separate();
  out_ += std::to_string(value);
  need_comma_ = true;
  return *this;
}

JsonWriter& JsonWriter::number(std::int64_t value) {
  separate();
  out_ += std::to_string(value);
  need_comma_ = true;
  return *this;
}

JsonWriter& JsonWriter::boolean(bool value) {
  separate();
  out_ += value ? "true" : "false";
  need_comma_ = true;
  return *this;
}

JsonWriter& JsonWriter::null_value() {
  separate();
  out_ += "null";
  need_comma_ = true;
  return *this;
}

JsonWriter& JsonWriter::member(std::string_view name, std::string_view value) {
  key(name);
  return string(value);
}

JsonWriter& JsonWriter::member(std::string_view name, std::uint64_t value) {
  key(name);
  return number(value);
}

JsonWriter& JsonWriter::member(std::string_view name, bool value) {
  key(name);
  return boolean(value);
}

JsonWriter& JsonWriter::member_string_array(std::string_view name,
                                           const std::vector<std::string>& values) {
  key(name);
  begin_array();
  for (const auto& value : values) {
    string(value);
  }
  end_array();
  return *this;
}

namespace {

void write_primary_reason(JsonWriter& writer, const Violation& violation) {
  writer.key("primary_reason");
  writer.begin_object();
  writer.member("code", to_string(violation.code));
  writer.member("severity", to_string(violation.severity));
  writer.member("subject", violation.subject);
  writer.member("detail", violation.detail);
  writer.end_object();
}

void write_violations(JsonWriter& writer, const std::vector<Violation>& violations) {
  writer.key("reasons");
  writer.begin_array();
  for (const auto& violation : violations) {
    writer.begin_object();
    writer.member("code", to_string(violation.code));
    writer.member("severity", to_string(violation.severity));
    writer.member("subject", violation.subject);
    writer.member("detail", violation.detail);
    writer.end_object();
  }
  writer.end_array();
}

void write_evidence(JsonWriter& writer, const EvidenceVector& evidence) {
  writer.key("evidence");
  writer.begin_array();
  for (const auto& entry : evidence.entries) {
    writer.begin_object();
    writer.member("kind", to_string(entry.kind));
    writer.member("subject", entry.subject);
    writer.member("generation", entry.generation);
    writer.end_object();
  }
  writer.end_array();
}

}  // namespace

std::string to_json(const EvaluationResult& result) {
  JsonWriter writer;
  writer.begin_object();
  writer.member("path", result.path.str());
  writer.member("path_generation", result.path_generation.value());
  writer.member("authority_generation", result.authority_generation.value());
  writer.member("state", to_string(result.state));
  writer.member("outcome", to_string(result.primary));
  writer.member("stage", to_string(stage_for_outcome(result.primary)));
  writer.member("constraint_set", result.constraint_set.str());
  writer.member("constraint_generation", result.constraint_generation.value());
  writer.member("policy_generation", result.policy.value());
  writer.member("epoch", result.epoch.value());
  writer.member("path_digest", result.path_digest.hex());
  writer.member("authority_digest", result.authority_digest.hex());
  writer.member("idempotent", result.idempotent);
  writer.member("committed", result.committed);
  write_primary_reason(writer, result.primary_violation);
  write_violations(writer, result.secondary);
  write_evidence(writer, result.evidence);
  writer.end_object();
  return writer.str();
}

std::string to_json(const AuthoritySnapshot& snapshot) {
  JsonWriter writer;
  writer.begin_object();
  writer.member("snapshot", snapshot.id.str());
  writer.member("path", snapshot.path.str());
  writer.member("path_generation", snapshot.path_generation.value());
  writer.member("authority_generation", snapshot.authority_generation.value());
  writer.member("state", to_string(snapshot.state));
  writer.member("outcome", to_string(snapshot.last_outcome));
  writer.member("current", snapshot.current);
  writer.member("epoch", snapshot.epoch.value());
  writer.member("policy_generation", snapshot.policy.value());
  writer.member("constraint_set", snapshot.constraint_set.str());
  writer.member("constraint_generation", snapshot.constraint_generation.value());
  writer.member("path_digest", snapshot.path_digest.hex());
  writer.member("authority_digest", snapshot.authority_digest.hex());
  writer.member("snapshot_digest", snapshot.snapshot_digest().hex());
  writer.member("publisher", snapshot.publisher.str());
  writer.member("worker_boot", snapshot.worker_boot.str());
  writer.member("evaluations", snapshot.evaluations);
  writer.member("revalidations", snapshot.revalidations);
  write_primary_reason(writer, snapshot.primary_violation);
  writer.member("revoked", snapshot.revocation.has_value());
  if (snapshot.revocation.has_value()) {
    writer.key("revocation");
    writer.begin_object();
    writer.member("reason", to_string(snapshot.revocation->reason));
    writer.member("explanation", snapshot.revocation->explanation);
    writer.member("authority", snapshot.revocation->authority);
    writer.member("generation", snapshot.revocation->generation.value());
    writer.end_object();
  }
  write_violations(writer, snapshot.secondary);
  write_evidence(writer, snapshot.evidence);
  writer.key("stale");
  writer.begin_array();
  for (const auto& delta : snapshot.stale_dependencies) {
    writer.begin_object();
    writer.member("kind", to_string(delta.kind));
    writer.member("subject", delta.subject);
    writer.member("before", delta.before.has_value() ? std::to_string(*delta.before) : "absent");
    writer.member("after", delta.after.has_value() ? std::to_string(*delta.after) : "absent");
    writer.end_object();
  }
  writer.end_array();
  writer.end_object();
  return writer.str();
}

std::string to_json(const AuthorityDiff& diff) {
  JsonWriter writer;
  writer.begin_object();
  writer.member("path", diff.path.str());
  writer.member("before", diff.before.str());
  writer.member("after", diff.after.str());
  writer.member("changes", static_cast<std::uint64_t>(diff.entries.size()));
  writer.key("entries");
  writer.begin_array();
  for (const auto& entry : diff.entries) {
    writer.begin_object();
    writer.member("kind", to_string(entry.kind));
    writer.member("subject", entry.subject);
    writer.member("before", entry.before);
    writer.member("after", entry.after);
    writer.end_object();
  }
  writer.end_array();
  writer.end_object();
  return writer.str();
}

std::string to_json(const EvidenceVector& evidence) {
  JsonWriter writer;
  writer.begin_object();
  write_evidence(writer, evidence);
  writer.member("digest", evidence.digest().hex());
  writer.end_object();
  return writer.str();
}

std::string to_json(const PathDefinition& path) {
  JsonWriter writer;
  writer.begin_object();
  writer.member("path", path.id.str());
  writer.member("derived", path.derived_id().str());
  writer.member("path_generation", path.generation.value());
  writer.member("type", to_string(path.type));
  writer.member("scope", path.scope.str());
  writer.member("constraint_set", path.constraint_set.str());
  writer.member("constraint_generation", path.constraint_generation.value());
  writer.member("digest", path.semantic_digest().hex());
  writer.key("hops");
  writer.begin_array();
  for (const auto& hop : path.hops) {
    writer.begin_object();
    writer.member("kind", to_string(hop.kind));
    writer.member("id", hop.id);
    writer.member("generation", hop.generation.value());
    writer.member("layer", to_string(hop.layer));
    writer.member("relation", to_string(hop.relation));
    writer.end_object();
  }
  writer.end_array();
  if (path.underlying.has_value()) {
    writer.key("underlying");
    writer.begin_object();
    writer.member("path", path.underlying->path.str());
    writer.member("authority_generation", path.underlying->authority_generation.value());
    writer.member("nesting_depth", static_cast<std::uint64_t>(path.underlying->nesting_depth));
    writer.end_object();
  }
  writer.end_object();
  return writer.str();
}

std::string to_json(const InvalidationReport& report) {
  JsonWriter writer;
  writer.begin_object();
  writer.member("cause", to_string(report.cause));
  writer.member("subject", report.subject);
  writer.member("generation", report.generation);
  std::vector<std::string> required;
  for (const auto& path : report.revalidation_required) {
    required.push_back(path.str());
  }
  std::vector<std::string> current;
  for (const auto& path : report.already_current) {
    current.push_back(path.str());
  }
  writer.member_string_array("revalidation_required", required);
  writer.member_string_array("already_current", current);
  writer.end_object();
  return writer.str();
}

std::string to_json(const PersistenceInfo& info) {
  JsonWriter writer;
  writer.begin_object();
  writer.member("readable", info.readable);
  writer.member("format_version", static_cast<std::uint64_t>(info.format_version));
  writer.member("image_bytes", static_cast<std::uint64_t>(info.image_bytes));
  writer.member("payload_bytes", static_cast<std::uint64_t>(info.payload_bytes));
  writer.member("records", static_cast<std::uint64_t>(info.record_count));
  writer.member("epoch", info.epoch.value());
  writer.member("policy_generation", info.policy.value());
  writer.member("constraint_sets", static_cast<std::uint64_t>(info.constraint_sets));
  writer.member("revoked", static_cast<std::uint64_t>(info.revoked));
  writer.member("authorizing", static_cast<std::uint64_t>(info.authorizing));
  writer.member("image_digest", info.image_digest.hex());
  writer.member("problem", info.problem);
  writer.end_object();
  return writer.str();
}

std::string to_json(const DurableState& state) {
  JsonWriter writer;
  writer.begin_object();
  writer.member("format_version", static_cast<std::uint64_t>(state.format_version));
  writer.member("epoch", state.epoch.value());
  writer.member("policy_generation", state.policy.generation.value());
  writer.member("records", static_cast<std::uint64_t>(state.records.size()));
  writer.member("constraint_sets", static_cast<std::uint64_t>(state.constraint_sets.size()));
  writer.member("digest", state.digest().hex());
  writer.key("paths");
  writer.begin_array();
  for (const auto& record : state.records) {
    writer.begin_object();
    writer.member("path", record.definition.id.str());
    writer.member("authority_generation", record.authority_generation.value());
    writer.member("state", to_string(record.state));
    writer.member("outcome", to_string(record.outcome));
    writer.member("retired", record.retired);
    writer.member("revoked", record.revocation.has_value());
    writer.member("publisher", record.publisher.str());
    writer.member("worker_boot", record.worker_boot.str());
    writer.member("authority_digest", record.authority_digest.hex());
    writer.end_object();
  }
  writer.end_array();
  writer.end_object();
  return writer.str();
}

std::string to_json(const WorkerInfo& worker) {
  JsonWriter writer;
  writer.begin_object();
  writer.member("publisher", worker.publisher.str());
  writer.member("worker_boot", worker.worker_boot.str());
  writer.member("scope", worker.scope.str());
  writer.member("epoch", worker.epoch.value());
  writer.member("published", static_cast<std::uint64_t>(worker.published));
  writer.end_object();
  return writer.str();
}

std::string to_json(const std::vector<WorkerInfo>& workers) {
  JsonWriter writer;
  writer.begin_array();
  for (const auto& worker : workers) {
    writer.begin_object();
    writer.member("publisher", worker.publisher.str());
    writer.member("worker_boot", worker.worker_boot.str());
    writer.member("scope", worker.scope.str());
    writer.member("epoch", worker.epoch.value());
    writer.member("published", static_cast<std::uint64_t>(worker.published));
    writer.end_object();
  }
  writer.end_array();
  return writer.str();
}

}  // namespace path_authority
