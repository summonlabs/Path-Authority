// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/authority.hpp"

#include <algorithm>
#include <string>
#include <utility>

#include "path_authority/canonical.hpp"
#include "path_authority/runtime.hpp"
#include "path_authority/version.hpp"

namespace path_authority {

std::string_view to_string(AuthorityState state) noexcept {
  switch (state) {
    case AuthorityState::UNKNOWN: return "UNKNOWN";
    case AuthorityState::AUTHORIZED: return "AUTHORIZED";
    case AuthorityState::CONDITIONALLY_AUTHORIZED: return "CONDITIONALLY_AUTHORIZED";
    case AuthorityState::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case AuthorityState::REJECTED: return "REJECTED";
    case AuthorityState::REVOKED: return "REVOKED";
    case AuthorityState::STALE: return "STALE";
    case AuthorityState::RETIRED: return "RETIRED";
  }
  return "INVALID";
}

std::optional<AuthorityState> authority_state_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 0; raw <= 7; ++raw) {
    const auto candidate = static_cast<AuthorityState>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_defined_authority_state(std::uint8_t raw) noexcept { return raw <= 7; }

std::string_view to_string(EvaluationOutcome outcome) noexcept {
  switch (outcome) {
    case EvaluationOutcome::AUTHORIZED: return "AUTHORIZED";
    case EvaluationOutcome::IDEMPOTENT: return "IDEMPOTENT";
    case EvaluationOutcome::CONDITIONALLY_AUTHORIZED: return "CONDITIONALLY_AUTHORIZED";
    case EvaluationOutcome::MALFORMED_PATH: return "MALFORMED_PATH";
    case EvaluationOutcome::RESOURCE_LIMIT: return "RESOURCE_LIMIT";
    case EvaluationOutcome::STRUCTURALLY_INVALID: return "STRUCTURALLY_INVALID";
    case EvaluationOutcome::STALE_TOPOLOGY: return "STALE_TOPOLOGY";
    case EvaluationOutcome::CONSTRAINT_SET_UNKNOWN: return "CONSTRAINT_SET_UNKNOWN";
    case EvaluationOutcome::PATH_RETIRED: return "PATH_RETIRED";
    case EvaluationOutcome::PATH_UNKNOWN: return "PATH_UNKNOWN";
    case EvaluationOutcome::PORT_ADMIN_DISABLED: return "PORT_ADMIN_DISABLED";
    case EvaluationOutcome::PORT_REVALIDATION_REQUIRED: return "PORT_REVALIDATION_REQUIRED";
    case EvaluationOutcome::LINK_DOWN: return "LINK_DOWN";
    case EvaluationOutcome::LINK_DEGRADED: return "LINK_DEGRADED";
    case EvaluationOutcome::LINK_STATE_UNKNOWN: return "LINK_STATE_UNKNOWN";
    case EvaluationOutcome::CAPABILITY_MISSING: return "CAPABILITY_MISSING";
    case EvaluationOutcome::CAPABILITY_UNKNOWN: return "CAPABILITY_UNKNOWN";
    case EvaluationOutcome::FAILURE_DOMAIN_VIOLATION: return "FAILURE_DOMAIN_VIOLATION";
    case EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN:
      return "FAILURE_DOMAIN_COVERAGE_UNKNOWN";
    case EvaluationOutcome::STALE_EPOCH: return "STALE_EPOCH";
    case EvaluationOutcome::STALE_AUTHORITY: return "STALE_AUTHORITY";
    case EvaluationOutcome::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case EvaluationOutcome::POLICY_REJECTED: return "POLICY_REJECTED";
    case EvaluationOutcome::REVOKED: return "REVOKED";
    case EvaluationOutcome::EVALUATION_ATTEMPT_CONFLICT: return "EVALUATION_ATTEMPT_CONFLICT";
  }
  return "INVALID";
}

std::optional<EvaluationOutcome> evaluation_outcome_from_string(std::string_view text) noexcept {
  static constexpr std::uint16_t kCandidates[] = {
      1,   2,   3,   10,  11,  12,  13,  14,  15,  16,  20,  21,  30,  31,  32,  40,
      41,  50,  51,  60,  61,  62,  70,  80,  90};
  for (std::uint16_t raw : kCandidates) {
    const auto candidate = static_cast<EvaluationOutcome>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_defined_evaluation_outcome(std::uint16_t raw) noexcept {
  switch (static_cast<EvaluationOutcome>(raw)) {
    case EvaluationOutcome::AUTHORIZED:
    case EvaluationOutcome::IDEMPOTENT:
    case EvaluationOutcome::CONDITIONALLY_AUTHORIZED:
    case EvaluationOutcome::MALFORMED_PATH:
    case EvaluationOutcome::RESOURCE_LIMIT:
    case EvaluationOutcome::STRUCTURALLY_INVALID:
    case EvaluationOutcome::STALE_TOPOLOGY:
    case EvaluationOutcome::CONSTRAINT_SET_UNKNOWN:
    case EvaluationOutcome::PATH_RETIRED:
    case EvaluationOutcome::PATH_UNKNOWN:
    case EvaluationOutcome::PORT_ADMIN_DISABLED:
    case EvaluationOutcome::PORT_REVALIDATION_REQUIRED:
    case EvaluationOutcome::LINK_DOWN:
    case EvaluationOutcome::LINK_DEGRADED:
    case EvaluationOutcome::LINK_STATE_UNKNOWN:
    case EvaluationOutcome::CAPABILITY_MISSING:
    case EvaluationOutcome::CAPABILITY_UNKNOWN:
    case EvaluationOutcome::FAILURE_DOMAIN_VIOLATION:
    case EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN:
    case EvaluationOutcome::STALE_EPOCH:
    case EvaluationOutcome::STALE_AUTHORITY:
    case EvaluationOutcome::REVALIDATION_REQUIRED:
    case EvaluationOutcome::POLICY_REJECTED:
    case EvaluationOutcome::REVOKED:
    case EvaluationOutcome::EVALUATION_ATTEMPT_CONFLICT:
      return true;
  }
  return false;
}

AuthorityState state_for_outcome(EvaluationOutcome outcome) noexcept {
  switch (outcome) {
    case EvaluationOutcome::AUTHORIZED: return AuthorityState::AUTHORIZED;
    case EvaluationOutcome::CONDITIONALLY_AUTHORIZED:
      return AuthorityState::CONDITIONALLY_AUTHORIZED;
    case EvaluationOutcome::REVALIDATION_REQUIRED: return AuthorityState::REVALIDATION_REQUIRED;
    case EvaluationOutcome::PATH_RETIRED: return AuthorityState::RETIRED;
    case EvaluationOutcome::REVOKED: return AuthorityState::REVOKED;
    case EvaluationOutcome::STALE_EPOCH:
    case EvaluationOutcome::STALE_AUTHORITY:
      return AuthorityState::STALE;
    case EvaluationOutcome::IDEMPOTENT: return AuthorityState::UNKNOWN;
    default: return AuthorityState::REJECTED;
  }
}

bool is_authorizing_outcome(EvaluationOutcome outcome) noexcept {
  return outcome == EvaluationOutcome::AUTHORIZED ||
         outcome == EvaluationOutcome::CONDITIONALLY_AUTHORIZED ||
         outcome == EvaluationOutcome::IDEMPOTENT;
}

std::string_view to_string(EvaluationStage stage) noexcept {
  switch (stage) {
    case EvaluationStage::DECODE: return "DECODE";
    case EvaluationStage::PATH_IDENTITY: return "PATH_IDENTITY";
    case EvaluationStage::PATH_RETIREMENT: return "PATH_RETIREMENT";
    case EvaluationStage::FABRIC_EPOCH: return "FABRIC_EPOCH";
    case EvaluationStage::REVOCATION: return "REVOCATION";
    case EvaluationStage::STRUCTURAL_TOPOLOGY: return "STRUCTURAL_TOPOLOGY";
    case EvaluationStage::BOUND_INPUT_CURRENTNESS: return "BOUND_INPUT_CURRENTNESS";
    case EvaluationStage::PORT_ADMINISTRATIVE: return "PORT_ADMINISTRATIVE";
    case EvaluationStage::LINK_STATE: return "LINK_STATE";
    case EvaluationStage::CAPABILITY: return "CAPABILITY";
    case EvaluationStage::FAILURE_DOMAIN: return "FAILURE_DOMAIN";
    case EvaluationStage::POLICY: return "POLICY";
    case EvaluationStage::EXPECTED_GENERATION: return "EXPECTED_GENERATION";
    case EvaluationStage::COMMIT: return "COMMIT";
  }
  return "INVALID";
}

EvaluationStage stage_for_outcome(EvaluationOutcome outcome) noexcept {
  switch (outcome) {
    case EvaluationOutcome::MALFORMED_PATH:
    case EvaluationOutcome::EVALUATION_ATTEMPT_CONFLICT:
      return EvaluationStage::PATH_IDENTITY;
    case EvaluationOutcome::RESOURCE_LIMIT: return EvaluationStage::DECODE;
    case EvaluationOutcome::CONSTRAINT_SET_UNKNOWN: return EvaluationStage::DECODE;
    case EvaluationOutcome::PATH_RETIRED: return EvaluationStage::PATH_RETIREMENT;
    case EvaluationOutcome::STALE_EPOCH: return EvaluationStage::FABRIC_EPOCH;
    case EvaluationOutcome::REVOKED: return EvaluationStage::REVOCATION;
    case EvaluationOutcome::STRUCTURALLY_INVALID:
    case EvaluationOutcome::STALE_TOPOLOGY:
      return EvaluationStage::STRUCTURAL_TOPOLOGY;
    case EvaluationOutcome::PATH_UNKNOWN: return EvaluationStage::PATH_RETIREMENT;
    case EvaluationOutcome::PORT_ADMIN_DISABLED:
    case EvaluationOutcome::PORT_REVALIDATION_REQUIRED:
      return EvaluationStage::PORT_ADMINISTRATIVE;
    case EvaluationOutcome::LINK_DOWN:
    case EvaluationOutcome::LINK_DEGRADED:
    case EvaluationOutcome::LINK_STATE_UNKNOWN:
      return EvaluationStage::LINK_STATE;
    case EvaluationOutcome::CAPABILITY_MISSING:
    case EvaluationOutcome::CAPABILITY_UNKNOWN:
      return EvaluationStage::CAPABILITY;
    case EvaluationOutcome::FAILURE_DOMAIN_VIOLATION:
    case EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN:
      return EvaluationStage::FAILURE_DOMAIN;
    case EvaluationOutcome::POLICY_REJECTED: return EvaluationStage::POLICY;
    case EvaluationOutcome::STALE_AUTHORITY: return EvaluationStage::EXPECTED_GENERATION;
    case EvaluationOutcome::REVALIDATION_REQUIRED:
      return EvaluationStage::BOUND_INPUT_CURRENTNESS;
    case EvaluationOutcome::AUTHORIZED:
    case EvaluationOutcome::IDEMPOTENT:
    case EvaluationOutcome::CONDITIONALLY_AUTHORIZED:
      return EvaluationStage::COMMIT;
  }
  return EvaluationStage::DECODE;
}

std::string_view to_string(ViolationSeverity severity) noexcept {
  switch (severity) {
    case ViolationSeverity::PRIMARY: return "PRIMARY";
    case ViolationSeverity::HARD: return "HARD";
    case ViolationSeverity::CONDITION: return "CONDITION";
    case ViolationSeverity::INFORMATIONAL: return "INFORMATIONAL";
  }
  return "INVALID";
}

std::strong_ordering operator<=>(const Violation& lhs, const Violation& rhs) {
  if (const auto cmp = lhs.code <=> rhs.code; cmp != 0) {
    return cmp;
  }
  if (const auto cmp = lhs.subject <=> rhs.subject; cmp != 0) {
    return cmp;
  }
  if (const auto cmp = lhs.detail <=> rhs.detail; cmp != 0) {
    return cmp;
  }
  return lhs.severity <=> rhs.severity;
}

std::string Violation::render() const {
  std::string text = std::string(to_string(code));
  text += " [" + std::string(to_string(severity)) + "]";
  if (!subject.empty()) {
    text += " " + subject;
  }
  if (!detail.empty()) {
    text += ": " + detail;
  }
  return text;
}

Digest AuthorityDigestInput::compute() const {
  std::vector<EvaluationOutcome> codes = secondary_codes;
  std::sort(codes.begin(), codes.end());

  ByteWriter writer;
  writer.u32(kDigestSchemeVersion);
  writer.digest(path_digest);
  writer.u64(path_generation.value());
  writer.digest(constraint_digest);
  writer.u64(constraint_generation.value());
  writer.digest(evidence_digest);
  writer.u64(policy.value());
  writer.u64(epoch.value());
  writer.u8(static_cast<std::uint8_t>(state));
  writer.u16(static_cast<std::uint16_t>(primary));
  writer.u32(static_cast<std::uint32_t>(codes.size()));
  for (EvaluationOutcome code : codes) {
    writer.u16(static_cast<std::uint16_t>(code));
  }
  return Digest::of(writer.data());
}

std::string EvaluationResult::render() const {
  std::string text;
  text += "path=" + path.str() + "\n";
  text += "state=" + std::string(to_string(state)) + "\n";
  text += "outcome=" + std::string(to_string(primary)) + "\n";
  text += "stage=" + std::string(to_string(stage_for_outcome(primary))) + "\n";
  text += "authority_generation=" + std::to_string(authority_generation.value()) + "\n";
  text += "path_generation=" + std::to_string(path_generation.value()) + "\n";
  text += "epoch=" + std::to_string(epoch.value()) + "\n";
  text += "policy_generation=" + std::to_string(policy.value()) + "\n";
  text += "constraint_set=" + constraint_set.str() + "@" +
          std::to_string(constraint_generation.value()) + "\n";
  text += "authority_digest=" + authority_digest.hex() + "\n";
  text += "idempotent=" + std::string(idempotent ? "true" : "false") + "\n";
  text += "committed=" + std::string(committed ? "true" : "false") + "\n";
  for (const auto& violation : secondary) {
    text += "reason=" + violation.render() + "\n";
  }
  return text;
}

std::string_view to_string(RevocationReason reason) noexcept {
  switch (reason) {
    case RevocationReason::ADMINISTRATIVE: return "ADMINISTRATIVE";
    case RevocationReason::TOPOLOGY_CHANGE: return "TOPOLOGY_CHANGE";
    case RevocationReason::LINK_STATE_CHANGE: return "LINK_STATE_CHANGE";
    case RevocationReason::CAPABILITY_CHANGE: return "CAPABILITY_CHANGE";
    case RevocationReason::FAILURE_DOMAIN_CHANGE: return "FAILURE_DOMAIN_CHANGE";
    case RevocationReason::EPOCH_CHANGE: return "EPOCH_CHANGE";
    case RevocationReason::POLICY_CHANGE: return "POLICY_CHANGE";
    case RevocationReason::PORT_STATE_CHANGE: return "PORT_STATE_CHANGE";
    case RevocationReason::ENTITY_SUPERSESSION: return "ENTITY_SUPERSESSION";
  }
  return "INVALID";
}

std::optional<RevocationReason> revocation_reason_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 9; ++raw) {
    const auto candidate = static_cast<RevocationReason>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_defined_revocation_reason(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 9; }

std::string RevocationRecord::render() const {
  std::string text = std::string(to_string(reason));
  text += " at_generation=" + std::to_string(generation.value());
  text += " epoch=" + std::to_string(epoch.value());
  if (!authority.empty()) {
    text += " authority=" + authority;
  }
  if (!explanation.empty()) {
    text += " explanation=" + explanation;
  }
  return text;
}

std::string_view to_string(InvalidationCause cause) noexcept {
  switch (cause) {
    case InvalidationCause::TOPOLOGY_CHANGE: return "TOPOLOGY_CHANGE";
    case InvalidationCause::LINK_STATE_CHANGE: return "LINK_STATE_CHANGE";
    case InvalidationCause::PORT_STATE_CHANGE: return "PORT_STATE_CHANGE";
    case InvalidationCause::CAPABILITY_CHANGE: return "CAPABILITY_CHANGE";
    case InvalidationCause::FAILURE_DOMAIN_CHANGE: return "FAILURE_DOMAIN_CHANGE";
    case InvalidationCause::EPOCH_CHANGE: return "EPOCH_CHANGE";
    case InvalidationCause::POLICY_CHANGE: return "POLICY_CHANGE";
    case InvalidationCause::CONSTRAINT_CHANGE: return "CONSTRAINT_CHANGE";
    case InvalidationCause::UNDERLYING_AUTHORITY_CHANGE: return "UNDERLYING_AUTHORITY_CHANGE";
    case InvalidationCause::PUBLISHER_LOST: return "PUBLISHER_LOST";
  }
  return "INVALID";
}

std::optional<InvalidationCause> invalidation_cause_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 10; ++raw) {
    const auto candidate = static_cast<InvalidationCause>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_defined_invalidation_cause(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 10; }

std::string InvalidationReport::render() const {
  std::string text;
  text += "cause=" + std::string(to_string(cause)) + "\n";
  text += "subject=" + subject + "\n";
  text += "generation=" + std::to_string(generation) + "\n";
  text += "revalidation_required=" + std::to_string(revalidation_required.size()) + "\n";
  for (const auto& path : revalidation_required) {
    text += "affected=" + path.str() + "\n";
  }
  text += "already_current=" + std::to_string(already_current.size()) + "\n";
  for (const auto& path : already_current) {
    text += "unaffected=" + path.str() + "\n";
  }
  return text;
}

std::string HistoryEntry::render() const {
  std::string text = "generation=" + std::to_string(generation.value());
  text += " state=" + std::string(to_string(state));
  text += " outcome=" + std::string(to_string(outcome));
  text += " epoch=" + std::to_string(epoch.value());
  if (!cause.empty()) {
    text += " cause=" + cause;
  }
  return text;
}

}  // namespace path_authority
