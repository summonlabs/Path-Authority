// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "path_authority/constraints.hpp"
#include "path_authority/digest.hpp"
#include "path_authority/evidence.hpp"
#include "path_authority/export.hpp"
#include "path_authority/ids.hpp"
#include "path_authority/path.hpp"

namespace path_authority {

// ---------------------------------------------------------------------------
// Authority state. Existing, structurally valid, constraint-satisfying and
// currently authorized are distinct conditions and never collapse into one.
// ---------------------------------------------------------------------------
enum class AuthorityState : std::uint8_t {
  UNKNOWN = 0,
  AUTHORIZED = 1,
  CONDITIONALLY_AUTHORIZED = 2,
  REVALIDATION_REQUIRED = 3,
  REJECTED = 4,
  REVOKED = 5,
  STALE = 6,
  RETIRED = 7,
};

PATH_AUTHORITY_API std::string_view to_string(AuthorityState state) noexcept;
PATH_AUTHORITY_API std::optional<AuthorityState> authority_state_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API bool is_defined_authority_state(std::uint8_t raw) noexcept;

// ---------------------------------------------------------------------------
// Deterministic authorization outcomes. Every evaluation returns exactly one
// primary outcome; the primary outcome is a function of the path, the current
// evidence and the fixed stage precedence, never of arrival order.
// ---------------------------------------------------------------------------
enum class EvaluationOutcome : std::uint16_t {
  AUTHORIZED = 1,
  IDEMPOTENT = 2,
  CONDITIONALLY_AUTHORIZED = 3,

  MALFORMED_PATH = 10,
  RESOURCE_LIMIT = 11,
  STRUCTURALLY_INVALID = 12,
  STALE_TOPOLOGY = 13,
  CONSTRAINT_SET_UNKNOWN = 14,
  PATH_RETIRED = 15,
  PATH_UNKNOWN = 16,

  PORT_ADMIN_DISABLED = 20,
  PORT_REVALIDATION_REQUIRED = 21,

  LINK_DOWN = 30,
  LINK_DEGRADED = 31,
  LINK_STATE_UNKNOWN = 32,

  CAPABILITY_MISSING = 40,
  CAPABILITY_UNKNOWN = 41,

  FAILURE_DOMAIN_VIOLATION = 50,
  FAILURE_DOMAIN_COVERAGE_UNKNOWN = 51,

  STALE_EPOCH = 60,
  STALE_AUTHORITY = 61,
  REVALIDATION_REQUIRED = 62,

  POLICY_REJECTED = 70,

  REVOKED = 80,
  EVALUATION_ATTEMPT_CONFLICT = 90,
};

PATH_AUTHORITY_API std::string_view to_string(EvaluationOutcome outcome) noexcept;
PATH_AUTHORITY_API std::optional<EvaluationOutcome> evaluation_outcome_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API bool is_defined_evaluation_outcome(std::uint16_t raw) noexcept;

// Authority state implied by a primary outcome. IDEMPOTENT is not mapped: an
// idempotent replay returns the previously committed state unchanged.
PATH_AUTHORITY_API AuthorityState state_for_outcome(EvaluationOutcome outcome) noexcept;
PATH_AUTHORITY_API bool is_authorizing_outcome(EvaluationOutcome outcome) noexcept;

// Name of the fixed evaluation stage that produces an outcome. The stage order
// is the deterministic rejection precedence and is part of the rule set
// version (kRuleSetVersion).
enum class EvaluationStage : std::uint8_t {
  DECODE = 1,
  PATH_IDENTITY = 2,
  PATH_RETIREMENT = 3,
  FABRIC_EPOCH = 4,
  REVOCATION = 5,
  STRUCTURAL_TOPOLOGY = 6,
  BOUND_INPUT_CURRENTNESS = 7,
  PORT_ADMINISTRATIVE = 8,
  LINK_STATE = 9,
  CAPABILITY = 10,
  FAILURE_DOMAIN = 11,
  POLICY = 12,
  EXPECTED_GENERATION = 13,
  COMMIT = 14,
};

PATH_AUTHORITY_API std::string_view to_string(EvaluationStage stage) noexcept;
PATH_AUTHORITY_API EvaluationStage stage_for_outcome(EvaluationOutcome outcome) noexcept;

enum class ViolationSeverity : std::uint8_t {
  PRIMARY = 0,
  HARD = 1,
  CONDITION = 2,
  INFORMATIONAL = 3,
};

PATH_AUTHORITY_API std::string_view to_string(ViolationSeverity severity) noexcept;

// One structured reason. Diagnostic richness never changes the authoritative
// primary outcome.
struct PATH_AUTHORITY_API Violation {
  EvaluationOutcome code = EvaluationOutcome::MALFORMED_PATH;
  ViolationSeverity severity = ViolationSeverity::HARD;
  std::string subject;
  std::string detail;

  friend bool operator==(const Violation&, const Violation&) = default;
  friend std::strong_ordering operator<=>(const Violation& lhs, const Violation& rhs);
  std::string render() const;
};

// Inputs of the authoritative semantic digest. Every field is a value the
// coordinator can independently recompute, so a published decision can be
// re-derived and verified by a different process.
struct PATH_AUTHORITY_API AuthorityDigestInput {
  Digest path_digest;
  PathGeneration path_generation;
  Digest constraint_digest;
  ConstraintGeneration constraint_generation;
  Digest evidence_digest;
  PolicyGeneration policy;
  CoordinatorEpoch epoch;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome primary = EvaluationOutcome::MALFORMED_PATH;
  std::vector<EvaluationOutcome> secondary_codes;

  Digest compute() const;
};

// Structured outcome of one evaluation.
struct PATH_AUTHORITY_API EvaluationResult {
  PathId path;
  PathGeneration path_generation;
  PathAuthorityGeneration authority_generation;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome primary = EvaluationOutcome::MALFORMED_PATH;
  // Structured detail of the primary reason: which hop, link, port, capability
  // or domain produced it. Diagnostic only; the semantic digest binds the code.
  Violation primary_violation;
  std::vector<Violation> secondary;
  EvidenceVector evidence;
  ConstraintSetId constraint_set;
  ConstraintGeneration constraint_generation;
  PolicyGeneration policy;
  CoordinatorEpoch epoch;
  Digest path_digest;
  Digest authority_digest;
  bool idempotent = false;
  bool committed = false;

  bool authorizing() const noexcept { return is_authorizing_outcome(primary); }
  std::string render() const;
};

// ---------------------------------------------------------------------------
// Revocation and evidence-driven invalidation are different mechanisms and
// never share a code path: revocation is an administrative, durable decision;
// invalidation is a currentness consequence of changed evidence.
// ---------------------------------------------------------------------------
enum class RevocationReason : std::uint8_t {
  ADMINISTRATIVE = 1,
  TOPOLOGY_CHANGE = 2,
  LINK_STATE_CHANGE = 3,
  CAPABILITY_CHANGE = 4,
  FAILURE_DOMAIN_CHANGE = 5,
  EPOCH_CHANGE = 6,
  POLICY_CHANGE = 7,
  PORT_STATE_CHANGE = 8,
  ENTITY_SUPERSESSION = 9,
};

PATH_AUTHORITY_API std::string_view to_string(RevocationReason reason) noexcept;
PATH_AUTHORITY_API std::optional<RevocationReason> revocation_reason_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API bool is_defined_revocation_reason(std::uint8_t raw) noexcept;

struct PATH_AUTHORITY_API RevocationRecord {
  RevocationReason reason = RevocationReason::ADMINISTRATIVE;
  std::string explanation;
  PathAuthorityGeneration generation;
  CoordinatorEpoch epoch;
  std::string authority;
  MutationAttemptId attempt;
  bool durable = true;

  friend bool operator==(const RevocationRecord&, const RevocationRecord&) = default;
  std::string render() const;
};

enum class InvalidationCause : std::uint8_t {
  TOPOLOGY_CHANGE = 1,
  LINK_STATE_CHANGE = 2,
  PORT_STATE_CHANGE = 3,
  CAPABILITY_CHANGE = 4,
  FAILURE_DOMAIN_CHANGE = 5,
  EPOCH_CHANGE = 6,
  POLICY_CHANGE = 7,
  CONSTRAINT_CHANGE = 8,
  UNDERLYING_AUTHORITY_CHANGE = 9,
  PUBLISHER_LOST = 10,
};

PATH_AUTHORITY_API std::string_view to_string(InvalidationCause cause) noexcept;
PATH_AUTHORITY_API std::optional<InvalidationCause> invalidation_cause_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API bool is_defined_invalidation_cause(std::uint8_t raw) noexcept;

// Bounded diagnostic history. Current authority comes from current evidence;
// history is never a source of authority.
struct PATH_AUTHORITY_API HistoryEntry {
  PathAuthorityGeneration generation;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome outcome = EvaluationOutcome::MALFORMED_PATH;
  std::string cause;
  CoordinatorEpoch epoch;

  friend bool operator==(const HistoryEntry&, const HistoryEntry&) = default;
  std::string render() const;
};

}  // namespace path_authority
