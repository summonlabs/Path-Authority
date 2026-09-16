// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "path_authority/digest.hpp"
#include "path_authority/export.hpp"
#include "path_authority/ids.hpp"
#include "path_authority/limits.hpp"
#include "path_authority/path.hpp"

namespace path_authority {

enum class DomainClassKind : std::uint8_t {
  UNKNOWN = 0,
  POWER = 1,
  COOLING = 2,
  RACK = 3,
  LINE_CARD = 4,
  SHARED_RISK_LINK_GROUP = 5,
  SITE = 6,
  REGION = 7,
  SHELF = 8,
  CHANNEL = 9,
};

PATH_AUTHORITY_API std::string_view to_string(DomainClassKind value) noexcept;
PATH_AUTHORITY_API std::optional<DomainClassKind> domain_class_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API bool is_defined_domain_class(std::uint8_t raw) noexcept;

// ---------------------------------------------------------------------------
// Capability requirement model. Bounded, typed, deterministic, no scripting.
// ---------------------------------------------------------------------------
enum class CapabilityValueType : std::uint8_t {
  UNSIGNED = 1,
  SIGNED = 2,
  BOOLEAN = 3,
  TEXT = 4,
  VERSION = 5,
};

PATH_AUTHORITY_API std::string_view to_string(CapabilityValueType value) noexcept;
PATH_AUTHORITY_API bool is_defined_capability_value_type(std::uint8_t raw) noexcept;

struct PATH_AUTHORITY_API SemanticVersion {
  std::uint32_t major = 0;
  std::uint32_t minor = 0;
  std::uint32_t patch = 0;

  friend bool operator==(const SemanticVersion&, const SemanticVersion&) = default;
  friend std::strong_ordering operator<=>(const SemanticVersion&, const SemanticVersion&) = default;
  std::string render() const;
};

// A capability value as reported by Fabric Capability Registry. Values are
// typed; mixed-type comparisons are a hard evaluation error rather than an
// implicit coercion.
class PATH_AUTHORITY_API CapabilityValue {
 public:
  CapabilityValue() = default;

  static CapabilityValue unsigned_integer(std::uint64_t value);
  static CapabilityValue signed_integer(std::int64_t value);
  static CapabilityValue boolean(bool value);
  static CapabilityValue text(std::string value);
  static CapabilityValue version(SemanticVersion value);

  CapabilityValueType type() const noexcept { return type_; }
  bool is_unsigned() const noexcept { return type_ == CapabilityValueType::UNSIGNED; }
  bool is_signed() const noexcept { return type_ == CapabilityValueType::SIGNED; }
  bool is_boolean() const noexcept { return type_ == CapabilityValueType::BOOLEAN; }
  bool is_text() const noexcept { return type_ == CapabilityValueType::TEXT; }
  bool is_version() const noexcept { return type_ == CapabilityValueType::VERSION; }

  std::uint64_t as_unsigned() const;
  std::int64_t as_signed() const;
  bool as_boolean() const;
  const std::string& as_text() const;
  SemanticVersion as_version() const;

  // Truthiness used by SUPPORTS: boolean false, numeric zero, empty text and
  // version 0.0.0 are "not enabled"; every other value is "enabled".
  bool is_enabled() const;

  friend bool operator==(const CapabilityValue&, const CapabilityValue&) = default;
  friend std::strong_ordering operator<=>(const CapabilityValue& lhs, const CapabilityValue& rhs);
  std::string render() const;

 private:
  CapabilityValueType type_ = CapabilityValueType::UNSIGNED;
  std::uint64_t unsigned_ = 0;
  std::int64_t signed_ = 0;
  bool boolean_ = false;
  std::string text_;
  SemanticVersion version_;
};

enum class RequirementOp : std::uint8_t {
  SUPPORTS = 1,
  MINIMUM = 2,
  MAXIMUM = 3,
  IN_SET = 4,
  VERSION_AT_LEAST = 5,
  RANGE_CONTAINS = 6,
  ALL_OF = 7,
  ANY_OF = 8,
  NOT = 9,
};

PATH_AUTHORITY_API std::string_view to_string(RequirementOp value) noexcept;
PATH_AUTHORITY_API std::optional<RequirementOp> requirement_op_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API bool is_defined_requirement_op(std::uint8_t raw) noexcept;
PATH_AUTHORITY_API bool is_leaf_requirement(RequirementOp op) noexcept;

// Requirement expression node. Nesting depth and node count are bounded by the
// Limits passed to validation; evaluation is deterministic and total.
struct PATH_AUTHORITY_API Requirement {
  RequirementOp op = RequirementOp::SUPPORTS;
  std::string key;
  std::vector<CapabilityValue> values;
  std::vector<Requirement> children;

  friend bool operator==(const Requirement&, const Requirement&) = default;

  static Requirement leaf(RequirementOp op, std::string key, std::vector<CapabilityValue> values = {});
  static Requirement all_of(std::vector<Requirement> children);
  static Requirement any_of(std::vector<Requirement> children);
  static Requirement logical_not(Requirement child);

  std::size_t node_count() const noexcept;
  std::size_t depth() const noexcept;
  std::string render() const;
};

// Validation of a requirement expression against the configured bounds.
PATH_AUTHORITY_API bool validate_requirement(const Requirement& requirement,
                                             const Limits& limits,
                                             std::string& error);

// Tri-state outcome of evaluating one requirement. UNKNOWN never satisfies a
// hard requirement: unknown capability truth fails closed.
enum class RequirementStatus : std::uint8_t {
  SATISFIED = 0,
  UNSATISFIED = 1,
  UNKNOWN = 2,
};

PATH_AUTHORITY_API std::string_view to_string(RequirementStatus status) noexcept;

struct PATH_AUTHORITY_API RequirementOutcome {
  RequirementStatus status = RequirementStatus::UNKNOWN;
  std::string detail;
};

struct PATH_AUTHORITY_API CapabilityRequirement {
  std::string entity;
  CapabilityKey key;
  Requirement expression;
  bool fail_closed_on_unknown = true;

  friend bool operator==(const CapabilityRequirement&, const CapabilityRequirement&) = default;
  std::string render() const;
};

// ---------------------------------------------------------------------------
// Link, port and layer acceptance policies. There is deliberately no single
// global DEGRADED rule: DEGRADED behaviour is stated explicitly per policy.
// ---------------------------------------------------------------------------
struct PATH_AUTHORITY_API LinkStateAcceptance {
  bool allow_degraded = false;
  bool degraded_is_conditional = false;
  bool allow_unknown = false;
  bool unknown_is_conditional = false;

  friend bool operator==(const LinkStateAcceptance&, const LinkStateAcceptance&) = default;
  static LinkStateAcceptance strict() noexcept { return LinkStateAcceptance{}; }
  static LinkStateAcceptance degraded_conditional() noexcept {
    LinkStateAcceptance value;
    value.allow_degraded = true;
    value.degraded_is_conditional = true;
    return value;
  }
};

struct PATH_AUTHORITY_API PortAdminAcceptance {
  // DRAINING semantics: a path that is already authorized may remain legal
  // while the port drains, but a new authorization must reject.
  bool allow_draining_existing = true;
  bool allow_maintenance_existing = false;

  friend bool operator==(const PortAdminAcceptance&, const PortAdminAcceptance&) = default;
};

struct PATH_AUTHORITY_API PathLayerPolicy {
  std::vector<Layer> allowed_layers;
  bool allow_loops = false;

  friend bool operator==(const PathLayerPolicy&, const PathLayerPolicy&) = default;
  bool allows(Layer layer) const;
};

// ---------------------------------------------------------------------------
// Failure-domain constraints. Classification comes from Failure Domain
// Registry; Path Authority only evaluates the supplied predicates.
// ---------------------------------------------------------------------------
enum class FailureDomainConstraintKind : std::uint8_t {
  FORBIDDEN_DOMAIN = 1,
  MAX_MEMBERS_FROM_DOMAIN = 2,
  MAX_MEMBERS_FROM_CLASS = 3,
  EXCLUDE_DOMAIN_CLASS = 4,
  REQUIRE_COVERAGE_COMPLETENESS = 5,
  DIVERSE_FROM_PEER_PATH = 6,
};

PATH_AUTHORITY_API std::string_view to_string(FailureDomainConstraintKind value) noexcept;
PATH_AUTHORITY_API bool is_defined_failure_domain_constraint_kind(std::uint8_t raw) noexcept;

struct PATH_AUTHORITY_API PeerPathRef {
  PathId path;
  PathAuthorityGeneration authority_generation;
  friend bool operator==(const PeerPathRef&, const PeerPathRef&) = default;
};

struct PATH_AUTHORITY_API FailureDomainConstraint {
  FailureDomainConstraintKind kind = FailureDomainConstraintKind::FORBIDDEN_DOMAIN;
  FailureDomainId domain;
  DomainClassKind domain_class = DomainClassKind::UNKNOWN;
  std::uint32_t max_members = 1;
  PeerPathRef peer;
  std::vector<DomainClassKind> diversity_classes;

  friend bool operator==(const FailureDomainConstraint&, const FailureDomainConstraint&) = default;
  std::string render() const;
};

// ---------------------------------------------------------------------------
// Constraint sets and policy sets.
// ---------------------------------------------------------------------------
struct PATH_AUTHORITY_API ConstraintSet {
  ConstraintSetId id;
  ConstraintGeneration generation;
  ScopeId scope;
  std::vector<CapabilityRequirement> capabilities;
  std::vector<FailureDomainConstraint> failure_domains;
  LinkStateAcceptance link_state;
  PortAdminAcceptance port_admin;
  PathLayerPolicy layers;
  std::uint32_t max_hops = 0;  // 0 means "use Limits::max_hops"

  friend bool operator==(const ConstraintSet&, const ConstraintSet&) = default;
  // Semantic digest of the content (the generation is a version of it, not
  // part of it) so that re-registering identical content is idempotent.
  Digest digest() const;
};

struct PATH_AUTHORITY_API PolicySet {
  PolicyGeneration generation;
  ScopeId scope;
  LinkStateAcceptance link_state;
  PortAdminAcceptance port_admin;
  std::vector<CapabilityRequirement> required_capabilities;
  std::vector<DomainClassKind> forbidden_domain_classes;
  std::vector<Layer> forbidden_layers;
  bool allow_loops = false;
  std::uint32_t max_hops = 0;
  // When false, a conditionally authorized path is rejected outright.
  bool allow_conditional_authorization = true;
  bool allow_unknown_link_state = false;

  friend bool operator==(const PolicySet&, const PolicySet&) = default;
  Digest digest() const;
};

// The deterministic, most-restrictive combination of the path constraint set
// and the current policy generation.
struct PATH_AUTHORITY_API EffectiveRules {
  LinkStateAcceptance link_state;
  PortAdminAcceptance port_admin;
  PathLayerPolicy layers;
  std::uint32_t max_hops = 0;
  bool allow_conditional_authorization = true;
  std::vector<CapabilityRequirement> capabilities;
  // Sorted deterministically so evaluation order never depends on insertion.
  std::vector<FailureDomainConstraint> failure_domains;
  std::vector<DomainClassKind> forbidden_domain_classes;
  Digest digest;
};

PATH_AUTHORITY_API EffectiveRules combine_rules(const ConstraintSet& constraints,
                                                const PolicySet& policy,
                                                const Limits& limits);

}  // namespace path_authority
