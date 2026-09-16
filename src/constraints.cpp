// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/constraints.hpp"

#include <algorithm>
#include <string>
#include <utility>

#include "path_authority/canonical.hpp"

namespace path_authority {
namespace {

bool is_numeric(CapabilityValueType type) noexcept {
  return type == CapabilityValueType::UNSIGNED || type == CapabilityValueType::SIGNED;
}

}  // namespace

std::string_view to_string(DomainClassKind value) noexcept {
  switch (value) {
    case DomainClassKind::UNKNOWN: return "UNKNOWN";
    case DomainClassKind::POWER: return "POWER";
    case DomainClassKind::COOLING: return "COOLING";
    case DomainClassKind::RACK: return "RACK";
    case DomainClassKind::LINE_CARD: return "LINE_CARD";
    case DomainClassKind::SHARED_RISK_LINK_GROUP: return "SHARED_RISK_LINK_GROUP";
    case DomainClassKind::SITE: return "SITE";
    case DomainClassKind::REGION: return "REGION";
    case DomainClassKind::SHELF: return "SHELF";
    case DomainClassKind::CHANNEL: return "CHANNEL";
  }
  return "INVALID";
}

std::optional<DomainClassKind> domain_class_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 0; raw <= 9; ++raw) {
    const auto candidate = static_cast<DomainClassKind>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_defined_domain_class(std::uint8_t raw) noexcept { return raw <= 9; }

std::string_view to_string(CapabilityValueType value) noexcept {
  switch (value) {
    case CapabilityValueType::UNSIGNED: return "UNSIGNED";
    case CapabilityValueType::SIGNED: return "SIGNED";
    case CapabilityValueType::BOOLEAN: return "BOOLEAN";
    case CapabilityValueType::TEXT: return "TEXT";
    case CapabilityValueType::VERSION: return "VERSION";
  }
  return "INVALID";
}

bool is_defined_capability_value_type(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 5; }

std::string SemanticVersion::render() const {
  return std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
}

CapabilityValue CapabilityValue::unsigned_integer(std::uint64_t value) {
  CapabilityValue result;
  result.type_ = CapabilityValueType::UNSIGNED;
  result.unsigned_ = value;
  return result;
}

CapabilityValue CapabilityValue::signed_integer(std::int64_t value) {
  CapabilityValue result;
  result.type_ = CapabilityValueType::SIGNED;
  result.signed_ = value;
  return result;
}

CapabilityValue CapabilityValue::boolean(bool value) {
  CapabilityValue result;
  result.type_ = CapabilityValueType::BOOLEAN;
  result.boolean_ = value;
  return result;
}

CapabilityValue CapabilityValue::text(std::string value) {
  CapabilityValue result;
  result.type_ = CapabilityValueType::TEXT;
  result.text_ = std::move(value);
  return result;
}

CapabilityValue CapabilityValue::version(SemanticVersion value) {
  CapabilityValue result;
  result.type_ = CapabilityValueType::VERSION;
  result.version_ = value;
  return result;
}

std::uint64_t CapabilityValue::as_unsigned() const {
  if (type_ != CapabilityValueType::UNSIGNED) {
    throw IdentityError("capability value is not an unsigned integer");
  }
  return unsigned_;
}

std::int64_t CapabilityValue::as_signed() const {
  if (type_ != CapabilityValueType::SIGNED) {
    throw IdentityError("capability value is not a signed integer");
  }
  return signed_;
}

bool CapabilityValue::as_boolean() const {
  if (type_ != CapabilityValueType::BOOLEAN) {
    throw IdentityError("capability value is not a boolean");
  }
  return boolean_;
}

const std::string& CapabilityValue::as_text() const {
  if (type_ != CapabilityValueType::TEXT) {
    throw IdentityError("capability value is not text");
  }
  return text_;
}

SemanticVersion CapabilityValue::as_version() const {
  if (type_ != CapabilityValueType::VERSION) {
    throw IdentityError("capability value is not a version");
  }
  return version_;
}

bool CapabilityValue::is_enabled() const {
  switch (type_) {
    case CapabilityValueType::UNSIGNED: return unsigned_ != 0;
    case CapabilityValueType::SIGNED: return signed_ != 0;
    case CapabilityValueType::BOOLEAN: return boolean_;
    case CapabilityValueType::TEXT: return !text_.empty();
    case CapabilityValueType::VERSION: return !(version_ == SemanticVersion{});
  }
  return false;
}

std::strong_ordering operator<=>(const CapabilityValue& lhs, const CapabilityValue& rhs) {
  if (const auto cmp = lhs.type_ <=> rhs.type_; cmp != 0) {
    return cmp;
  }
  switch (lhs.type_) {
    case CapabilityValueType::UNSIGNED: return lhs.unsigned_ <=> rhs.unsigned_;
    case CapabilityValueType::SIGNED: return lhs.signed_ <=> rhs.signed_;
    case CapabilityValueType::BOOLEAN: return lhs.boolean_ <=> rhs.boolean_;
    case CapabilityValueType::TEXT: return lhs.text_ <=> rhs.text_;
    case CapabilityValueType::VERSION: return lhs.version_ <=> rhs.version_;
  }
  return std::strong_ordering::equal;
}

std::string CapabilityValue::render() const {
  switch (type_) {
    case CapabilityValueType::UNSIGNED: return std::to_string(unsigned_);
    case CapabilityValueType::SIGNED: return std::to_string(signed_);
    case CapabilityValueType::BOOLEAN: return boolean_ ? "true" : "false";
    case CapabilityValueType::TEXT: return text_;
    case CapabilityValueType::VERSION: return version_.render();
  }
  return "?";
}

std::string_view to_string(RequirementOp value) noexcept {
  switch (value) {
    case RequirementOp::SUPPORTS: return "SUPPORTS";
    case RequirementOp::MINIMUM: return "MINIMUM";
    case RequirementOp::MAXIMUM: return "MAXIMUM";
    case RequirementOp::IN_SET: return "IN_SET";
    case RequirementOp::VERSION_AT_LEAST: return "VERSION_AT_LEAST";
    case RequirementOp::RANGE_CONTAINS: return "RANGE_CONTAINS";
    case RequirementOp::ALL_OF: return "ALL_OF";
    case RequirementOp::ANY_OF: return "ANY_OF";
    case RequirementOp::NOT: return "NOT";
  }
  return "INVALID";
}

std::optional<RequirementOp> requirement_op_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 9; ++raw) {
    const auto candidate = static_cast<RequirementOp>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_defined_requirement_op(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 9; }

bool is_leaf_requirement(RequirementOp op) noexcept { return static_cast<std::uint8_t>(op) <= 6; }

Requirement Requirement::leaf(RequirementOp op, std::string key, std::vector<CapabilityValue> values) {
  Requirement requirement;
  requirement.op = op;
  requirement.key = std::move(key);
  requirement.values = std::move(values);
  return requirement;
}

Requirement Requirement::all_of(std::vector<Requirement> children) {
  Requirement requirement;
  requirement.op = RequirementOp::ALL_OF;
  requirement.children = std::move(children);
  return requirement;
}

Requirement Requirement::any_of(std::vector<Requirement> children) {
  Requirement requirement;
  requirement.op = RequirementOp::ANY_OF;
  requirement.children = std::move(children);
  return requirement;
}

Requirement Requirement::logical_not(Requirement child) {
  Requirement requirement;
  requirement.op = RequirementOp::NOT;
  requirement.children.push_back(std::move(child));
  return requirement;
}

std::size_t Requirement::node_count() const noexcept {
  std::size_t count = 1;
  for (const auto& child : children) {
    count += child.node_count();
  }
  return count;
}

std::size_t Requirement::depth() const noexcept {
  std::size_t deepest = 0;
  for (const auto& child : children) {
    deepest = std::max(deepest, child.depth());
  }
  return deepest + 1;
}

std::string Requirement::render() const {
  std::string text = std::string(to_string(op));
  if (is_leaf_requirement(op)) {
    text += "(" + key;
    for (const auto& value : values) {
      text += "," + value.render();
    }
    text += ")";
  } else {
    text += "(";
    for (std::size_t i = 0; i < children.size(); ++i) {
      if (i != 0) {
        text += ",";
      }
      text += children[i].render();
    }
    text += ")";
  }
  return text;
}

bool validate_requirement(const Requirement& requirement, const Limits& limits,
                          std::string& error) {
  if (requirement.node_count() > limits.max_requirement_nodes) {
    error = "requirement node count exceeds limits.max_requirement_nodes";
    return false;
  }
  if (requirement.depth() > limits.max_requirement_depth) {
    error = "requirement depth exceeds limits.max_requirement_depth";
    return false;
  }
  if (!is_defined_requirement_op(static_cast<std::uint8_t>(requirement.op))) {
    error = "undefined requirement operator";
    return false;
  }
  if (requirement.values.size() > limits.max_capability_values) {
    error = "requirement value count exceeds limits.max_capability_values";
    return false;
  }
  for (const auto& value : requirement.values) {
    if (!is_defined_capability_value_type(static_cast<std::uint8_t>(value.type()))) {
      error = "undefined capability value type";
      return false;
    }
    if (value.type() == CapabilityValueType::TEXT &&
        value.as_text().size() > limits.max_metadata_bytes) {
      error = "capability text value exceeds limits.max_metadata_bytes";
      return false;
    }
  }

  if (is_leaf_requirement(requirement.op)) {
    if (!requirement.children.empty()) {
      error = "leaf requirement must not have children";
      return false;
    }
    if (!CapabilityKey::from_wire(requirement.key).has_value()) {
      error = "malformed capability key";
      return false;
    }
    switch (requirement.op) {
      case RequirementOp::SUPPORTS:
        if (!requirement.values.empty()) {
          error = "SUPPORTS takes no operand";
          return false;
        }
        break;
      case RequirementOp::MINIMUM:
      case RequirementOp::MAXIMUM:
        if (requirement.values.size() != 1 ||
            !(is_numeric(requirement.values.front().type()) ||
              requirement.values.front().type() == CapabilityValueType::VERSION)) {
          error = "MINIMUM and MAXIMUM take exactly one numeric or version operand";
          return false;
        }
        break;
      case RequirementOp::VERSION_AT_LEAST:
        if (requirement.values.size() != 1 ||
            requirement.values.front().type() != CapabilityValueType::VERSION) {
          error = "VERSION_AT_LEAST takes exactly one version operand";
          return false;
        }
        break;
      case RequirementOp::IN_SET:
        if (requirement.values.empty()) {
          error = "IN_SET requires at least one operand";
          return false;
        }
        break;
      case RequirementOp::RANGE_CONTAINS:
        if (requirement.values.size() != 2) {
          error = "RANGE_CONTAINS takes exactly two operands";
          return false;
        }
        if (is_numeric(requirement.values[0].type()) != is_numeric(requirement.values[1].type()) ||
            (!is_numeric(requirement.values[0].type()) &&
             requirement.values[0].type() != CapabilityValueType::VERSION)) {
          error = "RANGE_CONTAINS operands must share one comparable type";
          return false;
        }
        if (requirement.values[0].type() != requirement.values[1].type()) {
          error = "RANGE_CONTAINS operands must share one type";
          return false;
        }
        if (requirement.values[1] < requirement.values[0]) {
          error = "RANGE_CONTAINS lower bound exceeds upper bound";
          return false;
        }
        break;
      default:
        break;
    }
    return true;
  }

  if (!requirement.key.empty() || !requirement.values.empty()) {
    error = "logical requirement must not carry a key or operands";
    return false;
  }
  if (requirement.op == RequirementOp::NOT) {
    if (requirement.children.size() != 1) {
      error = "NOT takes exactly one child";
      return false;
    }
  } else if (requirement.children.empty()) {
    error = "ALL_OF and ANY_OF require at least one child";
    return false;
  }
  for (const auto& child : requirement.children) {
    if (!validate_requirement(child, limits, error)) {
      return false;
    }
  }
  return true;
}

std::string_view to_string(RequirementStatus status) noexcept {
  switch (status) {
    case RequirementStatus::SATISFIED: return "SATISFIED";
    case RequirementStatus::UNSATISFIED: return "UNSATISFIED";
    case RequirementStatus::UNKNOWN: return "UNKNOWN";
  }
  return "INVALID";
}

std::string CapabilityRequirement::render() const {
  return entity + ":" + key.str() + " " + expression.render();
}

bool PathLayerPolicy::allows(Layer layer) const {
  if (allowed_layers.empty()) {
    return true;
  }
  return std::find(allowed_layers.begin(), allowed_layers.end(), layer) != allowed_layers.end();
}

std::string_view to_string(FailureDomainConstraintKind value) noexcept {
  switch (value) {
    case FailureDomainConstraintKind::FORBIDDEN_DOMAIN: return "FORBIDDEN_DOMAIN";
    case FailureDomainConstraintKind::MAX_MEMBERS_FROM_DOMAIN: return "MAX_MEMBERS_FROM_DOMAIN";
    case FailureDomainConstraintKind::MAX_MEMBERS_FROM_CLASS: return "MAX_MEMBERS_FROM_CLASS";
    case FailureDomainConstraintKind::EXCLUDE_DOMAIN_CLASS: return "EXCLUDE_DOMAIN_CLASS";
    case FailureDomainConstraintKind::REQUIRE_COVERAGE_COMPLETENESS:
      return "REQUIRE_COVERAGE_COMPLETENESS";
    case FailureDomainConstraintKind::DIVERSE_FROM_PEER_PATH: return "DIVERSE_FROM_PEER_PATH";
  }
  return "INVALID";
}

bool is_defined_failure_domain_constraint_kind(std::uint8_t raw) noexcept {
  return raw >= 1 && raw <= 6;
}

std::string FailureDomainConstraint::render() const {
  std::string text = std::string(to_string(kind));
  text += "(";
  if (domain.valid()) {
    text += domain.str();
  }
  if (domain_class != DomainClassKind::UNKNOWN) {
    text += std::string(domain.valid() ? "," : "") + std::string(to_string(domain_class));
  }
  if (kind == FailureDomainConstraintKind::MAX_MEMBERS_FROM_DOMAIN ||
      kind == FailureDomainConstraintKind::MAX_MEMBERS_FROM_CLASS) {
    text += ",max=" + std::to_string(max_members);
  }
  if (peer.path.valid()) {
    text += ",peer=" + peer.path.str();
  }
  for (DomainClassKind value : diversity_classes) {
    text += ",class=" + std::string(to_string(value));
  }
  text += ")";
  return text;
}

namespace {

bool capability_requirement_less(const CapabilityRequirement& lhs,
                                 const CapabilityRequirement& rhs) {
  if (lhs.entity != rhs.entity) {
    return lhs.entity < rhs.entity;
  }
  if (lhs.key != rhs.key) {
    return lhs.key < rhs.key;
  }
  return lhs.expression.render() < rhs.expression.render();
}

bool failure_domain_constraint_less(const FailureDomainConstraint& lhs,
                                    const FailureDomainConstraint& rhs) {
  if (lhs.kind != rhs.kind) {
    return lhs.kind < rhs.kind;
  }
  if (lhs.domain != rhs.domain) {
    return lhs.domain < rhs.domain;
  }
  if (lhs.domain_class != rhs.domain_class) {
    return lhs.domain_class < rhs.domain_class;
  }
  return lhs.render() < rhs.render();
}

}  // namespace

// Content digests are computed over the canonically ordered content so that two
// constraint sets that differ only in construction order are identical.
Digest ConstraintSet::digest() const {
  ConstraintSet content = *this;
  content.generation = ConstraintGeneration{};
  std::stable_sort(content.capabilities.begin(), content.capabilities.end(),
                   capability_requirement_less);
  std::stable_sort(content.failure_domains.begin(), content.failure_domains.end(),
                   failure_domain_constraint_less);
  std::stable_sort(content.layers.allowed_layers.begin(), content.layers.allowed_layers.end());
  return Digest::of(encode_constraint_set(content));
}

Digest PolicySet::digest() const {
  PolicySet content = *this;
  content.generation = PolicyGeneration{};
  std::stable_sort(content.required_capabilities.begin(), content.required_capabilities.end(),
                   capability_requirement_less);
  std::stable_sort(content.forbidden_domain_classes.begin(), content.forbidden_domain_classes.end());
  std::stable_sort(content.forbidden_layers.begin(), content.forbidden_layers.end());
  return Digest::of(encode_policy_set(content));
}

EffectiveRules combine_rules(const ConstraintSet& constraints, const PolicySet& policy,
                             const Limits& limits) {
  EffectiveRules rules;

  rules.link_state.allow_degraded = constraints.link_state.allow_degraded && policy.link_state.allow_degraded;
  rules.link_state.degraded_is_conditional =
      constraints.link_state.degraded_is_conditional || policy.link_state.degraded_is_conditional;
  rules.link_state.allow_unknown = constraints.link_state.allow_unknown &&
                                   policy.link_state.allow_unknown && policy.allow_unknown_link_state;
  rules.link_state.unknown_is_conditional =
      constraints.link_state.unknown_is_conditional || policy.link_state.unknown_is_conditional;

  rules.port_admin.allow_draining_existing =
      constraints.port_admin.allow_draining_existing && policy.port_admin.allow_draining_existing;
  rules.port_admin.allow_maintenance_existing =
      constraints.port_admin.allow_maintenance_existing && policy.port_admin.allow_maintenance_existing;

  rules.layers.allowed_layers = constraints.layers.allowed_layers;
  if (rules.layers.allowed_layers.empty()) {
    rules.layers.allowed_layers = {Layer::PHYSICAL, Layer::LOGICAL, Layer::OVERLAY, Layer::CONTROL};
  }
  if (!policy.forbidden_layers.empty()) {
    std::vector<Layer> filtered;
    for (Layer layer : rules.layers.allowed_layers) {
      if (std::find(policy.forbidden_layers.begin(), policy.forbidden_layers.end(), layer) ==
          policy.forbidden_layers.end()) {
        filtered.push_back(layer);
      }
    }
    rules.layers.allowed_layers = std::move(filtered);
  }
  rules.layers.allow_loops = constraints.layers.allow_loops && policy.allow_loops;

  rules.max_hops = limits.max_hops;
  if (constraints.max_hops != 0) {
    rules.max_hops = std::min(rules.max_hops, constraints.max_hops);
  }
  if (policy.max_hops != 0) {
    rules.max_hops = std::min(rules.max_hops, policy.max_hops);
  }

  rules.allow_conditional_authorization = policy.allow_conditional_authorization;

  rules.failure_domains = constraints.failure_domains;
  std::stable_sort(rules.failure_domains.begin(), rules.failure_domains.end(),
                   failure_domain_constraint_less);

  rules.capabilities = policy.required_capabilities;
  rules.capabilities.insert(rules.capabilities.end(), constraints.capabilities.begin(),
                            constraints.capabilities.end());
  std::stable_sort(rules.capabilities.begin(), rules.capabilities.end(),
                   capability_requirement_less);

  rules.forbidden_domain_classes = policy.forbidden_domain_classes;
  std::sort(rules.forbidden_domain_classes.begin(), rules.forbidden_domain_classes.end());
  rules.forbidden_domain_classes.erase(
      std::unique(rules.forbidden_domain_classes.begin(), rules.forbidden_domain_classes.end()),
      rules.forbidden_domain_classes.end());

  ConstraintSet effective;
  effective.id = constraints.id;
  effective.generation = constraints.generation;
  effective.scope = constraints.scope;
  effective.capabilities = rules.capabilities;
  effective.failure_domains = rules.failure_domains;
  effective.link_state = rules.link_state;
  effective.port_admin = rules.port_admin;
  effective.layers = rules.layers;
  effective.max_hops = rules.max_hops;

  ByteWriter writer;
  writer.digest(Digest::of(encode_constraint_set(effective)));
  writer.u64(policy.generation.value());
  writer.digest(policy.digest());
  rules.digest = Digest::of(writer.data());
  return rules;
}

}  // namespace path_authority
