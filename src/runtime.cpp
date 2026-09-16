// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/runtime.hpp"

#include <algorithm>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include "path_authority/canonical.hpp"
#include "path_authority/in_memory.hpp"
#include "path_authority/persistence.hpp"
#include "path_authority/version.hpp"

namespace path_authority {
namespace {

using PathKey = std::string;

std::string path_key(const PathId& id) { return id.str(); }

std::string structural_subject(ElementKind kind, std::string_view id) {
  return element_key(kind, id);
}

std::string capability_subject(std::string_view entity, std::string_view key) {
  return capability_key(entity, key);
}

std::string domain_subject(const FailureDomainId& id) { return "domain:" + id.str(); }

std::string membership_subject(const ElementRef& element) {
  return "member:" + element.render();
}

std::string underlying_subject(const PathId& id) { return "underlying:" + id.str(); }

constexpr std::uint64_t kAbsentGeneration = 0;

// ---------------------------------------------------------------------------
// Committed authority record and its dependency indexes.
// ---------------------------------------------------------------------------
struct AttemptIndexEntry {
  PathId path;
  Digest input_digest;
};

struct Record {
  PathDefinition definition;
  PathAuthorityGeneration generation;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome outcome = EvaluationOutcome::MALFORMED_PATH;
  EvidenceVector evidence;
  Digest path_digest;
  Digest constraint_digest;
  Digest authority_digest;
  Digest input_digest;
  Violation primary_violation;
  std::vector<Violation> violations;
  std::optional<RevocationRecord> revocation;
  std::deque<HistoryEntry> history;
  bool retired = false;
  bool identity_bound = true;
  PublisherId publisher;
  WorkerBootId worker_boot;
  std::uint64_t evaluations = 0;
  std::uint64_t revalidations = 0;
  std::vector<ElementRef> elements;
  std::vector<std::pair<std::string, std::string>> capability_dependencies;
  std::vector<FailureDomainId> domain_dependencies;
  std::vector<std::string> membership_dependencies;
  std::vector<PathKey> underlying_dependencies;
};

struct UnderlyingChain {
  bool found = false;
  bool cycle = false;
  std::uint32_t depth = 0;
  PathAuthorityGeneration generation;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome outcome = EvaluationOutcome::MALFORMED_PATH;
};

struct PeerPathInfo {
  bool found = false;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome outcome = EvaluationOutcome::MALFORMED_PATH;
  std::vector<ElementRef> elements;
  std::vector<FailureDomainId> domains;
};

struct Computation {
  EvaluationOutcome primary = EvaluationOutcome::AUTHORIZED;
  std::vector<Violation> violations;
  EvidenceVector evidence;
  Digest path_digest;
  Digest constraint_digest;
  EffectiveRules rules;
  PolicySet policy;
  ConstraintSet constraints;
  CoordinatorEpoch epoch;
  bool hard_failure = false;
  Violation primary_violation;
};

// Collects violations in fixed stage order. The first hard violation becomes
// the primary outcome; later stages still run to enrich diagnostics without
// ever changing the authoritative result.
class StageCollector {
 public:
  StageCollector(Computation& computation, const Limits& limits)
      : computation_(computation), limits_(limits) {}

  void hard(EvaluationOutcome code, std::string subject, std::string detail) {
    if (!computation_.hard_failure) {
      computation_.hard_failure = true;
      computation_.primary = code;
      computation_.primary_violation = Violation{code, ViolationSeverity::PRIMARY, subject, detail};
    }
    push(Violation{code, ViolationSeverity::HARD, std::move(subject), std::move(detail)});
  }

  void condition(EvaluationOutcome code, std::string subject, std::string detail) {
    push(Violation{code, ViolationSeverity::CONDITION, std::move(subject), std::move(detail)});
  }

  void informational(EvaluationOutcome code, std::string subject, std::string detail) {
    push(Violation{code, ViolationSeverity::INFORMATIONAL, std::move(subject), std::move(detail)});
  }

  bool failed() const noexcept { return computation_.hard_failure; }

 private:
  void push(Violation violation) {
    if (computation_.violations.size() >= limits_.max_explanation_entries) {
      return;
    }
    computation_.violations.push_back(std::move(violation));
  }

  Computation& computation_;
  const Limits& limits_;
};

Digest compute_input_digest(const Digest& path_digest, const PathDefinition& path,
                            const Digest& constraint_digest, const PolicySet& policy,
                            CoordinatorEpoch epoch) {
  ByteWriter writer;
  writer.u32(kDigestSchemeVersion);
  writer.digest(path_digest);
  writer.u64(path.generation.value());
  writer.digest(constraint_digest);
  writer.u64(path.constraint_generation.value());
  writer.digest(policy.digest());
  writer.u64(policy.generation.value());
  writer.u64(epoch.value());
  return Digest::of(writer.data());
}

HistoryEntry history_entry(const Record& record, std::string cause) {
  HistoryEntry entry;
  entry.generation = record.generation;
  entry.state = record.state;
  entry.outcome = record.outcome;
  entry.cause = std::move(cause);
  entry.epoch = record.evidence.epoch();
  return entry;
}

void push_history(Record& record, std::string cause, const Limits& limits) {
  record.history.push_back(history_entry(record, std::move(cause)));
  while (record.history.size() > limits.max_history) {
    record.history.pop_front();
  }
}

AuthorityDigestInput digest_input_for(const PathDefinition& definition, const Digest& path_digest,
                                      const Digest& constraint_digest, const EvidenceVector& evidence,
                                      AuthorityState state, EvaluationOutcome outcome,
                                      const std::vector<Violation>& violations) {
  AuthorityDigestInput input;
  input.path_digest = path_digest;
  input.path_generation = definition.generation;
  input.constraint_digest = constraint_digest;
  input.constraint_generation = definition.constraint_generation;
  input.evidence_digest = evidence.digest();
  input.policy = evidence.policy();
  input.epoch = evidence.epoch();
  input.state = state;
  input.primary = outcome;
  for (const auto& violation : violations) {
    input.secondary_codes.push_back(violation.code);
  }
  return input;
}

}  // namespace

namespace {

// ---------------------------------------------------------------------------
// Requirement evaluation (tri-state, fail closed).
// ---------------------------------------------------------------------------
RequirementOutcome evaluate_requirement_node(const Requirement& requirement, const CapabilityRecord& record);

RequirementOutcome evaluate_leaf(const Requirement& requirement, const CapabilityRecord& record) {
  RequirementOutcome outcome;
  if (!record.known) {
    outcome.status = RequirementStatus::UNKNOWN;
    outcome.detail = "capability registry holds no current truth for " + requirement.key;
    return outcome;
  }
  const CapabilityValue& value = record.value;
  switch (requirement.op) {
    case RequirementOp::SUPPORTS:
      outcome.status = value.is_enabled() ? RequirementStatus::SATISFIED : RequirementStatus::UNSATISFIED;
      outcome.detail = requirement.key + " is " + value.render();
      return outcome;
    case RequirementOp::MINIMUM:
    case RequirementOp::MAXIMUM: {
      const CapabilityValue& bound = requirement.values.front();
      if (value.type() != bound.type()) {
        outcome.status = RequirementStatus::UNSATISFIED;
        outcome.detail = std::string(to_string(requirement.op)) + " compares " +
                         std::string(to_string(value.type())) + " against " +
                         std::string(to_string(bound.type()));
        return outcome;
      }
      const bool satisfied =
          requirement.op == RequirementOp::MINIMUM ? !(value < bound) : !(bound < value);
      outcome.status = satisfied ? RequirementStatus::SATISFIED : RequirementStatus::UNSATISFIED;
      outcome.detail = requirement.key + " is " + value.render() + ", bound " + bound.render();
      return outcome;
    }
    case RequirementOp::VERSION_AT_LEAST: {
      const CapabilityValue& bound = requirement.values.front();
      if (value.type() != CapabilityValueType::VERSION) {
        outcome.status = RequirementStatus::UNSATISFIED;
        outcome.detail = requirement.key + " is not a version";
        return outcome;
      }
      outcome.status = !(value < bound) ? RequirementStatus::SATISFIED : RequirementStatus::UNSATISFIED;
      outcome.detail = requirement.key + " is " + value.render() + ", floor " + bound.render();
      return outcome;
    }
    case RequirementOp::IN_SET: {
      const bool found = std::find(requirement.values.begin(), requirement.values.end(), value) !=
                         requirement.values.end();
      outcome.status = found ? RequirementStatus::SATISFIED : RequirementStatus::UNSATISFIED;
      outcome.detail = requirement.key + " is " + value.render();
      return outcome;
    }
    case RequirementOp::RANGE_CONTAINS: {
      const CapabilityValue& lower = requirement.values[0];
      const CapabilityValue& upper = requirement.values[1];
      if (value.type() != lower.type()) {
        outcome.status = RequirementStatus::UNSATISFIED;
        outcome.detail = requirement.key + " type does not match the range";
        return outcome;
      }
      const bool inside = !(value < lower) && !(upper < value);
      outcome.status = inside ? RequirementStatus::SATISFIED : RequirementStatus::UNSATISFIED;
      outcome.detail = requirement.key + " is " + value.render() + ", range " + lower.render() +
                       ".." + upper.render();
      return outcome;
    }
    default:
      break;
  }
  outcome.status = RequirementStatus::UNKNOWN;
  outcome.detail = "logical operator reached leaf evaluation";
  return outcome;
}

RequirementOutcome evaluate_requirement_node(const Requirement& requirement,
                                             const CapabilityRecord& record) {
  switch (requirement.op) {
    case RequirementOp::NOT: {
      RequirementOutcome inner = evaluate_requirement_node(requirement.children.front(), record);
      RequirementOutcome outcome;
      outcome.detail = "NOT(" + inner.detail + ")";
      switch (inner.status) {
        case RequirementStatus::SATISFIED: outcome.status = RequirementStatus::UNSATISFIED; break;
        case RequirementStatus::UNSATISFIED: outcome.status = RequirementStatus::SATISFIED; break;
        case RequirementStatus::UNKNOWN: outcome.status = RequirementStatus::UNKNOWN; break;
      }
      return outcome;
    }
    case RequirementOp::ALL_OF: {
      RequirementOutcome outcome;
      outcome.status = RequirementStatus::SATISFIED;
      for (const auto& child : requirement.children) {
        const RequirementOutcome inner = evaluate_requirement_node(child, record);
        if (inner.status == RequirementStatus::UNSATISFIED) {
          outcome.status = RequirementStatus::UNSATISFIED;
          outcome.detail = inner.detail;
          return outcome;
        }
        if (inner.status == RequirementStatus::UNKNOWN) {
          outcome.status = RequirementStatus::UNKNOWN;
          outcome.detail = inner.detail;
        }
      }
      if (outcome.status == RequirementStatus::SATISFIED) {
        outcome.detail = "all requirements satisfied";
      }
      return outcome;
    }
    case RequirementOp::ANY_OF: {
      RequirementOutcome outcome;
      outcome.status = RequirementStatus::UNSATISFIED;
      bool saw_unknown = false;
      std::string unknown_detail;
      for (const auto& child : requirement.children) {
        const RequirementOutcome inner = evaluate_requirement_node(child, record);
        if (inner.status == RequirementStatus::SATISFIED) {
          outcome.status = RequirementStatus::SATISFIED;
          outcome.detail = inner.detail;
          return outcome;
        }
        if (inner.status == RequirementStatus::UNKNOWN) {
          saw_unknown = true;
          unknown_detail = inner.detail;
        }
      }
      if (saw_unknown) {
        outcome.status = RequirementStatus::UNKNOWN;
        outcome.detail = unknown_detail;
      } else {
        outcome.detail = "no alternative satisfied";
      }
      return outcome;
    }
    default:
      return evaluate_leaf(requirement, record);
  }
}

}  // namespace

RequirementOutcome evaluate_requirement(const Requirement& requirement,
                                        const CapabilityRecord& record) {
  return evaluate_requirement_node(requirement, record);
}

namespace {

// ---------------------------------------------------------------------------
// Evaluation computation. Pure: it reads evidence views and returns a value;
// it never mutates runtime state and never runs under the state lock.
// ---------------------------------------------------------------------------
Computation compute_evaluation(const PathDefinition& path, const EvidenceSources& sources,
                               const Limits& limits, const ConstraintSet& constraints,
                               const PolicySet& policy, CoordinatorEpoch epoch,
                               const UnderlyingChain& underlying,
                               const std::map<std::string, PeerPathInfo>& peers,
                               bool existing_authorized, bool* evidence_overflow) {
  Computation computation;
  computation.constraints = constraints;
  computation.policy = policy;
  computation.epoch = epoch;
  computation.path_digest = path.semantic_digest();
  computation.constraint_digest = constraints.digest();
  computation.rules = combine_rules(constraints, policy, limits);

  EvidenceVector& evidence = computation.evidence;
  bool overflow = false;
  auto remember = [&](EvidenceKind kind, std::string subject, std::uint64_t generation) {
    if (!evidence.set(kind, std::move(subject), generation, limits)) {
      overflow = true;
    }
  };
  remember(EvidenceKind::EPOCH, std::string(EvidenceVector::kScalarSubject), epoch.value());
  remember(EvidenceKind::POLICY, std::string(EvidenceVector::kScalarSubject), policy.generation.value());
  remember(EvidenceKind::CONSTRAINTS, std::string(EvidenceVector::kScalarSubject),
           constraints.generation.value());
  remember(EvidenceKind::TOPOLOGY, std::string(EvidenceVector::kScalarSubject),
           sources.topology->generation().value());

  StageCollector stage(computation, limits);

  // ---- stage: structural topology ---------------------------------------
  for (const auto& hop : path.hops) {
    const ElementRef ref = hop.ref();
    const std::string subject = ref.render();
    const auto record = sources.topology->element(hop.kind, hop.id);
    if (!record.has_value()) {
      remember(EvidenceKind::STRUCTURAL_ELEMENT, structural_subject(hop.kind, hop.id), kAbsentGeneration);
      stage.hard(EvaluationOutcome::STRUCTURALLY_INVALID, subject,
                 "structural element is not present in Fabric Topology");
      continue;
    }
    remember(EvidenceKind::STRUCTURAL_ELEMENT, structural_subject(hop.kind, hop.id),
             record->generation.value());
    if (record->retired) {
      stage.hard(EvaluationOutcome::STRUCTURALLY_INVALID, subject, "structural element is retired");
    } else if (record->superseded) {
      stage.hard(EvaluationOutcome::STRUCTURALLY_INVALID, subject,
                 "structural element is superseded by " + record->superseded_by);
    } else if (record->generation != hop.generation) {
      stage.hard(EvaluationOutcome::STALE_TOPOLOGY, subject,
                 "path bound structural generation " + std::to_string(hop.generation.value()) +
                     ", Fabric Topology reports " + std::to_string(record->generation.value()));
    }
  }
  for (std::size_t i = 1; i < path.hops.size(); ++i) {
    const HopCheck check = sources.topology->check_hop(path.hops[i - 1], path.hops[i]);
    if (!check.legal()) {
      stage.hard(EvaluationOutcome::STRUCTURALLY_INVALID,
                 path.hops[i - 1].ref().render() + " -> " + path.hops[i].ref().render(),
                 check.detail.empty() ? std::string(to_string(check.legality)) : check.detail);
    }
  }

  // ---- stage: currentness of bound inputs --------------------------------
  if (path.underlying.has_value()) {
    const PathId& under = path.underlying->path;
    const std::string subject = under.str();
    if (!underlying.found) {
      stage.hard(EvaluationOutcome::REVALIDATION_REQUIRED, subject,
                 "underlying path authority has not been established");
    } else {
      remember(EvidenceKind::UNDERLYING_AUTHORITY, underlying_subject(under),
               underlying.generation.value());
      if (underlying.generation != path.underlying->authority_generation) {
        stage.hard(EvaluationOutcome::REVALIDATION_REQUIRED, subject,
                   "underlying authority generation moved from " +
                       std::to_string(path.underlying->authority_generation.value()) + " to " +
                       std::to_string(underlying.generation.value()));
      } else if (!is_authorizing_outcome(underlying.outcome)) {
        stage.hard(EvaluationOutcome::REVALIDATION_REQUIRED, subject,
                   "underlying path is " + std::string(to_string(underlying.state)) + " (" +
                       std::string(to_string(underlying.outcome)) + ")");
      }
    }
  }

  // ---- stage: port administrative state ----------------------------------
  for (const auto& hop : path.hops) {
    if (hop.kind != ElementKind::PORT) {
      continue;
    }
    const std::string subject = element_key(ElementKind::PORT, hop.id);
    const auto port = sources.port_state->port(hop.id);
    if (!port.has_value()) {
      remember(EvidenceKind::PORT_CONFIG, structural_subject(hop.kind, hop.id), kAbsentGeneration);
      stage.hard(EvaluationOutcome::PORT_REVALIDATION_REQUIRED, subject,
                 "Port Fabric reports no current administrative record");
      continue;
    }
    remember(EvidenceKind::PORT_CONFIG, structural_subject(hop.kind, hop.id), port->generation.value());
    switch (port->admin) {
      case PortAdminState::ACTIVE:
        break;
      case PortAdminState::ADMIN_DISABLED:
        stage.hard(EvaluationOutcome::PORT_ADMIN_DISABLED, subject, "port is administratively disabled");
        break;
      case PortAdminState::RETIRED:
        stage.hard(EvaluationOutcome::PORT_ADMIN_DISABLED, subject, "port is retired");
        break;
      case PortAdminState::SUPERSEDED:
        stage.hard(EvaluationOutcome::PORT_ADMIN_DISABLED, subject, "port is superseded");
        break;
      case PortAdminState::MAINTENANCE:
        if (existing_authorized && computation.rules.port_admin.allow_maintenance_existing) {
          stage.condition(EvaluationOutcome::PORT_ADMIN_DISABLED, subject,
                          "port is in maintenance; existing authorization may persist");
        } else {
          stage.hard(EvaluationOutcome::PORT_ADMIN_DISABLED, subject,
                     "port is in maintenance and new authorization is rejected");
        }
        break;
      case PortAdminState::DRAINING:
        if (existing_authorized && computation.rules.port_admin.allow_draining_existing) {
          stage.condition(EvaluationOutcome::PORT_ADMIN_DISABLED, subject,
                          "port is draining; existing authorization may persist");
        } else {
          stage.hard(EvaluationOutcome::PORT_ADMIN_DISABLED, subject,
                     "port is draining and new authorization is rejected");
        }
        break;
      case PortAdminState::REVALIDATION_REQUIRED:
        stage.hard(EvaluationOutcome::PORT_REVALIDATION_REQUIRED, subject,
                   "port configuration requires revalidation");
        break;
      case PortAdminState::UNKNOWN:
        stage.hard(EvaluationOutcome::PORT_REVALIDATION_REQUIRED, subject,
                   "port administrative state is unknown");
        break;
    }
  }

  // ---- stage: link state --------------------------------------------------
  for (const auto& hop : path.hops) {
    if (hop.kind != ElementKind::LINK) {
      continue;
    }
    const std::string subject = element_key(ElementKind::LINK, hop.id);
    const auto link = sources.link_state->link(hop.id);
    if (!link.has_value()) {
      remember(EvidenceKind::LINK_STATE, structural_subject(hop.kind, hop.id), kAbsentGeneration);
      if (!computation.rules.link_state.allow_unknown) {
        stage.hard(EvaluationOutcome::LINK_STATE_UNKNOWN, subject,
                   "Link State Fabric reports no current record and proof is required");
      } else if (computation.rules.link_state.unknown_is_conditional) {
        stage.condition(EvaluationOutcome::LINK_STATE_UNKNOWN, subject,
                        "Link State Fabric reports no current record; authorization is conditional");
      } else {
        stage.informational(EvaluationOutcome::LINK_STATE_UNKNOWN, subject,
                            "Link State Fabric reports no current record and this is accepted");
      }
      continue;
    }
    remember(EvidenceKind::LINK_STATE, structural_subject(hop.kind, hop.id), link->generation.value());
    switch (link->state) {
      case LinkState::UP:
        break;
      case LinkState::DOWN:
        stage.hard(EvaluationOutcome::LINK_DOWN, subject, "link is down");
        break;
      case LinkState::FAULTED:
        stage.hard(EvaluationOutcome::LINK_DOWN, subject, "link is faulted");
        break;
      case LinkState::RETIRED:
        stage.hard(EvaluationOutcome::LINK_DOWN, subject, "link is retired");
        break;
      case LinkState::REVALIDATION_REQUIRED:
        stage.hard(EvaluationOutcome::REVALIDATION_REQUIRED, subject,
                   "link state requires revalidation");
        break;
      case LinkState::DEGRADED:
        if (!computation.rules.link_state.allow_degraded) {
          stage.hard(EvaluationOutcome::LINK_DEGRADED, subject,
                     "link is degraded and the effective rules reject degraded links");
        } else if (computation.rules.link_state.degraded_is_conditional) {
          stage.condition(EvaluationOutcome::LINK_DEGRADED, subject,
                          "link is degraded; authorization is conditional");
        } else {
          stage.informational(EvaluationOutcome::LINK_DEGRADED, subject,
                              "link is degraded and explicitly accepted");
        }
        break;
      case LinkState::UNKNOWN:
        if (!computation.rules.link_state.allow_unknown) {
          stage.hard(EvaluationOutcome::LINK_STATE_UNKNOWN, subject,
                     "link state is unknown and current proof is required");
        } else if (computation.rules.link_state.unknown_is_conditional) {
          stage.condition(EvaluationOutcome::LINK_STATE_UNKNOWN, subject,
                          "link state is unknown; authorization is conditional");
        } else {
          stage.informational(EvaluationOutcome::LINK_STATE_UNKNOWN, subject,
                              "link state is unknown and explicitly accepted");
        }
        break;
    }
  }

  // ---- stage: capability requirements -------------------------------------
  for (const auto& requirement : computation.rules.capabilities) {
    const std::string subject = capability_subject(requirement.entity, requirement.key.view());
    const CapabilityRecord record =
        sources.capability->lookup(requirement.entity, requirement.key.view());
    remember(EvidenceKind::CAPABILITY, subject,
             record.known ? record.generation.value() : kAbsentGeneration);
    const RequirementOutcome outcome = evaluate_requirement(requirement.expression, record);
    if (outcome.status == RequirementStatus::UNSATISFIED) {
      stage.hard(EvaluationOutcome::CAPABILITY_MISSING, subject, outcome.detail);
    } else if (outcome.status == RequirementStatus::UNKNOWN) {
      if (requirement.fail_closed_on_unknown) {
        stage.hard(EvaluationOutcome::CAPABILITY_UNKNOWN, subject, outcome.detail);
      } else {
        stage.condition(EvaluationOutcome::CAPABILITY_UNKNOWN, subject, outcome.detail);
      }
    }
  }

  // ---- stage: failure domain constraints ----------------------------------
  std::map<std::string, std::vector<FailureDomainId>> memberships;
  std::map<std::string, bool> coverage;
  std::map<std::string, std::vector<DomainClassKind>> class_cache;
  auto ensure_membership = [&](const ElementRef& ref) {
    const std::string key = ref.render();
    if (memberships.find(key) != memberships.end()) {
      return;
    }
    memberships[key] = sources.failure_domain->memberships(ref);
    coverage[key] = sources.failure_domain->coverage_for(ref);
    remember(EvidenceKind::FAILURE_DOMAIN, membership_subject(ref),
             sources.failure_domain->membership_generation(ref).value());
    std::vector<DomainClassKind> classes;
    for (const auto& domain : memberships[key]) {
      const auto record = sources.failure_domain->domain(domain);
      remember(EvidenceKind::FAILURE_DOMAIN, domain_subject(domain),
               record.has_value() ? record->generation.value() : kAbsentGeneration);
      if (record.has_value()) {
        classes.push_back(record->domain_class);
      } else {
        classes.push_back(DomainClassKind::UNKNOWN);
      }
    }
    class_cache[key] = std::move(classes);
  };

  const bool domain_stage_needed = !constraints.failure_domains.empty() ||
                                   !computation.rules.forbidden_domain_classes.empty();
  if (domain_stage_needed) {
    for (const auto& hop : path.hops) {
      ensure_membership(hop.ref());
    }
  }

  for (const auto& constraint : computation.rules.failure_domains) {
    switch (constraint.kind) {
      case FailureDomainConstraintKind::FORBIDDEN_DOMAIN: {
        for (const auto& hop : path.hops) {
          const ElementRef ref = hop.ref();
          ensure_membership(ref);
          const std::string key = ref.render();
          if (!coverage[key]) {
            stage.hard(EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN, key,
                       "incomplete failure domain coverage prevents proving that " + key +
                           " avoids " + constraint.domain.str());
            continue;
          }
          const auto& list = memberships[key];
          if (std::find(list.begin(), list.end(), constraint.domain) != list.end()) {
            stage.hard(EvaluationOutcome::FAILURE_DOMAIN_VIOLATION, key,
                       "member of forbidden failure domain " + constraint.domain.str());
          }
        }
        break;
      }
      case FailureDomainConstraintKind::MAX_MEMBERS_FROM_DOMAIN: {
        std::size_t count = 0;
        bool incomplete = false;
        for (const auto& hop : path.hops) {
          const ElementRef ref = hop.ref();
          ensure_membership(ref);
          const std::string key = ref.render();
          if (!coverage[key]) {
            incomplete = true;
            continue;
          }
          const auto& list = memberships[key];
          if (std::find(list.begin(), list.end(), constraint.domain) != list.end()) {
            ++count;
          }
        }
        if (incomplete) {
          stage.hard(EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN, constraint.domain.str(),
                     "incomplete failure domain coverage prevents counting members of " +
                         constraint.domain.str());
        } else if (count > constraint.max_members) {
          stage.hard(EvaluationOutcome::FAILURE_DOMAIN_VIOLATION, constraint.domain.str(),
                     "path uses " + std::to_string(count) + " members of failure domain " +
                         constraint.domain.str() + ", limit " +
                         std::to_string(constraint.max_members));
        }
        break;
      }
      case FailureDomainConstraintKind::MAX_MEMBERS_FROM_CLASS: {
        std::size_t count = 0;
        bool incomplete = false;
        for (const auto& hop : path.hops) {
          const ElementRef ref = hop.ref();
          ensure_membership(ref);
          const std::string key = ref.render();
          if (!coverage[key]) {
            incomplete = true;
            continue;
          }
          const auto& classes = class_cache[key];
          if (std::find(classes.begin(), classes.end(), constraint.domain_class) != classes.end()) {
            ++count;
          }
        }
        if (incomplete) {
          stage.hard(EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN,
                     std::string(to_string(constraint.domain_class)),
                     "incomplete failure domain coverage prevents counting members of class " +
                         std::string(to_string(constraint.domain_class)));
        } else if (count > constraint.max_members) {
          stage.hard(EvaluationOutcome::FAILURE_DOMAIN_VIOLATION,
                     std::string(to_string(constraint.domain_class)),
                     "path uses " + std::to_string(count) + " members of class " +
                         std::string(to_string(constraint.domain_class)) + ", limit " +
                         std::to_string(constraint.max_members));
        }
        break;
      }
      case FailureDomainConstraintKind::EXCLUDE_DOMAIN_CLASS: {
        for (const auto& hop : path.hops) {
          const ElementRef ref = hop.ref();
          ensure_membership(ref);
          const std::string key = ref.render();
          if (!coverage[key]) {
            stage.hard(EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN, key,
                       "incomplete failure domain coverage prevents proving exclusion of class " +
                           std::string(to_string(constraint.domain_class)));
            continue;
          }
          const auto& list = memberships[key];
          const auto& classes = class_cache[key];
          for (std::size_t i = 0; i < list.size(); ++i) {
            if (classes[i] == constraint.domain_class) {
              stage.hard(EvaluationOutcome::FAILURE_DOMAIN_VIOLATION, key,
                         "member of " + list[i].str() + " in excluded class " +
                             std::string(to_string(constraint.domain_class)));
            }
          }
        }
        break;
      }
      case FailureDomainConstraintKind::REQUIRE_COVERAGE_COMPLETENESS: {
        for (const auto& hop : path.hops) {
          const ElementRef ref = hop.ref();
          ensure_membership(ref);
          const std::string key = ref.render();
          if (!coverage[key]) {
            stage.hard(EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN, key,
                       "Failure Domain Registry reports incomplete coverage for " + key);
          }
        }
        break;
      }
      case FailureDomainConstraintKind::DIVERSE_FROM_PEER_PATH: {
        const std::string peer_key = constraint.peer.path.str();
        const auto peer = peers.find(peer_key);
        if (peer == peers.end() || !peer->second.found ||
            !is_authorizing_outcome(peer->second.outcome)) {
          stage.hard(EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN, peer_key,
                     "peer path authority is not established, so diversity cannot be proven");
          break;
        }
        bool peer_incomplete = false;
        for (const auto& ref : peer->second.elements) {
          ensure_membership(ref);
          if (!coverage[ref.render()]) {
            peer_incomplete = true;
          }
        }
        bool self_incomplete = false;
        for (const auto& hop : path.hops) {
          const ElementRef ref = hop.ref();
          ensure_membership(ref);
          if (!coverage[ref.render()]) {
            self_incomplete = true;
          }
        }
        if (peer_incomplete || self_incomplete) {
          stage.hard(EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN, peer_key,
                     "incomplete failure domain coverage prevents proving diversity");
          break;
        }
        for (const auto& hop : path.hops) {
          const ElementRef ref = hop.ref();
          if (std::find(peer->second.elements.begin(), peer->second.elements.end(), ref) !=
              peer->second.elements.end()) {
            stage.hard(EvaluationOutcome::FAILURE_DOMAIN_VIOLATION, ref.render(),
                       "shares structural element with peer path " + peer_key);
          }
        }
        std::vector<DomainClassKind> classes = constraint.diversity_classes;
        if (classes.empty()) {
          classes = {DomainClassKind::POWER,      DomainClassKind::COOLING,
                     DomainClassKind::RACK,       DomainClassKind::LINE_CARD,
                     DomainClassKind::SHARED_RISK_LINK_GROUP, DomainClassKind::SITE,
                     DomainClassKind::REGION,     DomainClassKind::SHELF,
                     DomainClassKind::CHANNEL};
        }
        for (DomainClassKind klass : classes) {
          for (const auto& hop : path.hops) {
            const ElementRef ref = hop.ref();
            const std::string key = ref.render();
            const auto& list = memberships[key];
            const auto& own_classes = class_cache[key];
            for (std::size_t i = 0; i < list.size(); ++i) {
              if (own_classes[i] != klass) {
                continue;
              }
              for (const auto& peer_ref : peer->second.elements) {
                const std::string peer_element_key = peer_ref.render();
                const auto& peer_list = memberships[peer_element_key];
                const auto& peer_classes = class_cache[peer_element_key];
                for (std::size_t j = 0; j < peer_list.size(); ++j) {
                  if (peer_classes[j] == klass && peer_list[j] == list[i]) {
                    stage.hard(EvaluationOutcome::FAILURE_DOMAIN_VIOLATION, key,
                               "shares " + std::string(to_string(klass)) + " domain " +
                                   list[i].str() + " with peer path " + peer_key);
                  }
                }
              }
            }
          }
        }
        break;
      }
    }
  }

  // ---- stage: policy ------------------------------------------------------
  for (const auto& hop : path.hops) {
    if (!computation.rules.layers.allows(hop.layer)) {
      stage.hard(EvaluationOutcome::POLICY_REJECTED, hop.ref().render(),
                 "layer " + std::string(to_string(hop.layer)) + " is not permitted by policy");
    }
  }
  if (!computation.rules.layers.allow_loops) {
    std::set<std::string> seen;
    for (const auto& hop : path.hops) {
      const std::string key = hop.ref().render();
      if (!seen.insert(key).second) {
        stage.hard(EvaluationOutcome::POLICY_REJECTED, key,
                   "policy does not permit a path that repeats a structural element");
      }
    }
  }
  if (path.hops.size() > computation.rules.max_hops) {
    stage.hard(EvaluationOutcome::POLICY_REJECTED, path.id.str(),
               "hop count " + std::to_string(path.hops.size()) +
                   " exceeds the effective maximum " + std::to_string(computation.rules.max_hops));
  }
  for (DomainClassKind forbidden : computation.rules.forbidden_domain_classes) {
    for (const auto& hop : path.hops) {
      const ElementRef ref = hop.ref();
      ensure_membership(ref);
      const std::string key = ref.render();
      if (!coverage[key]) {
        stage.hard(EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN, key,
                   "incomplete failure domain coverage prevents proving exclusion of class " +
                       std::string(to_string(forbidden)));
        continue;
      }
      const auto& list = memberships[key];
      const auto& classes = class_cache[key];
      for (std::size_t i = 0; i < list.size(); ++i) {
        if (classes[i] == forbidden) {
          stage.hard(EvaluationOutcome::POLICY_REJECTED, key,
                     "member of " + list[i].str() + " in forbidden domain class " +
                         std::string(to_string(forbidden)));
        }
      }
    }
  }

  // ---- resolution of conditional authorization ----------------------------
  if (!computation.hard_failure) {
    bool conditional = false;
    for (auto& violation : computation.violations) {
      if (violation.severity != ViolationSeverity::CONDITION) {
        continue;
      }
      if (computation.rules.allow_conditional_authorization) {
        conditional = true;
        continue;
      }
      violation.severity = ViolationSeverity::HARD;
      computation.primary = violation.code;
      computation.hard_failure = true;
      break;
    }
    if (!computation.hard_failure) {
      computation.primary =
          conditional ? EvaluationOutcome::CONDITIONALLY_AUTHORIZED : EvaluationOutcome::AUTHORIZED;
    }
  }

  if (overflow) {
    stage.hard(EvaluationOutcome::RESOURCE_LIMIT, path.id.str(),
               "evidence vector exceeds limits.max_dependencies_per_path");
  }

  *evidence_overflow = overflow;
  return computation;
}

}  // namespace

namespace {

struct ExistingInfo {
  bool found = false;
  bool retired = false;
  bool revoked = false;
  bool authorizing = false;
  PathAuthorityGeneration generation;
  Digest authority_digest;
  std::optional<RevocationRecord> revocation;
};

struct CommitRequest {
  PathDefinition path;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome primary = EvaluationOutcome::MALFORMED_PATH;
  Violation primary_violation;
  EvidenceVector evidence;
  Digest path_digest;
  Digest constraint_digest;
  Digest authority_digest;
  std::vector<Violation> secondary;
  Digest input_digest;
  bool identity_bound = true;
  PublisherId publisher;
  WorkerBootId worker_boot;
  std::optional<PathAuthorityGeneration> expected_generation;
  MutationAttemptId attempt;
  PolicySet policy_for_dependencies;
};

struct CommitResult {
  bool committed = false;
  bool idempotent = false;
  bool rejected = false;
  EvaluationOutcome override_primary = EvaluationOutcome::AUTHORIZED;
  std::string detail;
  PathAuthorityGeneration generation;
};

bool index_insert(std::map<std::string, std::set<std::string>>& index, const std::string& key,
                  const std::string& path) {
  if (key.empty()) {
    return true;
  }
  return index[key].insert(path).second;
}

void index_erase(std::map<std::string, std::set<std::string>>& index, const std::string& key,
                 const std::string& path) {
  const auto it = index.find(key);
  if (it == index.end()) {
    return;
  }
  it->second.erase(path);
  if (it->second.empty()) {
    index.erase(it);
  }
}

}  // namespace

AuthoritySnapshot snapshot_from_record(const Record& record, EvidenceVector current_evidence,
                                       bool current_state) {
  AuthoritySnapshot snapshot;
  snapshot.path = record.definition.id;
  snapshot.path_generation = record.definition.generation;
  snapshot.authority_generation = record.generation;
  snapshot.state = record.state;
  snapshot.last_outcome = record.outcome;
  snapshot.evidence = record.evidence;
  snapshot.constraint_set = record.definition.constraint_set;
  snapshot.constraint_generation = record.definition.constraint_generation;
  snapshot.policy = record.evidence.policy();
  snapshot.epoch = record.evidence.epoch();
  snapshot.path_digest = record.path_digest;
  snapshot.authority_digest = record.authority_digest;
  snapshot.definition = record.definition;
  snapshot.primary_violation = record.primary_violation;
  snapshot.secondary = record.violations;
  snapshot.history.assign(record.history.begin(), record.history.end());
  snapshot.revocation = record.revocation;
  snapshot.publisher = record.publisher;
  snapshot.worker_boot = record.worker_boot;
  snapshot.evaluations = record.evaluations;
  snapshot.revalidations = record.revalidations;
  const std::vector<EvidenceDelta> deltas = diff_evidence(record.evidence, current_evidence);
  const bool authorizing_state = record.state == AuthorityState::AUTHORIZED ||
                                 record.state == AuthorityState::CONDITIONALLY_AUTHORIZED ||
                                 record.state == AuthorityState::REJECTED ||
                                 record.state == AuthorityState::REVOKED ||
                                 record.state == AuthorityState::RETIRED;
  snapshot.stale_dependencies = deltas;
  snapshot.current = current_state && deltas.empty() && authorizing_state;
  snapshot.id = PathSnapshotId::parse("snap-" + snapshot.snapshot_digest().short_hex(32));
  return snapshot;
}

struct PathAuthorityRuntime::Impl {
  Impl(EvidenceSources source_views, RuntimeConfig configuration)
      : sources(source_views), config(std::move(configuration)) {}

  EvidenceSources sources;
  RuntimeConfig config;
  mutable std::shared_mutex mutex;
  std::map<std::string, Record> records;
  std::map<std::string, std::set<std::string>> element_index;
  std::map<std::string, std::set<std::string>> capability_index;
  std::map<std::string, std::set<std::string>> domain_index;
  std::map<std::string, std::set<std::string>> underlying_index;
  std::map<std::string, ConstraintSet> constraint_sets;
  std::map<std::string, AttemptIndexEntry> attempts;
  std::deque<std::string> attempt_order;
  std::map<std::string, AuthoritySnapshot> snapshots;
  std::map<std::string, std::deque<std::string>> snapshots_by_path;
  // Highest invalidated generation per evidence subject. An evaluation that was
  // already in flight when its evidence was invalidated must not commit current
  // authority: the watermark turns that race into REVALIDATION_REQUIRED.
  std::map<std::string, std::uint64_t> watermarks;

  static std::string watermark_key(EvidenceKind kind, const std::string& subject) {
    return std::string(to_string(kind)) + "|" + subject;
  }

  void raise_watermark(EvidenceKind kind, const std::string& subject, std::uint64_t generation) {
    auto& slot = watermarks[watermark_key(kind, subject)];
    if (generation > slot) {
      slot = generation;
    }
  }

  std::optional<std::string> stale_evidence(const EvidenceVector& evidence) const {
    for (const auto& entry : evidence.entries) {
      const auto it = watermarks.find(watermark_key(entry.kind, entry.subject));
      if (it != watermarks.end() && entry.generation < it->second) {
        return it->first;
      }
    }
    return std::nullopt;
  }

  // ---- index maintenance (caller holds the exclusive lock) ---------------
  void index_record(const Record& record) {
    const std::string key = path_key(record.definition.id);
    for (const auto& element : record.elements) {
      index_insert(element_index, element_key(element), key);
    }
    for (const auto& membership : record.membership_dependencies) {
      index_insert(element_index, membership, key);
    }
    for (const auto& capability : record.capability_dependencies) {
      index_insert(capability_index, capability_key(capability.first, capability.second), key);
    }
    for (const auto& domain : record.domain_dependencies) {
      index_insert(domain_index, domain.str(), key);
    }
    for (const auto& underlying : record.underlying_dependencies) {
      index_insert(underlying_index, underlying, key);
    }
  }

  void unindex_record(const Record& record) {
    const std::string key = path_key(record.definition.id);
    for (const auto& element : record.elements) {
      index_erase(element_index, element_key(element), key);
    }
    for (const auto& membership : record.membership_dependencies) {
      index_erase(element_index, membership, key);
    }
    for (const auto& capability : record.capability_dependencies) {
      index_erase(capability_index, capability_key(capability.first, capability.second), key);
    }
    for (const auto& domain : record.domain_dependencies) {
      index_erase(domain_index, domain.str(), key);
    }
    for (const auto& underlying : record.underlying_dependencies) {
      index_erase(underlying_index, underlying, key);
    }
  }

  void rebuild_record_dependencies(Record& record, const PolicySet& policy) {
    record.elements.clear();
    record.capability_dependencies.clear();
    record.domain_dependencies.clear();
    record.membership_dependencies.clear();
    record.underlying_dependencies.clear();

    for (const auto& hop : record.definition.hops) {
      record.elements.push_back(hop.ref());
    }
    const auto constraint = constraint_sets.find(record.definition.constraint_set.str());
    if (constraint != constraint_sets.end()) {
      const EffectiveRules rules = combine_rules(constraint->second, policy, config.limits);
      for (const auto& requirement : rules.capabilities) {
        record.capability_dependencies.emplace_back(requirement.entity, requirement.key.str());
      }
      for (const auto& domain_constraint : rules.failure_domains) {
        if (domain_constraint.domain.valid()) {
          record.domain_dependencies.push_back(domain_constraint.domain);
        }
      }
      if (!rules.failure_domains.empty() || !rules.forbidden_domain_classes.empty()) {
        for (const auto& element : record.elements) {
          record.membership_dependencies.push_back(membership_subject(element));
        }
      }
    }
    if (record.definition.underlying.has_value()) {
      record.underlying_dependencies.push_back(record.definition.underlying->path.str());
    }
  }

  // ---- currentness -------------------------------------------------------
  EvidenceVector current_evidence(const Record& record) const {
    EvidenceVector evidence;
    const Limits& limits = config.limits;
    const CoordinatorEpoch epoch = sources.epoch->current();
    const PolicySet policy = sources.policy->current_policy();
    evidence.set(EvidenceKind::EPOCH, std::string(EvidenceVector::kScalarSubject), epoch.value(), limits);
    evidence.set(EvidenceKind::POLICY, std::string(EvidenceVector::kScalarSubject),
                 policy.generation.value(), limits);
    evidence.set(EvidenceKind::TOPOLOGY, std::string(EvidenceVector::kScalarSubject),
                 sources.topology->generation().value(), limits);
    const auto constraint = constraint_sets.find(record.definition.constraint_set.str());
    evidence.set(EvidenceKind::CONSTRAINTS, std::string(EvidenceVector::kScalarSubject),
                 constraint != constraint_sets.end() ? constraint->second.generation.value() : 0,
                 limits);
    for (const auto& element : record.elements) {
      const auto structural = sources.topology->element(element.kind, element.id);
      evidence.set(EvidenceKind::STRUCTURAL_ELEMENT, element_key(element),
                   structural.has_value() ? structural->generation.value() : 0, limits);
      if (element.kind == ElementKind::LINK) {
        const auto link = sources.link_state->link(element.id);
        evidence.set(EvidenceKind::LINK_STATE, element_key(element),
                     link.has_value() ? link->generation.value() : 0, limits);
      }
      if (element.kind == ElementKind::PORT) {
        const auto port = sources.port_state->port(element.id);
        evidence.set(EvidenceKind::PORT_CONFIG, element_key(element),
                     port.has_value() ? port->generation.value() : 0, limits);
      }
    }
    for (const auto& dependency : record.capability_dependencies) {
      const CapabilityRecord record_value =
          sources.capability->lookup(dependency.first, dependency.second);
      evidence.set(EvidenceKind::CAPABILITY, capability_key(dependency.first, dependency.second),
                   record_value.known ? record_value.generation.value() : 0, limits);
    }
    for (const auto& domain : record.domain_dependencies) {
      const auto domain_record = sources.failure_domain->domain(domain);
      evidence.set(EvidenceKind::FAILURE_DOMAIN, domain_subject(domain),
                   domain_record.has_value() ? domain_record->generation.value() : 0, limits);
    }
    for (const auto& membership : record.membership_dependencies) {
      ElementRef ref;
      const std::size_t split = membership.find(':');
      if (split == std::string::npos) {
        continue;
      }
      const auto kind = element_kind_from_string(membership.substr(0, split));
      if (!kind.has_value()) {
        continue;
      }
      ref.kind = *kind;
      ref.id = membership.substr(split + 1);
      evidence.set(EvidenceKind::FAILURE_DOMAIN, membership_subject(ref),
                   sources.failure_domain->membership_generation(ref).value(), limits);
    }
    return evidence;
  }

  UnderlyingChain resolve_underlying(const PathDefinition& definition) const {
    UnderlyingChain chain;
    if (!definition.underlying.has_value()) {
      return chain;
    }
    std::set<std::string> visited;
    visited.insert(path_key(definition.id));
    PathId cursor = definition.underlying->path;
    for (std::uint32_t depth = 1; depth <= config.limits.max_nesting_depth; ++depth) {
      if (!visited.insert(path_key(cursor)).second) {
        chain.cycle = true;
        return chain;
      }
      const auto it = records.find(path_key(cursor));
      if (it == records.end()) {
        return chain;
      }
      chain.found = true;
      chain.depth = depth;
      chain.generation = it->second.generation;
      chain.state = it->second.state;
      chain.outcome = it->second.outcome;
      if (!it->second.definition.underlying.has_value()) {
        return chain;
      }
      cursor = it->second.definition.underlying->path;
    }
    chain.cycle = true;
    return chain;
  }

  std::map<std::string, PeerPathInfo> resolve_peers(const ConstraintSet& constraints) const {
    std::map<std::string, PeerPathInfo> peers;
    for (const auto& constraint : constraints.failure_domains) {
      if (constraint.kind != FailureDomainConstraintKind::DIVERSE_FROM_PEER_PATH ||
          !constraint.peer.path.valid()) {
        continue;
      }
      const std::string key = path_key(constraint.peer.path);
      if (peers.find(key) != peers.end()) {
        continue;
      }
      PeerPathInfo info;
      const auto it = records.find(key);
      if (it != records.end()) {
        info.found = true;
        info.state = it->second.state;
        info.outcome = it->second.outcome;
        for (const auto& hop : it->second.definition.hops) {
          info.elements.push_back(hop.ref());
        }
        for (const auto& domain : it->second.domain_dependencies) {
          info.domains.push_back(domain);
        }
      }
      peers.emplace(key, std::move(info));
    }
    return peers;
  }

  ExistingInfo existing_info(const PathId& id) const {
    ExistingInfo info;
    const auto it = records.find(path_key(id));
    if (it == records.end()) {
      return info;
    }
    info.found = true;
    info.retired = it->second.retired;
    info.revoked = it->second.revocation.has_value();
    info.revocation = it->second.revocation;
    info.authorizing = is_authorizing_outcome(it->second.outcome);
    info.generation = it->second.generation;
    info.authority_digest = it->second.authority_digest;
    return info;
  }

  void mark_revalidation_required(Record& record, const std::string& cause, const Limits& limits) {
    if (record.state == AuthorityState::REVALIDATION_REQUIRED) {
      return;
    }
    if (!PathAuthorityGeneration::can_advance(record.generation.value())) {
      return;
    }
    record.generation = record.generation.next();
    record.state = AuthorityState::REVALIDATION_REQUIRED;
    record.outcome = EvaluationOutcome::REVALIDATION_REQUIRED;
    AuthorityDigestInput input = digest_input_for(record.definition, record.path_digest,
                                                  record.constraint_digest, record.evidence,
                                                  record.state, record.outcome, record.violations);
    record.authority_digest = input.compute();
    push_history(record, cause, limits);
  }

  void remember_attempt(const std::string& attempt, const PathId& path, const Digest& input_digest,
                        const Limits& limits) {
    const auto existing = attempts.find(attempt);
    if (existing != attempts.end()) {
      existing->second.input_digest = input_digest;
      existing->second.path = path;
      return;
    }
    attempts.emplace(attempt, AttemptIndexEntry{path, input_digest});
    attempt_order.push_back(attempt);
    while (attempt_order.size() > limits.max_outstanding_attempts) {
      attempts.erase(attempt_order.front());
      attempt_order.pop_front();
    }
  }

  // Invalidation by evidence subject. When index_key is empty every record is
  // a candidate (scalar evidence); otherwise only indexed dependents are.
  InvalidationReport invalidate(InvalidationCause cause, std::string subject,
                                EvidenceKind kind, std::string evidence_subject,
                                std::uint64_t generation, bool scalar) {
    InvalidationReport report;
    report.cause = cause;
    report.subject = subject;
    report.generation = generation;
    const std::unique_lock lock(mutex);
    raise_watermark(kind, evidence_subject, generation);
    for (auto& [key, record] : records) {
      (void)key;
      const auto stored = record.evidence.find(kind, evidence_subject);
      const bool bound_to_new_generation = stored.has_value() && *stored == generation;
      if (bound_to_new_generation || record.state == AuthorityState::REVALIDATION_REQUIRED) {
        report.already_current.push_back(record.definition.id);
        continue;
      }
      mark_revalidation_required(record,
                                 std::string(to_string(cause)) + " " + subject, config.limits);
      report.revalidation_required.push_back(record.definition.id);
    }
    (void)scalar;
    return report;
  }

  InvalidationReport invalidate_indexed(InvalidationCause cause, std::string subject,
                                        EvidenceKind kind, std::string evidence_subject,
                                        std::uint64_t generation,
                                        const std::map<std::string, std::set<std::string>>& index,
                                        const std::string& index_key) {
    InvalidationReport report;
    report.cause = cause;
    report.subject = subject;
    report.generation = generation;
    const std::unique_lock lock(mutex);
    raise_watermark(kind, evidence_subject, generation);
    const auto candidates = index.find(index_key);
    if (candidates == index.end()) {
      return report;
    }
    std::vector<std::string> keys(candidates->second.begin(), candidates->second.end());
    for (const auto& key : keys) {
      const auto it = records.find(key);
      if (it == records.end()) {
        continue;
      }
      Record& record = it->second;
      const auto stored = record.evidence.find(kind, evidence_subject);
      const bool bound_to_new_generation = stored.has_value() && *stored == generation;
      if (bound_to_new_generation || record.state == AuthorityState::REVALIDATION_REQUIRED) {
        report.already_current.push_back(record.definition.id);
        continue;
      }
      mark_revalidation_required(record,
                                 std::string(to_string(cause)) + " " + subject, config.limits);
      report.revalidation_required.push_back(record.definition.id);
    }
    return report;
  }

  std::vector<PathId> dependents(const std::map<std::string, std::set<std::string>>& index,
                                 const std::string& key) const {
    std::vector<PathId> paths;
    const std::shared_lock lock(mutex);
    const auto it = index.find(key);
    if (it == index.end()) {
      return paths;
    }
    for (const auto& path : it->second) {
      const auto parsed = PathId::from_wire(path);
      if (parsed.has_value()) {
        paths.push_back(*parsed);
      }
    }
    return paths;
  }

  // Commits one evaluated or published decision. This is the single mutation
  // point for authority state: it validates the compare-and-set expectation,
  // rejects a conflicting attempt id, applies exact-replay idempotency and only
  // then advances the authority generation and the dependency indexes.
  CommitResult commit(const CommitRequest& request) {
    CommitResult result;
    const Limits& limits = config.limits;
    const std::string key = path_key(request.path.id);
    const auto it = records.find(key);
    const bool is_new = it == records.end();
    const ExistingInfo existing = existing_info(request.path.id);

    if (is_new && records.size() >= limits.max_paths) {
      result.rejected = true;
      result.override_primary = EvaluationOutcome::RESOURCE_LIMIT;
      result.detail = "path record count reached Limits::max_paths";
      return result;
    }

    if (const auto stale = stale_evidence(request.evidence); stale.has_value()) {
      result.rejected = true;
      result.override_primary = EvaluationOutcome::REVALIDATION_REQUIRED;
      result.detail = "evidence " + *stale +
                      " was invalidated while this evaluation was in flight; re-evaluate " +
                      "against current evidence";
      return result;
    }

    if (request.expected_generation.has_value()) {
      const PathAuthorityGeneration current =
          existing.found ? existing.generation : PathAuthorityGeneration{};
      if (*request.expected_generation != current) {
        result.rejected = true;
        result.override_primary = EvaluationOutcome::STALE_AUTHORITY;
        result.detail = "expected authority generation " +
                        std::to_string(request.expected_generation->value()) +
                        " does not match the committed generation " +
                        std::to_string(current.value());
        return result;
      }
    }

    if (existing.found && config.idempotent_replay &&
        existing.authority_digest == request.authority_digest) {
      result.idempotent = true;
      result.generation = existing.generation;
      Record& already = records.find(key)->second;
      already.evaluations += 1;
      if (request.attempt.valid()) {
        remember_attempt(request.attempt.str(), request.path.id, request.input_digest, limits);
      }
      return result;
    }

    Record& record = is_new ? records[key] : it->second;
    if (!is_new) {
      unindex_record(record);
    }
    PathAuthorityGeneration next_generation;
    if (is_new) {
      next_generation = PathAuthorityGeneration::from_value(1);
    } else if (PathAuthorityGeneration::can_advance(record.generation.value())) {
      next_generation = record.generation.next();
    }
    if (!next_generation.is_set()) {
      result.rejected = true;
      result.override_primary = EvaluationOutcome::RESOURCE_LIMIT;
      result.detail = "path authority generation space is exhausted";
      return result;
    }

    record.definition = request.path;
    record.generation = next_generation;
    record.state = request.state;
    record.outcome = request.primary;
    record.primary_violation = request.primary_violation;
    record.evidence = request.evidence;
    record.path_digest = request.path_digest;
    record.constraint_digest = request.constraint_digest;
    record.authority_digest = request.authority_digest;
    record.input_digest = request.input_digest;
    record.violations = request.secondary;
    record.publisher = request.publisher;
    record.worker_boot = request.worker_boot;
    record.identity_bound = request.identity_bound;
    record.evaluations += 1;
    rebuild_record_dependencies(record, request.policy_for_dependencies);
    index_record(record);
    push_history(record, "commit " + std::string(to_string(request.primary)), limits);

    result.committed = true;
    result.generation = next_generation;
    if (request.attempt.valid()) {
      remember_attempt(request.attempt.str(), request.path.id, request.input_digest, limits);
    }
    if (config.retain_snapshots) {
      retain_snapshot(snapshot_from_record(record, record.evidence, false), limits);
    }
    return result;
  }

  void retain_snapshot(const AuthoritySnapshot& snapshot, const Limits& limits) {
    if (!config.retain_snapshots) {
      return;
    }
    const std::string id = snapshot.id.str();
    snapshots[id] = snapshot;
    auto& owned = snapshots_by_path[path_key(snapshot.path)];
    owned.push_back(id);
    while (owned.size() > limits.max_history) {
      const std::string oldest = owned.front();
      owned.pop_front();
      snapshots.erase(oldest);
    }
  }
};
namespace {

EvaluationResult early_result(const PathDefinition& path, EvaluationOutcome outcome,
                              std::string subject, std::string detail, const PolicySet& policy,
                              CoordinatorEpoch epoch) {
  EvaluationResult result;
  result.path = path.id;
  result.path_generation = path.generation;
  result.constraint_set = path.constraint_set;
  result.constraint_generation = path.constraint_generation;
  result.policy = policy.generation;
  result.epoch = epoch;
  result.primary = outcome;
  result.state = state_for_outcome(outcome);
  result.primary_violation =
      Violation{outcome, ViolationSeverity::PRIMARY, subject, detail};
  result.secondary.push_back(
      Violation{outcome, ViolationSeverity::HARD, std::move(subject), std::move(detail)});
  result.committed = false;
  return result;
}

void sort_violations(std::vector<Violation>& violations) {
  std::stable_sort(violations.begin(), violations.end());
}

}  // namespace

PathAuthorityRuntime::PathAuthorityRuntime(EvidenceSources sources, RuntimeConfig config)
    : impl_(std::make_unique<Impl>(sources, std::move(config))) {
  if (!sources.complete()) {
    throw std::invalid_argument(
        "PathAuthorityRuntime requires every evidence view to be non-null: topology, link state, "
        "port state, capability, failure domain, epoch and policy");
  }
  if (!impl_->config.limits.valid()) {
    throw std::invalid_argument("PathAuthorityRuntime received invalid limits");
  }
}

PathAuthorityRuntime::PathAuthorityRuntime(EvidenceSources sources, Limits limits)
    : PathAuthorityRuntime(sources, RuntimeConfig{limits, false, true}) {}

PathAuthorityRuntime::~PathAuthorityRuntime() = default;

const Limits& PathAuthorityRuntime::limits() const noexcept { return impl_->config.limits; }

CoordinatorEpoch PathAuthorityRuntime::current_epoch() const { return impl_->sources.epoch->current(); }

PolicySet PathAuthorityRuntime::policy() const { return impl_->sources.policy->current_policy(); }

PathAuthorityRuntime::ConstraintRegistration PathAuthorityRuntime::register_constraint_set(
    ConstraintSet set) {
  const Limits& limits = impl_->config.limits;
  if (!set.id.valid() || !set.scope.valid()) {
    throw std::invalid_argument("constraint set requires a valid id and scope");
  }
  if (set.capabilities.size() > limits.max_constraints) {
    throw std::invalid_argument("constraint set exceeds Limits::max_constraints");
  }
  if (set.failure_domains.size() > limits.max_failure_domain_refs) {
    throw std::invalid_argument("constraint set exceeds Limits::max_failure_domain_refs");
  }
  for (const auto& requirement : set.capabilities) {
    std::string error;
    if (!validate_requirement(requirement.expression, limits, error)) {
      throw std::invalid_argument("malformed capability requirement: " + error);
    }
    if (!CapabilityKey::from_wire(requirement.key.view()).has_value()) {
      throw std::invalid_argument("malformed capability key in constraint set");
    }
  }

  const Digest content = set.digest();
  ConstraintRegistration registration;
  registration.id = set.id;

  std::vector<std::string> affected;
  {
    const std::unique_lock lock(impl_->mutex);
    const auto existing = impl_->constraint_sets.find(set.id.str());
    if (existing != impl_->constraint_sets.end() && existing->second.digest() == content) {
      registration.generation = existing->second.generation;
      registration.created = false;
      return registration;
    }
    const std::uint64_t previous =
        existing != impl_->constraint_sets.end() ? existing->second.generation.value() : 0;
    if (!ConstraintGeneration::can_advance(previous) || previous == UINT64_MAX) {
      throw std::logic_error("constraint generation space is exhausted");
    }
    set.generation = ConstraintGeneration::from_value(previous + 1);
    impl_->constraint_sets[set.id.str()] = set;
    registration.generation = set.generation;
    registration.created = true;
    for (const auto& [key, record] : impl_->records) {
      if (record.definition.constraint_set == set.id) {
        affected.push_back(key);
      }
    }
  }

  // Invalidation happens outside the first lock so that a view call (policy) is
  // never made while the state lock is held.
  for (const auto& key : affected) {
    const std::unique_lock lock(impl_->mutex);
    const auto it = impl_->records.find(key);
    if (it == impl_->records.end()) {
      continue;
    }
    if (it->second.definition.constraint_generation == set.generation) {
      continue;
    }
    const bool was_required = it->second.state == AuthorityState::REVALIDATION_REQUIRED;
    impl_->mark_revalidation_required(it->second, "CONSTRAINT_CHANGE " + set.id.str(), limits);
    if (!was_required) {
      ++registration.invalidated;
    }
  }
  return registration;
}

std::optional<ConstraintSet> PathAuthorityRuntime::constraint_set(const ConstraintSetId& id) const {
  const std::shared_lock lock(impl_->mutex);
  const auto it = impl_->constraint_sets.find(id.str());
  if (it == impl_->constraint_sets.end()) {
    return std::nullopt;
  }
  return it->second;
}

RuntimeStats PathAuthorityRuntime::stats() const {
  RuntimeStats stats;
  const std::shared_lock lock(impl_->mutex);
  stats.paths = impl_->records.size();
  for (const auto& [key, record] : impl_->records) {
    (void)key;
    switch (record.state) {
      case AuthorityState::AUTHORIZED:
      case AuthorityState::CONDITIONALLY_AUTHORIZED:
        ++stats.authorizing;
        break;
      case AuthorityState::REVALIDATION_REQUIRED:
        ++stats.revalidation_required;
        break;
      case AuthorityState::REVOKED:
        ++stats.revoked;
        break;
      case AuthorityState::REJECTED:
        ++stats.rejected;
        break;
      case AuthorityState::UNKNOWN:
      case AuthorityState::STALE:
      case AuthorityState::RETIRED:
        break;
    }
  }
  stats.elements_indexed = impl_->element_index.size();
  stats.capabilities_indexed = impl_->capability_index.size();
  stats.domains_indexed = impl_->domain_index.size();
  stats.attempts_tracked = impl_->attempts.size();
  stats.policy = impl_->sources.policy->current_policy().generation;
  stats.epoch = impl_->sources.epoch->current();
  return stats;
}

namespace {

bool is_attempt_usable(const MutationAttemptId& attempt) noexcept { return attempt.valid(); }

}  // namespace

EvaluationResult PathAuthorityRuntime::evaluate(const PathDefinition& path,
                                               const EvaluationRequest& request) {
  Impl& impl = *impl_;
  const Limits& limits = impl.config.limits;
  const PolicySet policy = impl.sources.policy->current_policy();
  const CoordinatorEpoch epoch = impl.sources.epoch->current();

  const PathShapeResult shape = validate_path_shape(path, limits, request.require_identity_binding);
  if (!shape.ok()) {
    const bool resource = shape.status == PathShapeStatus::TOO_MANY_HOPS ||
                          shape.status == PathShapeStatus::METADATA_TOO_LARGE;
    return early_result(path, resource ? EvaluationOutcome::RESOURCE_LIMIT
                                       : EvaluationOutcome::MALFORMED_PATH,
                        path.id.valid() ? path.id.str() : std::string("<unset path id>"),
                        std::string(to_string(shape.status)) + ": " + shape.detail, policy, epoch);
  }

  // Input preconditions: the bound constraint set must resolve to the exact
  // bound generation before any evidence stage runs, otherwise the applicable
  // rules are unknown and no evidence may be consulted.
  std::optional<ConstraintSet> constraints;
  {
    const std::shared_lock lock(impl.mutex);
    const auto it = impl.constraint_sets.find(path.constraint_set.str());
    if (it != impl.constraint_sets.end()) {
      constraints = it->second;
    }
  }
  if (!constraints.has_value()) {
    return early_result(path, EvaluationOutcome::CONSTRAINT_SET_UNKNOWN, path.constraint_set.str(),
                        "the constraint set bound by this path is not registered", policy, epoch);
  }
  if (constraints->generation != path.constraint_generation) {
    return early_result(path, EvaluationOutcome::REVALIDATION_REQUIRED, path.constraint_set.str(),
                        "path binds constraint generation " +
                            std::to_string(path.constraint_generation.value()) +
                            " but the registered generation is " +
                            std::to_string(constraints->generation.value()), policy, epoch);
  }

  const Digest path_digest = path.semantic_digest();
  const Digest constraint_digest = constraints->digest();
  const Digest input_digest =
      compute_input_digest(path_digest, path, constraint_digest, policy, epoch);

  if (is_attempt_usable(request.attempt)) {
    const std::shared_lock lock(impl.mutex);
    const auto attempt = impl.attempts.find(request.attempt.str());
    if (attempt != impl.attempts.end() && attempt->second.input_digest != input_digest) {
      EvaluationResult conflict =
          early_result(path, EvaluationOutcome::EVALUATION_ATTEMPT_CONFLICT, request.attempt.str(),
                       "this mutation attempt id was already committed with different semantic "
                       "input", policy, epoch);
      conflict.path_digest = path_digest;
      return conflict;
    }
  }

  const ExistingInfo existing = impl.existing_info(path.id);
  if (existing.retired) {
    return early_result(path, EvaluationOutcome::PATH_RETIRED, path.id.str(),
                        "this path has been retired", policy, epoch);
  }
  if (request.binding_epoch.has_value() && *request.binding_epoch != epoch) {
    return early_result(path, EvaluationOutcome::STALE_EPOCH, path.id.str(),
                        "publisher asserted epoch " + std::to_string(request.binding_epoch->value()) +
                            " but current Fabric Epoch is " + std::to_string(epoch.value()),
                        policy, epoch);
  }
  if (existing.revocation.has_value()) {
    EvaluationResult revoked =
        early_result(path, EvaluationOutcome::REVOKED, path.id.str(),
                     "this path was revoked: " + existing.revocation->render(), policy, epoch);
    return revoked;
  }

  UnderlyingChain chain;
  std::map<std::string, PeerPathInfo> peers;
  {
    const std::shared_lock lock(impl.mutex);
    chain = impl.resolve_underlying(path);
    if (chain.cycle) {
      return early_result(path, EvaluationOutcome::MALFORMED_PATH, path.id.str(),
                          "underlying path dependencies form a cycle", policy, epoch);
    }
    peers = impl.resolve_peers(*constraints);
  }

  bool overflow = false;
  Computation computation =
      compute_evaluation(path, impl.sources, limits, *constraints, policy, epoch, chain, peers,
                         existing.authorizing, &overflow);

  std::vector<Violation> secondary;
  bool primary_taken = false;
  for (const auto& violation : computation.violations) {
    if (!primary_taken && computation.hard_failure && violation.severity == ViolationSeverity::HARD &&
        violation.code == computation.primary) {
      primary_taken = true;
      continue;
    }
    secondary.push_back(violation);
  }
  sort_violations(secondary);

  const AuthorityState state = state_for_outcome(computation.primary);
  const AuthorityDigestInput digest_input =
      digest_input_for(path, computation.path_digest, computation.constraint_digest,
                       computation.evidence, state, computation.primary, secondary);
  const Digest authority_digest = digest_input.compute();

  EvaluationResult result;
  result.path = path.id;
  result.path_generation = path.generation;
  result.state = state;
  result.primary = computation.primary;
  result.primary_violation = computation.primary_violation;
  result.secondary = secondary;
  result.evidence = computation.evidence;
  result.constraint_set = path.constraint_set;
  result.constraint_generation = path.constraint_generation;
  result.policy = policy.generation;
  result.epoch = epoch;
  result.path_digest = computation.path_digest;
  result.authority_digest = authority_digest;

  CommitRequest commit_request;
  commit_request.path = path;
  commit_request.state = state;
  commit_request.primary = computation.primary;
  commit_request.primary_violation = computation.primary_violation;
  commit_request.evidence = computation.evidence;
  commit_request.path_digest = computation.path_digest;
  commit_request.constraint_digest = computation.constraint_digest;
  commit_request.authority_digest = authority_digest;
  commit_request.secondary = secondary;
  commit_request.input_digest = input_digest;
  commit_request.identity_bound = request.require_identity_binding;
  commit_request.publisher = request.publisher;
  commit_request.worker_boot = request.worker_boot;
  commit_request.expected_generation = request.expected_authority_generation;
  commit_request.attempt = request.attempt;
  commit_request.policy_for_dependencies = policy;

  CommitResult committed;
  {
    const std::unique_lock lock(impl.mutex);
    committed = impl.commit(commit_request);
  }

  if (committed.rejected) {
    result.primary = committed.override_primary;
    result.state = state_for_outcome(result.primary);
    result.secondary.insert(result.secondary.begin(),
                            Violation{result.primary, ViolationSeverity::HARD, path.id.str(),
                                      committed.detail});
    sort_violations(result.secondary);
    return result;
  }
  if (committed.idempotent) {
    result.primary = EvaluationOutcome::IDEMPOTENT;
    result.idempotent = true;
    result.committed = false;
    result.authority_generation = committed.generation;
    const std::shared_lock lock(impl.mutex);
    const auto record = impl.records.find(path_key(path.id));
    if (record != impl.records.end()) {
      result.state = record->second.state;
      result.authority_digest = record->second.authority_digest;
      result.evidence = record->second.evidence;
    }
    return result;
  }

  result.authority_generation = committed.generation;
  result.committed = true;
  return result;
}

std::vector<EvaluationResult> PathAuthorityRuntime::evaluate_batch(
    const std::vector<BatchEntry>& batch, const EvaluationRequest& request) {
  std::vector<EvaluationResult> results;
  if (batch.size() > impl_->config.limits.max_batch) {
    EvaluationResult result;
    result.primary = EvaluationOutcome::RESOURCE_LIMIT;
    result.state = state_for_outcome(result.primary);
    result.secondary.push_back(Violation{result.primary, ViolationSeverity::HARD, "batch",
                                          "batch size exceeds Limits::max_batch"});
    results.push_back(std::move(result));
    return results;
  }
  results.reserve(batch.size());
  for (const auto& entry : batch) {
    EvaluationRequest per_entry = request;
    per_entry.attempt = entry.attempt;
    results.push_back(evaluate(entry.path, per_entry));
  }
  return results;
}

std::optional<AuthoritySnapshot> PathAuthorityRuntime::query(const PathId& path) const {
  Record copy;
  {
    const std::shared_lock lock(impl_->mutex);
    const auto it = impl_->records.find(path_key(path));
    if (it == impl_->records.end()) {
      return std::nullopt;
    }
    copy = it->second;
  }
  const EvidenceVector current = impl_->current_evidence(copy);
  return snapshot_from_record(copy, current, true);
}

std::optional<AuthoritySnapshot> PathAuthorityRuntime::snapshot(const PathId& path) const {
  return query(path);
}

std::vector<AuthoritySnapshot> PathAuthorityRuntime::snapshots_all() const {
  std::vector<Record> copies;
  {
    const std::shared_lock lock(impl_->mutex);
    copies.reserve(impl_->records.size());
    for (const auto& [key, record] : impl_->records) {
      (void)key;
      copies.push_back(record);
    }
  }
  std::vector<AuthoritySnapshot> snapshots;
  snapshots.reserve(copies.size());
  for (const auto& record : copies) {
    const EvidenceVector current = impl_->current_evidence(record);
    snapshots.push_back(snapshot_from_record(record, current, true));
  }
  return snapshots;
}

std::vector<EvidenceDelta> PathAuthorityRuntime::stale_dependencies(const PathId& path) const {
  const auto snapshot_value = query(path);
  if (!snapshot_value.has_value()) {
    return {};
  }
  return snapshot_value->stale_dependencies;
}

std::string PathAuthorityRuntime::explain(const PathId& path) const {
  const auto snapshot_value = query(path);
  if (!snapshot_value.has_value()) {
    return "path=" + path.str() + "\nstate=UNKNOWN\nreason=PATH_UNKNOWN\n";
  }
  const AuthoritySnapshot& snapshot = *snapshot_value;
  std::string text;
  text += "path=" + snapshot.path.str() + "\n";
  text += "state=" + std::string(to_string(snapshot.state)) + "\n";
  text += "why=" + std::string(to_string(snapshot.last_outcome)) + " at stage " +
          std::string(to_string(stage_for_outcome(snapshot.last_outcome))) + "\n";
  if (!snapshot.primary_violation.subject.empty() || !snapshot.primary_violation.detail.empty()) {
    text += "reason=" + snapshot.primary_violation.render() + "\n";
  }
  text += "authority_generation=" + std::to_string(snapshot.authority_generation.value()) + "\n";
  text += "epoch=" + std::to_string(snapshot.epoch.value()) + "\n";
  text += "policy_generation=" + std::to_string(snapshot.policy.value()) + "\n";
  text += "current=" + std::string(snapshot.current ? "true" : "false") + "\n";
  for (const auto& violation : snapshot.secondary) {
    text += "reason=" + violation.render() + "\n";
  }
  for (const auto& delta : snapshot.stale_dependencies) {
    text += "stale=" + delta.render() + "\n";
  }
  if (snapshot.revocation.has_value()) {
    text += "revocation=" + snapshot.revocation->render() + "\n";
  }
  return text;
}

EvaluationResult PathAuthorityRuntime::revalidate(const PathId& path,
                                                 const RevalidationRequest& request) {
  const PolicySet policy = impl_->sources.policy->current_policy();
  const CoordinatorEpoch epoch = impl_->sources.epoch->current();

  PathDefinition definition;
  {
    const std::shared_lock lock(impl_->mutex);
    const auto it = impl_->records.find(path_key(path));
    if (it == impl_->records.end()) {
      PathDefinition placeholder;
      placeholder.id = path;
      return early_result(placeholder, EvaluationOutcome::PATH_UNKNOWN, path.str(),
                          "no authority record exists for this path", policy, epoch);
    }
    definition = it->second.definition;
  }

  EvaluationRequest evaluation;
  evaluation.attempt = request.attempt;
  evaluation.expected_authority_generation = request.expected_authority_generation;
  evaluation.publisher = request.publisher;
  evaluation.worker_boot = request.worker_boot;
  {
    const std::shared_lock lock(impl_->mutex);
    const auto it = impl_->records.find(path_key(path));
    evaluation.require_identity_binding = it != impl_->records.end() && it->second.identity_bound;
  }

  EvaluationResult result = evaluate(definition, evaluation);
  if (result.committed) {
    const std::unique_lock lock(impl_->mutex);
    const auto it = impl_->records.find(path_key(path));
    if (it != impl_->records.end()) {
      it->second.revalidations += 1;
    }
  }
  return result;
}

EvaluationResult PathAuthorityRuntime::revoke(const PathId& path,
                                             const RevocationRequest& request) {
  Impl& impl = *impl_;
  const Limits& limits = impl.config.limits;
  const PolicySet policy = impl.sources.policy->current_policy();
  const CoordinatorEpoch epoch = impl.sources.epoch->current();
  if (request.reason == RevocationReason::ADMINISTRATIVE && request.authority.empty()) {
    throw std::invalid_argument("an administrative revocation requires the revoking authority");
  }
  if (request.explanation.size() > limits.max_metadata_bytes) {
    throw std::invalid_argument("revocation explanation exceeds Limits::max_metadata_bytes");
  }

  const std::unique_lock lock(impl.mutex);
  const auto it = impl.records.find(path_key(path));
  if (it == impl.records.end()) {
    PathDefinition placeholder;
    placeholder.id = path;
    return early_result(placeholder, EvaluationOutcome::PATH_UNKNOWN, path.str(),
                        "no authority record exists for this path", policy, epoch);
  }
  Record& record = it->second;

  if (request.expected_authority_generation.has_value() &&
      *request.expected_authority_generation != record.generation) {
    PathDefinition placeholder;
    placeholder.id = path;
    return early_result(placeholder, EvaluationOutcome::STALE_AUTHORITY, path.str(),
                        "expected authority generation " +
                            std::to_string(request.expected_authority_generation->value()) +
                            " does not match the committed generation " +
                            std::to_string(record.generation.value()),
                        policy, epoch);
  }

  if (record.revocation.has_value() && record.revocation->reason == request.reason &&
      record.revocation->explanation == request.explanation &&
      record.revocation->authority == request.authority) {
    EvaluationResult idempotent;
    idempotent.path = path;
    idempotent.path_generation = record.definition.generation;
    idempotent.authority_generation = record.generation;
    idempotent.state = record.state;
    idempotent.primary = EvaluationOutcome::IDEMPOTENT;
    idempotent.idempotent = true;
    idempotent.evidence = record.evidence;
    idempotent.constraint_set = record.definition.constraint_set;
    idempotent.constraint_generation = record.definition.constraint_generation;
    idempotent.policy = record.evidence.policy();
    idempotent.epoch = record.evidence.epoch();
    idempotent.path_digest = record.path_digest;
    idempotent.authority_digest = record.authority_digest;
    return idempotent;
  }

  if (!PathAuthorityGeneration::can_advance(record.generation.value())) {
    PathDefinition placeholder;
    placeholder.id = path;
    return early_result(placeholder, EvaluationOutcome::RESOURCE_LIMIT, path.str(),
                        "path authority generation space is exhausted", policy, epoch);
  }

  record.generation = record.generation.next();
  RevocationRecord revocation;
  revocation.reason = request.reason;
  revocation.explanation = request.explanation;
  revocation.generation = record.generation;
  revocation.epoch = impl.sources.epoch->current();
  revocation.authority = request.authority;
  revocation.attempt = request.attempt;
  revocation.durable = request.durable;
  record.revocation = revocation;
  record.state = AuthorityState::REVOKED;
  record.outcome = EvaluationOutcome::REVOKED;
  const AuthorityDigestInput input =
      digest_input_for(record.definition, record.path_digest, record.constraint_digest,
                       record.evidence, record.state, record.outcome, record.violations);
  record.authority_digest = input.compute();
  push_history(record, "revoke " + std::string(to_string(request.reason)), limits);

  EvaluationResult result;
  result.path = path;
  result.path_generation = record.definition.generation;
  result.authority_generation = record.generation;
  result.state = AuthorityState::REVOKED;
  result.primary = EvaluationOutcome::REVOKED;
  result.evidence = record.evidence;
  result.constraint_set = record.definition.constraint_set;
  result.constraint_generation = record.definition.constraint_generation;
  result.policy = record.evidence.policy();
  result.epoch = record.evidence.epoch();
  result.path_digest = record.path_digest;
  result.authority_digest = record.authority_digest;
  result.secondary.push_back(Violation{EvaluationOutcome::REVOKED, ViolationSeverity::HARD,
                                       path.str(), revocation.render()});
  result.committed = true;
  if (impl.config.retain_snapshots) {
    impl.retain_snapshot(snapshot_from_record(record, record.evidence, false), limits);
  }
  return result;
}

EvaluationResult PathAuthorityRuntime::retire(const PathId& path, const MutationAttemptId& attempt,
                                             std::string_view explanation) {
  Impl& impl = *impl_;
  const Limits& limits = impl.config.limits;
  const PolicySet policy = impl.sources.policy->current_policy();
  const CoordinatorEpoch epoch = impl.sources.epoch->current();
  const std::unique_lock lock(impl.mutex);
  const auto it = impl.records.find(path_key(path));
  if (it == impl.records.end()) {
    PathDefinition placeholder;
    placeholder.id = path;
    return early_result(placeholder, EvaluationOutcome::PATH_UNKNOWN, path.str(),
                        "no authority record exists for this path", policy, epoch);
  }
  Record& record = it->second;
  if (record.retired) {
    EvaluationResult idempotent;
    idempotent.path = path;
    idempotent.path_generation = record.definition.generation;
    idempotent.authority_generation = record.generation;
    idempotent.state = record.state;
    idempotent.primary = EvaluationOutcome::IDEMPOTENT;
    idempotent.idempotent = true;
    idempotent.authority_digest = record.authority_digest;
    return idempotent;
  }
  if (!PathAuthorityGeneration::can_advance(record.generation.value())) {
    PathDefinition placeholder;
    placeholder.id = path;
    return early_result(placeholder, EvaluationOutcome::RESOURCE_LIMIT, path.str(),
                        "path authority generation space is exhausted", policy, epoch);
  }
  record.generation = record.generation.next();
  record.retired = true;
  record.state = AuthorityState::RETIRED;
  record.outcome = EvaluationOutcome::PATH_RETIRED;
  const AuthorityDigestInput input =
      digest_input_for(record.definition, record.path_digest, record.constraint_digest,
                       record.evidence, record.state, record.outcome, record.violations);
  record.authority_digest = input.compute();
  push_history(record, "retire " + std::string(explanation), limits);

  EvaluationResult result;
  result.path = path;
  result.path_generation = record.definition.generation;
  result.authority_generation = record.generation;
  result.state = AuthorityState::RETIRED;
  result.primary = EvaluationOutcome::PATH_RETIRED;
  result.evidence = record.evidence;
  result.path_digest = record.path_digest;
  result.authority_digest = record.authority_digest;
  result.policy = record.evidence.policy();
  result.epoch = record.evidence.epoch();
  result.constraint_set = record.definition.constraint_set;
  result.constraint_generation = record.definition.constraint_generation;
  result.secondary.push_back(Violation{EvaluationOutcome::PATH_RETIRED, ViolationSeverity::HARD,
                                       path.str(), std::string(explanation)});
  result.committed = true;
  (void)attempt;
  return result;
}

InvalidationReport PathAuthorityRuntime::invalidate_link(const LinkId& link,
                                                         LinkStateGeneration generation) {
  const std::string key = element_key(ElementKind::LINK, link.view());
  return impl_->invalidate_indexed(InvalidationCause::LINK_STATE_CHANGE, key,
                                   EvidenceKind::LINK_STATE, key, generation.value(),
                                   impl_->element_index, key);
}

InvalidationReport PathAuthorityRuntime::invalidate_port(const PortId& port,
                                                         PortConfigGeneration generation) {
  const std::string key = element_key(ElementKind::PORT, port.view());
  return impl_->invalidate_indexed(InvalidationCause::PORT_STATE_CHANGE, key,
                                   EvidenceKind::PORT_CONFIG, key, generation.value(),
                                   impl_->element_index, key);
}

InvalidationReport PathAuthorityRuntime::invalidate_element(ElementKind kind, std::string_view id,
                                                            StructuralGeneration generation) {
  const std::string key = element_key(kind, id);
  return impl_->invalidate_indexed(InvalidationCause::TOPOLOGY_CHANGE, key,
                                   EvidenceKind::STRUCTURAL_ELEMENT, key, generation.value(),
                                   impl_->element_index, key);
}

InvalidationReport PathAuthorityRuntime::invalidate_topology(TopologyGeneration generation) {
  return impl_->invalidate(InvalidationCause::TOPOLOGY_CHANGE, "topology", EvidenceKind::TOPOLOGY,
                           std::string(EvidenceVector::kScalarSubject), generation.value(), true);
}

InvalidationReport PathAuthorityRuntime::invalidate_capability(std::string_view entity,
                                                               const CapabilityKey& key,
                                                               CapabilityGeneration generation) {
  const std::string subject = capability_key(entity, key.view());
  return impl_->invalidate_indexed(InvalidationCause::CAPABILITY_CHANGE, subject,
                                   EvidenceKind::CAPABILITY, subject, generation.value(),
                                   impl_->capability_index, subject);
}

InvalidationReport PathAuthorityRuntime::invalidate_failure_domain(
    const FailureDomainId& domain, FailureDomainGeneration generation) {
  const std::string subject = domain_subject(domain);
  return impl_->invalidate_indexed(InvalidationCause::FAILURE_DOMAIN_CHANGE, subject,
                                   EvidenceKind::FAILURE_DOMAIN, subject, generation.value(),
                                   impl_->domain_index, domain.str());
}

InvalidationReport PathAuthorityRuntime::invalidate_membership(
    const ElementRef& element, FailureDomainGeneration generation) {
  const std::string key = element_key(element);
  const std::string subject = membership_subject(element);
  return impl_->invalidate_indexed(InvalidationCause::FAILURE_DOMAIN_CHANGE, subject,
                                   EvidenceKind::FAILURE_DOMAIN, subject, generation.value(),
                                   impl_->element_index, key);
}

InvalidationReport PathAuthorityRuntime::invalidate_epoch(CoordinatorEpoch epoch) {
  return impl_->invalidate(InvalidationCause::EPOCH_CHANGE, "epoch", EvidenceKind::EPOCH,
                           std::string(EvidenceVector::kScalarSubject), epoch.value(), true);
}

InvalidationReport PathAuthorityRuntime::invalidate_policy(PolicyGeneration generation) {
  return impl_->invalidate(InvalidationCause::POLICY_CHANGE, "policy", EvidenceKind::POLICY,
                           std::string(EvidenceVector::kScalarSubject), generation.value(), true);
}

InvalidationReport PathAuthorityRuntime::invalidate_constraints(const ConstraintSetId& id,
                                                               ConstraintGeneration generation) {
  return impl_->invalidate(InvalidationCause::CONSTRAINT_CHANGE, id.str(),
                           EvidenceKind::CONSTRAINTS, id.str(), generation.value(), true);
}

InvalidationReport PathAuthorityRuntime::invalidate_underlying(
    const PathId& underlying, PathAuthorityGeneration generation) {
  const std::string key = underlying.str();
  return impl_->invalidate_indexed(InvalidationCause::UNDERLYING_AUTHORITY_CHANGE, key,
                                   EvidenceKind::UNDERLYING_AUTHORITY, underlying_subject(underlying),
                                   generation.value(), impl_->underlying_index, key);
}

InvalidationReport PathAuthorityRuntime::invalidate_publisher(const PublisherId& publisher,
                                                             const WorkerBootId& boot) {
  Impl& impl = *impl_;
  InvalidationReport report;
  report.cause = InvalidationCause::PUBLISHER_LOST;
  report.subject = publisher.str() + "/" + boot.str();
  const std::unique_lock lock(impl.mutex);
  for (auto& [key, record] : impl.records) {
    (void)key;
    if (record.publisher != publisher || record.worker_boot != boot) {
      continue;
    }
    if (record.state == AuthorityState::REVALIDATION_REQUIRED) {
      report.already_current.push_back(record.definition.id);
      continue;
    }
    impl.mark_revalidation_required(record, "PUBLISHER_LOST " + report.subject, impl.config.limits);
    report.revalidation_required.push_back(record.definition.id);
  }
  return report;
}

std::vector<PathId> PathAuthorityRuntime::dependents_of_element(ElementKind kind,
                                                               std::string_view id) const {
  return impl_->dependents(impl_->element_index, element_key(kind, id));
}

std::vector<PathId> PathAuthorityRuntime::dependents_of_capability(
    std::string_view entity, const CapabilityKey& key) const {
  return impl_->dependents(impl_->capability_index, capability_key(entity, key.view()));
}

std::vector<PathId> PathAuthorityRuntime::dependents_of_failure_domain(
    const FailureDomainId& domain) const {
  return impl_->dependents(impl_->domain_index, domain.str());
}

std::vector<PathId> PathAuthorityRuntime::dependents_of_underlying(const PathId& underlying) const {
  return impl_->dependents(impl_->underlying_index, underlying.str());
}

std::optional<AuthoritySnapshot> PathAuthorityRuntime::retained_snapshot(
    const PathSnapshotId& id) const {
  const std::shared_lock lock(impl_->mutex);
  const auto it = impl_->snapshots.find(id.str());
  if (it == impl_->snapshots.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<AuthorityDiff> PathAuthorityRuntime::diff(const PathSnapshotId& before,
                                                        const PathSnapshotId& after) const {
  const auto before_snapshot = retained_snapshot(before);
  const auto after_snapshot = retained_snapshot(after);
  if (!before_snapshot.has_value() || !after_snapshot.has_value()) {
    return std::nullopt;
  }
  return diff_snapshots(*before_snapshot, *after_snapshot);
}

DurableState PathAuthorityRuntime::export_state() const {
  DurableState state;
  state.format_version = kPersistenceFormatVersion;
  state.epoch = impl_->sources.epoch->current();
  state.policy = impl_->sources.policy->current_policy();
  const std::shared_lock lock(impl_->mutex);
  state.constraint_sets.reserve(impl_->constraint_sets.size());
  for (const auto& [id, set] : impl_->constraint_sets) {
    (void)id;
    state.constraint_sets.push_back(set);
  }
  state.records.reserve(impl_->records.size());
  for (const auto& [key, record] : impl_->records) {
    (void)key;
    DurablePathRecord durable;
    durable.definition = record.definition;
    durable.authority_generation = record.generation;
    durable.state = record.state;
    durable.outcome = record.outcome;
    durable.evidence = record.evidence;
    durable.authority_digest = record.authority_digest;
    durable.revocation = record.revocation;
    durable.history.assign(record.history.begin(), record.history.end());
    durable.retired = record.retired;
    durable.publisher = record.publisher;
    durable.worker_boot = record.worker_boot;
    state.records.push_back(std::move(durable));
  }
  return state;
}

void PathAuthorityRuntime::import_state(DurableState state) {
  Impl& impl = *impl_;
  const Limits& limits = impl.config.limits;
  if (state.format_version != kPersistenceFormatVersion) {
    throw PersistenceError("unsupported durable format version " +
                           std::to_string(state.format_version));
  }
  if (!state.epoch.is_set()) {
    throw PersistenceError("durable state carries no Fabric Epoch");
  }
  if (state.records.size() > limits.max_store_records) {
    throw PersistenceError("durable record count exceeds Limits::max_store_records");
  }
  for (const auto& set : state.constraint_sets) {
    std::string error;
    for (const auto& requirement : set.capabilities) {
      if (!validate_requirement(requirement.expression, limits, error)) {
        throw PersistenceError("durable constraint set " + set.id.str() + " is malformed: " + error);
      }
    }
    if (!set.id.valid() || !set.generation.is_set()) {
      throw PersistenceError("durable constraint set has an unset identity or generation");
    }
  }

  std::set<std::string> known_paths;
  for (const auto& record : state.records) {
    if (!record.authority_generation.is_set() || !record.definition.id.valid() ||
        !record.definition.generation.is_set()) {
      throw PersistenceError("durable path record has an unset identity or generation");
    }
    if (!known_paths.insert(path_key(record.definition.id)).second) {
      throw PersistenceError("duplicate PathId in durable state: " + record.definition.id.str());
    }
    const PathShapeResult shape =
        validate_path_shape(record.definition, limits, false);
    if (!shape.ok()) {
      throw PersistenceError("durable path " + record.definition.id.str() + " is malformed: " +
                             std::string(to_string(shape.status)) + " " + shape.detail);
    }
    if (!record.evidence.valid()) {
      throw PersistenceError("durable path " + record.definition.id.str() +
                             " carries an invalid evidence vector");
    }
    if (record.definition.underlying.has_value() &&
        !known_paths.count(path_key(record.definition.underlying->path))) {
      // The referenced path may appear later in the image; the second pass
      // below enforces the dependency strictly.
    }
  }
  for (const auto& record : state.records) {
    if (record.definition.underlying.has_value() &&
        !known_paths.count(path_key(record.definition.underlying->path))) {
      throw PersistenceError("durable path " + record.definition.id.str() +
                             " depends on an absent underlying path " +
                             record.definition.underlying->path.str());
    }
  }

  const PolicySet policy = impl.sources.policy->current_policy();
  const std::unique_lock lock(impl.mutex);
  impl.records.clear();
  impl.element_index.clear();
  impl.capability_index.clear();
  impl.domain_index.clear();
  impl.underlying_index.clear();
  impl.constraint_sets.clear();
  impl.attempts.clear();
  impl.attempt_order.clear();
  impl.snapshots.clear();
  impl.snapshots_by_path.clear();

  for (const auto& set : state.constraint_sets) {
    impl.constraint_sets[set.id.str()] = set;
  }

  for (const auto& durable : state.records) {
    Record record;
    record.definition = durable.definition;
    record.generation = durable.authority_generation;
    record.state = durable.state;
    record.outcome = durable.outcome;
    record.evidence = durable.evidence;
    record.path_digest = durable.definition.semantic_digest();
    record.authority_digest = durable.authority_digest;
    record.revocation = durable.revocation;
    record.history.assign(durable.history.begin(), durable.history.end());
    record.retired = durable.retired;
    record.publisher = durable.publisher;
    record.worker_boot = durable.worker_boot;
    const auto constraint = impl.constraint_sets.find(durable.definition.constraint_set.str());
    record.constraint_digest =
        constraint != impl.constraint_sets.end() ? constraint->second.digest() : Digest{};

    // Conservative recovery: live authority never survives a restart. An
    // authorizing record becomes REVALIDATION_REQUIRED at a new authority
    // generation; a revocation, a retirement or a rejection is durable.
    const bool had_live_authority = durable.state == AuthorityState::AUTHORIZED ||
                                    durable.state == AuthorityState::CONDITIONALLY_AUTHORIZED ||
                                    durable.state == AuthorityState::REVALIDATION_REQUIRED ||
                                    durable.state == AuthorityState::STALE ||
                                    durable.state == AuthorityState::UNKNOWN;
    if (had_live_authority) {
      if (!PathAuthorityGeneration::can_advance(record.generation.value())) {
        throw PersistenceError("durable path " + record.definition.id.str() +
                               " has an exhausted authority generation");
      }
      record.generation = record.generation.next();
      record.state = AuthorityState::REVALIDATION_REQUIRED;
      record.outcome = EvaluationOutcome::REVALIDATION_REQUIRED;
    }
    record.violations.clear();
    impl.rebuild_record_dependencies(record, policy);
    impl.index_record(record);
    push_history(record, "recovered", limits);
    impl.records[path_key(record.definition.id)] = std::move(record);
  }
}

EvaluationResult PathAuthorityRuntime::publish_decision(const PathDefinition& path,
                                                       const PublishedDecision& decision,
                                                       const EvaluationRequest& request) {
  Impl& impl = *impl_;
  const Limits& limits = impl.config.limits;
  const PolicySet policy = impl.sources.policy->current_policy();
  const CoordinatorEpoch epoch = impl.sources.epoch->current();

  const PathShapeResult shape = validate_path_shape(path, limits, request.require_identity_binding);
  if (!shape.ok()) {
    const bool resource = shape.status == PathShapeStatus::TOO_MANY_HOPS ||
                          shape.status == PathShapeStatus::METADATA_TOO_LARGE;
    return early_result(path, resource ? EvaluationOutcome::RESOURCE_LIMIT
                                       : EvaluationOutcome::MALFORMED_PATH,
                        path.id.str(), std::string(to_string(shape.status)) + ": " + shape.detail,
                        policy, epoch);
  }
  if (!is_defined_authority_state(static_cast<std::uint8_t>(decision.state)) ||
      !is_defined_evaluation_outcome(static_cast<std::uint16_t>(decision.primary))) {
    return early_result(path, EvaluationOutcome::MALFORMED_PATH, path.id.str(),
                        "published decision carries an undefined state or outcome", policy, epoch);
  }
  if (decision.state != state_for_outcome(decision.primary)) {
    return early_result(path, EvaluationOutcome::MALFORMED_PATH, path.id.str(),
                        "published decision state does not match its primary outcome", policy,
                        epoch);
  }
  if (!decision.evidence.valid()) {
    return early_result(path, EvaluationOutcome::MALFORMED_PATH, path.id.str(),
                        "published decision carries an invalid evidence vector", policy, epoch);
  }

  std::optional<ConstraintSet> constraints;
  {
    const std::shared_lock lock(impl.mutex);
    const auto it = impl.constraint_sets.find(path.constraint_set.str());
    if (it != impl.constraint_sets.end()) {
      constraints = it->second;
    }
  }
  if (!constraints.has_value()) {
    return early_result(path, EvaluationOutcome::CONSTRAINT_SET_UNKNOWN, path.constraint_set.str(),
                        "the constraint set bound by this path is not registered", policy, epoch);
  }
  if (constraints->generation != path.constraint_generation) {
    return early_result(path, EvaluationOutcome::REVALIDATION_REQUIRED, path.constraint_set.str(),
                        "path binds constraint generation " +
                            std::to_string(path.constraint_generation.value()) +
                            " but the registered generation is " +
                            std::to_string(constraints->generation.value()), policy, epoch);
  }

  const PathDefinition* declared = &path;
  if (request.binding_epoch.has_value() && *request.binding_epoch != epoch) {
    return early_result(*declared, EvaluationOutcome::STALE_EPOCH, path.id.str(),
                        "publisher asserted epoch " + std::to_string(request.binding_epoch->value()) +
                            " but current Fabric Epoch is " + std::to_string(epoch.value()),
                        policy, epoch);
  }
  if (decision.evidence.epoch() != epoch) {
    return early_result(*declared, EvaluationOutcome::STALE_EPOCH, path.id.str(),
                        "published evidence is bound to epoch " +
                            std::to_string(decision.evidence.epoch().value()) +
                            " but current Fabric Epoch is " + std::to_string(epoch.value()),
                        policy, epoch);
  }
  if (decision.evidence.policy() != policy.generation) {
    return early_result(*declared, EvaluationOutcome::STALE_AUTHORITY, path.id.str(),
                        "published evidence is bound to policy generation " +
                            std::to_string(decision.evidence.policy().value()) +
                            " but the current policy generation is " +
                            std::to_string(policy.generation.value()),
                        policy, epoch);
  }

  const Digest path_digest = path.semantic_digest();
  if (!(path_digest == decision.path_digest)) {
    return early_result(*declared, EvaluationOutcome::MALFORMED_PATH, path.id.str(),
                        "published path digest does not match the canonical path", policy, epoch);
  }
  const Digest constraint_digest = constraints->digest();
  if (!(constraint_digest == decision.constraint_digest)) {
    return early_result(*declared, EvaluationOutcome::MALFORMED_PATH, path.id.str(),
                        "published constraint digest does not match the bound constraint set",
                        policy, epoch);
  }
  const AuthorityDigestInput digest_input =
      digest_input_for(path, path_digest, constraint_digest, decision.evidence, decision.state,
                       decision.primary, decision.secondary);
  if (!(digest_input.compute() == decision.authority_digest)) {
    return early_result(*declared, EvaluationOutcome::MALFORMED_PATH, path.id.str(),
                        "published authority digest does not match its components", policy, epoch);
  }

  const ExistingInfo existing = impl.existing_info(path.id);
  if (existing.retired) {
    return early_result(*declared, EvaluationOutcome::PATH_RETIRED, path.id.str(),
                        "this path has been retired", policy, epoch);
  }
  if (existing.revocation.has_value()) {
    return early_result(*declared, EvaluationOutcome::REVOKED, path.id.str(),
                        "this path was revoked: " + existing.revocation->render(), policy, epoch);
  }

  const Digest input_digest =
      compute_input_digest(path_digest, path, constraint_digest, policy, epoch);
  if (is_attempt_usable(request.attempt)) {
    const std::shared_lock lock(impl.mutex);
    const auto attempt = impl.attempts.find(request.attempt.str());
    if (attempt != impl.attempts.end() && attempt->second.input_digest != input_digest) {
      return early_result(*declared, EvaluationOutcome::EVALUATION_ATTEMPT_CONFLICT,
                          request.attempt.str(),
                          "this mutation attempt id was already committed with different semantic "
                          "input", policy, epoch);
    }
  }

  CommitRequest commit_request;
  commit_request.path = path;
  commit_request.state = decision.state;
  commit_request.primary = decision.primary;
  commit_request.primary_violation = decision.primary_violation;
  commit_request.evidence = decision.evidence;
  commit_request.path_digest = path_digest;
  commit_request.constraint_digest = constraint_digest;
  commit_request.authority_digest = decision.authority_digest;
  commit_request.secondary = decision.secondary;
  commit_request.input_digest = input_digest;
  commit_request.identity_bound = request.require_identity_binding;
  commit_request.publisher = request.publisher;
  commit_request.worker_boot = request.worker_boot;
  commit_request.expected_generation = request.expected_authority_generation;
  commit_request.attempt = request.attempt;
  commit_request.policy_for_dependencies = policy;

  CommitResult committed;
  {
    const std::unique_lock lock(impl.mutex);
    committed = impl.commit(commit_request);
  }

  EvaluationResult result;
  result.path = path.id;
  result.path_generation = path.generation;
  result.state = decision.state;
  result.primary = decision.primary;
  result.primary_violation = decision.primary_violation;
  result.secondary = decision.secondary;
  result.evidence = decision.evidence;
  result.constraint_set = path.constraint_set;
  result.constraint_generation = path.constraint_generation;
  result.policy = policy.generation;
  result.epoch = epoch;
  result.path_digest = path_digest;
  result.authority_digest = decision.authority_digest;

  if (committed.rejected) {
    result.primary = committed.override_primary;
    result.state = state_for_outcome(result.primary);
    result.secondary.insert(result.secondary.begin(),
                            Violation{result.primary, ViolationSeverity::HARD, path.id.str(),
                                      committed.detail});
    sort_violations(result.secondary);
    return result;
  }
  if (committed.idempotent) {
    result.primary = EvaluationOutcome::IDEMPOTENT;
    result.idempotent = true;
    result.authority_generation = committed.generation;
    return result;
  }
  result.authority_generation = committed.generation;
  result.committed = true;
  return result;
}

}  // namespace path_authority

