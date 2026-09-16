// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/synthetic.hpp"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "path_authority/authority.hpp"

namespace path_authority {
namespace {

constexpr std::string_view kConstraintSetId = "leaf-spine-constraints";
constexpr std::string_view kBackupConstraintSetId = "leaf-spine-diverse-constraints";

PathElement hop(ElementKind kind, std::string id, Layer layer = Layer::PHYSICAL,
                RelationType relation = RelationType::NONE) {
  PathElement element;
  element.kind = kind;
  element.id = std::move(id);
  element.generation = StructuralGeneration::from_value(1);
  element.layer = layer;
  element.relation = relation;
  return element;
}

CapabilityRequirement minimum(std::string entity, std::string key, std::uint64_t bound) {
  CapabilityRequirement requirement;
  requirement.entity = std::move(entity);
  requirement.key = CapabilityKey::parse(key);
  requirement.expression =
      Requirement::leaf(RequirementOp::MINIMUM, std::move(key),
                        {CapabilityValue::unsigned_integer(bound)});
  return requirement;
}

CapabilityRequirement supports(std::string entity, std::string key) {
  CapabilityRequirement requirement;
  requirement.entity = std::move(entity);
  requirement.key = CapabilityKey::parse(key);
  requirement.expression = Requirement::leaf(RequirementOp::SUPPORTS, key);
  return requirement;
}

}  // namespace

PolicySet default_policy() {
  PolicySet policy;
  policy.generation = PolicyGeneration::from_value(1);
  policy.scope = default_scope();
  policy.link_state = LinkStateAcceptance::strict();
  policy.port_admin = PortAdminAcceptance{};
  policy.allow_loops = false;
  policy.allow_conditional_authorization = true;
  policy.max_hops = 0;
  return policy;
}

struct SyntheticEnvironment::Impl {
  std::string scenario;
  InMemoryEvidence evidence;
  Elements elements;
  ConstraintSet constraints;
  ConstraintSet backup_constraints;
  PathDefinition path;
  PathDefinition backup;
  CoordinatorEpoch epoch = CoordinatorEpoch::from_value(1);
  bool backup_present = false;

  Impl(std::string scenario_name) : scenario(std::move(scenario_name)) {
    build();
  }

  void register_element(ElementKind kind, const std::string& id) {
    StructuralElementRecord record;
    record.kind = kind;
    record.id = id;
    record.generation = StructuralGeneration::from_value(1);
    evidence.topology.put(record);
  }

  void allow(ElementKind from_kind, const std::string& from, ElementKind to_kind,
             const std::string& to) {
    evidence.topology.allow_hop(ElementRef{from_kind, from}, ElementRef{to_kind, to});
  }

  void build() {
    elements.endpoint_a = "host-alpha";
    elements.endpoint_b = "host-bravo";
    elements.port_a = "port-alpha-1";
    elements.port_b = "port-bravo-1";
    elements.link_a = "link-alpha-leaf";
    elements.link_b = "link-leaf-spine";
    elements.link_c = "link-spine-bravo";
    elements.backup_link_a = "link-alpha-leaf-b";
    elements.backup_link_b = "link-leaf-bravo";
    elements.switch_a = "switch-leaf-1";
    elements.switch_b = "switch-spine-1";
    elements.switch_c = "switch-leaf-2";
    elements.scope = "fabric-lab";

    const std::vector<std::pair<ElementKind, std::string>> elements_to_register = {
        {ElementKind::ENDPOINT, elements.endpoint_a},
        {ElementKind::ENDPOINT, elements.endpoint_b},
        {ElementKind::PORT, elements.port_a},
        {ElementKind::PORT, elements.port_b},
        {ElementKind::PORT, "port-alpha-2"},
        {ElementKind::PORT, "port-bravo-2"},
        {ElementKind::LINK, elements.link_a},
        {ElementKind::LINK, elements.link_b},
        {ElementKind::LINK, elements.link_c},
        {ElementKind::LINK, elements.backup_link_a},
        {ElementKind::LINK, elements.backup_link_b},
        {ElementKind::SWITCH, elements.switch_a},
        {ElementKind::SWITCH, elements.switch_b},
        {ElementKind::SWITCH, elements.switch_c},
    };
    for (const auto& [kind, id] : elements_to_register) {
      register_element(kind, id);
    }

    allow(ElementKind::ENDPOINT, elements.endpoint_a, ElementKind::PORT, elements.port_a);
    allow(ElementKind::PORT, elements.port_a, ElementKind::LINK, elements.link_a);
    allow(ElementKind::LINK, elements.link_a, ElementKind::SWITCH, elements.switch_a);
    allow(ElementKind::SWITCH, elements.switch_a, ElementKind::LINK, elements.link_b);
    allow(ElementKind::LINK, elements.link_b, ElementKind::SWITCH, elements.switch_b);
    allow(ElementKind::SWITCH, elements.switch_b, ElementKind::LINK, elements.link_c);
    allow(ElementKind::LINK, elements.link_c, ElementKind::PORT, elements.port_b);
    allow(ElementKind::PORT, elements.port_b, ElementKind::ENDPOINT, elements.endpoint_b);

    allow(ElementKind::ENDPOINT, elements.endpoint_a, ElementKind::PORT, "port-alpha-2");
    allow(ElementKind::PORT, "port-alpha-2", ElementKind::LINK, elements.backup_link_a);
    allow(ElementKind::LINK, elements.backup_link_a, ElementKind::SWITCH, elements.switch_c);
    allow(ElementKind::SWITCH, elements.switch_c, ElementKind::LINK, elements.backup_link_b);
    allow(ElementKind::LINK, elements.backup_link_b, ElementKind::PORT, "port-bravo-2");
    allow(ElementKind::PORT, "port-bravo-2", ElementKind::ENDPOINT, elements.endpoint_b);

    for (const auto& [kind, id] : elements_to_register) {
      if (kind != ElementKind::LINK) {
        continue;
      }
      evidence.link_state.put(LinkId::parse(id), LinkState::UP, LinkStateGeneration::from_value(1));
    }
    for (const std::string& port : {elements.port_a, elements.port_b, std::string("port-alpha-2"),
                                    std::string("port-bravo-2")}) {
      evidence.port_state.put(PortId::parse(port), PortAdminState::ACTIVE,
                              PortConfigGeneration::from_value(1));
    }

    for (const std::string& link : {elements.link_a, elements.link_b, elements.link_c,
                                    elements.backup_link_a, elements.backup_link_b}) {
      evidence.capability.put(link, CapabilityKey::parse("mtu"),
                              CapabilityValue::unsigned_integer(9000),
                              CapabilityGeneration::from_value(1));
      evidence.capability.put(link, CapabilityKey::parse("speed_gbps"),
                              CapabilityValue::unsigned_integer(400),
                              CapabilityGeneration::from_value(1));
      evidence.capability.put(link, CapabilityKey::parse("protocol_family"),
                              CapabilityValue::text("ethernet"),
                              CapabilityGeneration::from_value(1));
      evidence.capability.put(link, CapabilityKey::parse("rdma"),
                              CapabilityValue::boolean(false),
                              CapabilityGeneration::from_value(1));
    }
    evidence.capability.put(elements.switch_a, CapabilityKey::parse("tunnel_support"),
                            CapabilityValue::boolean(true), CapabilityGeneration::from_value(1));

    FailureDomainRecord power_one;
    power_one.id = FailureDomainId::parse("power-zone-1");
    power_one.domain_class = DomainClassKind::POWER;
    power_one.generation = FailureDomainGeneration::from_value(1);
    evidence.failure_domains.put(power_one);
    FailureDomainRecord power_two;
    power_two.id = FailureDomainId::parse("power-zone-2");
    power_two.domain_class = DomainClassKind::POWER;
    power_two.generation = FailureDomainGeneration::from_value(1);
    evidence.failure_domains.put(power_two);
    FailureDomainRecord srlg;
    srlg.id = FailureDomainId::parse("srlg-alpha");
    srlg.domain_class = DomainClassKind::SHARED_RISK_LINK_GROUP;
    srlg.generation = FailureDomainGeneration::from_value(1);
    evidence.failure_domains.put(srlg);

    evidence.failure_domains.add_member(FailureDomainId::parse("power-zone-1"),
                                        ElementRef{ElementKind::SWITCH, elements.switch_a});
    evidence.failure_domains.add_member(FailureDomainId::parse("power-zone-2"),
                                        ElementRef{ElementKind::SWITCH, elements.switch_c});
    evidence.failure_domains.add_member(FailureDomainId::parse("srlg-alpha"),
                                        ElementRef{ElementKind::LINK, elements.link_b});
    for (const auto& [kind, id] : elements_to_register) {
      evidence.failure_domains.set_coverage(ElementRef{kind, id}, true);
      evidence.failure_domains.set_membership_generation(ElementRef{kind, id},
                                                         FailureDomainGeneration::from_value(1));
    }

    constraints.id = ConstraintSetId::parse(std::string(kConstraintSetId));
    constraints.generation = ConstraintGeneration::from_value(1);
    constraints.scope = ScopeId::parse(elements.scope);
    constraints.capabilities.push_back(minimum(elements.link_b, "mtu", 9000));
    constraints.link_state = LinkStateAcceptance::strict();
    constraints.layers.allowed_layers = {Layer::PHYSICAL, Layer::LOGICAL};

    backup_constraints = constraints;
    backup_constraints.id = ConstraintSetId::parse(std::string(kBackupConstraintSetId));

    path.type = PathType::PHYSICAL;
    path.generation = PathGeneration::from_value(1);
    path.scope = ScopeId::parse(elements.scope);
    path.constraint_set = constraints.id;
    path.constraint_generation = constraints.generation;
    path.hops = {
        hop(ElementKind::ENDPOINT, elements.endpoint_a),
        hop(ElementKind::PORT, elements.port_a),
        hop(ElementKind::LINK, elements.link_a),
        hop(ElementKind::SWITCH, elements.switch_a),
        hop(ElementKind::LINK, elements.link_b),
        hop(ElementKind::SWITCH, elements.switch_b),
        hop(ElementKind::LINK, elements.link_c),
        hop(ElementKind::PORT, elements.port_b),
        hop(ElementKind::ENDPOINT, elements.endpoint_b),
    };
    path.id = path.derived_id();

    apply_scenario();
  }

  void apply_scenario() {
    if (scenario == "authorized" || scenario == "multi-hop") {
      return;
    }
    if (scenario == "degraded-link") {
      evidence.link_state.put(LinkId::parse(elements.link_b), LinkState::DEGRADED,
                              LinkStateGeneration::from_value(2));
      return;
    }
    if (scenario == "degraded-conditional") {
      evidence.link_state.put(LinkId::parse(elements.link_b), LinkState::DEGRADED,
                              LinkStateGeneration::from_value(2));
      constraints.link_state = LinkStateAcceptance::degraded_conditional();
      path.constraint_generation = constraints.generation;
      path.id = path.derived_id();
      return;
    }
    if (scenario == "failed-link") {
      evidence.link_state.put(LinkId::parse(elements.link_b), LinkState::DOWN,
                              LinkStateGeneration::from_value(2));
      return;
    }
    if (scenario == "link-state-unknown") {
      evidence.link_state.erase(elements.link_b);
      return;
    }
    if (scenario == "missing-capability") {
      evidence.capability.put(elements.link_b, CapabilityKey::parse("mtu"),
                              CapabilityValue::unsigned_integer(1500),
                              CapabilityGeneration::from_value(2));
      return;
    }
    if (scenario == "unknown-capability") {
      evidence.capability.erase(elements.link_b, "mtu");
      return;
    }
    if (scenario == "shared-risk") {
      FailureDomainConstraint forbidden;
      forbidden.kind = FailureDomainConstraintKind::FORBIDDEN_DOMAIN;
      forbidden.domain = FailureDomainId::parse("srlg-alpha");
      constraints.failure_domains.push_back(forbidden);
      path.id = path.derived_id();
      return;
    }
    if (scenario == "incomplete-coverage") {
      FailureDomainConstraint forbidden;
      forbidden.kind = FailureDomainConstraintKind::FORBIDDEN_DOMAIN;
      forbidden.domain = FailureDomainId::parse("srlg-alpha");
      constraints.failure_domains.push_back(forbidden);
      evidence.failure_domains.set_coverage(ElementRef{ElementKind::LINK, elements.link_b}, false);
      path.id = path.derived_id();
      return;
    }
    if (scenario == "stale-topology") {
      StructuralElementRecord record;
      record.kind = ElementKind::LINK;
      record.id = elements.link_b;
      record.generation = StructuralGeneration::from_value(2);
      evidence.topology.put(record);
      evidence.topology.set_generation(TopologyGeneration::from_value(2));
      return;
    }
    if (scenario == "retired-element") {
      StructuralElementRecord record;
      record.kind = ElementKind::LINK;
      record.id = elements.link_b;
      record.generation = StructuralGeneration::from_value(1);
      record.retired = true;
      evidence.topology.put(record);
      return;
    }
    if (scenario == "port-disabled") {
      evidence.port_state.put(PortId::parse(elements.port_b), PortAdminState::ADMIN_DISABLED,
                              PortConfigGeneration::from_value(2));
      return;
    }
    if (scenario == "port-draining") {
      evidence.port_state.put(PortId::parse(elements.port_b), PortAdminState::DRAINING,
                              PortConfigGeneration::from_value(2));
      return;
    }
    if (scenario == "port-revalidation") {
      evidence.port_state.put(PortId::parse(elements.port_b), PortAdminState::REVALIDATION_REQUIRED,
                              PortConfigGeneration::from_value(2));
      return;
    }
    if (scenario == "epoch-advance") {
      epoch = evidence.epoch.advance();
      return;
    }
    if (scenario == "policy-change") {
      PolicySet changed = default_policy();
      changed.generation = PolicyGeneration::from_value(2);
      changed.forbidden_layers = {Layer::PHYSICAL};
      evidence.policy.set(changed);
      return;
    }
    if (scenario == "policy-capability") {
      PolicySet changed = default_policy();
      changed.generation = PolicyGeneration::from_value(2);
      changed.required_capabilities.push_back(supports(elements.switch_b, "tunnel_support"));
      evidence.policy.set(changed);
      return;
    }
    if (scenario == "logical-path") {
      // The logical candidate path depends on the physical path above; both
      // layers are validated and logical authority is never inferred.
      PathDefinition logical;
      logical.type = PathType::LOGICAL;
      logical.generation = PathGeneration::from_value(1);
      logical.scope = ScopeId::parse(elements.scope);
      logical.constraint_set = constraints.id;
      logical.constraint_generation = constraints.generation;
      logical.hops = {
          hop(ElementKind::ENDPOINT, elements.endpoint_a),
          hop(ElementKind::TUNNEL, "tunnel-alpha-bravo", Layer::OVERLAY, RelationType::TUNNEL_UNDERLAY),
          hop(ElementKind::ENDPOINT, elements.endpoint_b),
      };
      UnderlyingPathRef underlying;
      underlying.path = path.id;
      underlying.authority_generation = PathAuthorityGeneration::from_value(1);
      underlying.nesting_depth = 1;
      logical.underlying = underlying;
      logical.id = logical.derived_id();
      backup = logical;
      backup_present = true;
      return;
    }
    if (scenario == "primary-backup") {
      PathDefinition backup_path;
      backup_path.type = PathType::PHYSICAL;
      backup_path.generation = PathGeneration::from_value(1);
      backup_path.scope = ScopeId::parse(elements.scope);
      backup_path.constraint_set = backup_constraints.id;
      backup_path.constraint_generation = backup_constraints.generation;
      backup_path.hops = {
          hop(ElementKind::ENDPOINT, elements.endpoint_a),
          hop(ElementKind::PORT, "port-alpha-2"),
          hop(ElementKind::LINK, elements.backup_link_a),
          hop(ElementKind::SWITCH, elements.switch_c),
          hop(ElementKind::LINK, elements.backup_link_b),
          hop(ElementKind::PORT, "port-bravo-2"),
          hop(ElementKind::ENDPOINT, elements.endpoint_b),
      };
      backup_path.id = backup_path.derived_id();
      backup = backup_path;
      backup_present = true;
      return;
    }
    throw std::invalid_argument("unknown synthetic scenario: " + scenario);
  }
};

std::vector<std::string> SyntheticEnvironment::scenario_names() {
  return {"authorized",        "multi-hop",         "degraded-link",  "degraded-conditional",
          "failed-link",       "link-state-unknown", "missing-capability",
          "unknown-capability", "shared-risk",       "incomplete-coverage",
          "stale-topology",    "retired-element",   "port-disabled",  "port-draining",
          "port-revalidation", "epoch-advance",     "policy-change",  "policy-capability",
          "logical-path",      "primary-backup"};
}

bool SyntheticEnvironment::scenario_exists(std::string_view name) {
  const auto names = scenario_names();
  return std::find(names.begin(), names.end(), std::string(name)) != names.end();
}

SyntheticEnvironment::SyntheticEnvironment(std::string_view scenario)
    : impl_(std::make_unique<Impl>(std::string(scenario))) {
  impl_->evidence.policy.set(default_policy());
  impl_->evidence.epoch.set(impl_->epoch);
}

SyntheticEnvironment::~SyntheticEnvironment() = default;

const std::string& SyntheticEnvironment::scenario() const noexcept { return impl_->scenario; }

EvidenceSources SyntheticEnvironment::sources() { return impl_->evidence.sources(); }

PathDefinition SyntheticEnvironment::path() const { return impl_->path; }

PathDefinition SyntheticEnvironment::backup_path() const {
  if (impl_->backup_present) {
    return impl_->backup;
  }
  return impl_->path;
}

ConstraintSet SyntheticEnvironment::constraints() const { return impl_->constraints; }

PolicySet SyntheticEnvironment::policy() const { return impl_->evidence.policy.current_policy(); }

InMemoryEvidence& SyntheticEnvironment::evidence() { return impl_->evidence; }
InMemoryTopology& SyntheticEnvironment::topology() { return impl_->evidence.topology; }
InMemoryLinkState& SyntheticEnvironment::link_state() { return impl_->evidence.link_state; }
InMemoryPortState& SyntheticEnvironment::port_state() { return impl_->evidence.port_state; }
InMemoryCapabilityRegistry& SyntheticEnvironment::capability() { return impl_->evidence.capability; }
InMemoryFailureDomains& SyntheticEnvironment::failure_domains() {
  return impl_->evidence.failure_domains;
}
InMemoryEpochAuthority& SyntheticEnvironment::epoch() { return impl_->evidence.epoch; }
InMemoryPolicyStore& SyntheticEnvironment::policy_store() { return impl_->evidence.policy; }

const SyntheticEnvironment::Elements& SyntheticEnvironment::elements() const noexcept {
  return impl_->elements;
}

std::string SyntheticEnvironment::describe() const {
  std::string text;
  text += "classification=SYNTHETIC\n";
  text += "scenario=" + impl_->scenario + "\n";
  text += "scope=" + impl_->elements.scope + "\n";
  text += "path=" + impl_->path.id.str() + "\n";
  text += "hops=" + std::to_string(impl_->path.hops.size()) + "\n";
  text += "constraint_set=" + impl_->constraints.id.str() + "\n";
  text += "epoch=" + std::to_string(impl_->evidence.epoch.current().value()) + "\n";
  text += "policy_generation=" +
          std::to_string(impl_->evidence.policy.current_policy().generation.value()) + "\n";
  text += "note=modelled fixture; not evidence about a physical fabric\n";
  return text;
}

}  // namespace path_authority
