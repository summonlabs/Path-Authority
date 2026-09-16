// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

// Shared fixture: one small fabric whose every element can be mutated
// individually so tests can prove exact dependency behaviour.
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "path_authority/path_authority.hpp"
#include "test_support.hpp"

namespace pa_fixture {

using namespace path_authority;

inline MutationAttemptId attempt(std::string_view text) {
  return MutationAttemptId::parse(text);
}

inline PathElement hop(ElementKind kind, std::string id, StructuralGeneration generation,
                       Layer layer = Layer::PHYSICAL, RelationType relation = RelationType::NONE) {
  PathElement element;
  element.kind = kind;
  element.id = std::move(id);
  element.generation = generation;
  element.layer = layer;
  element.relation = relation;
  return element;
}

inline CapabilityRequirement at_least(std::string entity, std::string key, std::uint64_t bound) {
  CapabilityRequirement requirement;
  requirement.entity = std::move(entity);
  requirement.key = CapabilityKey::parse(key);
  requirement.expression = Requirement::leaf(RequirementOp::MINIMUM, std::move(key),
                                             {CapabilityValue::unsigned_integer(bound)});
  return requirement;
}

struct Fabric {
  InMemoryEvidence evidence;
  ConstraintSet constraints;
  PathDefinition definition;
  std::unique_ptr<PathAuthorityRuntime> runtime;
  Limits limits;

  Fabric() {
    evidence.topology.set_generation(TopologyGeneration::from_value(1));
    const std::vector<std::pair<ElementKind, std::string>> elements = {
        {ElementKind::ENDPOINT, "ep-a"}, {ElementKind::PORT, "port-a"},
        {ElementKind::LINK, "link-1"},   {ElementKind::SWITCH, "sw-1"},
        {ElementKind::LINK, "link-2"},   {ElementKind::PORT, "port-b"},
        {ElementKind::ENDPOINT, "ep-b"},
    };
    for (const auto& [kind, id] : elements) {
      add_element(kind, id, 1);
    }
    allow(ElementKind::ENDPOINT, "ep-a", ElementKind::PORT, "port-a");
    allow(ElementKind::PORT, "port-a", ElementKind::LINK, "link-1");
    allow(ElementKind::LINK, "link-1", ElementKind::SWITCH, "sw-1");
    allow(ElementKind::SWITCH, "sw-1", ElementKind::LINK, "link-2");
    allow(ElementKind::LINK, "link-2", ElementKind::PORT, "port-b");
    allow(ElementKind::PORT, "port-b", ElementKind::ENDPOINT, "ep-b");

    set_link("link-1", LinkState::UP, 1);
    set_link("link-2", LinkState::UP, 1);
    set_port("port-a", PortAdminState::ACTIVE, 1);
    set_port("port-b", PortAdminState::ACTIVE, 1);
    set_capability("link-1", "mtu", CapabilityValue::unsigned_integer(9000), 1);
    set_capability("link-2", "mtu", CapabilityValue::unsigned_integer(9000), 1);
    for (const auto& [kind, id] : elements) {
      evidence.failure_domains.set_coverage(ElementRef{kind, id}, true);
      evidence.failure_domains.set_membership_generation(ElementRef{kind, id},
                                                         FailureDomainGeneration::from_value(1));
    }

    constraints.id = ConstraintSetId::parse("test-constraints");
    constraints.scope = ScopeId::parse("test-scope");
    constraints.link_state = LinkStateAcceptance::strict();
    constraints.layers.allowed_layers = {Layer::PHYSICAL, Layer::LOGICAL};
    constraints.capabilities.push_back(at_least("link-1", "mtu", 9000));

    runtime = std::make_unique<PathAuthorityRuntime>(evidence.sources());
    const auto registration = runtime->register_constraint_set(constraints);
    constraints.generation = registration.generation;
    definition = build_definition(constraints);
  }

  void add_element(ElementKind kind, const std::string& id, std::uint64_t generation) {
    StructuralElementRecord record;
    record.kind = kind;
    record.id = id;
    record.generation = StructuralGeneration::from_value(generation);
    evidence.topology.put(record);
  }

  void allow(ElementKind from_kind, const std::string& from, ElementKind to_kind,
             const std::string& to) {
    evidence.topology.allow_hop(ElementRef{from_kind, from}, ElementRef{to_kind, to});
  }

  void set_link(const std::string& id, LinkState state, std::uint64_t generation) {
    evidence.link_state.put(LinkId::parse(id), state, LinkStateGeneration::from_value(generation));
  }

  void set_port(const std::string& id, PortAdminState state, std::uint64_t generation) {
    evidence.port_state.put(PortId::parse(id), state, PortConfigGeneration::from_value(generation));
  }

  void set_capability(const std::string& entity, const std::string& key, CapabilityValue value,
                      std::uint64_t generation) {
    evidence.capability.put(entity, CapabilityKey::parse(key), std::move(value),
                            CapabilityGeneration::from_value(generation));
  }

  PathDefinition build_definition(const ConstraintSet& set) const {
    PathDefinition path;
    path.type = PathType::PHYSICAL;
    path.generation = PathGeneration::from_value(1);
    path.scope = ScopeId::parse("test-scope");
    path.constraint_set = set.id;
    path.constraint_generation = set.generation;
    path.hops = {
        hop(ElementKind::ENDPOINT, "ep-a", StructuralGeneration::from_value(1)),
        hop(ElementKind::PORT, "port-a", StructuralGeneration::from_value(1)),
        hop(ElementKind::LINK, "link-1", StructuralGeneration::from_value(1)),
        hop(ElementKind::SWITCH, "sw-1", StructuralGeneration::from_value(1)),
        hop(ElementKind::LINK, "link-2", StructuralGeneration::from_value(1)),
        hop(ElementKind::PORT, "port-b", StructuralGeneration::from_value(1)),
        hop(ElementKind::ENDPOINT, "ep-b", StructuralGeneration::from_value(1)),
    };
    path.id = path.derived_id();
    return path;
  }

  EvaluationRequest request(std::string_view attempt_text,
                            std::optional<PathAuthorityGeneration> expected = std::nullopt) const {
    EvaluationRequest value;
    value.attempt = attempt(attempt_text);
    value.publisher = PublisherId::parse("test-publisher");
    value.worker_boot = WorkerBootId::parse("test-boot");
    value.expected_authority_generation = expected;
    return value;
  }

  EvaluationResult evaluate(std::string_view attempt_text = "attempt-1") {
    return runtime->evaluate(definition, request(attempt_text));
  }
};

}  // namespace pa_fixture
