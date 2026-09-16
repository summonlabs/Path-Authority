// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <algorithm>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "path_authority/path_authority.hpp"

using namespace path_authority;
using pa_fixture::attempt;
using pa_fixture::Fabric;

namespace {

// Builds a second, only partially related path so that unrelated dependency
// changes can be proven not to invalidate it.
// Builds a second path that shares the first two hops and then diverges, so a
// change on link-2 must not reach it while a change on link-1 must.
Fabric& add_neighbour(Fabric& fabric, const std::string& suffix, PathDefinition& out) {
  const std::string link = "link-other-" + suffix;
  const std::string port = "port-other-" + suffix;
  for (const auto& [kind, id] : {std::pair{ElementKind::LINK, link},
                                 std::pair{ElementKind::PORT, port}}) {
    StructuralElementRecord element;
    element.kind = kind;
    element.id = id;
    element.generation = StructuralGeneration::from_value(1);
    fabric.evidence.topology.put(element);
  }
  fabric.set_link(link, LinkState::UP, 1);
  fabric.set_port(port, PortAdminState::ACTIVE, 1);
  fabric.set_capability(link, "mtu", CapabilityValue::unsigned_integer(9000), 1);
  fabric.evidence.topology.allow_hop(ElementRef{ElementKind::SWITCH, "sw-1"},
                                     ElementRef{ElementKind::LINK, link});
  fabric.evidence.topology.allow_hop(ElementRef{ElementKind::LINK, link},
                                     ElementRef{ElementKind::PORT, port});
  fabric.evidence.topology.allow_hop(ElementRef{ElementKind::PORT, port},
                                     ElementRef{ElementKind::ENDPOINT, "ep-b"});
  out = fabric.definition;
  out.hops[4] = pa_fixture::hop(ElementKind::LINK, link, StructuralGeneration::from_value(1));
  out.hops[5] = pa_fixture::hop(ElementKind::PORT, port, StructuralGeneration::from_value(1));
  out.generation = PathGeneration::from_value(2);
  out.id = out.derived_id();
  return fabric;
}

}  // namespace

PA_TEST(link_state_change_invalidates_only_dependent_paths) {
  Fabric fabric;
  PathDefinition neighbour;
  add_neighbour(fabric, "a", neighbour);
  PA_CHECK(fabric.evaluate("dep-1").authorizing());
  PA_CHECK(fabric.runtime->evaluate(neighbour, fabric.request("dep-neighbour")).authorizing());

  const InvalidationReport report = fabric.runtime->invalidate_link(
      LinkId::parse("link-2"), LinkStateGeneration::from_value(2));
  PA_CHECK_EQ(report.revalidation_required.size(), std::size_t{1});
  PA_CHECK_EQ(report.revalidation_required.front().str(), fabric.definition.id.str());

  const auto main = fabric.runtime->query(fabric.definition.id);
  const auto other = fabric.runtime->query(neighbour.id);
  PA_REQUIRE(main.has_value() && other.has_value());
  PA_CHECK_EQ(main->state, AuthorityState::REVALIDATION_REQUIRED);
  PA_CHECK_EQ(other->state, AuthorityState::AUTHORIZED);
  PA_CHECK(other->current);
}

PA_TEST(unrelated_link_change_does_not_invalidate) {
  Fabric fabric;
  fabric.evaluate("unrelated-1");
  const InvalidationReport report = fabric.runtime->invalidate_link(
      LinkId::parse("link-not-used"), LinkStateGeneration::from_value(9));
  PA_CHECK(report.revalidation_required.empty());
  PA_CHECK(report.already_current.empty());
  const auto snapshot = fabric.runtime->query(fabric.definition.id);
  PA_REQUIRE(snapshot.has_value());
  PA_CHECK_EQ(snapshot->state, AuthorityState::AUTHORIZED);
  PA_CHECK(snapshot->current);
}

PA_TEST(unchanged_generation_refresh_keeps_authority_current) {
  Fabric fabric;
  fabric.evaluate("refresh-1");
  const InvalidationReport report = fabric.runtime->invalidate_link(
      LinkId::parse("link-2"), LinkStateGeneration::from_value(1));
  PA_CHECK(report.revalidation_required.empty());
  PA_CHECK_EQ(report.already_current.size(), std::size_t{1});
  const auto snapshot = fabric.runtime->query(fabric.definition.id);
  PA_REQUIRE(snapshot.has_value());
  PA_CHECK_EQ(snapshot->state, AuthorityState::AUTHORIZED);
}

PA_TEST(port_topology_capability_and_domain_changes_invalidate_precisely) {
  Fabric fabric;
  fabric.evaluate("precise-1");

  PA_CHECK_EQ(fabric.runtime
                  ->invalidate_port(PortId::parse("port-a"), PortConfigGeneration::from_value(2))
                  .revalidation_required.size(),
              std::size_t{1});
  PA_CHECK_EQ(fabric.runtime
                  ->invalidate_element(ElementKind::SWITCH, "sw-1",
                                       StructuralGeneration::from_value(2))
                  .already_current.size(),
              std::size_t{1});
  // The record is already REVALIDATION_REQUIRED, so a second dependency change
  // is reported as already requiring revalidation rather than advancing again.
  PA_CHECK_EQ(fabric.runtime
                  ->invalidate_capability("link-1", CapabilityKey::parse("mtu"),
                                          CapabilityGeneration::from_value(2))
                  .already_current.size(),
              std::size_t{1});

  const auto snapshot = fabric.runtime->query(fabric.definition.id);
  PA_REQUIRE(snapshot.has_value());
  PA_CHECK_EQ(snapshot->state, AuthorityState::REVALIDATION_REQUIRED);
  PA_CHECK_EQ(snapshot->authority_generation.value(), std::uint64_t{2});
}

PA_TEST(policy_and_epoch_changes_invalidate_every_path) {
  Fabric fabric;
  PathDefinition neighbour;
  add_neighbour(fabric, "b", neighbour);
  fabric.evaluate("mass-1");
  fabric.runtime->evaluate(neighbour, fabric.request("mass-2"));

  const InvalidationReport policy_report =
      fabric.runtime->invalidate_policy(PolicyGeneration::from_value(2));
  PA_CHECK_EQ(policy_report.revalidation_required.size(), std::size_t{2});

  const InvalidationReport epoch_report =
      fabric.runtime->invalidate_epoch(CoordinatorEpoch::from_value(2));
  PA_CHECK_EQ(epoch_report.already_current.size(), std::size_t{2});
  PA_CHECK(epoch_report.revalidation_required.empty());
}

PA_TEST(failure_domain_membership_and_classification_invalidate_dependents) {
  Fabric fabric;
  FailureDomainRecord record;
  record.id = FailureDomainId::parse("srlg-2");
  record.domain_class = DomainClassKind::SHARED_RISK_LINK_GROUP;
  record.generation = FailureDomainGeneration::from_value(1);
  fabric.evidence.failure_domains.put(record);
  FailureDomainConstraint constraint;
  constraint.kind = FailureDomainConstraintKind::FORBIDDEN_DOMAIN;
  constraint.domain = FailureDomainId::parse("srlg-2");
  fabric.constraints.failure_domains.push_back(constraint);
  const auto registration = fabric.runtime->register_constraint_set(fabric.constraints);
  PathDefinition path = fabric.build_definition(fabric.constraints);
  path.constraint_generation = registration.generation;
  path.id = path.derived_id();
  PA_CHECK(fabric.runtime->evaluate(path, fabric.request("domain-dep-1")).authorizing());

  PA_CHECK_EQ(fabric.runtime->dependents_of_failure_domain(FailureDomainId::parse("srlg-2")).size(),
              std::size_t{1});
  const InvalidationReport report = fabric.runtime->invalidate_failure_domain(
      FailureDomainId::parse("srlg-2"), FailureDomainGeneration::from_value(2));
  PA_CHECK_EQ(report.revalidation_required.size(), std::size_t{1});

  const InvalidationReport membership = fabric.runtime->invalidate_membership(
      ElementRef{ElementKind::LINK, "link-2"}, FailureDomainGeneration::from_value(2));
  PA_CHECK_EQ(membership.already_current.size(), std::size_t{1});
  PA_CHECK_EQ(fabric.runtime->dependents_of_failure_domain(FailureDomainId::parse("unrelated")).size(),
              std::size_t{0});
}

PA_TEST(dependency_indexes_are_consistent_after_mutation) {
  Fabric fabric;
  fabric.evaluate("index-1");
  PA_CHECK_EQ(fabric.runtime->dependents_of_element(ElementKind::LINK, "link-1").size(),
              std::size_t{1});
  PA_CHECK_EQ(fabric.runtime->dependents_of_element(ElementKind::LINK, "link-2").size(),
              std::size_t{1});
  PA_CHECK_EQ(fabric.runtime->dependents_of_element(ElementKind::LINK, "absent").size(),
              std::size_t{0});
  PA_CHECK_EQ(fabric.runtime->dependents_of_capability("link-1", CapabilityKey::parse("mtu")).size(),
              std::size_t{1});

  // Re-evaluating the same path must not duplicate index entries.
  fabric.evaluate("index-2");
  PA_CHECK_EQ(fabric.runtime->dependents_of_element(ElementKind::LINK, "link-1").size(),
              std::size_t{1});
  const RuntimeStats stats = fabric.runtime->stats();
  PA_CHECK_EQ(stats.paths, std::size_t{1});
  PA_CHECK_EQ(stats.elements_indexed, std::size_t{7});
}

PA_TEST(underlying_authority_change_reaches_dependent_logical_paths) {
  Fabric fabric;
  fabric.constraints.layers.allowed_layers = {Layer::PHYSICAL, Layer::LOGICAL, Layer::OVERLAY};
  {
    const auto registration = fabric.runtime->register_constraint_set(fabric.constraints);
    fabric.constraints.generation = registration.generation;
    fabric.definition = fabric.build_definition(fabric.constraints);
  }
  const EvaluationResult physical = fabric.evaluate("underlying-1");
  PA_REQUIRE(physical.authorizing());

  StructuralElementRecord tunnel;
  tunnel.kind = ElementKind::TUNNEL;
  tunnel.id = "tunnel-dep";
  tunnel.generation = StructuralGeneration::from_value(1);
  fabric.evidence.topology.put(tunnel);
  fabric.evidence.topology.allow_hop(ElementRef{ElementKind::ENDPOINT, "ep-a"},
                                     ElementRef{ElementKind::TUNNEL, "tunnel-dep"});
  fabric.evidence.topology.allow_hop(ElementRef{ElementKind::TUNNEL, "tunnel-dep"},
                                     ElementRef{ElementKind::ENDPOINT, "ep-b"});
  PathDefinition logical;
  logical.type = PathType::LOGICAL;
  logical.generation = PathGeneration::from_value(1);
  logical.scope = ScopeId::parse("test-scope");
  logical.constraint_set = fabric.constraints.id;
  logical.constraint_generation = fabric.constraints.generation;
  logical.hops = {pa_fixture::hop(ElementKind::ENDPOINT, "ep-a", StructuralGeneration::from_value(1)),
                  pa_fixture::hop(ElementKind::TUNNEL, "tunnel-dep", StructuralGeneration::from_value(1),
                                  Layer::OVERLAY, RelationType::TUNNEL_UNDERLAY),
                  pa_fixture::hop(ElementKind::ENDPOINT, "ep-b", StructuralGeneration::from_value(1))};
  UnderlyingPathRef underlying;
  underlying.path = fabric.definition.id;
  underlying.authority_generation = physical.authority_generation;
  underlying.nesting_depth = 1;
  logical.underlying = underlying;
  logical.id = logical.derived_id();
  PA_CHECK(fabric.runtime->evaluate(logical, fabric.request("underlying-2")).authorizing());

  PA_CHECK_EQ(fabric.runtime->dependents_of_underlying(fabric.definition.id).size(), std::size_t{1});
  const InvalidationReport report = fabric.runtime->invalidate_underlying(
      fabric.definition.id, PathAuthorityGeneration::from_value(2));
  PA_CHECK_EQ(report.revalidation_required.size(), std::size_t{1});
  const auto snapshot = fabric.runtime->query(logical.id);
  PA_REQUIRE(snapshot.has_value());
  PA_CHECK_EQ(snapshot->state, AuthorityState::REVALIDATION_REQUIRED);
}

PA_TEST(constraint_generation_change_invalidates_bound_paths) {
  Fabric fabric;
  fabric.evaluate("constraint-dep-1");
  ConstraintSet changed = fabric.constraints;
  changed.capabilities.push_back(pa_fixture::at_least("link-2", "mtu", 9000));
  const auto registration = fabric.runtime->register_constraint_set(changed);
  PA_CHECK_EQ(registration.generation.value(), std::uint64_t{2});
  PA_CHECK_EQ(registration.invalidated, std::size_t{1});
  const auto snapshot = fabric.runtime->query(fabric.definition.id);
  PA_REQUIRE(snapshot.has_value());
  PA_CHECK_EQ(snapshot->state, AuthorityState::REVALIDATION_REQUIRED);

  // Re-issuing the path against the old binding is refused rather than
  // silently re-evaluated under different rules.
  const EvaluationResult stale = fabric.evaluate("constraint-dep-2");
  PA_CHECK_EQ(stale.primary, EvaluationOutcome::REVALIDATION_REQUIRED);

  // Registering identical content again keeps the generation stable.
  const auto repeat = fabric.runtime->register_constraint_set(changed);
  PA_CHECK_EQ(repeat.generation.value(), std::uint64_t{2});
  PA_CHECK(!repeat.created);
}

PA_TEST_MAIN()
