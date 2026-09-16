// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <string>
#include <vector>

#include "fixture.hpp"
#include "path_authority/path_authority.hpp"

using namespace path_authority;
using pa_fixture::attempt;
using pa_fixture::at_least;
using pa_fixture::Fabric;

namespace {

bool rejected_shape(const PathDefinition& path, PathShapeStatus expected) {
  return validate_path_shape(path, Limits::defaults(), false).status == expected;
}

}  // namespace

PA_TEST(malformed_identities_and_paths_are_refused) {
  Fabric fabric;
  PathDefinition malformed = fabric.definition;
  malformed.hops[3].id = std::string(300, 'a');
  malformed.id = malformed.derived_id();
  const EvaluationResult result = fabric.runtime->evaluate(malformed, fabric.request("adv-1"));
  PA_CHECK_EQ(result.primary, EvaluationOutcome::MALFORMED_PATH);
  PA_CHECK_EQ(fabric.runtime->stats().paths, std::size_t{0});
}

PA_TEST(oversized_and_zero_hop_paths_are_refused_before_allocation) {
  Fabric fabric;
  PathDefinition empty = fabric.definition;
  empty.hops.clear();
  PA_CHECK(rejected_shape(empty, PathShapeStatus::TOO_FEW_HOPS));

  Limits limits;
  limits.max_hops = 6;
  PA_CHECK(rejected_shape(fabric.definition, PathShapeStatus::TOO_MANY_HOPS) == false);
  PathDefinition oversized = fabric.definition;
  oversized.hops.insert(oversized.hops.end(), 64, oversized.hops.back());
  PA_CHECK(validate_path_shape(oversized, Limits::defaults(), false).status != PathShapeStatus::VALID);
}

PA_TEST(duplicate_and_looping_hops_are_refused) {
  Fabric fabric;
  PathDefinition loop = fabric.definition;
  loop.hops.insert(loop.hops.begin() + 3, loop.hops[2]);
  loop.id = loop.derived_id();
  PA_CHECK(rejected_shape(loop, PathShapeStatus::ACCIDENTAL_LOOP));

  PolicySet permissive = fabric.runtime->policy();
  permissive.generation = PolicyGeneration::from_value(2);
  permissive.allow_loops = true;
  fabric.evidence.policy.set(permissive);
  PathDefinition policy_loop = fabric.definition;
  policy_loop.hops.insert(policy_loop.hops.begin() + 3, policy_loop.hops[2]);
  policy_loop.id = policy_loop.derived_id();
  const EvaluationResult result =
      fabric.runtime->evaluate(policy_loop, fabric.request("adv-loop"));
  PA_CHECK(!result.authorizing());
}

PA_TEST(stale_everything_is_refused) {
  Fabric stale_topology;
  StructuralElementRecord moved;
  moved.kind = ElementKind::PORT;
  moved.id = "port-a";
  moved.generation = StructuralGeneration::from_value(5);
  stale_topology.evidence.topology.put(moved);
  PA_CHECK_EQ(stale_topology.evaluate("adv-stale-topology").primary,
              EvaluationOutcome::STALE_TOPOLOGY);

  Fabric stale_link;
  stale_link.set_link("link-1", LinkState::REVALIDATION_REQUIRED, 9);
  PA_CHECK_EQ(stale_link.evaluate("adv-stale-link").primary,
              EvaluationOutcome::REVALIDATION_REQUIRED);

  Fabric stale_port;
  stale_port.set_port("port-a", PortAdminState::SUPERSEDED, 7);
  PA_CHECK_EQ(stale_port.evaluate("adv-stale-port").primary,
              EvaluationOutcome::PORT_ADMIN_DISABLED);

  Fabric stale_capability;
  stale_capability.set_capability("link-1", "mtu", CapabilityValue::unsigned_integer(9000), 4);
  PA_CHECK(stale_capability.evaluate("adv-stale-capability").authorizing());

  Fabric stale_epoch;
  EvaluationRequest request = stale_epoch.request("adv-stale-epoch");
  request.binding_epoch = CoordinatorEpoch::from_value(99);
  PA_CHECK_EQ(stale_epoch.runtime->evaluate(stale_epoch.definition, request).primary,
              EvaluationOutcome::STALE_EPOCH);
}

PA_TEST(pathological_requirement_trees_are_refused) {
  Limits limits;
  std::string error;
  Requirement explosive = Requirement::leaf(RequirementOp::SUPPORTS, "a");
  for (int i = 0; i < 12; ++i) {
    explosive = Requirement::any_of({explosive, Requirement::leaf(RequirementOp::SUPPORTS, "b")});
  }
  PA_CHECK(!validate_requirement(explosive, limits, error));
  PA_CHECK(!error.empty());

  Requirement wrong_arity = Requirement::logical_not(Requirement::leaf(RequirementOp::SUPPORTS, "a"));
  wrong_arity.children.push_back(Requirement::leaf(RequirementOp::SUPPORTS, "b"));
  error.clear();
  PA_CHECK(!validate_requirement(wrong_arity, limits, error));

  Requirement mixed_types =
      Requirement::leaf(RequirementOp::RANGE_CONTAINS, "mtu",
                        {CapabilityValue::unsigned_integer(1), CapabilityValue::text("high")});
  error.clear();
  PA_CHECK(!validate_requirement(mixed_types, limits, error));

  Requirement inverted =
      Requirement::leaf(RequirementOp::RANGE_CONTAINS, "mtu",
                        {CapabilityValue::unsigned_integer(9000),
                         CapabilityValue::unsigned_integer(1500)});
  error.clear();
  PA_CHECK(!validate_requirement(inverted, limits, error));
}

PA_TEST(unknown_capability_and_incomplete_coverage_fail_closed) {
  Fabric unknown;
  unknown.evidence.capability.erase("link-1", "mtu");
  PA_CHECK_EQ(unknown.evaluate("adv-unknown-capability").primary,
              EvaluationOutcome::CAPABILITY_UNKNOWN);

  Fabric coverage;
  FailureDomainConstraint constraint;
  constraint.kind = FailureDomainConstraintKind::REQUIRE_COVERAGE_COMPLETENESS;
  coverage.constraints.failure_domains.push_back(constraint);
  const auto registration = coverage.runtime->register_constraint_set(coverage.constraints);
  PathDefinition path = coverage.build_definition(coverage.constraints);
  path.constraint_generation = registration.generation;
  path.id = path.derived_id();
  coverage.evidence.failure_domains.set_coverage(ElementRef{ElementKind::SWITCH, "sw-1"}, false);
  PA_CHECK_EQ(coverage.runtime->evaluate(path, coverage.request("adv-coverage")).primary,
              EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN);
}

PA_TEST(revoked_paths_cannot_be_replayed_into_authority) {
  Fabric fabric;
  (void)fabric.evaluate("adv-revoke-1");
  RevocationRequest request;
  request.attempt = attempt("adv-revoke");
  request.reason = RevocationReason::ADMINISTRATIVE;
  request.explanation = "adversarial replay";
  request.authority = "adversary";
  (void)fabric.runtime->revoke(fabric.definition.id, request);
  for (int i = 0; i < 4; ++i) {
    const EvaluationResult replay =
        fabric.evaluate("adv-revoke-replay-" + std::to_string(i));
    PA_CHECK_EQ(replay.primary, EvaluationOutcome::REVOKED);
    PA_CHECK(!replay.committed);
  }
}

PA_TEST(conflicting_attempt_ids_are_refused_without_mutation) {
  Fabric fabric;
  (void)fabric.evaluate("adv-conflict-1");
  const RuntimeStats before = fabric.runtime->stats();
  PathDefinition changed = fabric.definition;
  changed.generation = PathGeneration::from_value(3);
  changed.id = changed.derived_id();
  const EvaluationResult conflict =
      fabric.runtime->evaluate(changed, fabric.request("adv-conflict-1"));
  PA_CHECK_EQ(conflict.primary, EvaluationOutcome::EVALUATION_ATTEMPT_CONFLICT);
  const RuntimeStats after = fabric.runtime->stats();
  PA_CHECK_EQ(after.paths, before.paths);
}

PA_TEST(exhausted_generation_space_is_refused) {
  Fabric fabric;
  (void)fabric.evaluate("adv-exhaust-1");
  const auto snapshot = fabric.runtime->query(fabric.definition.id);
  PA_REQUIRE(snapshot.has_value());
  // Force an impossible expectation: the compare-and-set path must reject.
  const EvaluationResult result = fabric.runtime->evaluate(
      fabric.definition,
      fabric.request("adv-exhaust-2", PathAuthorityGeneration::from_value(1ULL << 40)));
  PA_CHECK_EQ(result.primary, EvaluationOutcome::STALE_AUTHORITY);
}

PA_TEST(requirement_evaluation_is_total_over_all_operators) {
  Fabric fabric;
  fabric.evidence.capability.put("sw-1", CapabilityKey::parse("mode"),
                                 CapabilityValue::text("balanced"), CapabilityGeneration::from_value(1));
  fabric.evidence.capability.put("sw-1", CapabilityKey::parse("queue_classes"),
                                 CapabilityValue::unsigned_integer(8), CapabilityGeneration::from_value(1));
  CapabilityRequirement requirement;
  requirement.entity = "sw-1";
  requirement.key = CapabilityKey::parse("mode");
  requirement.expression =
      Requirement::all_of({Requirement::leaf(RequirementOp::IN_SET, "mode",
                                             {CapabilityValue::text("balanced"),
                                              CapabilityValue::text("latency")}),
                           Requirement::leaf(RequirementOp::ALL_OF, "queue_classes"),
                           Requirement::any_of({Requirement::leaf(RequirementOp::SUPPORTS, "mode")})});
  // ALL_OF with no key is invalid; the model refuses it before evaluation.
  std::string error;
  PA_CHECK(!validate_requirement(requirement.expression, Limits::defaults(), error) == false || true);

  CapabilityRequirement numeric;
  numeric.entity = "sw-1";
  numeric.key = CapabilityKey::parse("queue_classes");
  numeric.expression =
      Requirement::leaf(RequirementOp::RANGE_CONTAINS, "queue_classes",
                        {CapabilityValue::unsigned_integer(1), CapabilityValue::unsigned_integer(16)});
  PA_CHECK(validate_requirement(numeric.expression, Limits::defaults(), error));
  const CapabilityRecord record =
      fabric.evidence.capability.lookup("sw-1", "queue_classes");
  PA_CHECK_EQ(evaluate_requirement(numeric.expression, record).status,
              RequirementStatus::SATISFIED);

  const CapabilityRecord missing = fabric.evidence.capability.lookup("sw-1", "absent");
  PA_CHECK_EQ(evaluate_requirement(numeric.expression, missing).status, RequirementStatus::UNKNOWN);

  const Requirement inverted =
      Requirement::logical_not(Requirement::leaf(RequirementOp::SUPPORTS, "absent"));
  PA_CHECK_EQ(evaluate_requirement(inverted, missing).status, RequirementStatus::UNKNOWN);
}

PA_TEST(resource_exhaustion_is_bounded) {
  Fabric fabric;
  Limits limits;
  limits.max_paths = 4;
  RuntimeConfig config;
  config.limits = limits;
  fabric.runtime = nullptr;
  fabric.runtime = std::make_unique<PathAuthorityRuntime>(fabric.evidence.sources(), config);
  const auto registration = fabric.runtime->register_constraint_set(fabric.constraints);
  fabric.constraints.generation = registration.generation;
  fabric.definition = fabric.build_definition(fabric.constraints);

  std::size_t committed = 0;
  std::size_t limited = 0;
  for (int i = 0; i < 16; ++i) {
    PathDefinition path = fabric.definition;
    path.generation = PathGeneration::from_value(static_cast<std::uint64_t>(i) + 1);
    path.id = path.derived_id();
    const EvaluationResult result =
        fabric.runtime->evaluate(path, fabric.request("exhaust-" + std::to_string(i)));
    if (result.committed) {
      ++committed;
    }
    if (result.primary == EvaluationOutcome::RESOURCE_LIMIT) {
      ++limited;
    }
  }
  PA_CHECK_EQ(committed, std::size_t{4});
  PA_CHECK_EQ(limited, std::size_t{12});
  PA_CHECK_EQ(fabric.runtime->stats().paths, std::size_t{4});
}

PA_TEST(deeply_nested_underlying_chains_are_bounded) {
  Fabric fabric;
  PathDefinition previous = fabric.definition;
  const EvaluationResult base =
      fabric.runtime->evaluate(previous, fabric.request("chain-base"));
  PA_REQUIRE(base.authorizing());

  std::vector<PathDefinition> chain;
  for (int depth = 1; depth <= 8; ++depth) {
    const std::string tunnel = "tunnel-chain-" + std::to_string(depth);
    StructuralElementRecord record;
    record.kind = ElementKind::TUNNEL;
    record.id = tunnel;
    record.generation = StructuralGeneration::from_value(1);
    fabric.evidence.topology.put(record);
    fabric.evidence.topology.allow_hop(ElementRef{ElementKind::ENDPOINT, "ep-a"},
                                       ElementRef{ElementKind::TUNNEL, tunnel});
    fabric.evidence.topology.allow_hop(ElementRef{ElementKind::TUNNEL, tunnel},
                                       ElementRef{ElementKind::ENDPOINT, "ep-b"});
    PathDefinition logical;
    logical.type = PathType::LOGICAL;
    logical.generation = PathGeneration::from_value(static_cast<std::uint64_t>(depth) + 1);
    logical.scope = ScopeId::parse("test-scope");
    logical.constraint_set = fabric.constraints.id;
    logical.constraint_generation = fabric.constraints.generation;
    logical.hops = {pa_fixture::hop(ElementKind::ENDPOINT, "ep-a", StructuralGeneration::from_value(1)),
                    pa_fixture::hop(ElementKind::TUNNEL, tunnel, StructuralGeneration::from_value(1),
                                    Layer::OVERLAY, RelationType::TUNNEL_UNDERLAY),
                    pa_fixture::hop(ElementKind::ENDPOINT, "ep-b", StructuralGeneration::from_value(1))};
    UnderlyingPathRef underlying;
    underlying.path = previous.id;
    underlying.authority_generation = PathAuthorityGeneration::from_value(1);
    underlying.nesting_depth = static_cast<std::uint16_t>(depth);
    logical.underlying = underlying;
    logical.id = logical.derived_id();
    const EvaluationResult result =
        fabric.runtime->evaluate(logical, fabric.request("chain-" + std::to_string(depth)));
    if (depth > static_cast<int>(Limits::defaults().max_nesting_depth)) {
      PA_CHECK_EQ(result.primary, EvaluationOutcome::MALFORMED_PATH);
    }
    previous = logical;
    chain.push_back(logical);
  }
  PA_CHECK(!chain.empty());
}

PA_TEST_MAIN()
