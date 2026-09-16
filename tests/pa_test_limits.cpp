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

Fabric& reconfigure(Fabric& fabric, const Limits& limits) {
  RuntimeConfig config;
  config.limits = limits;
  fabric.runtime = std::make_unique<PathAuthorityRuntime>(fabric.evidence.sources(), config);
  const auto registration = fabric.runtime->register_constraint_set(fabric.constraints);
  fabric.constraints.generation = registration.generation;
  fabric.definition = fabric.build_definition(fabric.constraints);
  return fabric;
}

}  // namespace

PA_TEST(max_hops_is_enforced_by_shape_validation) {
  Fabric fabric;
  Limits limits;
  limits.max_hops = 4;
  reconfigure(fabric, limits);
  const EvaluationResult result = fabric.evaluate("limit-hops");
  PA_CHECK_EQ(result.primary, EvaluationOutcome::RESOURCE_LIMIT);
  PA_CHECK(!result.committed);
}

PA_TEST(max_paths_is_enforced) {
  Fabric fabric;
  Limits limits;
  limits.max_paths = 2;
  reconfigure(fabric, limits);
  for (int i = 0; i < 2; ++i) {
    PathDefinition variant = fabric.definition;
    variant.generation = PathGeneration::from_value(static_cast<std::uint64_t>(i) + 1);
    variant.id = variant.derived_id();
    PA_CHECK(fabric.runtime->evaluate(variant, fabric.request("limit-path-" + std::to_string(i)))
                 .authorizing());
  }
  PathDefinition overflow = fabric.definition;
  overflow.generation = PathGeneration::from_value(9);
  overflow.id = overflow.derived_id();
  const EvaluationResult result =
      fabric.runtime->evaluate(overflow, fabric.request("limit-path-overflow"));
  PA_CHECK_EQ(result.primary, EvaluationOutcome::RESOURCE_LIMIT);
}

PA_TEST(max_constraints_and_failure_domain_refs_are_enforced) {
  Fabric fabric;
  Limits limits;
  limits.max_constraints = 1;
  limits.max_failure_domain_refs = 1;
  {
    RuntimeConfig config;
    config.limits = limits;
    fabric.runtime = std::make_unique<PathAuthorityRuntime>(fabric.evidence.sources(), config);
  }
  ConstraintSet oversized = fabric.constraints;
  oversized.capabilities.push_back(at_least("link-2", "mtu", 9000));
  bool rejected = false;
  try {
    (void)fabric.runtime->register_constraint_set(oversized);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  PA_CHECK(rejected);

  Fabric limited;
  RuntimeConfig config;
  config.limits = limits;
  limited.runtime = std::make_unique<PathAuthorityRuntime>(limited.evidence.sources(), config);
  ConstraintSet domains = limited.constraints;
  FailureDomainConstraint first;
  first.domain = FailureDomainId::parse("d1");
  domains.failure_domains.push_back(first);
  FailureDomainConstraint second;
  second.domain = FailureDomainId::parse("d2");
  domains.failure_domains.push_back(second);
  rejected = false;
  try {
    (void)limited.runtime->register_constraint_set(domains);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  PA_CHECK(rejected);
}

PA_TEST(requirement_bounds_are_enforced) {
  Limits limits;
  limits.max_requirement_nodes = 3;
  limits.max_requirement_depth = 2;
  std::string error;

  Requirement deep = Requirement::leaf(RequirementOp::SUPPORTS, "a");
  for (int i = 0; i < 4; ++i) {
    deep = Requirement::logical_not(std::move(deep));
  }
  PA_CHECK(!validate_requirement(deep, limits, error));

  Requirement wide = Requirement::all_of({Requirement::leaf(RequirementOp::SUPPORTS, "a"),
                                          Requirement::leaf(RequirementOp::SUPPORTS, "b"),
                                          Requirement::leaf(RequirementOp::SUPPORTS, "c"),
                                          Requirement::leaf(RequirementOp::SUPPORTS, "d")});
  error.clear();
  PA_CHECK(!validate_requirement(wide, limits, error));

  Requirement too_many_values =
      Requirement::leaf(RequirementOp::IN_SET, "mode",
                        std::vector<CapabilityValue>(limits.max_capability_values + 1,
                                                     CapabilityValue::unsigned_integer(1)));
  error.clear();
  PA_CHECK(!validate_requirement(too_many_values, limits, error));

  Requirement malformed = Requirement::leaf(RequirementOp::MINIMUM, "mtu", {});
  error.clear();
  PA_CHECK(!validate_requirement(malformed, limits, error));
}

PA_TEST(nesting_depth_limit_is_enforced_by_shape_validation) {
  Fabric fabric;
  PathDefinition logical = fabric.definition;
  logical.type = PathType::LOGICAL;
  UnderlyingPathRef underlying;
  underlying.path = fabric.definition.id;
  underlying.authority_generation = PathAuthorityGeneration::from_value(1);
  underlying.nesting_depth = 9;
  logical.underlying = underlying;
  logical.id = logical.derived_id();
  const PathShapeResult shape = validate_path_shape(logical, Limits::defaults(), false);
  PA_CHECK_EQ(shape.status, PathShapeStatus::NESTING_DEPTH_EXCEEDED);
}

PA_TEST(evidence_dependency_limit_is_enforced) {
  Fabric fabric;
  Limits limits;
  limits.max_dependencies_per_path = 4;
  reconfigure(fabric, limits);
  const EvaluationResult result = fabric.evaluate("limit-evidence");
  PA_CHECK_EQ(result.primary, EvaluationOutcome::RESOURCE_LIMIT);
}

PA_TEST(explanation_and_history_bounds_are_enforced) {
  Fabric fabric;
  Limits limits;
  limits.max_explanation_entries = 2;
  limits.max_history = 2;
  RuntimeConfig config;
  config.limits = limits;
  fabric.runtime = std::make_unique<PathAuthorityRuntime>(fabric.evidence.sources(), config);
  const auto registration = fabric.runtime->register_constraint_set(fabric.constraints);
  fabric.constraints.generation = registration.generation;
  fabric.definition = fabric.build_definition(fabric.constraints);

  fabric.set_link("link-1", LinkState::DOWN, 2);
  fabric.set_link("link-2", LinkState::DOWN, 2);
  fabric.set_port("port-a", PortAdminState::ADMIN_DISABLED, 2);
  fabric.evidence.capability.erase("link-1", "mtu");
  const EvaluationResult result = fabric.evaluate("limit-explanations");
  PA_CHECK(result.secondary.size() <= limits.max_explanation_entries);

  for (int i = 0; i < 6; ++i) {
    fabric.set_link("link-2", static_cast<LinkState>(i % 2 == 0 ? 1 : 2),
                    static_cast<std::uint64_t>(i) + 3);
    (void)fabric.runtime->evaluate(
        fabric.definition, fabric.request("limit-history-" + std::to_string(i)));
  }
  const auto snapshot = fabric.runtime->query(fabric.definition.id);
  PA_REQUIRE(snapshot.has_value());
  PA_CHECK(snapshot->history.size() <= limits.max_history);
}

PA_TEST(attempt_tracking_bound_evicts_oldest_entries) {
  Fabric fabric;
  Limits limits;
  limits.max_outstanding_attempts = 4;
  reconfigure(fabric, limits);
  for (int i = 0; i < 12; ++i) {
    PathDefinition variant = fabric.definition;
    variant.generation = PathGeneration::from_value(static_cast<std::uint64_t>(i) + 1);
    variant.id = variant.derived_id();
    (void)fabric.runtime->evaluate(variant, fabric.request("bound-" + std::to_string(i)));
  }
  const RuntimeStats stats = fabric.runtime->stats();
  PA_CHECK(stats.attempts_tracked <= limits.max_outstanding_attempts);
}

PA_TEST(metadata_bytes_bound_is_enforced) {
  Fabric fabric;
  Limits limits;
  limits.max_metadata_bytes = 16;
  reconfigure(fabric, limits);
  fabric.evaluate("metadata-1");
  RevocationRequest request;
  request.attempt = attempt("metadata-revoke");
  request.reason = RevocationReason::ADMINISTRATIVE;
  request.authority = "test";
  request.explanation = std::string(64, 'x');
  bool rejected = false;
  try {
    (void)fabric.runtime->revoke(fabric.definition.id, request);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  PA_CHECK(rejected);
}

PA_TEST(limits_are_validated_at_construction) {
  Limits limits;
  limits.max_hops = 0;
  PA_CHECK(!limits.valid());
  Fabric fabric;
  RuntimeConfig config;
  config.limits = limits;
  bool rejected = false;
  try {
    PathAuthorityRuntime runtime(fabric.evidence.sources(), config);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  PA_CHECK(rejected);
}

PA_TEST_MAIN()
