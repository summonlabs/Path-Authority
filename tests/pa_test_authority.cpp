// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <algorithm>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "path_authority/path_authority.hpp"

using namespace path_authority;
using pa_fixture::attempt;
using pa_fixture::at_least;
using pa_fixture::Fabric;
using pa_fixture::hop;

namespace {

bool has_code(const std::vector<Violation>& violations, EvaluationOutcome code) {
  return std::any_of(violations.begin(), violations.end(),
                     [code](const Violation& violation) { return violation.code == code; });
}

}  // namespace

PA_TEST(authorized_path_binds_complete_evidence) {
  Fabric fabric;
  const EvaluationResult result = fabric.evaluate("authorized-1");
  PA_CHECK_EQ(result.primary, EvaluationOutcome::AUTHORIZED);
  PA_CHECK_EQ(result.state, AuthorityState::AUTHORIZED);
  PA_CHECK(result.committed);
  PA_CHECK(!result.idempotent);
  PA_CHECK_EQ(result.authority_generation.value(), std::uint64_t{1});
  PA_CHECK_EQ(result.epoch.value(), std::uint64_t{1});
  PA_CHECK(!result.path_digest.is_zero());
  PA_CHECK(!result.authority_digest.is_zero());
  PA_CHECK_EQ(result.evidence.find(EvidenceKind::LINK_STATE, "LINK:link-1").value_or(0), 1u);
  PA_CHECK_EQ(result.evidence.find(EvidenceKind::CAPABILITY, "link-1|mtu").value_or(0), 1u);
  PA_CHECK_EQ(result.evidence.find(EvidenceKind::EPOCH).value_or(0), 1u);
  PA_CHECK_EQ(result.evidence.find(EvidenceKind::POLICY).value_or(0), 1u);
  PA_CHECK(result.secondary.empty());
}

PA_TEST(link_down_rejects_with_link_down) {
  Fabric fabric;
  fabric.evaluate("down-0");
  fabric.set_link("link-2", LinkState::DOWN, 2);
  const EvaluationResult result = fabric.evaluate("down-1");
  PA_CHECK_EQ(result.primary, EvaluationOutcome::LINK_DOWN);
  PA_CHECK_EQ(result.state, AuthorityState::REJECTED);
  PA_CHECK(result.committed);
}

PA_TEST(link_faulted_and_retired_reject_as_down) {
  Fabric fabric;
  fabric.set_link("link-1", LinkState::FAULTED, 2);
  PA_CHECK_EQ(fabric.evaluate("faulted-1").primary, EvaluationOutcome::LINK_DOWN);
  fabric.set_link("link-1", LinkState::RETIRED, 3);
  PA_CHECK_EQ(fabric.evaluate("retired-link-1").primary, EvaluationOutcome::LINK_DOWN);
}

PA_TEST(degraded_semantics_are_policy_explicit) {
  Fabric fabric;
  fabric.evaluate("degraded-0");
  fabric.set_link("link-1", LinkState::DEGRADED, 2);
  PA_CHECK_EQ(fabric.evaluate("degraded-strict").primary, EvaluationOutcome::LINK_DEGRADED);

  ConstraintSet conditional = fabric.constraints;
  conditional.link_state = LinkStateAcceptance::degraded_conditional();
  PolicySet tolerant = fabric.runtime->policy();
  tolerant.generation = PolicyGeneration::from_value(2);
  tolerant.link_state = LinkStateAcceptance::degraded_conditional();
  fabric.evidence.policy.set(tolerant);
  const auto registration = fabric.runtime->register_constraint_set(conditional);
  PathDefinition path = fabric.definition;
  path.constraint_generation = registration.generation;
  path.id = path.derived_id();
  const EvaluationResult result = fabric.runtime->evaluate(path, fabric.request("degraded-ok"));
  PA_CHECK_EQ(result.primary, EvaluationOutcome::CONDITIONALLY_AUTHORIZED);
  PA_CHECK_EQ(result.state, AuthorityState::CONDITIONALLY_AUTHORIZED);
  PA_CHECK(has_code(result.secondary, EvaluationOutcome::LINK_DEGRADED));
}

PA_TEST(unknown_link_state_fails_closed_and_can_be_conditionally_allowed) {
  Fabric fabric;
  fabric.evidence.link_state.erase("link-1");
  PA_CHECK_EQ(fabric.evaluate("unknown-link").primary, EvaluationOutcome::LINK_STATE_UNKNOWN);

  ConstraintSet tolerance = fabric.constraints;
  tolerance.link_state.allow_unknown = true;
  tolerance.link_state.unknown_is_conditional = true;
  const auto registration = fabric.runtime->register_constraint_set(tolerance);
  PolicySet policy = fabric.runtime->policy();
  policy.generation = PolicyGeneration::from_value(2);
  policy.link_state.allow_unknown = true;
  policy.link_state.unknown_is_conditional = true;
  policy.allow_unknown_link_state = true;
  fabric.evidence.policy.set(policy);
  PathDefinition reissued = fabric.definition;
  reissued.constraint_generation = registration.generation;
  reissued.id = reissued.derived_id();
  const EvaluationResult result =
      fabric.runtime->evaluate(reissued, fabric.request("unknown-link-tolerant"));
  PA_CHECK_EQ(result.primary, EvaluationOutcome::CONDITIONALLY_AUTHORIZED);
  PA_CHECK(has_code(result.secondary, EvaluationOutcome::LINK_STATE_UNKNOWN));
}

PA_TEST(port_administrative_states_reject) {
  Fabric fabric;
  fabric.set_port("port-b", PortAdminState::ADMIN_DISABLED, 2);
  PA_CHECK_EQ(fabric.evaluate("port-disabled").primary, EvaluationOutcome::PORT_ADMIN_DISABLED);

  Fabric retired;
  retired.set_port("port-b", PortAdminState::RETIRED, 2);
  PA_CHECK_EQ(retired.evaluate("port-retired").primary, EvaluationOutcome::PORT_ADMIN_DISABLED);

  Fabric revalidation;
  revalidation.set_port("port-a", PortAdminState::REVALIDATION_REQUIRED, 2);
  PA_CHECK_EQ(revalidation.evaluate("port-revalidation").primary,
              EvaluationOutcome::PORT_REVALIDATION_REQUIRED);

  Fabric missing;
  missing.evidence.port_state.erase("port-a");
  PA_CHECK_EQ(missing.evaluate("port-missing").primary,
              EvaluationOutcome::PORT_REVALIDATION_REQUIRED);
}

PA_TEST(draining_keeps_existing_authority_but_rejects_new_authorization) {
  Fabric fabric;
  PA_CHECK_EQ(fabric.evaluate("draining-first").primary, EvaluationOutcome::AUTHORIZED);
  fabric.set_port("port-b", PortAdminState::DRAINING, 2);
  const EvaluationResult revalidated = fabric.runtime->revalidate(
      fabric.definition.id, RevalidationRequest{attempt("draining-revalidate"), std::nullopt,
                                                PublisherId::parse("test-publisher"),
                                                WorkerBootId::parse("test-boot")});
  PA_CHECK_EQ(revalidated.primary, EvaluationOutcome::CONDITIONALLY_AUTHORIZED);
  PA_CHECK(has_code(revalidated.secondary, EvaluationOutcome::PORT_ADMIN_DISABLED));

  PathDefinition fresh = fabric.definition;
  fresh.generation = PathGeneration::from_value(2);
  fresh.id = fresh.derived_id();
  const EvaluationResult created = fabric.runtime->evaluate(fresh, fabric.request("draining-new"));
  PA_CHECK_EQ(created.primary, EvaluationOutcome::PORT_ADMIN_DISABLED);
}

PA_TEST(capability_requirements_are_evaluated_against_registry_truth) {
  Fabric fabric;
  fabric.set_capability("link-1", "mtu", CapabilityValue::unsigned_integer(1500), 2);
  PA_CHECK_EQ(fabric.evaluate("capability-low").primary, EvaluationOutcome::CAPABILITY_MISSING);

  Fabric unknown;
  unknown.evidence.capability.erase("link-1", "mtu");
  PA_CHECK_EQ(unknown.evaluate("capability-unknown").primary, EvaluationOutcome::CAPABILITY_UNKNOWN);

  Fabric versioned;
  versioned.constraints.capabilities.clear();
  CapabilityRequirement requirement;
  requirement.entity = "sw-1";
  requirement.key = CapabilityKey::parse("firmware");
  requirement.expression =
      Requirement::leaf(RequirementOp::VERSION_AT_LEAST, "firmware",
                        {CapabilityValue::version(SemanticVersion{4, 2, 0})});
  versioned.constraints.capabilities.push_back(requirement);
  versioned.evidence.capability.put("sw-1", CapabilityKey::parse("firmware"),
                                    CapabilityValue::version(SemanticVersion{4, 1, 0}),
                                    CapabilityGeneration::from_value(1));
  const auto registration = versioned.runtime->register_constraint_set(versioned.constraints);
  PathDefinition path = versioned.build_definition(versioned.constraints);
  path.constraint_generation = registration.generation;
  path.id = path.derived_id();
  const EvaluationResult result = versioned.runtime->evaluate(path, versioned.request("version-low"));
  PA_CHECK_EQ(result.primary, EvaluationOutcome::CAPABILITY_MISSING);
}

PA_TEST(logical_requirement_operators_fail_closed_on_unknown) {
  Fabric fabric;
  CapabilityRequirement requirement;
  requirement.entity = "sw-1";
  requirement.key = CapabilityKey::parse("tunnel");
  requirement.expression =
      Requirement::all_of({Requirement::leaf(RequirementOp::SUPPORTS, "tunnel"),
                           Requirement::logical_not(
                               Requirement::leaf(RequirementOp::SUPPORTS, "tunnel"))});
  fabric.constraints.capabilities = {requirement};
  fabric.runtime->register_constraint_set(fabric.constraints);
  fabric.evidence.capability.put("sw-1", CapabilityKey::parse("tunnel"),
                                 CapabilityValue::boolean(true), CapabilityGeneration::from_value(1));
  PathDefinition path = fabric.build_definition(fabric.constraints);
  path.constraint_generation = fabric.runtime->constraint_set(fabric.constraints.id)->generation;
  path.id = path.derived_id();
  const EvaluationResult result = fabric.runtime->evaluate(path, fabric.request("logic-1"));
  PA_CHECK_EQ(result.primary, EvaluationOutcome::CAPABILITY_MISSING);
}

PA_TEST(failure_domain_constraints_are_enforced) {
  Fabric fabric;
  FailureDomainRecord record;
  record.id = FailureDomainId::parse("srlg-1");
  record.domain_class = DomainClassKind::SHARED_RISK_LINK_GROUP;
  record.generation = FailureDomainGeneration::from_value(1);
  fabric.evidence.failure_domains.put(record);
  fabric.evidence.failure_domains.add_member(FailureDomainId::parse("srlg-1"),
                                             ElementRef{ElementKind::LINK, "link-2"});

  FailureDomainConstraint forbidden;
  forbidden.kind = FailureDomainConstraintKind::FORBIDDEN_DOMAIN;
  forbidden.domain = FailureDomainId::parse("srlg-1");
  fabric.constraints.failure_domains.push_back(forbidden);
  const auto registration = fabric.runtime->register_constraint_set(fabric.constraints);
  PathDefinition path = fabric.build_definition(fabric.constraints);
  path.constraint_generation = registration.generation;
  path.id = path.derived_id();
  const EvaluationResult result = fabric.runtime->evaluate(path, fabric.request("domain-forbidden"));
  PA_CHECK_EQ(result.primary, EvaluationOutcome::FAILURE_DOMAIN_VIOLATION);
}

PA_TEST(incomplete_failure_domain_coverage_never_implies_independence) {
  Fabric fabric;
  FailureDomainRecord record;
  record.id = FailureDomainId::parse("srlg-1");
  record.domain_class = DomainClassKind::SHARED_RISK_LINK_GROUP;
  record.generation = FailureDomainGeneration::from_value(1);
  fabric.evidence.failure_domains.put(record);
  FailureDomainConstraint forbidden;
  forbidden.kind = FailureDomainConstraintKind::FORBIDDEN_DOMAIN;
  forbidden.domain = FailureDomainId::parse("srlg-1");
  fabric.constraints.failure_domains.push_back(forbidden);
  const auto registration = fabric.runtime->register_constraint_set(fabric.constraints);
  PathDefinition path = fabric.build_definition(fabric.constraints);
  path.constraint_generation = registration.generation;
  path.id = path.derived_id();
  fabric.evidence.failure_domains.set_coverage(ElementRef{ElementKind::LINK, "link-1"}, false);
  const EvaluationResult result = fabric.runtime->evaluate(path, fabric.request("domain-coverage"));
  PA_CHECK_EQ(result.primary, EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN);
}

PA_TEST(structural_validation_rejects_unknown_retired_and_stale_elements) {
  Fabric unknown;
  unknown.evidence.topology.erase(ElementKind::LINK, "link-1");
  PA_CHECK_EQ(unknown.evaluate("unknown-element").primary, EvaluationOutcome::STRUCTURALLY_INVALID);

  Fabric retired;
  StructuralElementRecord record;
  record.kind = ElementKind::SWITCH;
  record.id = "sw-1";
  record.generation = StructuralGeneration::from_value(1);
  record.retired = true;
  retired.evidence.topology.put(record);
  PA_CHECK_EQ(retired.evaluate("retired-element").primary, EvaluationOutcome::STRUCTURALLY_INVALID);

  Fabric superseded;
  record.retired = false;
  record.superseded = true;
  record.superseded_by = "sw-2";
  superseded.evidence.topology.put(record);
  PA_CHECK_EQ(superseded.evaluate("superseded-element").primary,
              EvaluationOutcome::STRUCTURALLY_INVALID);

  Fabric stale;
  StructuralElementRecord moved;
  moved.kind = ElementKind::LINK;
  moved.id = "link-1";
  moved.generation = StructuralGeneration::from_value(2);
  stale.evidence.topology.put(moved);
  PA_CHECK_EQ(stale.evaluate("stale-element").primary, EvaluationOutcome::STALE_TOPOLOGY);
}

PA_TEST(adjacency_direction_and_layer_are_validated) {
  Fabric missing_adjacency;
  InMemoryTopology& topology = missing_adjacency.evidence.topology;
  topology.forbid_hop(ElementRef{ElementKind::LINK, "link-1"}, ElementRef{ElementKind::SWITCH, "sw-1"});
  const EvaluationResult result = missing_adjacency.evaluate("no-adjacency");
  PA_CHECK_EQ(result.primary, EvaluationOutcome::STRUCTURALLY_INVALID);
  PA_CHECK_EQ(result.primary_violation.code, EvaluationOutcome::STRUCTURALLY_INVALID);

  Fabric wrong_direction;
  wrong_direction.evidence.topology.allow_hop(ElementRef{ElementKind::LINK, "link-1"},
                                              ElementRef{ElementKind::SWITCH, "sw-1"});
  wrong_direction.definition.hops[2] =
      hop(ElementKind::SWITCH, "sw-1", StructuralGeneration::from_value(1));
  wrong_direction.definition.hops[3] =
      hop(ElementKind::LINK, "link-1", StructuralGeneration::from_value(1));
  wrong_direction.definition.id = wrong_direction.definition.derived_id();
  const EvaluationResult directed =
      wrong_direction.runtime->evaluate(wrong_direction.definition, wrong_direction.request("dir"));
  PA_CHECK_EQ(directed.primary, EvaluationOutcome::STRUCTURALLY_INVALID);
}

PA_TEST(stale_epoch_binding_rejects) {
  Fabric fabric;
  EvaluationRequest request = fabric.request("stale-epoch");
  request.binding_epoch = CoordinatorEpoch::from_value(7);
  const EvaluationResult result = fabric.runtime->evaluate(fabric.definition, request);
  PA_CHECK_EQ(result.primary, EvaluationOutcome::STALE_EPOCH);
  PA_CHECK_EQ(result.state, AuthorityState::STALE);
  PA_CHECK(!result.committed);
  PA_CHECK_EQ(fabric.runtime->stats().paths, std::size_t{0});
}

PA_TEST(policy_generation_is_bound_and_forbidden_layers_reject) {
  Fabric fabric;
  PA_CHECK_EQ(fabric.evaluate("policy-ok").primary, EvaluationOutcome::AUTHORIZED);
  PolicySet policy = fabric.runtime->policy();
  policy.generation = PolicyGeneration::from_value(2);
  policy.forbidden_layers = {Layer::PHYSICAL};
  fabric.evidence.policy.set(policy);
  const EvaluationResult result = fabric.evaluate("policy-forbidden-layer");
  PA_CHECK_EQ(result.primary, EvaluationOutcome::POLICY_REJECTED);
  PA_CHECK_EQ(result.policy.value(), std::uint64_t{2});
}

PA_TEST(policy_required_capabilities_are_combined_with_constraints) {
  Fabric fabric;
  PolicySet policy = fabric.runtime->policy();
  policy.generation = PolicyGeneration::from_value(2);
  policy.required_capabilities.push_back(at_least("link-2", "mtu", 9000));
  fabric.evidence.policy.set(policy);
  fabric.set_capability("link-2", "mtu", CapabilityValue::unsigned_integer(1500), 2);
  const EvaluationResult result = fabric.evaluate("policy-capability");
  PA_CHECK_EQ(result.primary, EvaluationOutcome::CAPABILITY_MISSING);
}

PA_TEST(primary_rejection_precedence_is_deterministic_and_secondary_is_rich) {
  Fabric fabric;
  StructuralElementRecord moved;
  moved.kind = ElementKind::LINK;
  moved.id = "link-1";
  moved.generation = StructuralGeneration::from_value(2);
  fabric.evidence.topology.put(moved);
  fabric.set_link("link-2", LinkState::DOWN, 2);
  fabric.evidence.capability.erase("link-1", "mtu");
  fabric.set_port("port-b", PortAdminState::ADMIN_DISABLED, 2);

  const EvaluationResult first = fabric.evaluate("precedence-1");
  PA_CHECK_EQ(first.primary, EvaluationOutcome::STALE_TOPOLOGY);
  PA_CHECK(has_code(first.secondary, EvaluationOutcome::PORT_ADMIN_DISABLED));
  PA_CHECK(has_code(first.secondary, EvaluationOutcome::LINK_DOWN));
  PA_CHECK(has_code(first.secondary, EvaluationOutcome::CAPABILITY_UNKNOWN));

  for (const auto& violation : first.secondary) {
    PA_CHECK(violation.code != EvaluationOutcome::STALE_TOPOLOGY);
  }
  std::vector<Violation> sorted = first.secondary;
  std::sort(sorted.begin(), sorted.end());
  PA_CHECK(sorted == first.secondary);

  // The same violations on a different path resolve to the same primary reason.',
  PathDefinition variant = fabric.definition;
  variant.generation = PathGeneration::from_value(2);
  variant.id = variant.derived_id();
  const EvaluationResult second = fabric.runtime->evaluate(variant, fabric.request("precedence-2"));
  PA_CHECK_EQ(second.primary, first.primary);
  PA_CHECK(second.secondary == first.secondary);
}

PA_TEST(idempotent_replay_does_not_advance_the_authority_generation) {
  Fabric fabric;
  const EvaluationResult first = fabric.evaluate("idem-1");
  PA_CHECK(first.committed);
  PA_CHECK_EQ(first.authority_generation.value(), std::uint64_t{1});

  const EvaluationResult replay = fabric.evaluate("idem-2");
  PA_CHECK(replay.idempotent);
  PA_CHECK_EQ(replay.primary, EvaluationOutcome::IDEMPOTENT);
  PA_CHECK_EQ(replay.state, AuthorityState::AUTHORIZED);
  PA_CHECK_EQ(replay.authority_generation.value(), std::uint64_t{1});
  PA_CHECK(!replay.committed);

  fabric.set_link("link-2", LinkState::DOWN, 2);
  const EvaluationResult changed = fabric.evaluate("idem-3");
  PA_CHECK_EQ(changed.primary, EvaluationOutcome::LINK_DOWN);
  PA_CHECK_EQ(changed.authority_generation.value(), std::uint64_t{2});
  PA_CHECK(changed.committed);
}

PA_TEST(attempt_id_reuse_with_different_input_is_rejected) {
  Fabric fabric;
  PA_CHECK_EQ(fabric.evaluate("conflict-1").primary, EvaluationOutcome::AUTHORIZED);
  fabric.definition.generation = PathGeneration::from_value(2);
  fabric.definition.id = fabric.definition.derived_id();
  const EvaluationResult conflict = fabric.evaluate("conflict-1");
  PA_CHECK_EQ(conflict.primary, EvaluationOutcome::EVALUATION_ATTEMPT_CONFLICT);
  PA_CHECK(!conflict.committed);
}

PA_TEST(expected_authority_generation_is_compare_and_set) {
  Fabric fabric;
  const EvaluationResult first = fabric.evaluate("cas-1");
  PA_CHECK_EQ(first.authority_generation.value(), std::uint64_t{1});

  const EvaluationResult wrong =
      fabric.runtime->evaluate(fabric.definition,
                               fabric.request("cas-2", PathAuthorityGeneration::from_value(9)));
  PA_CHECK_EQ(wrong.primary, EvaluationOutcome::STALE_AUTHORITY);
  PA_CHECK(!wrong.committed);

  fabric.set_link("link-2", LinkState::DOWN, 2);
  const EvaluationResult right =
      fabric.runtime->evaluate(fabric.definition,
                               fabric.request("cas-3", PathAuthorityGeneration::from_value(1)));
  PA_CHECK_EQ(right.primary, EvaluationOutcome::LINK_DOWN);
  PA_CHECK_EQ(right.authority_generation.value(), std::uint64_t{2});
}

PA_TEST(revocation_is_durable_generation_bound_and_distinct_from_invalidation) {
  Fabric fabric;
  const EvaluationResult authorized = fabric.evaluate("revoke-1");
  PA_CHECK_EQ(authorized.primary, EvaluationOutcome::AUTHORIZED);

  RevocationRequest request;
  request.attempt = attempt("revoke-attempt");
  request.reason = RevocationReason::ADMINISTRATIVE;
  request.explanation = "administrative withdrawal";
  request.authority = "test-authority";
  const EvaluationResult revoked = fabric.runtime->revoke(fabric.definition.id, request);
  PA_CHECK_EQ(revoked.primary, EvaluationOutcome::REVOKED);
  PA_CHECK_EQ(revoked.state, AuthorityState::REVOKED);
  PA_CHECK_EQ(revoked.authority_generation.value(), std::uint64_t{2});

  const EvaluationResult again = fabric.runtime->revoke(fabric.definition.id, request);
  PA_CHECK(again.idempotent);
  PA_CHECK_EQ(again.primary, EvaluationOutcome::IDEMPOTENT);
  PA_CHECK_EQ(again.authority_generation.value(), std::uint64_t{2});

  const EvaluationResult replayed = fabric.evaluate("revoke-replay");
  PA_CHECK_EQ(replayed.primary, EvaluationOutcome::REVOKED);
  PA_CHECK(!replayed.committed);

  const auto snapshot = fabric.runtime->query(fabric.definition.id);
  PA_REQUIRE(snapshot.has_value());
  PA_CHECK(snapshot->revocation.has_value());
  PA_CHECK_EQ(snapshot->revocation->reason, RevocationReason::ADMINISTRATIVE);
}

PA_TEST(evidence_driven_invalidation_is_not_revocation) {
  Fabric fabric;
  fabric.evaluate("invalidate-1");
  fabric.set_link("link-2", LinkState::UP, 2);
  const InvalidationReport report = fabric.runtime->invalidate_link(
      LinkId::parse("link-2"), LinkStateGeneration::from_value(2));
  PA_CHECK_EQ(report.revalidation_required.size(), std::size_t{1});
  const auto snapshot = fabric.runtime->query(fabric.definition.id);
  PA_REQUIRE(snapshot.has_value());
  PA_CHECK_EQ(snapshot->state, AuthorityState::REVALIDATION_REQUIRED);
  PA_CHECK(!snapshot->revocation.has_value());
  PA_CHECK(!snapshot->current);
  PA_CHECK(!snapshot->stale_dependencies.empty());
}

PA_TEST(snapshot_digest_is_deterministic_and_diff_is_exact) {
  Fabric many_states;
  many_states.runtime = nullptr;
  many_states.runtime = std::make_unique<PathAuthorityRuntime>(
      many_states.evidence.sources(), RuntimeConfig{many_states.limits, true, true});
  const auto registration = many_states.runtime->register_constraint_set(many_states.constraints);
  many_states.constraints.generation = registration.generation;
  many_states.definition = many_states.build_definition(many_states.constraints);

  const EvaluationResult first = many_states.evaluate("snapshot-1");
  PA_CHECK_EQ(first.primary, EvaluationOutcome::AUTHORIZED);
  const auto before = many_states.runtime->query(many_states.definition.id);
  PA_REQUIRE(before.has_value());

  many_states.set_link("link-2", LinkState::DOWN, 2);
  const EvaluationResult second = many_states.evaluate("snapshot-2");
  PA_CHECK_EQ(second.primary, EvaluationOutcome::LINK_DOWN);
  const auto after = many_states.runtime->query(many_states.definition.id);
  PA_REQUIRE(after.has_value());

  PA_CHECK(!(before->snapshot_digest() == after->snapshot_digest()));
  const AuthorityDiff diff = diff_snapshots(*before, *after);
  PA_CHECK(!diff.empty());
  bool saw_state = false;
  bool saw_link = false;
  for (const auto& entry : diff.entries) {
    if (entry.kind == AuthorityDiffKind::AUTHORITY_STATE) {
      saw_state = true;
      PA_CHECK_EQ(entry.before, std::string("AUTHORIZED"));
      PA_CHECK_EQ(entry.after, std::string("REJECTED"));
    }
    if (entry.kind == AuthorityDiffKind::LINK_STATE && entry.subject == "LINK:link-2") {
      saw_link = true;
    }
  }
  PA_CHECK(saw_state);
  PA_CHECK(saw_link);
  std::vector<AuthorityDiffEntry> sorted = diff.entries;
  std::sort(sorted.begin(), sorted.end());
  PA_CHECK(sorted == diff.entries);

  const AuthorityDiff again = diff_snapshots(*before, *after);
  PA_CHECK(again.render() == diff.render());
}

PA_TEST(revalidation_of_unchanged_evidence_is_idempotent) {
  Fabric fabric;
  fabric.evaluate("revalidate-1");
  RevalidationRequest request;
  request.attempt = attempt("revalidate-attempt");
  request.publisher = PublisherId::parse("test-publisher");
  request.worker_boot = WorkerBootId::parse("test-boot");
  const EvaluationResult result = fabric.runtime->revalidate(fabric.definition.id, request);
  PA_CHECK(result.idempotent);
  PA_CHECK_EQ(result.primary, EvaluationOutcome::IDEMPOTENT);
  PA_CHECK_EQ(result.state, AuthorityState::AUTHORIZED);
}

PA_TEST(retirement_is_durable_and_reported_distinctly) {
  Fabric fabric;
  fabric.evaluate("retire-1");
  const EvaluationResult retired =
      fabric.runtime->retire(fabric.definition.id, attempt("retire-attempt"), "decommissioned");
  PA_CHECK_EQ(retired.primary, EvaluationOutcome::PATH_RETIRED);
  PA_CHECK_EQ(retired.state, AuthorityState::RETIRED);
  const EvaluationResult replay = fabric.evaluate("retire-2");
  PA_CHECK_EQ(replay.primary, EvaluationOutcome::PATH_RETIRED);
}

PA_TEST(batch_evaluation_reports_each_path_and_enforces_the_batch_limit) {
  Fabric fabric;
  std::vector<BatchEntry> batch;
  for (int i = 0; i < 4; ++i) {
    PathDefinition variant = fabric.definition;
    variant.generation = PathGeneration::from_value(static_cast<std::uint64_t>(i) + 1);
    variant.id = variant.derived_id();
    batch.push_back(BatchEntry{variant, attempt("batch-" + std::to_string(i))});
  }
  const auto results = fabric.runtime->evaluate_batch(batch, fabric.request("batch"));
  PA_REQUIRE(results.size() == batch.size());
  for (const auto& result : results) {
    PA_CHECK(result.authorizing());
  }

  Limits small;
  small.max_batch = 2;
  Fabric limited;
  limited.runtime = nullptr;
  RuntimeConfig config;
  config.limits = small;
  limited.runtime = std::make_unique<PathAuthorityRuntime>(limited.evidence.sources(), config);
  const auto registration = limited.runtime->register_constraint_set(limited.constraints);
  limited.constraints.generation = registration.generation;
  limited.definition = limited.build_definition(limited.constraints);
  const auto rejected = limited.runtime->evaluate_batch(batch, limited.request("batch"));
  PA_REQUIRE(rejected.size() == 1);
  PA_CHECK_EQ(rejected.front().primary, EvaluationOutcome::RESOURCE_LIMIT);
}

PA_TEST(logical_paths_require_current_underlying_authority) {
  Fabric fabric;
  fabric.constraints.layers.allowed_layers = {Layer::PHYSICAL, Layer::LOGICAL, Layer::OVERLAY};
  {
    const auto registration = fabric.runtime->register_constraint_set(fabric.constraints);
    fabric.constraints.generation = registration.generation;
    fabric.definition = fabric.build_definition(fabric.constraints);
  }
  const EvaluationResult physical = fabric.evaluate("logical-physical");
  PA_CHECK_EQ(physical.primary, EvaluationOutcome::AUTHORIZED);

  InMemoryTopology& topology = fabric.evidence.topology;
  StructuralElementRecord tunnel;
  tunnel.kind = ElementKind::TUNNEL;
  tunnel.id = "tunnel-1";
  tunnel.generation = StructuralGeneration::from_value(1);
  topology.put(tunnel);
  topology.allow_hop(ElementRef{ElementKind::ENDPOINT, "ep-a"}, ElementRef{ElementKind::TUNNEL, "tunnel-1"});
  topology.allow_hop(ElementRef{ElementKind::TUNNEL, "tunnel-1"}, ElementRef{ElementKind::ENDPOINT, "ep-b"});

  PathDefinition logical;
  logical.type = PathType::LOGICAL;
  logical.generation = PathGeneration::from_value(1);
  logical.scope = ScopeId::parse("test-scope");
  logical.constraint_set = fabric.constraints.id;
  logical.constraint_generation = fabric.constraints.generation;
  logical.hops = {hop(ElementKind::ENDPOINT, "ep-a", StructuralGeneration::from_value(1)),
                  hop(ElementKind::TUNNEL, "tunnel-1", StructuralGeneration::from_value(1),
                       Layer::OVERLAY, RelationType::TUNNEL_UNDERLAY),
                  hop(ElementKind::ENDPOINT, "ep-b", StructuralGeneration::from_value(1))};
  UnderlyingPathRef underlying;
  underlying.path = fabric.definition.id;
  underlying.authority_generation = physical.authority_generation;
  underlying.nesting_depth = 1;
  logical.underlying = underlying;
  logical.id = logical.derived_id();

  const EvaluationResult accepted = fabric.runtime->evaluate(logical, fabric.request("logical-1"));
  PA_CHECK_EQ(accepted.primary, EvaluationOutcome::AUTHORIZED);
  PA_CHECK_EQ(accepted.evidence
                  .find(EvidenceKind::UNDERLYING_AUTHORITY,
                        "underlying:" + fabric.definition.id.str())
                  .value_or(0),
              physical.authority_generation.value());

  // Underlying authority moves: the logical path must be revalidated, not
  // silently kept authorized.
  fabric.set_link("link-2", LinkState::DOWN, 2);
  fabric.evaluate("logical-physical-2");
  const EvaluationResult stale =
      fabric.runtime->evaluate(logical, fabric.request("logical-2"));
  PA_CHECK_EQ(stale.primary, EvaluationOutcome::REVALIDATION_REQUIRED);

  // A cycle in the underlying dependencies is a structural defect. Path
  // identity is derived from content, so a cycle can only enter through a
  // durable image; the runtime refuses to evaluate it.
  Fabric cyclic;
  {
    DurableState state;
    state.epoch = CoordinatorEpoch::from_value(1);
    state.policy = cyclic.evidence.policy.current_policy();
    ConstraintSet set = cyclic.constraints;
    set.generation = ConstraintGeneration::from_value(1);
    state.constraint_sets.push_back(set);
    const EvaluationResult base = cyclic.evaluate("cycle-base");
    PA_REQUIRE(base.authorizing());
    const DurablePathRecord template_record = cyclic.runtime->export_state().records.front();
    PathDefinition first = cyclic.definition;
    first.type = PathType::LOGICAL;
    first.id = PathId::parse("path-cycle-a");
    UnderlyingPathRef first_underlying;
    first_underlying.path = PathId::parse("path-cycle-b");
    first_underlying.authority_generation = PathAuthorityGeneration::from_value(1);
    first_underlying.nesting_depth = 1;
    first.underlying = first_underlying;
    PathDefinition second = first;
    second.id = PathId::parse("path-cycle-b");
    second.underlying->path = PathId::parse("path-cycle-a");
    for (const PathDefinition& definition : {first, second}) {
      DurablePathRecord record = template_record;
      record.definition = definition;
      record.authority_generation = PathAuthorityGeneration::from_value(1);
      record.state = AuthorityState::AUTHORIZED;
      record.outcome = EvaluationOutcome::AUTHORIZED;
      state.records.push_back(record);
    }
    cyclic.runtime->import_state(state);
  }
  EvaluationRequest relaxed = cyclic.request("logical-3");
  relaxed.require_identity_binding = false;
  PathDefinition cyclic_definition = cyclic.definition;
  cyclic_definition.type = PathType::LOGICAL;
  cyclic_definition.id = PathId::parse("path-cycle-a");
  UnderlyingPathRef cyclic_underlying;
  cyclic_underlying.path = PathId::parse("path-cycle-b");
  cyclic_underlying.authority_generation = PathAuthorityGeneration::from_value(1);
  cyclic_underlying.nesting_depth = 1;
  cyclic_definition.underlying = cyclic_underlying;
  const EvaluationResult cycle = cyclic.runtime->evaluate(cyclic_definition, relaxed);
  PA_CHECK_EQ(cycle.primary, EvaluationOutcome::MALFORMED_PATH);
}

PA_TEST(nested_path_authority_does_not_survive_underlying_revocation) {
  Fabric fabric;
  fabric.constraints.layers.allowed_layers = {Layer::PHYSICAL, Layer::LOGICAL, Layer::OVERLAY};
  {
    const auto registration = fabric.runtime->register_constraint_set(fabric.constraints);
    fabric.constraints.generation = registration.generation;
    fabric.definition = fabric.build_definition(fabric.constraints);
  }
  const EvaluationResult physical = fabric.evaluate("nested-physical");
  PA_CHECK(physical.authorizing());

  InMemoryTopology& topology = fabric.evidence.topology;
  StructuralElementRecord tunnel;
  tunnel.kind = ElementKind::TUNNEL;
  tunnel.id = "tunnel-2";
  tunnel.generation = StructuralGeneration::from_value(1);
  topology.put(tunnel);
  topology.allow_hop(ElementRef{ElementKind::ENDPOINT, "ep-a"}, ElementRef{ElementKind::TUNNEL, "tunnel-2"});
  topology.allow_hop(ElementRef{ElementKind::TUNNEL, "tunnel-2"}, ElementRef{ElementKind::ENDPOINT, "ep-b"});

  PathDefinition logical;
  logical.type = PathType::LOGICAL;
  logical.generation = PathGeneration::from_value(1);
  logical.scope = ScopeId::parse("test-scope");
  logical.constraint_set = fabric.constraints.id;
  logical.constraint_generation = fabric.constraints.generation;
  logical.hops = {hop(ElementKind::ENDPOINT, "ep-a", StructuralGeneration::from_value(1)),
                  hop(ElementKind::TUNNEL, "tunnel-2", StructuralGeneration::from_value(1),
                       Layer::OVERLAY, RelationType::TUNNEL_UNDERLAY),
                  hop(ElementKind::ENDPOINT, "ep-b", StructuralGeneration::from_value(1))};
  UnderlyingPathRef underlying;
  underlying.path = fabric.definition.id;
  underlying.authority_generation = physical.authority_generation;
  underlying.nesting_depth = 1;
  logical.underlying = underlying;
  logical.id = logical.derived_id();
  PA_CHECK(fabric.runtime->evaluate(logical, fabric.request("nested-1")).authorizing());

  RevocationRequest request;
  request.attempt = attempt("nested-revoke");
  request.reason = RevocationReason::ENTITY_SUPERSESSION;
  request.explanation = "underlying element superseded";
  (void)fabric.runtime->revoke(fabric.definition.id, request);
  const EvaluationResult after = fabric.runtime->evaluate(logical, fabric.request("nested-2"));
  PA_CHECK_EQ(after.primary, EvaluationOutcome::REVALIDATION_REQUIRED);
}

PA_TEST(structured_outputs_are_deterministic_and_complete) {
  Fabric fabric;
  const EvaluationResult result = fabric.evaluate("json-1");
  const auto snapshot = fabric.runtime->query(fabric.definition.id);
  PA_REQUIRE(snapshot.has_value());

  const std::string result_json = to_json(result);
  PA_CHECK(result_json == to_json(result));
  PA_CHECK(result_json.find("\"outcome\":\"AUTHORIZED\"") != std::string::npos);
  PA_CHECK(result_json.find("\"evidence\"") != std::string::npos);

  const std::string snapshot_json = to_json(*snapshot);
  PA_CHECK(snapshot_json.find("\"snapshot\"") != std::string::npos);
  PA_CHECK(snapshot_json.find("\"current\":true") != std::string::npos);

  const AuthorityDiff diff = diff_snapshots(*snapshot, *snapshot);
  PA_CHECK(diff.empty());
  PA_CHECK(to_json(diff).find("\"changes\":0") != std::string::npos);

  PA_CHECK(!to_json(fabric.definition).empty());
  PA_CHECK(!to_json(result.evidence).empty());
  PA_CHECK(!to_json(fabric.runtime->export_state()).empty());

  const InvalidationReport report = fabric.runtime->invalidate_link(
      LinkId::parse("link-1"), LinkStateGeneration::from_value(2));
  PA_CHECK(to_json(report).find("\"revalidation_required\"") != std::string::npos);

  WorkerInfo worker;
  worker.publisher = PublisherId::parse("evaluator-a");
  worker.worker_boot = WorkerBootId::parse("boot-a");
  worker.scope = ScopeId::parse("fabric");
  PA_CHECK(!to_json(worker).empty());
  PA_CHECK(!to_json(std::vector<WorkerInfo>{worker}).empty());

  for (const std::string& document :
       {result_json, snapshot_json, to_json(diff), to_json(fabric.definition),
        to_json(result.evidence), to_json(fabric.runtime->export_state()), to_json(report),
        to_json(worker), to_json(std::vector<WorkerInfo>{worker})}) {
    PA_CHECK(document.find(",,") == std::string::npos);
    PA_CHECK(document.find("{,") == std::string::npos);
    PA_CHECK(document.find("[,]") == std::string::npos);
    PA_CHECK(document.find(",}") == std::string::npos);
    PA_CHECK(document.find(":]") == std::string::npos);
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (char character : document) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character == '\\') {
        escaped = true;
        continue;
      }
      if (character == '"') {
        in_string = !in_string;
        continue;
      }
      if (in_string) {
        continue;
      }
      if (character == '{' || character == '[') {
        ++depth;
      } else if (character == '}' || character == ']') {
        --depth;
      }
      PA_CHECK(depth >= 0);
    }
    PA_CHECK_EQ(depth, 0);
    PA_CHECK(!in_string);
  }

  const std::optional<Digest> parsed = Digest::from_hex(result.authority_digest.hex());
  PA_REQUIRE(parsed.has_value());
  PA_CHECK(*parsed == result.authority_digest);
  PA_CHECK(!Digest::from_hex("not-a-digest").has_value());
  PA_CHECK(!Digest::from_hex(std::string(63, 'a')).has_value());
  PA_CHECK_EQ(Digest::of("x").short_hex(8).size(), std::size_t{8});
}

PA_TEST(explanation_rendering_is_deterministic) {
  Fabric fabric;
  fabric.set_link("link-1", LinkState::DOWN, 2);
  fabric.evaluate("explain-1");
  const std::string first = fabric.runtime->explain(fabric.definition.id);
  const std::string second = fabric.runtime->explain(fabric.definition.id);
  PA_CHECK(first == second);
  PA_CHECK(first.find("state=REJECTED") != std::string::npos);
  PA_CHECK(first.find("why=LINK_DOWN") != std::string::npos);
  PA_CHECK(first.find("LINK:link-1") != std::string::npos);
}

PA_TEST_MAIN()
