// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Two supplied candidate paths are each evaluated on their own merits, and the
// diversity requirement between them is evaluated without Path Authority ever
// selecting or computing a path.
#include "example_support.hpp"

using namespace path_authority;

int main() {
  SyntheticEnvironment fabric("primary-backup");
  PathAuthorityRuntime runtime(fabric.sources());
  runtime.register_constraint_set(fabric.constraints());
  ConstraintSet backup_constraints = fabric.constraints();
  backup_constraints.id = ConstraintSetId::parse("leaf-spine-diverse-constraints");
  runtime.register_constraint_set(backup_constraints);

  EvaluationRequest primary_request;
  primary_request.attempt = pa_example::attempt("example-primary");
  const EvaluationResult primary = runtime.evaluate(fabric.path(), primary_request);
  std::cout << primary.render();

  EvaluationRequest backup_request;
  backup_request.attempt = pa_example::attempt("example-backup");
  const EvaluationResult backup = runtime.evaluate(fabric.backup_path(), backup_request);
  std::cout << backup.render();

  // A diversity constraint on a third candidate proves the cross-path check.
  ConstraintSet diverse = fabric.constraints();
  diverse.id = ConstraintSetId::parse("leaf-spine-diversity");
  FailureDomainConstraint independent;
  independent.kind = FailureDomainConstraintKind::DIVERSE_FROM_PEER_PATH;
  independent.peer.path = primary.path;
  independent.peer.authority_generation = primary.authority_generation;
  independent.diversity_classes = {DomainClassKind::POWER,
                                   DomainClassKind::SHARED_RISK_LINK_GROUP};
  diverse.failure_domains.push_back(independent);
  const auto registration = runtime.register_constraint_set(diverse);

  PathDefinition combined = fabric.path();
  combined.constraint_set = diverse.id;
  combined.constraint_generation = registration.generation;
  combined.generation = PathGeneration::from_value(2);
  combined.id = combined.derived_id();
  EvaluationRequest combined_request;
  combined_request.attempt = pa_example::attempt("example-diversity");
  const EvaluationResult self_peer = runtime.evaluate(combined, combined_request);
  std::cout << self_peer.render();

  const bool ok = primary.primary == EvaluationOutcome::AUTHORIZED &&
                  backup.primary == EvaluationOutcome::AUTHORIZED &&
                  self_peer.primary == EvaluationOutcome::FAILURE_DOMAIN_VIOLATION;
  return pa_example::report("primary_backup_diversity", ok, "");
}
