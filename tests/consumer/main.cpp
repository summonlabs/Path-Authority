// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Downstream consumer: find the installed package, build a synthetic candidate
// path, evaluate it, invalidate exactly one dependency and observe revalidation.
#include <iostream>
#include <string>

#include <path_authority/path_authority.hpp>

using namespace path_authority;

int main() {
  std::cout << "package_version=" << version_string() << "\n";

  SyntheticEnvironment fabric("authorized");
  PathAuthorityRuntime runtime(fabric.sources());
  runtime.register_constraint_set(fabric.constraints());

  const PathDefinition path = fabric.path();
  EvaluationRequest request;
  request.attempt = MutationAttemptId::parse("consumer-evaluate");
  request.publisher = PublisherId::parse("consumer");
  request.worker_boot = WorkerBootId::parse("consumer-boot");

  const EvaluationResult authorized = runtime.evaluate(path, request);
  std::cout << "path=" << path.id.str() << "\n";
  std::cout << "first_outcome=" << to_string(authorized.primary) << "\n";
  if (authorized.primary != EvaluationOutcome::AUTHORIZED || !authorized.committed) {
    std::cerr << "expected the candidate path to be authorized\n";
    return 1;
  }

  const InvalidationReport report = runtime.invalidate_link(
      LinkId::parse(fabric.elements().link_b), LinkStateGeneration::from_value(2));
  if (report.revalidation_required.size() != 1) {
    std::cerr << "expected exactly one dependent path to require revalidation\n";
    return 1;
  }
  const auto snapshot = runtime.query(path.id);
  if (!snapshot.has_value() || snapshot->state != AuthorityState::REVALIDATION_REQUIRED ||
      snapshot->current) {
    std::cerr << "expected the path to require revalidation\n";
    return 1;
  }
  std::cout << "second_state=" << to_string(snapshot->state) << "\n";

  fabric.link_state().put(LinkId::parse(fabric.elements().link_b), LinkState::DOWN,
                          LinkStateGeneration::from_value(2));
  RevalidationRequest revalidation;
  revalidation.attempt = MutationAttemptId::parse("consumer-revalidate");
  const EvaluationResult rejected = runtime.revalidate(path.id, revalidation);
  std::cout << "third_outcome=" << to_string(rejected.primary) << "\n";
  if (rejected.primary != EvaluationOutcome::LINK_DOWN) {
    std::cerr << "expected the path to be rejected once its link is down\n";
    return 1;
  }

  std::cout << "consumer=ok\n";
  return 0;
}
