// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// The smallest useful workflow: take a candidate path that already exists,
// evaluate it against current authoritative evidence, and read the structured
// result. Path Authority never computed this path.
#include "example_support.hpp"

using namespace path_authority;

int main() {
  SyntheticEnvironment fabric("authorized");
  PathAuthorityRuntime runtime(fabric.sources());
  const auto registration = runtime.register_constraint_set(fabric.constraints());

  PathDefinition candidate = fabric.path();
  EvaluationRequest request;
  request.attempt = pa_example::attempt("example-authorized");
  request.publisher = PublisherId::parse("example");
  request.worker_boot = WorkerBootId::parse("example-boot");

  const EvaluationResult result = runtime.evaluate(candidate, request);
  std::cout << "classification=SYNTHETIC\n";
  std::cout << fabric.describe();
  std::cout << "constraint_set=" << registration.id.str() << "@"
            << registration.generation.value() << "\n";
  std::cout << result.render();

  const bool ok = result.primary == EvaluationOutcome::AUTHORIZED && result.committed &&
                  result.authority_generation.value() == 1 && !result.authority_digest.is_zero();
  return pa_example::report("authorized_path", ok, "");
}
