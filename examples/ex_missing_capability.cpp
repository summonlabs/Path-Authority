// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Capability requirements are evaluated against Fabric Capability Registry.
// Path Authority does not invent capability truth and fails closed when the
// registry holds no current record.
#include "example_support.hpp"

using namespace path_authority;

int main() {
  SyntheticEnvironment unsatisfied("missing-capability");
  PathAuthorityRuntime runtime(unsatisfied.sources());
  runtime.register_constraint_set(unsatisfied.constraints());
  EvaluationRequest request;
  request.attempt = pa_example::attempt("example-capability");
  const EvaluationResult low = runtime.evaluate(unsatisfied.path(), request);
  std::cout << low.render();

  SyntheticEnvironment unknown("unknown-capability");
  PathAuthorityRuntime unknown_runtime(unknown.sources());
  unknown_runtime.register_constraint_set(unknown.constraints());
  EvaluationRequest unknown_request;
  unknown_request.attempt = pa_example::attempt("example-capability-unknown");
  const EvaluationResult absent = unknown_runtime.evaluate(unknown.path(), unknown_request);
  std::cout << absent.render();

  const bool ok = low.primary == EvaluationOutcome::CAPABILITY_MISSING &&
                  absent.primary == EvaluationOutcome::CAPABILITY_UNKNOWN;
  return pa_example::report("missing_capability", ok, "");
}
