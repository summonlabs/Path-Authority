// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Port Fabric administrative state participates in legality, and DRAINING has
// explicit semantics: an existing authorization may persist while a new one is
// refused.
#include "example_support.hpp"

using namespace path_authority;

int main() {
  SyntheticEnvironment disabled("port-disabled");
  PathAuthorityRuntime runtime(disabled.sources());
  runtime.register_constraint_set(disabled.constraints());
  EvaluationRequest request;
  request.attempt = pa_example::attempt("example-port-disabled");
  const EvaluationResult rejected = runtime.evaluate(disabled.path(), request);
  std::cout << rejected.render();

  SyntheticEnvironment draining("port-draining");
  PathAuthorityRuntime draining_runtime(draining.sources());
  draining_runtime.register_constraint_set(draining.constraints());
  EvaluationRequest draining_request;
  draining_request.attempt = pa_example::attempt("example-port-draining");
  const EvaluationResult refused = draining_runtime.evaluate(draining.path(), draining_request);
  std::cout << refused.render();

  const bool ok = rejected.primary == EvaluationOutcome::PORT_ADMIN_DISABLED &&
                  refused.primary == EvaluationOutcome::PORT_ADMIN_DISABLED;
  return pa_example::report("port_disabled", ok, "");
}
