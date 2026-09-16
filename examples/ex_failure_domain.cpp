// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Failure-domain predicates come from Failure Domain Registry. Incomplete
// coverage never implies independence.
#include "example_support.hpp"

using namespace path_authority;

int main() {
  SyntheticEnvironment forbidden("shared-risk");
  PathAuthorityRuntime runtime(forbidden.sources());
  runtime.register_constraint_set(forbidden.constraints());
  EvaluationRequest request;
  request.attempt = pa_example::attempt("example-domain");
  const EvaluationResult violation = runtime.evaluate(forbidden.path(), request);
  std::cout << violation.render();

  SyntheticEnvironment incomplete("incomplete-coverage");
  PathAuthorityRuntime incomplete_runtime(incomplete.sources());
  incomplete_runtime.register_constraint_set(incomplete.constraints());
  EvaluationRequest incomplete_request;
  incomplete_request.attempt = pa_example::attempt("example-domain-coverage");
  const EvaluationResult coverage = incomplete_runtime.evaluate(incomplete.path(), incomplete_request);
  std::cout << coverage.render();

  const bool ok = violation.primary == EvaluationOutcome::FAILURE_DOMAIN_VIOLATION &&
                  coverage.primary == EvaluationOutcome::FAILURE_DOMAIN_COVERAGE_UNKNOWN;
  return pa_example::report("failure_domain", ok, "");
}
