// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// A path that exists and is structurally valid is still not authorized when a
// required link is down. The rejection names the exact hop.
#include "example_support.hpp"

using namespace path_authority;

int main() {
  SyntheticEnvironment fabric("failed-link");
  PathAuthorityRuntime runtime(fabric.sources());
  runtime.register_constraint_set(fabric.constraints());

  EvaluationRequest request;
  request.attempt = pa_example::attempt("example-link-down");
  const EvaluationResult result = runtime.evaluate(fabric.path(), request);
  std::cout << result.render();

  const bool ok = result.primary == EvaluationOutcome::LINK_DOWN &&
                  result.state == AuthorityState::REJECTED &&
                  result.primary_violation.subject == element_key(ElementKind::LINK, "link-leaf-spine");
  return pa_example::report("link_down", ok, "");
}
