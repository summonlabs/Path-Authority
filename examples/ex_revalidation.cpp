// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// An authorized path is invalidated by exactly the dependency that changed, and
// revalidation under unchanged evidence is idempotent.
#include "example_support.hpp"

using namespace path_authority;

int main() {
  SyntheticEnvironment fabric("authorized");
  PathAuthorityRuntime runtime(fabric.sources());
  runtime.register_constraint_set(fabric.constraints());
  EvaluationRequest request;
  request.attempt = pa_example::attempt("example-revalidation");
  const EvaluationResult authorized = runtime.evaluate(fabric.path(), request);
  std::cout << authorized.render();

  RevalidationRequest unchanged;
  unchanged.attempt = pa_example::attempt("example-revalidation-idempotent");
  const EvaluationResult idempotent = runtime.revalidate(fabric.path().id, unchanged);
  std::cout << idempotent.render();

  // One link state generation moves: only the dependent path is affected.
  const InvalidationReport report = runtime.invalidate_link(
      LinkId::parse(fabric.elements().link_b), LinkStateGeneration::from_value(2));
  std::cout << report.render();
  const auto snapshot = runtime.query(fabric.path().id);
  if (snapshot.has_value()) {
    std::cout << snapshot->render();
  }

  const bool ok = authorized.primary == EvaluationOutcome::AUTHORIZED && idempotent.idempotent &&
                  report.revalidation_required.size() == 1 && snapshot.has_value() &&
                  snapshot->state == AuthorityState::REVALIDATION_REQUIRED &&
                  runtime.dependents_of_element(ElementKind::LINK, fabric.elements().link_b).size() == 1;
  return pa_example::report("revalidation", ok, "");
}
