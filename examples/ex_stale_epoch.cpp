// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Decisions bind to Fabric Epoch. A publisher that evaluates under an epoch it
// no longer holds cannot make its result current.
#include "example_support.hpp"

using namespace path_authority;

int main() {
  SyntheticEnvironment fabric("epoch-advance");
  PathAuthorityRuntime runtime(fabric.sources());
  runtime.register_constraint_set(fabric.constraints());

  EvaluationRequest stale;
  stale.attempt = pa_example::attempt("example-stale-epoch");
  stale.binding_epoch = CoordinatorEpoch::from_value(1);
  const EvaluationResult rejected = runtime.evaluate(fabric.path(), stale);
  std::cout << rejected.render();

  EvaluationRequest current;
  current.attempt = pa_example::attempt("example-current-epoch");
  current.binding_epoch = fabric.epoch().current();
  const EvaluationResult accepted = runtime.evaluate(fabric.path(), current);
  std::cout << accepted.render();

  const bool ok = rejected.primary == EvaluationOutcome::STALE_EPOCH &&
                  rejected.state == AuthorityState::STALE && !rejected.committed &&
                  accepted.primary == EvaluationOutcome::AUTHORIZED;
  return pa_example::report("stale_epoch", ok, "");
}
