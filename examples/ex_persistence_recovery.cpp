// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Durable state survives a process; live authority does not. Recovery restores
// descriptions and revocations and requires revalidation.
#include <cstdio>
#include <filesystem>

#include "example_support.hpp"

using namespace path_authority;

int main() {
  const std::filesystem::path store =
      std::filesystem::temp_directory_path() / "path-authority-example-recovery.pauth";
  std::error_code error;
  std::filesystem::remove(store, error);

  SyntheticEnvironment fabric("authorized");
  PathAuthorityRuntime runtime(fabric.sources());
  runtime.register_constraint_set(fabric.constraints());
  EvaluationRequest request;
  request.attempt = pa_example::attempt("example-persistence");
  const EvaluationResult authorized = runtime.evaluate(fabric.path(), request);
  std::cout << authorized.render();

  write_store(runtime.export_state(), store, Limits::defaults());
  const PersistenceInfo info = inspect_store(store, Limits::defaults());
  std::cout << "store_records=" << info.record_count << " store_authorizing=" << info.authorizing
            << "\n";

  SyntheticEnvironment restarted("authorized");
  PathAuthorityRuntime recovered(restarted.sources());
  recovered.register_constraint_set(restarted.constraints());
  recovered.import_state(read_store(store, Limits::defaults()));
  const auto snapshot = recovered.query(fabric.path().id);
  if (snapshot.has_value()) {
    std::cout << snapshot->render();
  }

  std::filesystem::remove(store, error);
  const bool ok = info.readable && info.record_count == 1 && snapshot.has_value() &&
                  snapshot->state == AuthorityState::REVALIDATION_REQUIRED && !snapshot->current;
  return pa_example::report("persistence_recovery", ok, "");
}
