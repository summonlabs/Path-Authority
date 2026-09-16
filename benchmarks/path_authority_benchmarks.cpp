// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Completion benchmarks. Every number reported here is a measured, completed
// operation count on the machine that ran it; no performance guarantee is
// implied. The populations are SYNTHETIC.
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "path_authority/path_authority.hpp"

using namespace path_authority;

namespace {

constexpr std::string_view kRoot = PATH_AUTHORITY_BENCHMARK_TEMP_ROOT;

struct Measurement {
  std::string label;
  std::size_t operations = 0;
  double milliseconds = 0.0;
};

std::vector<Measurement> g_measurements;

void record(const std::string& label, std::size_t operations, double milliseconds) {
  g_measurements.push_back(Measurement{label, operations, milliseconds});
  std::cout << "measure=" << label << " operations=" << operations
            << " milliseconds=" << static_cast<std::uint64_t>(milliseconds * 1000.0) / 1000.0
            << " per_operation_us="
            << (operations == 0 ? 0.0 : (milliseconds * 1000.0) / static_cast<double>(operations))
            << "\n";
  std::cout.flush();
}

class Timer {
 public:
  Timer() : start_(std::chrono::steady_clock::now()) {}
  double milliseconds() const {
    const auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(now - start_).count();
  }

 private:
  std::chrono::steady_clock::time_point start_;
};

PathDefinition populate(const SyntheticEnvironment& fabric, std::size_t index,
                        ConstraintGeneration constraint_generation) {
  PathDefinition path = fabric.path();
  path.generation = PathGeneration::from_value(static_cast<std::uint64_t>(index) + 1);
  path.constraint_generation = constraint_generation;
  path.id = path.derived_id();
  return path;
}

MutationAttemptId attempt_for(std::string_view prefix, std::size_t index) {
  return MutationAttemptId::parse(std::string(prefix) + "-" + std::to_string(index));
}

struct Bench {
  SyntheticEnvironment fabric{"authorized"};
  std::unique_ptr<PathAuthorityRuntime> runtime;
  std::vector<PathDefinition> paths;

  explicit Bench(std::size_t population) {
    runtime = std::make_unique<PathAuthorityRuntime>(fabric.sources());
    // A failure domain constraint is added so that domain invalidation measures
    // real work. No element of this fixture is a member of the domain, so the
    // paths stay authorized while the dependency exists.
    ConstraintSet constraints = fabric.constraints();
    FailureDomainConstraint forbidden;
    forbidden.kind = FailureDomainConstraintKind::FORBIDDEN_DOMAIN;
    forbidden.domain = FailureDomainId::parse("srlg-benchmark");
    constraints.failure_domains.push_back(forbidden);
    FailureDomainRecord domain;
    domain.id = FailureDomainId::parse("srlg-benchmark");
    domain.domain_class = DomainClassKind::SHARED_RISK_LINK_GROUP;
    domain.generation = FailureDomainGeneration::from_value(1);
    fabric.failure_domains().put(domain);
    const auto registration = runtime->register_constraint_set(constraints);
    constraint_generation = registration.generation;
    paths.reserve(population);
    for (std::size_t i = 0; i < population; ++i) {
      paths.push_back(populate(fabric, i, constraint_generation));
    }
  }

  ConstraintGeneration constraint_generation;

  void authorize() {
    Timer timer;
    std::size_t completed = 0;
    for (std::size_t i = 0; i < paths.size(); ++i) {
      EvaluationRequest request;
      request.attempt = attempt_for("authorize", i);
      if (runtime->evaluate(paths[i], request).committed) {
        ++completed;
      }
    }
    record("authorize_" + std::to_string(paths.size()) + "_paths", completed, timer.milliseconds());
  }

  void query() {
    Timer timer;
    std::size_t completed = 0;
    for (const auto& path : paths) {
      if (runtime->query(path.id).has_value()) {
        ++completed;
      }
    }
    record("query_" + std::to_string(paths.size()) + "_paths", completed, timer.milliseconds());
  }

  void revalidate_unchanged() {
    Timer timer;
    std::size_t completed = 0;
    for (std::size_t i = 0; i < paths.size(); ++i) {
      RevalidationRequest request;
      request.attempt = attempt_for("revalidate", i);
      if (runtime->revalidate(paths[i].id, request).idempotent) {
        ++completed;
      }
    }
    record("revalidate_unchanged_" + std::to_string(paths.size()) + "_paths", completed,
           timer.milliseconds());
  }

  void invalidate_link(const LinkId& link) {
    Timer timer;
    const InvalidationReport report = runtime->invalidate_link(link, LinkStateGeneration::from_value(9));
    record("invalidate_link_dependents", report.dependents(), timer.milliseconds());
  }

  void invalidate_capability() {
    Timer timer;
    const InvalidationReport report = runtime->invalidate_capability(
        "link-leaf-spine", CapabilityKey::parse("mtu"), CapabilityGeneration::from_value(9));
    record("invalidate_capability_dependents", report.dependents(), timer.milliseconds());
  }

  void invalidate_domain() {
    Timer timer;
    const InvalidationReport report = runtime->invalidate_failure_domain(
        FailureDomainId::parse("srlg-benchmark"), FailureDomainGeneration::from_value(3));
    record("invalidate_failure_domain_dependents", report.dependents(), timer.milliseconds());
  }

  void invalidate_epoch() {
    Timer timer;
    const InvalidationReport report = runtime->invalidate_epoch(CoordinatorEpoch::from_value(4));
    record("invalidate_epoch_paths", report.dependents(), timer.milliseconds());
  }

  void snapshot_and_digest() {
    {
      Timer timer;
      std::size_t completed = 0;
      for (const auto& path : paths) {
        const auto snapshot = runtime->query(path.id);
        if (snapshot.has_value()) {
          (void)snapshot->snapshot_digest();
          ++completed;
        }
      }
      record("snapshot_and_digest_" + std::to_string(paths.size()) + "_paths", completed,
             timer.milliseconds());
    }
    {
      Timer timer;
      std::size_t completed = 0;
      for (const auto& path : paths) {
        (void)path.semantic_digest();
        ++completed;
      }
      record("path_digest_" + std::to_string(paths.size()) + "_paths", completed,
             timer.milliseconds());
    }
  }

  void store_round_trip() {
    const std::filesystem::path store =
        std::filesystem::path(kRoot) / "benchmark-store.pauth";
    std::error_code error;
    std::filesystem::create_directories(store.parent_path(), error);
    const DurableState state = runtime->export_state();
    {
      Timer timer;
      write_store(state, store, Limits::defaults());
      record("persistence_save_" + std::to_string(state.records.size()) + "_records",
             state.records.size(), timer.milliseconds());
    }
    {
      Timer timer;
      const DurableState loaded = read_store(store, Limits::defaults());
      record("persistence_load_" + std::to_string(loaded.records.size()) + "_records",
             loaded.records.size(), timer.milliseconds());
    }
    std::filesystem::remove(store, error);
  }
};

void run_population(std::size_t population, bool include_persistence) {
  Bench bench(population);
  std::cout << "population=" << population << " classification=SYNTHETIC\n";
  bench.authorize();
  bench.query();
  bench.revalidate_unchanged();
  bench.snapshot_and_digest();
  if (include_persistence) {
    bench.store_round_trip();
  }
  bench.invalidate_link(LinkId::parse("link-leaf-spine"));
  bench.invalidate_capability();
  bench.invalidate_domain();
  bench.invalidate_epoch();
}

}  // namespace

int main() {
  std::cout << version_report();
  run_population(1000, true);
  run_population(10000, false);
  run_population(100000, false);

  double total_operations = 0.0;
  for (const auto& measurement : g_measurements) {
    total_operations += static_cast<double>(measurement.operations);
  }
  std::cout << "measurements=" << g_measurements.size()
            << " completed_operations=" << static_cast<std::uint64_t>(total_operations) << "\n";
  return 0;
}
