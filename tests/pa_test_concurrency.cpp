// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <atomic>
#include <barrier>
#include <string>
#include <thread>
#include <vector>

#include "fixture.hpp"
#include "path_authority/path_authority.hpp"

using namespace path_authority;
using pa_fixture::attempt;
using pa_fixture::Fabric;

namespace {

PathDefinition variant_of(const Fabric& fabric, std::uint64_t generation) {
  PathDefinition path = fabric.definition;
  path.generation = PathGeneration::from_value(generation);
  path.id = path.derived_id();
  return path;
}

// Recomputes the semantic authority digest from a snapshot and compares it with
// the digest the snapshot carries. A mismatch would prove an observation of a
// partially updated record.
bool snapshot_is_internally_consistent(const AuthoritySnapshot& snapshot,
                                       const Digest& constraint_digest) {
  AuthorityDigestInput input;
  input.path_digest = snapshot.path_digest;
  input.path_generation = snapshot.path_generation;
  input.constraint_digest = constraint_digest;
  input.constraint_generation = snapshot.constraint_generation;
  input.evidence_digest = snapshot.evidence.digest();
  input.policy = snapshot.policy;
  input.epoch = snapshot.epoch;
  input.state = snapshot.state;
  input.primary = snapshot.last_outcome;
  for (const auto& violation : snapshot.secondary) {
    input.secondary_codes.push_back(violation.code);
  }
  return input.compute() == snapshot.authority_digest;
}

}  // namespace

PA_TEST(revocation_wins_regardless_of_race_order) {
  for (int order = 0; order < 2; ++order) {
    Fabric fabric;
    const EvaluationResult initial = fabric.evaluate("race-initial");
    PA_REQUIRE(initial.authorizing());
    std::barrier gate(2);
    EvaluationResult evaluated;
    EvaluationResult revoked;

    std::thread evaluating([&]() {
      gate.arrive_and_wait();
      evaluated = fabric.evaluate("race-evaluate");
    });
    std::thread revoking([&]() {
      gate.arrive_and_wait();
      RevocationRequest request;
      request.attempt = attempt("race-revoke");
      request.reason = RevocationReason::ADMINISTRATIVE;
      request.explanation = "race withdrawal";
      request.authority = "race";
      revoked = fabric.runtime->revoke(fabric.definition.id, request);
    });
    evaluating.join();
    revoking.join();

    PA_CHECK_EQ(revoked.primary, EvaluationOutcome::REVOKED);
    if (order == 1) {
      PA_CHECK_EQ(evaluated.primary, EvaluationOutcome::REVOKED);
    }

    const auto snapshot = fabric.runtime->query(fabric.definition.id);
    PA_REQUIRE(snapshot.has_value());
    PA_CHECK_EQ(snapshot->state, AuthorityState::REVOKED);
    PA_CHECK(snapshot->revocation.has_value());

    const EvaluationResult after = fabric.evaluate("race-after");
    PA_CHECK_EQ(after.primary, EvaluationOutcome::REVOKED);
  }
}

PA_TEST(authorization_and_link_invalidation_racing_never_leaves_stale_authority) {
  for (int iteration = 0; iteration < 24; ++iteration) {
    Fabric fabric;
    std::barrier gate(2);
    EvaluationResult evaluated;
    std::thread evaluating([&]() {
      gate.arrive_and_wait();
      evaluated = fabric.evaluate("race-link-" + std::to_string(iteration));
    });
    std::thread invalidating([&]() {
      gate.arrive_and_wait();
      (void)fabric.runtime->invalidate_link(LinkId::parse("link-2"),
                                            LinkStateGeneration::from_value(2));
    });
    evaluating.join();
    invalidating.join();

    const auto snapshot = fabric.runtime->query(fabric.definition.id);
    if (!snapshot.has_value()) {
      // The invalidation landed while the evaluation was in flight, so the
      // commit was refused as stale and nothing was recorded.
      PA_CHECK_EQ(evaluated.primary, EvaluationOutcome::REVALIDATION_REQUIRED);
      continue;
    }
    PA_CHECK(snapshot->state == AuthorityState::REVALIDATION_REQUIRED ||
             snapshot->state == AuthorityState::AUTHORIZED);
    PA_CHECK(snapshot_is_internally_consistent(*snapshot, fabric.constraints.digest()));
    if (snapshot->state == AuthorityState::AUTHORIZED) {
      PA_CHECK(snapshot->current);
    }
  }
}

PA_TEST(concurrent_queries_never_observe_a_partially_updated_record) {
  Fabric fabric;
  fabric.evaluate("reader-0");
  std::atomic<bool> stop{false};
  std::atomic<int> observed{0};
  std::atomic<int> inconsistent{0};
  const Digest constraint_digest = fabric.constraints.digest();

  std::vector<std::thread> readers;
  for (int i = 0; i < 4; ++i) {
    readers.emplace_back([&]() {
      while (!stop.load()) {
        const auto snapshot = fabric.runtime->query(fabric.definition.id);
        if (!snapshot.has_value()) {
          continue;
        }
        observed.fetch_add(1);
        if (!snapshot_is_internally_consistent(*snapshot, constraint_digest)) {
          inconsistent.fetch_add(1);
        }
      }
    });
  }

  for (int i = 0; i < 40; ++i) {
    fabric.set_link("link-2", i % 2 == 0 ? LinkState::DOWN : LinkState::UP,
                    static_cast<std::uint64_t>(i) + 2);
    (void)fabric.runtime->evaluate(fabric.definition,
                                   fabric.request("writer-" + std::to_string(i)));
    (void)fabric.runtime->snapshots_all();
  }
  stop.store(true);
  for (auto& reader : readers) {
    reader.join();
  }
  PA_CHECK(observed.load() > 0);
  PA_CHECK_EQ(inconsistent.load(), 0);
}

PA_TEST(concurrent_independent_evaluations_all_commit) {
  Fabric fabric;
  constexpr int kThreads = 8;
  constexpr int kPerThread = 16;
  std::barrier gate(kThreads);
  std::atomic<int> authorized{0};
  std::vector<std::thread> workers;
  for (int t = 0; t < kThreads; ++t) {
    workers.emplace_back([&, t]() {
      gate.arrive_and_wait();
      for (int i = 0; i < kPerThread; ++i) {
        PathDefinition path =
            variant_of(fabric, static_cast<std::uint64_t>(t * kPerThread + i) + 1);
        const EvaluationResult result =
            fabric.runtime->evaluate(path, fabric.request("concurrent-" + std::to_string(t) + "-" +
                                                           std::to_string(i)));
        if (result.primary == EvaluationOutcome::AUTHORIZED) {
          authorized.fetch_add(1);
        }
      }
    });
  }
  for (auto& worker : workers) {
    worker.join();
  }
  PA_CHECK_EQ(authorized.load(), kThreads * kPerThread);
  const RuntimeStats stats = fabric.runtime->stats();
  PA_CHECK_EQ(stats.paths, static_cast<std::size_t>(kThreads * kPerThread));
  PA_CHECK_EQ(stats.authorizing, static_cast<std::size_t>(kThreads * kPerThread));
}

PA_TEST(concurrent_invalidation_storm_marks_every_dependent_path) {
  Fabric fabric;
  constexpr int kPaths = 128;
  for (int i = 0; i < kPaths; ++i) {
    PathDefinition path = variant_of(fabric, static_cast<std::uint64_t>(i) + 1);
    PA_CHECK(fabric.runtime->evaluate(path, fabric.request("storm-" + std::to_string(i))).committed);
  }

  std::vector<std::thread> invalidators;
  std::barrier gate(4);
  std::atomic<std::size_t> affected{0};
  for (int i = 0; i < 4; ++i) {
    invalidators.emplace_back([&, i]() {
      gate.arrive_and_wait();
      const InvalidationReport report = fabric.runtime->invalidate_link(
          LinkId::parse(i % 2 == 0 ? "link-1" : "link-2"),
          LinkStateGeneration::from_value(static_cast<std::uint64_t>(i) + 2));
      affected.fetch_add(report.revalidation_required.size());
    });
  }
  for (auto& invalidator : invalidators) {
    invalidator.join();
  }
  PA_CHECK_EQ(affected.load(), static_cast<std::size_t>(kPaths));

  const auto snapshots = fabric.runtime->snapshots_all();
  PA_CHECK_EQ(snapshots.size(), static_cast<std::size_t>(kPaths));
  std::size_t stale = 0;
  for (const auto& snapshot : snapshots) {
    if (snapshot.state == AuthorityState::REVALIDATION_REQUIRED) {
      ++stale;
    }
  }
  PA_CHECK_EQ(stale, static_cast<std::size_t>(kPaths));
}

PA_TEST(epoch_advance_racing_evaluation_never_yields_stale_authority) {
  for (int iteration = 0; iteration < 16; ++iteration) {
    Fabric fabric;
    std::barrier gate(2);
    std::thread evaluating([&]() {
      gate.arrive_and_wait();
      (void)fabric.evaluate("epoch-race-" + std::to_string(iteration));
    });
    std::thread advancing([&]() {
      gate.arrive_and_wait();
      const CoordinatorEpoch next = fabric.evidence.epoch.advance();
      (void)fabric.runtime->invalidate_epoch(next);
    });
    evaluating.join();
    advancing.join();

    const auto snapshot = fabric.runtime->query(fabric.definition.id);
    if (!snapshot.has_value()) {
      // The epoch advanced while the evaluation was in flight, so the commit
      // was refused as stale and no authority was recorded at all.
      continue;
    }
    if (snapshot->state == AuthorityState::AUTHORIZED) {
      PA_CHECK(snapshot->current);
      PA_CHECK_EQ(snapshot->epoch.value(), fabric.evidence.epoch.current().value());
    }
  }
}

PA_TEST(concurrent_snapshot_retention_is_bounded_and_consistent) {
  Fabric fabric;
  RuntimeConfig config;
  config.retain_snapshots = true;
  config.limits.max_history = 8;
  fabric.runtime = nullptr;
  fabric.runtime = std::make_unique<PathAuthorityRuntime>(fabric.evidence.sources(), config);
  const auto registration = fabric.runtime->register_constraint_set(fabric.constraints);
  fabric.constraints.generation = registration.generation;
  fabric.definition = fabric.build_definition(fabric.constraints);

  std::vector<std::thread> writers;
  for (int t = 0; t < 4; ++t) {
    writers.emplace_back([&, t]() {
      for (int i = 0; i < 8; ++i) {
        PathDefinition path =
            variant_of(fabric, static_cast<std::uint64_t>(t * 8 + i) + 1);
        (void)fabric.runtime->evaluate(path, fabric.request("snapshot-race-" + std::to_string(t) +
                                                            "-" + std::to_string(i)));
      }
    });
  }
  for (auto& writer : writers) {
    writer.join();
  }
  PA_CHECK_EQ(fabric.runtime->stats().paths, std::size_t{32});
}

PA_TEST_MAIN()
