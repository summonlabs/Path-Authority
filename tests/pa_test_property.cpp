// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <algorithm>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "path_authority/path_authority.hpp"

using namespace path_authority;
using pa_fixture::attempt;
using pa_fixture::Fabric;

namespace {

// Seeded randomized population. The seed is reported when a property fails so
// the exact population can be replayed.
struct Population {
  Fabric fabric;
  std::vector<PathDefinition> paths;
  std::mt19937_64 engine;

  explicit Population(std::uint64_t seed) : engine(seed) {
    for (int i = 0; i < 64; ++i) {
      PathDefinition path = fabric.definition;
      path.generation = PathGeneration::from_value(static_cast<std::uint64_t>(i) + 1);
      path.id = path.derived_id();
      paths.push_back(path);
    }
  }

  std::uint64_t next(std::uint64_t bound) { return engine() % bound; }
};

}  // namespace

PA_TEST(property_authorized_paths_never_reference_a_down_link) {
  Population population(0x5eed1234ULL);
  for (std::size_t i = 0; i < population.paths.size(); ++i) {
    const bool down = population.next(4) == 0;
    population.fabric.set_link("link-2", down ? LinkState::DOWN : LinkState::UP,
                               static_cast<std::uint64_t>(i) + 2);
    const EvaluationResult result = population.fabric.runtime->evaluate(
        population.paths[i], population.fabric.request("property-" + std::to_string(i)));
    if (result.authorizing()) {
      const auto link = population.fabric.evidence.link_state.link("link-2");
      PA_REQUIRE(link.has_value());
      PA_CHECK(link->state != LinkState::DOWN);
      PA_CHECK(link->state != LinkState::FAULTED);
      PA_CHECK_EQ(result.evidence.find(EvidenceKind::LINK_STATE, "LINK:link-2").value_or(0),
                  link->generation.value());
    }
  }
}

PA_TEST(property_authority_generations_are_monotonic_per_path) {
  Population population(0xabcdef01ULL);
  std::vector<std::uint64_t> last(population.paths.size(), 0);
  for (int round = 0; round < 6; ++round) {
    for (std::size_t i = 0; i < population.paths.size(); ++i) {
      const bool down = population.next(3) == 0;
      population.fabric.set_link("link-1", down ? LinkState::DOWN : LinkState::UP,
                                 static_cast<std::uint64_t>(round * 100 + i) + 2);
      const EvaluationResult result = population.fabric.runtime->evaluate(
          population.paths[i],
          population.fabric.request("monotonic-" + std::to_string(round) + "-" + std::to_string(i)));
      PA_CHECK(result.authority_generation.value() >= last[i]);
      last[i] = result.authority_generation.value();
      if (result.idempotent) {
        PA_CHECK_EQ(result.authority_generation.value(), last[i]);
      }
    }
  }
}

PA_TEST(property_idempotent_replay_never_advances_or_changes_state) {
  Population population(0x1234567ULL);
  for (std::size_t i = 0; i < population.paths.size(); ++i) {
    const EvaluationResult first = population.fabric.runtime->evaluate(
        population.paths[i], population.fabric.request("replay-first-" + std::to_string(i)));
    const EvaluationResult second = population.fabric.runtime->evaluate(
        population.paths[i], population.fabric.request("replay-second-" + std::to_string(i)));
    PA_CHECK_EQ(second.primary, EvaluationOutcome::IDEMPOTENT);
    PA_CHECK_EQ(second.authority_generation.value(), first.authority_generation.value());
    PA_CHECK_EQ(static_cast<int>(second.state), static_cast<int>(first.state));
    PA_CHECK(second.authority_digest == first.authority_digest);
  }
}

PA_TEST(property_revoked_paths_never_return_authorized) {
  Population population(0xfeedbeefULL);
  for (std::size_t i = 0; i < 16; ++i) {
    const EvaluationResult first = population.fabric.runtime->evaluate(
        population.paths[i], population.fabric.request("revoke-first-" + std::to_string(i)));
    PA_REQUIRE(first.authorizing());
    RevocationRequest request;
    request.attempt = attempt("revoke-" + std::to_string(i));
    request.reason = RevocationReason::ADMINISTRATIVE;
    request.explanation = "population withdrawal";
    request.authority = "property-test";
    (void)population.fabric.runtime->revoke(population.paths[i].id, request);
    for (int round = 0; round < 3; ++round) {
      const EvaluationResult after = population.fabric.runtime->evaluate(
          population.paths[i], population.fabric.request("revoked-replay-" + std::to_string(i) + "-" +
                                                         std::to_string(round)));
      PA_CHECK(!after.authorizing());
      PA_CHECK_EQ(after.primary, EvaluationOutcome::REVOKED);
    }
    const auto snapshot = population.fabric.runtime->query(population.paths[i].id);
    PA_REQUIRE(snapshot.has_value());
    PA_CHECK_EQ(snapshot->state, AuthorityState::REVOKED);
  }
}

PA_TEST(property_persistence_round_trips_and_never_resurrects_authority) {
  Population population(0x99887766ULL);
  for (std::size_t i = 0; i < 8; ++i) {
    (void)population.fabric.runtime->evaluate(
        population.paths[i], population.fabric.request("persist-prop-" + std::to_string(i)));
  }
  const DurableState state = population.fabric.runtime->export_state();
  const Digest before = state.digest();
  const auto image = encode_durable_state(state, Limits::defaults());
  const DurableState decoded = decode_durable_state(image, Limits::defaults());
  PA_CHECK(decoded.digest() == before);

  Fabric recovered;
  recovered.runtime = nullptr;
  recovered.runtime = std::make_unique<PathAuthorityRuntime>(recovered.evidence.sources());
  recovered.runtime->import_state(decoded);
  for (std::size_t i = 0; i < 8; ++i) {
    const auto snapshot = recovered.runtime->query(population.paths[i].id);
    PA_REQUIRE(snapshot.has_value());
    PA_CHECK_EQ(snapshot->state, AuthorityState::REVALIDATION_REQUIRED);
    PA_CHECK(!snapshot->current);
  }
}

PA_TEST(property_digests_are_deterministic_and_content_bound) {
  Population population(0x2468ace0ULL);
  for (std::size_t i = 0; i < population.paths.size(); ++i) {
    const Digest first = population.paths[i].semantic_digest();
    PathDefinition copy = population.paths[i];
    PA_CHECK(copy.semantic_digest() == first);
    if (i + 1 < population.paths.size()) {
      PA_CHECK(!(population.paths[i + 1].semantic_digest() == first));
    }
  }
}

PA_TEST(property_indexes_match_records_after_random_invalidation) {
  Population population(0x13572468ULL);
  for (std::size_t i = 0; i < population.paths.size(); ++i) {
    (void)population.fabric.runtime->evaluate(
        population.paths[i], population.fabric.request("index-prop-" + std::to_string(i)));
  }
  const RuntimeStats before = population.fabric.runtime->stats();
  PA_CHECK_EQ(before.paths, population.paths.size());

  for (int round = 0; round < 8; ++round) {
    const std::string link = population.next(2) == 0 ? "link-1" : "link-2";
    (void)population.fabric.runtime->invalidate_link(
        LinkId::parse(link), LinkStateGeneration::from_value(static_cast<std::uint64_t>(round) + 2));
  }
  const auto dependents = population.fabric.runtime->dependents_of_element(ElementKind::LINK, "link-1");
  PA_CHECK_EQ(dependents.size(), population.paths.size());
  for (const auto& path : dependents) {
    const auto snapshot = population.fabric.runtime->query(path);
    PA_REQUIRE(snapshot.has_value());
    PA_CHECK_EQ(snapshot->state, AuthorityState::REVALIDATION_REQUIRED);
  }
}

PA_TEST_MAIN()
