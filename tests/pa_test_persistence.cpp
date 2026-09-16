// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "path_authority/path_authority.hpp"

using namespace path_authority;
using pa_fixture::attempt;
using pa_fixture::Fabric;

namespace {

constexpr std::string_view kRoot = PATH_AUTHORITY_TEST_TEMP_ROOT;

std::filesystem::path unique_store(const std::string& name) {
  return pa_test::unique_test_path(name).string().append(".pauth");
}

std::vector<std::byte> read_bytes(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  std::vector<std::byte> bytes;
  char chunk = 0;
  while (stream.get(chunk)) {
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(chunk)));
  }
  return bytes;
}

void write_bytes(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
}

bool rejects(const std::vector<std::byte>& image) {
  try {
    (void)decode_durable_state(image, Limits::defaults());
  } catch (const std::exception&) {
    return true;
  }
  return false;
}

}  // namespace

PA_TEST(durable_state_round_trips_through_an_atomic_store) {
  Fabric fabric;
  fabric.evaluate("persist-1");
  const std::filesystem::path store = unique_store("round-trip");
  const DurableState exported = fabric.runtime->export_state();
  write_store(exported, store, Limits::defaults());
  PA_CHECK(std::filesystem::exists(store));

  const DurableState loaded = read_store(store, Limits::defaults());
  PA_CHECK_EQ(loaded.records.size(), exported.records.size());
  PA_CHECK_EQ(loaded.epoch.value(), exported.epoch.value());
  PA_CHECK(loaded.digest() == exported.digest());

  const PersistenceInfo info = inspect_store(store, Limits::defaults());
  PA_CHECK(info.readable);
  PA_CHECK_EQ(info.record_count, std::size_t{1});
  PA_CHECK_EQ(info.authorizing, std::size_t{1});
  std::filesystem::remove(store);
}

PA_TEST(recovery_never_resurrects_live_authority) {
  Fabric fabric;
  fabric.evaluate("recovery-1");
  const std::filesystem::path store = unique_store("recovery");
  write_store(fabric.runtime->export_state(), store, Limits::defaults());

  Fabric recovered;
  recovered.runtime = nullptr;
  recovered.runtime = std::make_unique<PathAuthorityRuntime>(recovered.evidence.sources());
  recovered.runtime->import_state(read_store(store, Limits::defaults()));

  const auto snapshot = recovered.runtime->query(fabric.definition.id);
  PA_REQUIRE(snapshot.has_value());
  PA_CHECK_EQ(snapshot->state, AuthorityState::REVALIDATION_REQUIRED);
  PA_CHECK_EQ(snapshot->authority_generation.value(), std::uint64_t{2});
  PA_CHECK(!snapshot->current);

  // A durable revocation survives recovery and is still a revocation.
  RevocationRequest request;
  request.attempt = attempt("recovery-revoke");
  request.reason = RevocationReason::ADMINISTRATIVE;
  request.explanation = "withdrawn";
  request.authority = "test";
  (void)fabric.runtime->revoke(fabric.definition.id, request);
  write_store(fabric.runtime->export_state(), store, Limits::defaults());
  Fabric revoked;
  revoked.runtime = nullptr;
  revoked.runtime = std::make_unique<PathAuthorityRuntime>(revoked.evidence.sources());
  revoked.runtime->import_state(read_store(store, Limits::defaults()));
  const auto revoked_snapshot = revoked.runtime->query(fabric.definition.id);
  PA_REQUIRE(revoked_snapshot.has_value());
  PA_CHECK_EQ(revoked_snapshot->state, AuthorityState::REVOKED);
  PA_CHECK(revoked_snapshot->revocation.has_value());
  std::filesystem::remove(store);
}

PA_TEST(every_failure_domain_constraint_kind_round_trips) {
  Fabric fabric;
  for (const auto kind :
       {FailureDomainConstraintKind::FORBIDDEN_DOMAIN,
        FailureDomainConstraintKind::MAX_MEMBERS_FROM_DOMAIN,
        FailureDomainConstraintKind::MAX_MEMBERS_FROM_CLASS,
        FailureDomainConstraintKind::EXCLUDE_DOMAIN_CLASS,
        FailureDomainConstraintKind::REQUIRE_COVERAGE_COMPLETENESS,
        FailureDomainConstraintKind::DIVERSE_FROM_PEER_PATH}) {
    ConstraintSet set = fabric.constraints;
    set.id = ConstraintSetId::parse(std::string("round-trip-") + std::string(to_string(kind)));
    set.generation = ConstraintGeneration::from_value(1);
    FailureDomainConstraint constraint;
    constraint.kind = kind;
    constraint.domain = FailureDomainId::parse("srlg-round-trip");
    constraint.domain_class = DomainClassKind::SHARED_RISK_LINK_GROUP;
    constraint.max_members = 3;
    constraint.diversity_classes = {DomainClassKind::POWER, DomainClassKind::RACK};
    if (kind == FailureDomainConstraintKind::DIVERSE_FROM_PEER_PATH) {
      constraint.peer.path = PathId::parse("path-peer");
      constraint.peer.authority_generation = PathAuthorityGeneration::from_value(4);
    }
    set.failure_domains.push_back(constraint);
    const Digest expected = set.digest();
    const auto bytes = encode_constraint_set(set);
    ByteReader reader(bytes, Limits::defaults());
    const ConstraintSet decoded = decode_constraint_set(reader);
    PA_CHECK_EQ(decoded.failure_domains.size(), std::size_t{1});
    PA_CHECK_EQ(static_cast<int>(decoded.failure_domains.front().kind), static_cast<int>(kind));
    PA_CHECK_EQ(decoded.failure_domains.front().max_members, std::uint32_t{3});
    PA_CHECK(decoded.digest() == expected);
  }
}

PA_TEST(durable_encoding_is_deterministic_and_insertion_order_stable) {
  Fabric fabric;
  fabric.evaluate("determinism-1");
  const DurableState first = fabric.runtime->export_state();
  const DurableState second = fabric.runtime->export_state();
  const auto first_bytes = encode_durable_state(first, Limits::defaults());
  const auto second_bytes = encode_durable_state(second, Limits::defaults());
  PA_CHECK(first_bytes == second_bytes);
  PA_CHECK(first.digest() == second.digest());
}

PA_TEST(corrupt_store_images_are_rejected) {
  Fabric fabric;
  fabric.evaluate("corrupt-1");
  const auto image = encode_durable_state(fabric.runtime->export_state(), Limits::defaults());
  PA_CHECK(!rejects(image));

  PA_CHECK(rejects({}));
  PA_CHECK(rejects(std::vector<std::byte>(8, std::byte{0})));

  std::vector<std::byte> bad_magic = image;
  bad_magic[0] = std::byte{'X'};
  PA_CHECK(rejects(bad_magic));

  std::vector<std::byte> bad_version = image;
  bad_version[8] = std::byte{9};
  PA_CHECK(rejects(bad_version));

  std::vector<std::byte> trailing = image;
  trailing.push_back(std::byte{1});
  PA_CHECK(rejects(trailing));

  std::vector<std::byte> flipped = image;
  flipped[flipped.size() / 2] ^= std::byte{0x40};
  PA_CHECK(rejects(flipped));

  std::vector<std::byte> bad_checksum = image;
  bad_checksum.back() ^= std::byte{0xff};
  PA_CHECK(rejects(bad_checksum));

  // Sweep truncation positions: every shortened image must be rejected safely.
  for (std::size_t cut = 1; cut < image.size(); cut += 3) {
    std::vector<std::byte> truncated(image.begin(),
                                     image.begin() + static_cast<std::ptrdiff_t>(cut));
    PA_CHECK(rejects(truncated));
  }
}

PA_TEST(duplicate_and_impossible_records_are_rejected) {
  Fabric fabric;
  fabric.evaluate("duplicate-1");
  DurableState state = fabric.runtime->export_state();
  DurableState duplicated = state;
  duplicated.records.push_back(duplicated.records.front());
  const auto image = encode_durable_state(duplicated, Limits::defaults());
  PA_CHECK(rejects(image));

  DurableState impossible = state;
  impossible.records.front().authority_generation = PathAuthorityGeneration{};
  // Encoding an unset generation produces a zero field that decoding rejects.
  PA_CHECK(rejects(encode_durable_state(impossible, Limits::defaults())));
}

PA_TEST(dangling_underlying_dependency_is_rejected) {
  Fabric fabric;
  fabric.evaluate("dangling-1");
  DurableState state = fabric.runtime->export_state();
  PathDefinition definition = state.records.front().definition;
  definition.type = PathType::LOGICAL;
  UnderlyingPathRef underlying;
  underlying.path = PathId::parse("path-absent-underlying");
  underlying.authority_generation = PathAuthorityGeneration::from_value(1);
  underlying.nesting_depth = 1;
  definition.underlying = underlying;
  definition.id = definition.derived_id();
  state.records.front().definition = definition;
  PA_CHECK(rejects(encode_durable_state(state, Limits::defaults())));
}

PA_TEST(write_store_replaces_atomically_and_leaves_no_temporary_file) {
  Fabric fabric;
  const std::filesystem::path store = unique_store("atomic");
  write_store(fabric.runtime->export_state(), store, Limits::defaults());
  fabric.evaluate("atomic-1");
  write_store(fabric.runtime->export_state(), store, Limits::defaults());

  const PersistenceInfo info = inspect_store(store, Limits::defaults());
  PA_CHECK(info.readable);
  PA_CHECK_EQ(info.record_count, std::size_t{1});

  std::size_t temporaries = 0;
  const std::string prefix = store.filename().string() + ".tmp-";
  for (const auto& entry : std::filesystem::directory_iterator(store.parent_path())) {
    if (entry.path().filename().string().rfind(prefix, 0) == 0) {
      ++temporaries;
    }
  }
  PA_CHECK_EQ(temporaries, std::size_t{0});
  std::filesystem::remove(store);
}

PA_TEST(inspect_reports_the_problem_for_a_corrupt_store) {
  const std::filesystem::path store = unique_store("inspect-bad");
  write_bytes(store, std::vector<std::byte>(64, std::byte{0x5a}));
  const PersistenceInfo info = inspect_store(store, Limits::defaults());
  PA_CHECK(!info.readable);
  PA_CHECK(!info.problem.empty());
  std::filesystem::remove(store);
}

PA_TEST(import_state_rejects_malformed_durable_values) {
  Fabric fabric;
  DurableState state = fabric.runtime->export_state();
  state.format_version = 99;
  bool rejected = false;
  try {
    fabric.runtime->import_state(state);
  } catch (const PersistenceError&) {
    rejected = true;
  }
  PA_CHECK(rejected);

  DurableState no_epoch = fabric.runtime->export_state();
  no_epoch.epoch = CoordinatorEpoch{};
  rejected = false;
  try {
    fabric.runtime->import_state(no_epoch);
  } catch (const PersistenceError&) {
    rejected = true;
  }
  PA_CHECK(rejected);
}

PA_TEST_MAIN()
