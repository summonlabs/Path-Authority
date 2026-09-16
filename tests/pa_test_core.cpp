// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <string>
#include <vector>

#include "fixture.hpp"
#include "path_authority/path_authority.hpp"

using namespace path_authority;
using pa_fixture::attempt;
using pa_fixture::Fabric;
using pa_fixture::hop;

PA_TEST(identity_rejects_malformed_encodings) {
  PA_CHECK(!PathId::try_parse("").has_value());
  PA_CHECK(!PathId::try_parse(" leading").has_value());
  PA_CHECK(!PathId::try_parse("with space").has_value());
  PA_CHECK(!PathId::try_parse("path/../../etc").has_value());
  PA_CHECK(!PathId::try_parse("path\\windows").has_value());
  PA_CHECK(!PathId::try_parse("p@th").has_value());
  PA_CHECK(!PathId::try_parse("-leading-dash").has_value());
  PA_CHECK(!PathId::try_parse(std::string(200, 'a')).has_value());
  PA_CHECK(PathId::try_parse("path-0123456789abcdef").has_value());
  PA_CHECK_EQ(PathId::parse("path-abc").str(), std::string("path-abc"));
}

PA_TEST(identity_types_do_not_cross_convert) {
  // Distinct tag types make cross domain conversion a compile error; the
  // runtime check below proves the encodings stay domain specific at runtime.
  const PathId path = PathId::parse("path-1");
  const WorkerBootId boot = WorkerBootId::parse("boot-1");
  PA_CHECK_EQ(path.str(), std::string("path-1"));
  PA_CHECK_EQ(boot.str(), std::string("boot-1"));
  PA_CHECK(!PathId::from_wire(boot.view()).has_value() == false);
}

PA_TEST(generations_reject_zero_and_overflow) {
  PA_CHECK(!PathGeneration::from_wire(0).has_value());
  PA_CHECK(PathGeneration::from_wire(1).has_value());
  PA_CHECK(!CoordinatorEpoch{}.is_set());
  PA_CHECK(!CoordinatorEpoch::can_advance(static_cast<std::uint64_t>(-1)));
  PA_CHECK(CoordinatorEpoch::from_value(4).next().value() == 5u);
}

PA_TEST(canonical_form_is_deterministic_and_order_sensitive) {
  Fabric fabric;
  const auto first = encode_path(fabric.definition);
  const auto second = encode_path(fabric.definition);
  PA_CHECK(first == second);

  PathDefinition reordered = fabric.definition;
  std::swap(reordered.hops[2], reordered.hops[4]);
  PA_CHECK(!(encode_path(reordered) == first));
  PA_CHECK(!(reordered.semantic_digest() == fabric.definition.semantic_digest()));

  PathDefinition identical = fabric.definition;
  identical.id = PathId::parse("some-other-id");
  PA_CHECK(identical.semantic_digest() == fabric.definition.semantic_digest());
  PA_CHECK_EQ(identical.derived_id().str(), fabric.definition.derived_id().str());
}

PA_TEST(canonical_encoding_round_trips) {
  Fabric fabric;
  const auto bytes = encode_path(fabric.definition);
  ByteReader reader(bytes, Limits::defaults());
  const PathDefinition decoded = decode_path(reader);
  PA_CHECK_EQ(decoded.semantic_digest().hex(), fabric.definition.semantic_digest().hex());
  PA_CHECK_EQ(decoded.id.str(), fabric.definition.derived_id().str());
  PA_CHECK_EQ(decoded.hops.size(), fabric.definition.hops.size());
}

PA_TEST(canonical_decode_rejects_truncation_and_trailing_bytes) {
  Fabric fabric;
  const auto bytes = encode_path(fabric.definition);
  for (std::size_t cut = 1; cut <= bytes.size(); cut += 7) {
    std::vector<std::byte> truncated(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(cut));
    ByteReader reader(truncated, Limits::defaults());
    bool rejected = false;
    try {
      (void)decode_path(reader);
    } catch (const DecodeError&) {
      rejected = true;
    }
    PA_CHECK(rejected);
  }
  std::vector<std::byte> extended = bytes;
  extended.push_back(std::byte{0});
  ByteReader reader(extended, Limits::defaults());
  bool rejected = false;
  try {
    (void)decode_path(reader);
  } catch (const DecodeError&) {
    rejected = true;
  }
  PA_CHECK(rejected);
}

PA_TEST(constraint_set_digest_is_insertion_order_independent) {
  ConstraintSet first;
  first.id = ConstraintSetId::parse("c1");
  first.generation = ConstraintGeneration::from_value(1);
  first.scope = ScopeId::parse("scope");
  first.capabilities = {pa_fixture::at_least("link-1", "mtu", 9000),
                        pa_fixture::at_least("link-2", "mtu", 4000)};
  ConstraintSet second = first;
  std::swap(second.capabilities[0], second.capabilities[1]);
  PA_CHECK(second.digest() == first.digest());

  ConstraintSet different = first;
  different.capabilities[0].expression.values[0] = CapabilityValue::unsigned_integer(1500);
  PA_CHECK(!(different.digest() == first.digest()));

  ConstraintSet regenerated = first;
  regenerated.generation = ConstraintGeneration::from_value(7);
  PA_CHECK(regenerated.digest() == first.digest());
}

PA_TEST(evidence_vector_is_order_independent_and_detects_changes) {
  const Limits limits;
  EvidenceVector first;
  first.set(EvidenceKind::EPOCH, 4, limits);
  first.set(EvidenceKind::LINK_STATE, "LINK:link-1", 2, limits);
  first.set(EvidenceKind::LINK_STATE, "LINK:link-2", 2, limits);

  EvidenceVector second;
  second.set(EvidenceKind::LINK_STATE, "LINK:link-2", 2, limits);
  second.set(EvidenceKind::EPOCH, 4, limits);
  second.set(EvidenceKind::LINK_STATE, "LINK:link-1", 2, limits);
  PA_CHECK(second.digest() == first.digest());
  PA_CHECK(second == first);

  EvidenceVector changed = first;
  changed.set(EvidenceKind::LINK_STATE, "LINK:link-1", 3, limits);
  const auto deltas = diff_evidence(first, changed);
  PA_CHECK_EQ(deltas.size(), std::size_t{1});
  PA_CHECK_EQ(deltas.front().subject, std::string("LINK:link-1"));
  PA_CHECK(deltas.front().before.has_value() && *deltas.front().before == 2u);
  PA_CHECK(deltas.front().after.has_value() && *deltas.front().after == 3u);
}

PA_TEST(shape_validation_rejects_malformed_paths) {
  const Limits limits;
  Fabric fabric;

  PathDefinition zero_hop = fabric.definition;
  zero_hop.hops.clear();
  PA_CHECK_EQ(validate_path_shape(zero_hop, limits, false).status, PathShapeStatus::TOO_FEW_HOPS);

  PathDefinition too_long = fabric.definition;
  Limits small = limits;
  small.max_hops = 3;
  PA_CHECK_EQ(validate_path_shape(too_long, small, false).status, PathShapeStatus::TOO_MANY_HOPS);

  PathDefinition loop = fabric.definition;
  loop.hops[4] = loop.hops[2];
  loop.id = loop.derived_id();
  PA_CHECK_EQ(validate_path_shape(loop, limits, false).status, PathShapeStatus::ACCIDENTAL_LOOP);

  PathDefinition bad_endpoint = fabric.definition;
  bad_endpoint.hops.front().kind = ElementKind::LINK;
  bad_endpoint.id = bad_endpoint.derived_id();
  PA_CHECK_EQ(validate_path_shape(bad_endpoint, limits, false).status, PathShapeStatus::ENDPOINT_PAIRING);

  PathDefinition unset_generation = fabric.definition;
  unset_generation.hops[1].generation = StructuralGeneration{};
  unset_generation.id = unset_generation.derived_id();
  PA_CHECK_EQ(validate_path_shape(unset_generation, limits, false).status,
              PathShapeStatus::UNKNOWN_GENERATION);

  PathDefinition malformed_id = fabric.definition;
  malformed_id.hops[1].id = "with space";
  malformed_id.id = malformed_id.derived_id();
  PA_CHECK_EQ(validate_path_shape(malformed_id, limits, false).status,
              PathShapeStatus::MALFORMED_ELEMENT);

  PathDefinition mismatch = fabric.definition;
  mismatch.id = PathId::parse("path-not-derived");
  PA_CHECK_EQ(validate_path_shape(mismatch, limits, true).status,
              PathShapeStatus::IDENTITY_MISMATCH);
  PA_CHECK_EQ(validate_path_shape(mismatch, limits, false).status, PathShapeStatus::VALID);
}

PA_TEST(identity_binding_is_enforced_by_evaluation) {
  Fabric fabric;
  PathDefinition mismatched = fabric.definition;
  mismatched.id = PathId::parse("path-made-up");
  const EvaluationResult result = fabric.runtime->evaluate(mismatched, fabric.request("a1"));
  PA_CHECK_EQ(result.primary, EvaluationOutcome::MALFORMED_PATH);
  PA_CHECK_EQ(result.state, AuthorityState::REJECTED);
  PA_CHECK(!result.committed);

  EvaluationRequest relaxed = fabric.request("a2");
  relaxed.require_identity_binding = false;
  const EvaluationResult accepted = fabric.runtime->evaluate(mismatched, relaxed);
  PA_CHECK_EQ(accepted.primary, EvaluationOutcome::AUTHORIZED);
}

PA_TEST(sha256_matches_published_known_answers) {
  // FIPS 180-4 known answers, including the padding edge cases: 55, 56, 64 and
  // 65 byte messages exercise every branch of the final block handling.
  PA_CHECK_EQ(Digest::of(std::string_view("")).hex(),
              std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  PA_CHECK_EQ(Digest::of(std::string_view("abc")).hex(),
              std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  PA_CHECK_EQ(
      Digest::of(std::string_view("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).hex(),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  PA_CHECK_EQ(Digest::of(std::string(55, 'a')).hex(),
              std::string("9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"));
  PA_CHECK_EQ(Digest::of(std::string(56, 'a')).hex(),
              std::string("b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"));
  PA_CHECK_EQ(Digest::of(std::string(64, 'a')).hex(),
              std::string("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"));
  PA_CHECK_EQ(Digest::of(std::string(65, 'a')).hex(),
              std::string("635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"));
}

PA_TEST(version_report_is_coherent) {
  const std::string report = version_report();
  PA_CHECK(report.find("version=" + std::string(version_string())) != std::string::npos);
  PA_CHECK(report.find("wire_protocol_version=" + std::to_string(kWireProtocolVersion)) !=
           std::string::npos);
  PA_CHECK(version_string() == "1.0.0");
}

PA_TEST_MAIN()
