// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include <string>
#include <vector>

#include "fixture.hpp"
#include "path_authority/path_authority.hpp"

using namespace path_authority;
using pa_fixture::Fabric;

namespace {

// A malformed or incomplete buffer must never be accepted as a frame: it is
// either reported as an error or reported as needing more bytes.
bool decode_fails(const std::vector<std::byte>& bytes, std::string& reason) {
  std::size_t consumed = 0;
  std::string error;
  const auto frame = decode_frame(bytes, Limits::defaults(), consumed, error);
  if (frame.has_value()) {
    return false;
  }
  reason = error;
  return true;
}

template <class Encode, class Decode>
bool round_trips(Encode encode, Decode decode) {
  try {
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace

PA_TEST(frame_round_trips_and_covers_header_and_payload) {
  Frame frame;
  frame.type = MessageType::HEARTBEAT;
  frame.payload = {std::byte{1}, std::byte{2}, std::byte{3}};
  const auto bytes = encode_frame(frame, Limits::defaults());
  std::size_t consumed = 0;
  std::string error;
  const auto decoded = decode_frame(bytes, Limits::defaults(), consumed, error);
  PA_REQUIRE(decoded.has_value());
  PA_CHECK(error.empty());
  PA_CHECK_EQ(consumed, bytes.size());
  PA_CHECK_EQ(static_cast<std::uint16_t>(decoded->type),
              static_cast<std::uint16_t>(MessageType::HEARTBEAT));
  PA_CHECK(decoded->payload == frame.payload);

  for (std::size_t i = 0; i < bytes.size(); ++i) {
    std::vector<std::byte> corrupted = bytes;
    corrupted[i] ^= std::byte{0x80};
    std::string reason;
    PA_CHECK(decode_fails(corrupted, reason));
  }
}

PA_TEST(frame_decoding_rejects_malformed_input) {
  std::string reason;
  PA_CHECK(decode_fails({}, reason));
  PA_CHECK(decode_fails(std::vector<std::byte>(4, std::byte{'P'}), reason));

  Frame frame;
  frame.type = MessageType::QUERY;
  const auto bytes = encode_frame(frame, Limits::defaults());

  std::vector<std::byte> bad_magic = bytes;
  bad_magic[0] = std::byte{'Z'};
  PA_CHECK(decode_fails(bad_magic, reason));

  std::vector<std::byte> bad_version = bytes;
  bad_version[4] = std::byte{9};
  PA_CHECK(decode_fails(bad_version, reason));

  std::vector<std::byte> bad_type = bytes;
  bad_type[6] = std::byte{0x7f};
  PA_CHECK(decode_fails(bad_type, reason));

  std::vector<std::byte> bad_flags = bytes;
  bad_flags[8] = std::byte{1};
  PA_CHECK(decode_fails(bad_flags, reason));

  std::vector<std::byte> oversized = bytes;
  oversized[10] = std::byte{0xff};
  oversized[11] = std::byte{0xff};
  oversized[12] = std::byte{0xff};
  oversized[13] = std::byte{0xff};
  PA_CHECK(decode_fails(oversized, reason));

  // A partial frame is not an error: it simply needs more bytes.
  std::size_t consumed = 0;
  std::string error;
  const std::vector<std::byte> partial(bytes.begin(), bytes.begin() + 6);
  PA_CHECK(!decode_frame(partial, Limits::defaults(), consumed, error).has_value());
  PA_CHECK(error.empty());
}

PA_TEST(frame_encoding_enforces_the_frame_bound) {
  Limits limits;
  limits.max_frame_bytes = 16;
  Frame frame;
  frame.type = MessageType::PUBLISH;
  frame.payload.assign(64, std::byte{7});
  bool rejected = false;
  try {
    (void)encode_frame(frame, limits);
  } catch (const DecodeError&) {
    rejected = true;
  }
  PA_CHECK(rejected);
}

PA_TEST(register_message_round_trips) {
  RegisterRequest request;
  request.envelope.epoch = CoordinatorEpoch::from_value(3);
  request.envelope.scope = ScopeId::parse("fabric");
  request.envelope.publisher = PublisherId::parse("evaluator-a");
  request.envelope.worker_boot = WorkerBootId::parse("boot-a");
  request.agent = "path-authority-evaluator";
  const auto payload = encode_register_request(request);
  const RegisterRequest decoded = decode_register_request(payload, Limits::defaults());
  PA_CHECK_EQ(decoded.envelope.worker_boot.str(), std::string("boot-a"));
  PA_CHECK_EQ(decoded.envelope.epoch.value(), std::uint64_t{3});
  PA_CHECK_EQ(decoded.agent, std::string("path-authority-evaluator"));

  std::vector<std::byte> extended = payload;
  extended.push_back(std::byte{0});
  bool rejected = false;
  try {
    (void)decode_register_request(extended, Limits::defaults());
  } catch (const DecodeError&) {
    rejected = true;
  }
  PA_CHECK(rejected);
}

PA_TEST(publish_message_round_trips_with_full_fidelity) {
  Fabric fabric;
  const EvaluationResult local = fabric.evaluate("wire-publish");
  PA_REQUIRE(local.committed);

  PublishRequest request;
  request.envelope.epoch = local.epoch;
  request.envelope.scope = ScopeId::parse("test-scope");
  request.envelope.publisher = PublisherId::parse("evaluator-a");
  request.envelope.worker_boot = WorkerBootId::parse("boot-a");
  request.envelope.attempt = pa_fixture::attempt("wire-attempt");
  request.path = fabric.definition;
  request.state = local.state;
  request.primary = local.primary;
  request.evidence = local.evidence;
  request.path_digest = local.path_digest;
  request.authority_digest = local.authority_digest;
  request.constraint_digest = fabric.constraints.digest();
  request.constraint_generation = fabric.constraints.generation;
  request.secondary = local.secondary;

  const auto payload = encode_publish_request(request);
  const PublishRequest decoded = decode_publish_request(payload, Limits::defaults());
  PA_CHECK(decoded.authority_digest == request.authority_digest);
  PA_CHECK(decoded.path_digest == request.path_digest);
  PA_CHECK(decoded.evidence == request.evidence);
  PA_CHECK_EQ(decoded.path.id.str(), request.path.id.str());
  PA_CHECK_EQ(decoded.path.hops.size(), request.path.hops.size());
  PA_CHECK_EQ(static_cast<std::uint16_t>(decoded.primary),
              static_cast<std::uint16_t>(request.primary));
}

PA_TEST(acknowledgement_and_query_messages_round_trip) {
  PublishAck ack;
  ack.accepted = true;
  ack.outcome = EvaluationOutcome::AUTHORIZED;
  ack.state = AuthorityState::AUTHORIZED;
  ack.authority_generation = PathAuthorityGeneration::from_value(4);
  ack.epoch = CoordinatorEpoch::from_value(2);
  ack.authority_digest = Digest::of("authority");
  ack.detail = "committed";
  const PublishAck decoded_ack = decode_publish_ack(encode_publish_ack(ack), Limits::defaults());
  PA_CHECK(decoded_ack.accepted);
  PA_CHECK_EQ(decoded_ack.authority_generation.value(), std::uint64_t{4});
  PA_CHECK(decoded_ack.authority_digest == ack.authority_digest);

  QueryResult result;
  result.found = true;
  result.state = AuthorityState::REVALIDATION_REQUIRED;
  result.outcome = EvaluationOutcome::REVALIDATION_REQUIRED;
  result.authority_generation = PathAuthorityGeneration::from_value(5);
  result.epoch = CoordinatorEpoch::from_value(2);
  result.policy = PolicyGeneration::from_value(3);
  result.current = false;
  result.detail = "not current";
  const QueryResult decoded_result =
      decode_query_result(encode_query_result(result), Limits::defaults());
  PA_CHECK_EQ(decoded_result.state, AuthorityState::REVALIDATION_REQUIRED);
  PA_CHECK(!decoded_result.current);
  PA_CHECK_EQ(decoded_result.policy.value(), std::uint64_t{3});
}

PA_TEST(undefined_enumerations_in_payloads_are_rejected) {
  QueryResult result;
  result.found = true;
  result.state = AuthorityState::AUTHORIZED;
  const auto payload = encode_query_result(result);

  // The state byte sits after the found flag and the outcome word.
  std::vector<std::byte> corrupted = payload;
  corrupted[1] = std::byte{0x7f};
  bool rejected = false;
  try {
    (void)decode_query_result(corrupted, Limits::defaults());
  } catch (const DecodeError&) {
    rejected = true;
  }
  PA_CHECK(rejected);
}

PA_TEST(worker_list_round_trips_in_deterministic_order) {
  WorkersResult result;
  result.epoch = CoordinatorEpoch::from_value(6);
  result.fenced = 2;
  for (const char* name : {"evaluator-a", "evaluator-b"}) {
    WorkerInfo worker;
    worker.publisher = PublisherId::parse(name);
    worker.worker_boot = WorkerBootId::parse(std::string(name) + "-boot");
    worker.scope = ScopeId::parse("fabric");
    worker.epoch = CoordinatorEpoch::from_value(6);
    worker.published = 3;
    result.workers.push_back(worker);
  }
  const WorkersResult decoded = decode_workers_result(encode_workers_result(result), Limits::defaults());
  PA_REQUIRE(decoded.workers.size() == 2);
  PA_CHECK_EQ(decoded.workers.front().publisher.str(), std::string("evaluator-a"));
  PA_CHECK_EQ(decoded.fenced, std::size_t{2});
}

PA_TEST_MAIN()
