// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/wire.hpp"

#include <array>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "path_authority/version.hpp"

namespace path_authority {
namespace {

constexpr std::array<char, 4> kFrameMagic = {'P', 'A', 'F', '1'};
constexpr std::size_t kFrameHeaderBytes = kFrameMagic.size() + 2 + 2 + 2 + 4;
constexpr std::size_t kFrameChecksumBytes = Digest::kBytes;

std::string read_identity(ByteReader& reader, std::size_t max_length) {
  return reader.length_prefixed(static_cast<std::uint32_t>(max_length));
}

PathId read_path_id(ByteReader& reader) {
  const auto parsed = PathId::from_wire(read_identity(reader, 96));
  if (!parsed.has_value()) {
    throw DecodeError("malformed PathId in protocol payload");
  }
  return *parsed;
}

CapabilityKey read_capability_key(ByteReader& reader) {
  const auto parsed = CapabilityKey::from_wire(read_identity(reader, 64));
  if (!parsed.has_value()) {
    throw DecodeError("malformed capability key in protocol payload");
  }
  return *parsed;
}

std::optional<PathAuthorityGeneration> read_optional_generation(ByteReader& reader) {
  if (!reader.boolean()) {
    return std::nullopt;
  }
  const auto parsed = PathAuthorityGeneration::from_wire(reader.u64());
  if (!parsed.has_value()) {
    throw DecodeError("unset authority generation in protocol payload");
  }
  return parsed;
}

void write_optional_generation(ByteWriter& writer,
                               const std::optional<PathAuthorityGeneration>& generation) {
  writer.boolean(generation.has_value());
  if (generation.has_value()) {
    writer.u64(generation->value());
  }
}

PathDefinition read_embedded_path(ByteReader& reader) {
  const std::string bytes = reader.length_prefixed(reader.limits().max_frame_bytes);
  ByteReader path_reader(
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()),
      reader.limits());
  return decode_path(path_reader);
}

void write_embedded_path(ByteWriter& writer, const PathDefinition& path) {
  const std::vector<std::byte> bytes = encode_path(path);
  writer.length_prefixed(
      std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
}

EvidenceVector read_evidence(ByteReader& reader) {
  const std::string bytes = reader.length_prefixed(reader.limits().max_frame_bytes);
  ByteReader evidence_reader(
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()),
      reader.limits());
  return decode_evidence_vector(evidence_reader);
}

void write_evidence(ByteWriter& writer, const EvidenceVector& evidence) {
  const std::vector<std::byte> bytes = encode_evidence_vector(evidence);
  writer.length_prefixed(
      std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
}

AuthorityState read_state(ByteReader& reader) {
  const std::uint8_t raw = reader.u8();
  if (!is_defined_authority_state(raw)) {
    throw DecodeError("undefined authority state in protocol payload");
  }
  return static_cast<AuthorityState>(raw);
}

EvaluationOutcome read_outcome(ByteReader& reader) {
  const std::uint16_t raw = reader.u16();
  if (!is_defined_evaluation_outcome(raw)) {
    throw DecodeError("undefined evaluation outcome in protocol payload");
  }
  return static_cast<EvaluationOutcome>(raw);
}

Violation read_violation(ByteReader& reader) {
  Violation violation;
  violation.code = read_outcome(reader);
  const std::uint8_t severity = reader.u8();
  if (severity > static_cast<std::uint8_t>(ViolationSeverity::INFORMATIONAL)) {
    throw DecodeError("undefined violation severity in protocol payload");
  }
  violation.severity = static_cast<ViolationSeverity>(severity);
  violation.subject = reader.length_prefixed(reader.limits().max_metadata_bytes);
  violation.detail = reader.length_prefixed(reader.limits().max_metadata_bytes);
  return violation;
}

std::vector<Violation> read_violation_list(ByteReader& reader) {
  const std::uint32_t count = reader.u32();
  if (count > reader.limits().max_explanation_entries) {
    throw DecodeError("violation list exceeds Limits::max_explanation_entries");
  }
  std::vector<Violation> violations;
  violations.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    violations.push_back(read_violation(reader));
  }
  return violations;
}

void write_violation(ByteWriter& writer, const Violation& violation) {
  writer.u16(static_cast<std::uint16_t>(violation.code));
  writer.u8(static_cast<std::uint8_t>(violation.severity));
  writer.length_prefixed(violation.subject);
  writer.length_prefixed(violation.detail);
}

void write_violation_list(ByteWriter& writer, const std::vector<Violation>& violations) {
  writer.u32(static_cast<std::uint32_t>(violations.size()));
  for (const auto& violation : violations) {
    write_violation(writer, violation);
  }
}

}  // namespace

std::string_view to_string(MessageType type) noexcept {
  switch (type) {
    case MessageType::HELLO: return "HELLO";
    case MessageType::HELLO_ACK: return "HELLO_ACK";
    case MessageType::REGISTER: return "REGISTER";
    case MessageType::REGISTER_ACK: return "REGISTER_ACK";
    case MessageType::PUBLISH: return "PUBLISH";
    case MessageType::PUBLISH_ACK: return "PUBLISH_ACK";
    case MessageType::REVALIDATE: return "REVALIDATE";
    case MessageType::REVALIDATE_ACK: return "REVALIDATE_ACK";
    case MessageType::REVOKE: return "REVOKE";
    case MessageType::REVOKE_ACK: return "REVOKE_ACK";
    case MessageType::INVALIDATE: return "INVALIDATE";
    case MessageType::INVALIDATE_ACK: return "INVALIDATE_ACK";
    case MessageType::QUERY: return "QUERY";
    case MessageType::QUERY_RESULT: return "QUERY_RESULT";
    case MessageType::WORKERS: return "WORKERS";
    case MessageType::WORKERS_RESULT: return "WORKERS_RESULT";
    case MessageType::HEARTBEAT: return "HEARTBEAT";
    case MessageType::HEARTBEAT_ACK: return "HEARTBEAT_ACK";
    case MessageType::SHUTDOWN: return "SHUTDOWN";
    case MessageType::PROTOCOL_ERROR: return "PROTOCOL_ERROR";
  }
  return "INVALID";
}

std::optional<MessageType> message_type_from_string(std::string_view text) noexcept {
  for (std::uint16_t raw = 1; raw <= 20; ++raw) {
    const auto candidate = static_cast<MessageType>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_defined_message_type(std::uint16_t raw) noexcept { return raw >= 1 && raw <= 20; }

std::vector<std::byte> encode_frame(const Frame& frame, const Limits& limits) {
  if (!is_defined_message_type(static_cast<std::uint16_t>(frame.type))) {
    throw DecodeError("cannot encode an undefined message type");
  }
  if (frame.flags != 0) {
    throw DecodeError("cannot encode a frame with reserved flags set");
  }
  if (frame.payload.size() > limits.max_frame_bytes) {
    throw DecodeError("frame payload exceeds Limits::max_frame_bytes");
  }
  ByteWriter writer;
  for (char c : kFrameMagic) {
    writer.u8(static_cast<std::uint8_t>(c));
  }
  writer.u16(frame.version);
  writer.u16(static_cast<std::uint16_t>(frame.type));
  writer.u16(frame.flags);
  writer.u32(static_cast<std::uint32_t>(frame.payload.size()));
  writer.bytes(frame.payload);
  writer.digest(sha256(writer.data()));
  return std::move(writer).take();
}

std::optional<Frame> decode_frame(std::span<const std::byte> buffer, const Limits& limits,
                                  std::size_t& consumed, std::string& error) {
  consumed = 0;
  error.clear();
  if (buffer.size() < kFrameHeaderBytes) {
    return std::nullopt;
  }
  for (std::size_t i = 0; i < kFrameMagic.size(); ++i) {
    if (static_cast<char>(buffer[i]) != kFrameMagic[i]) {
      error = "frame magic mismatch";
      return std::nullopt;
    }
  }
  ByteReader header(buffer.subspan(kFrameMagic.size(), 2 + 2 + 2 + 4), limits);
  const std::uint16_t version = header.u16();
  if (version != kWireProtocolVersion) {
    error = "unsupported wire protocol version " + std::to_string(version);
    return std::nullopt;
  }
  const std::uint16_t type = header.u16();
  if (!is_defined_message_type(type)) {
    error = "undefined message type " + std::to_string(type);
    return std::nullopt;
  }
  const std::uint16_t flags = header.u16();
  if (flags != 0) {
    error = "reserved frame flags must be zero";
    return std::nullopt;
  }
  const std::uint32_t payload_length = header.u32();
  if (payload_length > limits.max_frame_bytes) {
    error = "frame payload exceeds Limits::max_frame_bytes";
    return std::nullopt;
  }
  const std::size_t total = kFrameHeaderBytes + payload_length + kFrameChecksumBytes;
  if (buffer.size() < total) {
    return std::nullopt;
  }
  const Digest actual = sha256(buffer.first(total - kFrameChecksumBytes));
  std::array<std::byte, Digest::kBytes> declared_bytes{};
  std::copy(buffer.begin() + static_cast<std::ptrdiff_t>(total - kFrameChecksumBytes),
            buffer.begin() + static_cast<std::ptrdiff_t>(total), declared_bytes.begin());
  if (!(actual == Digest::from_bytes(declared_bytes))) {
    error = "frame integrity check failed";
    return std::nullopt;
  }
  Frame frame;
  frame.version = version;
  frame.type = static_cast<MessageType>(type);
  frame.flags = flags;
  frame.payload.assign(buffer.begin() + static_cast<std::ptrdiff_t>(kFrameHeaderBytes),
                       buffer.begin() + static_cast<std::ptrdiff_t>(kFrameHeaderBytes + payload_length));
  consumed = total;
  return frame;
}

std::vector<std::byte> encode_envelope(const WireEnvelope& envelope) {
  ByteWriter writer;
  writer.u32(kCanonicalEncodingVersion);
  writer.u64(envelope.epoch.value());
  writer.length_prefixed(envelope.scope.view());
  writer.length_prefixed(envelope.publisher.view());
  writer.length_prefixed(envelope.worker_boot.view());
  writer.length_prefixed(envelope.attempt.view());
  return std::move(writer).take();
}

WireEnvelope decode_envelope(ByteReader& reader) {
  const std::uint32_t version = reader.u32();
  if (version != kCanonicalEncodingVersion) {
    throw DecodeError("unsupported canonical encoding version in protocol payload");
  }
  WireEnvelope envelope;
  const auto epoch = CoordinatorEpoch::from_wire(reader.u64());
  if (!epoch.has_value()) {
    throw DecodeError("unset CoordinatorEpoch in protocol payload");
  }
  envelope.epoch = *epoch;
  const auto scope = ScopeId::from_wire(read_identity(reader, 64));
  if (!scope.has_value()) {
    throw DecodeError("malformed scope in protocol payload");
  }
  envelope.scope = *scope;
  const auto publisher = PublisherId::from_wire(read_identity(reader, 64));
  if (!publisher.has_value()) {
    throw DecodeError("malformed publisher identity in protocol payload");
  }
  envelope.publisher = *publisher;
  const auto boot = WorkerBootId::from_wire(read_identity(reader, 64));
  if (!boot.has_value()) {
    throw DecodeError("malformed worker boot identity in protocol payload");
  }
  envelope.worker_boot = *boot;
  const std::string attempt = read_identity(reader, 96);
  if (!attempt.empty()) {
    const auto parsed = MutationAttemptId::from_wire(attempt);
    if (!parsed.has_value()) {
      throw DecodeError("malformed mutation attempt identity in protocol payload");
    }
    envelope.attempt = *parsed;
  }
  return envelope;
}

std::vector<std::byte> encode_register_request(const RegisterRequest& message) {
  ByteWriter writer;
  writer.bytes(encode_envelope(message.envelope));
  writer.length_prefixed(message.agent);
  return std::move(writer).take();
}

RegisterRequest decode_register_request(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  RegisterRequest message;
  message.envelope = decode_envelope(reader);
  message.agent = reader.length_prefixed(limits.max_metadata_bytes);
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_register_ack(const RegisterAck& message) {
  ByteWriter writer;
  writer.boolean(message.accepted);
  writer.u64(message.epoch.value());
  writer.u64(message.policy.value());
  writer.length_prefixed(message.detail);
  return std::move(writer).take();
}

RegisterAck decode_register_ack(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  RegisterAck message;
  message.accepted = reader.boolean();
  const auto epoch = CoordinatorEpoch::from_wire(reader.u64());
  if (!epoch.has_value()) {
    throw DecodeError("unset epoch in register acknowledgement");
  }
  message.epoch = *epoch;
  const auto policy = PolicyGeneration::from_wire(reader.u64());
  if (!policy.has_value()) {
    throw DecodeError("unset policy generation in register acknowledgement");
  }
  message.policy = *policy;
  message.detail = reader.length_prefixed(limits.max_metadata_bytes);
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_publish_request(const PublishRequest& message) {
  ByteWriter writer;
  writer.bytes(encode_envelope(message.envelope));
  write_embedded_path(writer, message.path);
  writer.u8(static_cast<std::uint8_t>(message.state));
  writer.u16(static_cast<std::uint16_t>(message.primary));
  write_evidence(writer, message.evidence);
  writer.digest(message.path_digest);
  writer.digest(message.authority_digest);
  writer.digest(message.constraint_digest);
  writer.u64(message.constraint_generation.value());
  write_violation(writer, message.primary_violation);
  write_violation_list(writer, message.secondary);
  write_optional_generation(writer, message.expected_authority_generation);
  return std::move(writer).take();
}

PublishRequest decode_publish_request(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  PublishRequest message;
  message.envelope = decode_envelope(reader);
  message.path = read_embedded_path(reader);
  message.state = read_state(reader);
  message.primary = read_outcome(reader);
  message.evidence = read_evidence(reader);
  message.path_digest = reader.digest();
  message.authority_digest = reader.digest();
  message.constraint_digest = reader.digest();
  const auto constraint_generation = ConstraintGeneration::from_wire(reader.u64());
  if (!constraint_generation.has_value()) {
    throw DecodeError("unset constraint generation in publish request");
  }
  message.constraint_generation = *constraint_generation;
  message.primary_violation = read_violation(reader);
  message.secondary = read_violation_list(reader);
  message.expected_authority_generation = read_optional_generation(reader);
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_publish_ack(const PublishAck& message) {
  ByteWriter writer;
  writer.boolean(message.accepted);
  writer.u16(static_cast<std::uint16_t>(message.outcome));
  writer.u8(static_cast<std::uint8_t>(message.state));
  writer.u64(message.authority_generation.value());
  writer.u64(message.epoch.value());
  writer.digest(message.authority_digest);
  writer.length_prefixed(message.detail);
  return std::move(writer).take();
}

PublishAck decode_publish_ack(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  PublishAck message;
  message.accepted = reader.boolean();
  message.outcome = read_outcome(reader);
  message.state = read_state(reader);
  message.authority_generation = PathAuthorityGeneration::from_wire(reader.u64()).value_or(
      PathAuthorityGeneration{});
  message.epoch = CoordinatorEpoch::from_wire(reader.u64()).value_or(CoordinatorEpoch{});
  message.authority_digest = reader.digest();
  message.detail = reader.length_prefixed(limits.max_metadata_bytes);
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_path_request(const PathRequest& message) {
  ByteWriter writer;
  writer.bytes(encode_envelope(message.envelope));
  writer.length_prefixed(message.path.view());
  write_optional_generation(writer, message.expected_authority_generation);
  return std::move(writer).take();
}

PathRequest decode_path_request(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  PathRequest message;
  message.envelope = decode_envelope(reader);
  message.path = read_path_id(reader);
  message.expected_authority_generation = read_optional_generation(reader);
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_revoke_request(const RevokeRequest& message) {
  ByteWriter writer;
  writer.bytes(encode_envelope(message.envelope));
  writer.length_prefixed(message.path.view());
  writer.u8(static_cast<std::uint8_t>(message.reason));
  writer.length_prefixed(message.explanation);
  writer.length_prefixed(message.authority);
  write_optional_generation(writer, message.expected_authority_generation);
  return std::move(writer).take();
}

RevokeRequest decode_revoke_request(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  RevokeRequest message;
  message.envelope = decode_envelope(reader);
  message.path = read_path_id(reader);
  const std::uint8_t reason = reader.u8();
  if (!is_defined_revocation_reason(reason)) {
    throw DecodeError("undefined revocation reason in revoke request");
  }
  message.reason = static_cast<RevocationReason>(reason);
  message.explanation = reader.length_prefixed(limits.max_metadata_bytes);
  message.authority = reader.length_prefixed(limits.max_metadata_bytes);
  message.expected_authority_generation = read_optional_generation(reader);
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_result_ack(const ResultAck& message) {
  ByteWriter writer;
  writer.boolean(message.accepted);
  writer.u16(static_cast<std::uint16_t>(message.outcome));
  writer.u8(static_cast<std::uint8_t>(message.state));
  writer.u64(message.authority_generation.value());
  writer.u64(message.epoch.value());
  writer.digest(message.authority_digest);
  writer.boolean(message.idempotent);
  writer.length_prefixed(message.detail);
  return std::move(writer).take();
}

ResultAck decode_result_ack(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  ResultAck message;
  message.accepted = reader.boolean();
  message.outcome = read_outcome(reader);
  message.state = read_state(reader);
  message.authority_generation = PathAuthorityGeneration::from_wire(reader.u64()).value_or(
      PathAuthorityGeneration{});
  message.epoch = CoordinatorEpoch::from_wire(reader.u64()).value_or(CoordinatorEpoch{});
  message.authority_digest = reader.digest();
  message.idempotent = reader.boolean();
  message.detail = reader.length_prefixed(limits.max_metadata_bytes);
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_query_request(const QueryRequest& message) {
  ByteWriter writer;
  writer.length_prefixed(message.path.view());
  return std::move(writer).take();
}

QueryRequest decode_query_request(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  QueryRequest message;
  message.path = read_path_id(reader);
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_query_result(const QueryResult& message) {
  ByteWriter writer;
  writer.boolean(message.found);
  writer.u8(static_cast<std::uint8_t>(message.state));
  writer.u16(static_cast<std::uint16_t>(message.outcome));
  writer.u64(message.authority_generation.value());
  writer.u64(message.epoch.value());
  writer.u64(message.policy.value());
  writer.digest(message.authority_digest);
  writer.boolean(message.current);
  writer.length_prefixed(message.detail);
  return std::move(writer).take();
}

QueryResult decode_query_result(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  QueryResult message;
  message.found = reader.boolean();
  message.state = read_state(reader);
  message.outcome = read_outcome(reader);
  message.authority_generation = PathAuthorityGeneration::from_wire(reader.u64()).value_or(
      PathAuthorityGeneration{});
  message.epoch = CoordinatorEpoch::from_wire(reader.u64()).value_or(CoordinatorEpoch{});
  message.policy = PolicyGeneration::from_wire(reader.u64()).value_or(PolicyGeneration{});
  message.authority_digest = reader.digest();
  message.current = reader.boolean();
  message.detail = reader.length_prefixed(limits.max_metadata_bytes);
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_workers_result(const WorkersResult& message) {
  ByteWriter writer;
  writer.u64(message.epoch.value());
  writer.u32(static_cast<std::uint32_t>(message.fenced));
  writer.u32(static_cast<std::uint32_t>(message.workers.size()));
  for (const auto& worker : message.workers) {
    writer.length_prefixed(worker.publisher.view());
    writer.length_prefixed(worker.worker_boot.view());
    writer.length_prefixed(worker.scope.view());
    writer.u64(worker.epoch.value());
    writer.u32(static_cast<std::uint32_t>(worker.published));
  }
  return std::move(writer).take();
}

WorkersResult decode_workers_result(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  WorkersResult message;
  message.epoch = CoordinatorEpoch::from_wire(reader.u64()).value_or(CoordinatorEpoch{});
  message.fenced = reader.u32();
  const std::uint32_t count = reader.u32();
  if (count > limits.max_batch) {
    throw DecodeError("worker list exceeds Limits::max_batch");
  }
  message.workers.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    WorkerInfo worker;
    const auto publisher = PublisherId::from_wire(read_identity(reader, 64));
    if (!publisher.has_value()) {
      throw DecodeError("malformed publisher identity in worker list");
    }
    worker.publisher = *publisher;
    const auto boot = WorkerBootId::from_wire(read_identity(reader, 64));
    if (!boot.has_value()) {
      throw DecodeError("malformed worker boot identity in worker list");
    }
    worker.worker_boot = *boot;
    const auto scope = ScopeId::from_wire(read_identity(reader, 64));
    if (!scope.has_value()) {
      throw DecodeError("malformed scope in worker list");
    }
    worker.scope = *scope;
    worker.epoch = CoordinatorEpoch::from_wire(reader.u64()).value_or(CoordinatorEpoch{});
    worker.published = reader.u32();
    message.workers.push_back(std::move(worker));
  }
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_invalidate_notice(const InvalidateNotice& message) {
  ByteWriter writer;
  writer.u8(static_cast<std::uint8_t>(message.cause));
  writer.length_prefixed(message.subject);
  writer.u64(message.generation);
  writer.u32(static_cast<std::uint32_t>(message.affected));
  writer.u64(message.epoch.value());
  return std::move(writer).take();
}

InvalidateNotice decode_invalidate_notice(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  InvalidateNotice message;
  const std::uint8_t cause = reader.u8();
  if (!is_defined_invalidation_cause(cause)) {
    throw DecodeError("undefined invalidation cause in notice");
  }
  message.cause = static_cast<InvalidationCause>(cause);
  message.subject = reader.length_prefixed(limits.max_metadata_bytes);
  message.generation = reader.u64();
  message.affected = reader.u32();
  message.epoch = CoordinatorEpoch::from_wire(reader.u64()).value_or(CoordinatorEpoch{});
  reader.require_end();
  return message;
}

std::vector<std::byte> encode_error_message(const ErrorMessage& message) {
  ByteWriter writer;
  writer.u16(message.code);
  writer.length_prefixed(message.detail);
  return std::move(writer).take();
}

ErrorMessage decode_error_message(std::span<const std::byte> payload, const Limits& limits) {
  ByteReader reader(payload, limits);
  ErrorMessage message;
  message.code = reader.u16();
  message.detail = reader.length_prefixed(limits.max_metadata_bytes);
  reader.require_end();
  return message;
}

}  // namespace path_authority
