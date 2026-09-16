// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "path_authority/authority.hpp"
#include "path_authority/canonical.hpp"
#include "path_authority/export.hpp"
#include "path_authority/limits.hpp"
#include "path_authority/version.hpp"

namespace path_authority {

// Framed protocol. Frame layout:
//   magic        4 bytes  "PAF1"
//   version      u16      kWireProtocolVersion
//   message id   u16      MessageType
//   flags        u16      reserved, must be 0
//   payload len  u32      bounded by Limits::max_frame_bytes
//   payload      bytes    per-message canonical encoding
//   sha256       32 bytes over every preceding byte of the frame
//
// The integrity check spans the header and the payload, so a corrupted
// version, message id, length or body is rejected before any decoding.
enum class MessageType : std::uint16_t {
  HELLO = 1,
  HELLO_ACK = 2,
  REGISTER = 3,
  REGISTER_ACK = 4,
  PUBLISH = 5,
  PUBLISH_ACK = 6,
  REVALIDATE = 7,
  REVALIDATE_ACK = 8,
  REVOKE = 9,
  REVOKE_ACK = 10,
  INVALIDATE = 11,
  INVALIDATE_ACK = 12,
  QUERY = 13,
  QUERY_RESULT = 14,
  WORKERS = 15,
  WORKERS_RESULT = 16,
  HEARTBEAT = 17,
  HEARTBEAT_ACK = 18,
  SHUTDOWN = 19,
  PROTOCOL_ERROR = 20,
};

PATH_AUTHORITY_API std::string_view to_string(MessageType type) noexcept;
PATH_AUTHORITY_API std::optional<MessageType> message_type_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API bool is_defined_message_type(std::uint16_t raw) noexcept;

struct PATH_AUTHORITY_API Frame {
  std::uint16_t version = kWireProtocolVersion;
  MessageType type = MessageType::PROTOCOL_ERROR;
  std::uint16_t flags = 0;
  std::vector<std::byte> payload;
};

PATH_AUTHORITY_API std::vector<std::byte> encode_frame(const Frame& frame, const Limits& limits);
// Returns nullopt when the buffer does not yet contain a whole frame; with
// consumed set to the frame length on success.
PATH_AUTHORITY_API std::optional<Frame> decode_frame(std::span<const std::byte> buffer,
                                                     const Limits& limits,
                                                     std::size_t& consumed,
                                                     std::string& error);

// ---------------------------------------------------------------------------
// Message payloads
// ---------------------------------------------------------------------------
struct PATH_AUTHORITY_API WireEnvelope {
  CoordinatorEpoch epoch;
  ScopeId scope;
  PublisherId publisher;
  WorkerBootId worker_boot;
  MutationAttemptId attempt;
};

struct PATH_AUTHORITY_API RegisterRequest {
  WireEnvelope envelope;
  std::string agent;
};

struct PATH_AUTHORITY_API RegisterAck {
  bool accepted = false;
  CoordinatorEpoch epoch;
  PolicyGeneration policy;
  std::string detail;
};

struct PATH_AUTHORITY_API PublishRequest {
  WireEnvelope envelope;
  PathDefinition path;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome primary = EvaluationOutcome::MALFORMED_PATH;
  EvidenceVector evidence;
  Digest path_digest;
  Digest authority_digest;
  Digest constraint_digest;
  ConstraintGeneration constraint_generation;
  // Structured detail of the primary reason plus every further violation. The
  // semantic authority digest is computed over their codes, so a tampered
  // violation set cannot reproduce the digest.
  Violation primary_violation;
  std::vector<Violation> secondary;
  std::optional<PathAuthorityGeneration> expected_authority_generation;
};

struct PATH_AUTHORITY_API PublishAck {
  bool accepted = false;
  EvaluationOutcome outcome = EvaluationOutcome::MALFORMED_PATH;
  AuthorityState state = AuthorityState::UNKNOWN;
  PathAuthorityGeneration authority_generation;
  CoordinatorEpoch epoch;
  Digest authority_digest;
  std::string detail;
};

struct PATH_AUTHORITY_API PathRequest {
  WireEnvelope envelope;
  PathId path;
  std::optional<PathAuthorityGeneration> expected_authority_generation;
};

struct PATH_AUTHORITY_API RevokeRequest {
  WireEnvelope envelope;
  PathId path;
  RevocationReason reason = RevocationReason::ADMINISTRATIVE;
  std::string explanation;
  std::string authority;
  std::optional<PathAuthorityGeneration> expected_authority_generation;
};

struct PATH_AUTHORITY_API ResultAck {
  bool accepted = false;
  EvaluationOutcome outcome = EvaluationOutcome::MALFORMED_PATH;
  AuthorityState state = AuthorityState::UNKNOWN;
  PathAuthorityGeneration authority_generation;
  CoordinatorEpoch epoch;
  Digest authority_digest;
  bool idempotent = false;
  std::string detail;
};

struct PATH_AUTHORITY_API QueryRequest {
  PathId path;
};

struct PATH_AUTHORITY_API QueryResult {
  bool found = false;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome outcome = EvaluationOutcome::MALFORMED_PATH;
  PathAuthorityGeneration authority_generation;
  CoordinatorEpoch epoch;
  PolicyGeneration policy;
  Digest authority_digest;
  bool current = false;
  std::string detail;
};

struct PATH_AUTHORITY_API WorkerInfo {
  PublisherId publisher;
  WorkerBootId worker_boot;
  ScopeId scope;
  CoordinatorEpoch epoch;
  std::size_t published = 0;
};

struct PATH_AUTHORITY_API WorkersResult {
  std::vector<WorkerInfo> workers;
  std::size_t fenced = 0;
  CoordinatorEpoch epoch;
};

struct PATH_AUTHORITY_API InvalidateNotice {
  InvalidationCause cause = InvalidationCause::LINK_STATE_CHANGE;
  std::string subject;
  std::uint64_t generation = 0;
  std::size_t affected = 0;
  CoordinatorEpoch epoch;
};

struct PATH_AUTHORITY_API ErrorMessage {
  std::uint16_t code = 0;
  std::string detail;
};

// Payload codecs. Decoding is bounded and rejects trailing bytes.
PATH_AUTHORITY_API std::vector<std::byte> encode_envelope(const WireEnvelope& envelope);
PATH_AUTHORITY_API WireEnvelope decode_envelope(ByteReader& reader);

PATH_AUTHORITY_API std::vector<std::byte> encode_register_request(const RegisterRequest& message);
PATH_AUTHORITY_API RegisterRequest decode_register_request(std::span<const std::byte> payload,
                                                          const Limits& limits);
PATH_AUTHORITY_API std::vector<std::byte> encode_register_ack(const RegisterAck& message);
PATH_AUTHORITY_API RegisterAck decode_register_ack(std::span<const std::byte> payload,
                                                  const Limits& limits);

PATH_AUTHORITY_API std::vector<std::byte> encode_publish_request(const PublishRequest& message);
PATH_AUTHORITY_API PublishRequest decode_publish_request(std::span<const std::byte> payload,
                                                        const Limits& limits);
PATH_AUTHORITY_API std::vector<std::byte> encode_publish_ack(const PublishAck& message);
PATH_AUTHORITY_API PublishAck decode_publish_ack(std::span<const std::byte> payload,
                                                const Limits& limits);

PATH_AUTHORITY_API std::vector<std::byte> encode_path_request(const PathRequest& message);
PATH_AUTHORITY_API PathRequest decode_path_request(std::span<const std::byte> payload,
                                                  const Limits& limits);
PATH_AUTHORITY_API std::vector<std::byte> encode_revoke_request(const RevokeRequest& message);
PATH_AUTHORITY_API RevokeRequest decode_revoke_request(std::span<const std::byte> payload,
                                                      const Limits& limits);
PATH_AUTHORITY_API std::vector<std::byte> encode_result_ack(const ResultAck& message);
PATH_AUTHORITY_API ResultAck decode_result_ack(std::span<const std::byte> payload,
                                              const Limits& limits);

PATH_AUTHORITY_API std::vector<std::byte> encode_query_request(const QueryRequest& message);
PATH_AUTHORITY_API QueryRequest decode_query_request(std::span<const std::byte> payload,
                                                    const Limits& limits);
PATH_AUTHORITY_API std::vector<std::byte> encode_query_result(const QueryResult& message);
PATH_AUTHORITY_API QueryResult decode_query_result(std::span<const std::byte> payload,
                                                  const Limits& limits);

PATH_AUTHORITY_API std::vector<std::byte> encode_workers_result(const WorkersResult& message);
PATH_AUTHORITY_API WorkersResult decode_workers_result(std::span<const std::byte> payload,
                                                      const Limits& limits);

PATH_AUTHORITY_API std::vector<std::byte> encode_invalidate_notice(const InvalidateNotice& message);
PATH_AUTHORITY_API InvalidateNotice decode_invalidate_notice(std::span<const std::byte> payload,
                                                            const Limits& limits);
PATH_AUTHORITY_API std::vector<std::byte> encode_error_message(const ErrorMessage& message);
PATH_AUTHORITY_API ErrorMessage decode_error_message(std::span<const std::byte> payload,
                                                    const Limits& limits);

}  // namespace path_authority
