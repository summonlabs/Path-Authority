// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/persistence.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <fstream>
#include <random>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "path_authority/canonical.hpp"
#include "path_authority/version.hpp"

namespace path_authority {
namespace {

constexpr std::array<char, 8> kMagic = {'P', 'A', 'T', 'H', 'A', 'U', 'T', 'H'};
constexpr std::size_t kHeaderBytes = kMagic.size() + 4 + 8;
constexpr std::size_t kChecksumBytes = Digest::kBytes;

void write_history(ByteWriter& writer, const std::vector<HistoryEntry>& history) {
  writer.u32(static_cast<std::uint32_t>(history.size()));
  for (const auto& entry : history) {
    writer.u64(entry.generation.value());
    writer.u8(static_cast<std::uint8_t>(entry.state));
    writer.u16(static_cast<std::uint16_t>(entry.outcome));
    writer.length_prefixed(entry.cause);
    writer.u64(entry.epoch.value());
  }
}

std::vector<HistoryEntry> read_history(ByteReader& reader) {
  const Limits& limits = reader.limits();
  const std::uint32_t count = reader.u32();
  if (count > limits.max_history) {
    throw PersistenceError("durable history exceeds Limits::max_history");
  }
  std::vector<HistoryEntry> history;
  history.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    HistoryEntry entry;
    const auto generation = PathAuthorityGeneration::from_wire(reader.u64());
    if (!generation.has_value()) {
      throw PersistenceError("durable history entry has an unset authority generation");
    }
    entry.generation = *generation;
    const std::uint8_t state = reader.u8();
    if (!is_defined_authority_state(state)) {
      throw PersistenceError("durable history entry has an invalid authority state");
    }
    entry.state = static_cast<AuthorityState>(state);
    const std::uint16_t outcome = reader.u16();
    if (!is_defined_evaluation_outcome(outcome)) {
      throw PersistenceError("durable history entry has an invalid outcome");
    }
    entry.outcome = static_cast<EvaluationOutcome>(outcome);
    entry.cause = reader.length_prefixed(limits.max_metadata_bytes);
    const auto epoch = CoordinatorEpoch::from_wire(reader.u64());
    if (!epoch.has_value()) {
      throw PersistenceError("durable history entry has an unset epoch");
    }
    entry.epoch = *epoch;
    history.push_back(std::move(entry));
  }
  return history;
}

void write_record(ByteWriter& writer, const DurablePathRecord& record) {
  const std::vector<std::byte> path_bytes = encode_path(record.definition);
  writer.length_prefixed(std::string_view(reinterpret_cast<const char*>(path_bytes.data()),
                                          path_bytes.size()));
  writer.u64(record.authority_generation.value());
  writer.u8(static_cast<std::uint8_t>(record.state));
  writer.u16(static_cast<std::uint16_t>(record.outcome));
  const std::vector<std::byte> evidence_bytes = encode_evidence_vector(record.evidence);
  writer.length_prefixed(std::string_view(reinterpret_cast<const char*>(evidence_bytes.data()),
                                          evidence_bytes.size()));
  writer.digest(record.authority_digest);
  writer.boolean(record.revocation.has_value());
  if (record.revocation.has_value()) {
    writer.u8(static_cast<std::uint8_t>(record.revocation->reason));
    writer.length_prefixed(record.revocation->explanation);
    writer.u64(record.revocation->generation.value());
    writer.u64(record.revocation->epoch.value());
    writer.length_prefixed(record.revocation->authority);
    writer.length_prefixed(record.revocation->attempt.view());
    writer.boolean(record.revocation->durable);
  }
  write_history(writer, record.history);
  writer.boolean(record.retired);
  writer.length_prefixed(record.publisher.view());
  writer.length_prefixed(record.worker_boot.view());
}

DurablePathRecord read_record(ByteReader& reader) {
  const Limits& limits = reader.limits();
  DurablePathRecord record;
  const std::string path_bytes = reader.length_prefixed(limits.max_frame_bytes);
  {
    ByteReader path_reader(std::span<const std::byte>(reinterpret_cast<const std::byte*>(path_bytes.data()),
                                                       path_bytes.size()),
                           limits);
    record.definition = decode_path(path_reader);
  }
  const auto generation = PathAuthorityGeneration::from_wire(reader.u64());
  if (!generation.has_value()) {
    throw PersistenceError("durable path record has an unset authority generation");
  }
  record.authority_generation = *generation;
  const std::uint8_t state = reader.u8();
  if (!is_defined_authority_state(state)) {
    throw PersistenceError("durable path record has an invalid authority state");
  }
  record.state = static_cast<AuthorityState>(state);
  const std::uint16_t outcome = reader.u16();
  if (!is_defined_evaluation_outcome(outcome)) {
    throw PersistenceError("durable path record has an invalid outcome");
  }
  record.outcome = static_cast<EvaluationOutcome>(outcome);
  const std::string evidence_bytes = reader.length_prefixed(limits.max_frame_bytes);
  {
    ByteReader evidence_reader(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(evidence_bytes.data()),
                                   evidence_bytes.size()),
        limits);
    record.evidence = decode_evidence_vector(evidence_reader);
  }
  record.authority_digest = reader.digest();
  if (reader.boolean()) {
    RevocationRecord revocation;
    const std::uint8_t reason = reader.u8();
    if (!is_defined_revocation_reason(reason)) {
      throw PersistenceError("durable path record has an invalid revocation reason");
    }
    revocation.reason = static_cast<RevocationReason>(reason);
    revocation.explanation = reader.length_prefixed(limits.max_metadata_bytes);
    const auto revocation_generation = PathAuthorityGeneration::from_wire(reader.u64());
    if (!revocation_generation.has_value()) {
      throw PersistenceError("durable revocation has an unset generation");
    }
    revocation.generation = *revocation_generation;
    const auto revocation_epoch = CoordinatorEpoch::from_wire(reader.u64());
    if (!revocation_epoch.has_value()) {
      throw PersistenceError("durable revocation has an unset epoch");
    }
    revocation.epoch = *revocation_epoch;
    revocation.authority = reader.length_prefixed(limits.max_metadata_bytes);
    const auto attempt =
        MutationAttemptId::from_wire(reader.length_prefixed(limits.max_id_length));
    if (attempt.has_value()) {
      revocation.attempt = *attempt;
    }
    revocation.durable = reader.boolean();
    record.revocation = std::move(revocation);
  }
  const auto history = read_history(reader);
  record.history = history;
  record.retired = reader.boolean();
  const auto publisher = PublisherId::from_wire(reader.length_prefixed(limits.max_id_length));
  if (publisher.has_value()) {
    record.publisher = *publisher;
  }
  const auto boot = WorkerBootId::from_wire(reader.length_prefixed(limits.max_id_length));
  if (boot.has_value()) {
    record.worker_boot = *boot;
  }
  return record;
}

std::vector<std::byte> read_file(const std::filesystem::path& path, const Limits& limits) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  if (error) {
    throw PersistenceError("cannot stat store " + path.string() + ": " + error.message());
  }
  if (size > limits.max_store_bytes) {
    throw PersistenceError("store exceeds Limits::max_store_bytes");
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    throw PersistenceError("cannot open store " + path.string());
  }
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  if (size != 0) {
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
    if (stream.gcount() != static_cast<std::streamsize>(size)) {
      throw PersistenceError("store " + path.string() + " could not be read completely");
    }
  }
  return bytes;
}

}  // namespace

std::vector<std::byte> encode_durable_state(const DurableState& state, const Limits& limits) {
  if (state.format_version != kPersistenceFormatVersion) {
    throw PersistenceError("refusing to encode durable state with format version " +
                           std::to_string(state.format_version));
  }
  if (!state.epoch.is_set()) {
    throw PersistenceError("durable state requires a Fabric Epoch");
  }
  if (state.records.size() > limits.max_store_records) {
    throw PersistenceError("durable state exceeds Limits::max_store_records");
  }

  ByteWriter payload;
  payload.u32(state.format_version);
  payload.u64(state.epoch.value());
  const std::vector<std::byte> policy_bytes = encode_policy_set(state.policy);
  payload.length_prefixed(
      std::string_view(reinterpret_cast<const char*>(policy_bytes.data()), policy_bytes.size()));
  payload.u32(static_cast<std::uint32_t>(state.constraint_sets.size()));
  for (const auto& set : state.constraint_sets) {
    const std::vector<std::byte> set_bytes = encode_constraint_set(set);
    payload.length_prefixed(
        std::string_view(reinterpret_cast<const char*>(set_bytes.data()), set_bytes.size()));
  }
  payload.u32(static_cast<std::uint32_t>(state.records.size()));
  for (const auto& record : state.records) {
    write_record(payload, record);
  }
  payload.u32(static_cast<std::uint32_t>(state.fenced.size()));
  for (const auto& boot : state.fenced) {
    payload.length_prefixed(boot.view());
  }

  ByteWriter image;
  for (char c : kMagic) {
    image.u8(static_cast<std::uint8_t>(c));
  }
  image.u32(kPersistenceFormatVersion);
  image.u64(static_cast<std::uint64_t>(payload.size()));
  image.bytes(payload.data());
  const Digest checksum = sha256(image.data());
  image.digest(checksum);
  if (image.size() > limits.max_store_bytes) {
    throw PersistenceError("encoded store exceeds Limits::max_store_bytes");
  }
  return std::move(image).take();
}

DurableState decode_durable_state(std::span<const std::byte> image, const Limits& limits) {
  if (image.size() < kHeaderBytes + kChecksumBytes) {
    throw PersistenceError("store image is shorter than the mandatory header");
  }
  if (image.size() > limits.max_store_bytes) {
    throw PersistenceError("store image exceeds Limits::max_store_bytes");
  }
  for (std::size_t i = 0; i < kMagic.size(); ++i) {
    if (static_cast<char>(image[i]) != kMagic[i]) {
      throw PersistenceError("store image has a bad magic value");
    }
  }
  ByteReader header(image.subspan(kMagic.size(), 4 + 8), limits);
  const std::uint32_t version = header.u32();
  if (version != kPersistenceFormatVersion) {
    throw PersistenceError("store image has unsupported format version " +
                           std::to_string(version));
  }
  const std::uint64_t payload_length = header.u64();
  const std::uint64_t expected_size =
      static_cast<std::uint64_t>(kHeaderBytes) + payload_length + kChecksumBytes;
  if (expected_size != image.size()) {
    throw PersistenceError("store image length does not match its header (expected " +
                           std::to_string(expected_size) + " bytes, found " +
                           std::to_string(image.size()) + ")");
  }
  const Digest stored_checksum = sha256(image.first(image.size() - kChecksumBytes));
  std::array<std::byte, Digest::kBytes> checksum_bytes{};
  std::copy(image.end() - kChecksumBytes, image.end(), checksum_bytes.begin());
  if (!(stored_checksum == Digest::from_bytes(checksum_bytes))) {
    throw PersistenceError("store image failed its integrity check");
  }

  ByteReader payload(image.subspan(kHeaderBytes, static_cast<std::size_t>(payload_length)), limits);
  DurableState state;
  state.format_version = payload.u32();
  if (state.format_version != kPersistenceFormatVersion) {
    throw PersistenceError("store payload has an unsupported format version");
  }
  const auto epoch = CoordinatorEpoch::from_wire(payload.u64());
  if (!epoch.has_value()) {
    throw PersistenceError("store payload has an unset Fabric Epoch");
  }
  state.epoch = *epoch;
  {
    const std::string policy_bytes = payload.length_prefixed(limits.max_frame_bytes);
    ByteReader policy_reader(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(policy_bytes.data()),
                                   policy_bytes.size()),
        limits);
    state.policy = decode_policy_set(policy_reader);
  }
  const std::uint32_t constraint_count = payload.u32();
  if (constraint_count > limits.max_constraints) {
    throw PersistenceError("store payload constraint set count exceeds Limits::max_constraints");
  }
  std::set<std::string> constraint_ids;
  for (std::uint32_t i = 0; i < constraint_count; ++i) {
    const std::string set_bytes = payload.length_prefixed(limits.max_frame_bytes);
    ByteReader set_reader(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(set_bytes.data()),
                                   set_bytes.size()),
        limits);
    ConstraintSet set = decode_constraint_set(set_reader);
    if (!constraint_ids.insert(set.id.str()).second) {
      throw PersistenceError("duplicate constraint set in store image: " + set.id.str());
    }
    state.constraint_sets.push_back(std::move(set));
  }
  const std::uint32_t record_count = payload.u32();
  if (record_count > limits.max_store_records) {
    throw PersistenceError("store payload record count exceeds Limits::max_store_records");
  }
  std::set<std::string> path_ids;
  for (std::uint32_t i = 0; i < record_count; ++i) {
    DurablePathRecord record = read_record(payload);
    if (!path_ids.insert(record.definition.id.str()).second) {
      throw PersistenceError("duplicate PathId in store image: " + record.definition.id.str());
    }
    state.records.push_back(std::move(record));
  }
  const std::uint32_t fenced_count = payload.u32();
  if (fenced_count > limits.max_publishers) {
    throw PersistenceError("store payload fenced worker count exceeds Limits::max_publishers");
  }
  for (std::uint32_t i = 0; i < fenced_count; ++i) {
    const auto boot = WorkerBootId::from_wire(payload.length_prefixed(limits.max_id_length));
    if (!boot.has_value()) {
      throw PersistenceError("store payload has a malformed fenced worker identity");
    }
    state.fenced.push_back(*boot);
  }
  payload.require_end();

  for (const auto& record : state.records) {
    if (record.definition.underlying.has_value() &&
        !path_ids.count(record.definition.underlying->path.str())) {
      throw PersistenceError("store image has a dangling underlying path dependency: " +
                             record.definition.underlying->path.str());
    }
    if (record.definition.constraint_set.valid() &&
        !constraint_ids.count(record.definition.constraint_set.str())) {
      throw PersistenceError("store image references an absent constraint set: " +
                             record.definition.constraint_set.str());
    }
    if (record.retired && !record.authority_generation.is_set()) {
      throw PersistenceError("store image has a retired record without an authority generation");
    }
  }
  return state;
}

Digest DurableState::digest() const {
  ByteWriter writer;
  writer.u32(kDigestSchemeVersion);
  writer.u32(format_version);
  writer.u64(epoch.value());
  writer.digest(policy.digest());
  writer.u64(policy.generation.value());
  for (const auto& set : constraint_sets) {
    writer.digest(set.digest());
    writer.u64(set.generation.value());
  }
  for (const auto& boot : fenced) {
    writer.length_prefixed(boot.view());
  }
  for (const auto& record : records) {
    writer.digest(record.definition.semantic_digest());
    writer.u64(record.authority_generation.value());
    writer.u8(static_cast<std::uint8_t>(record.state));
    writer.u16(static_cast<std::uint16_t>(record.outcome));
    writer.digest(record.evidence.digest());
    writer.digest(record.authority_digest);
    writer.boolean(record.revocation.has_value());
    writer.boolean(record.retired);
  }
  return Digest::of(writer.data());
}

void write_store(const DurableState& state, const std::filesystem::path& path,
                 const Limits& limits) {
  const std::vector<std::byte> image = encode_durable_state(state, limits);
  const std::filesystem::path directory =
      path.has_parent_path() ? path.parent_path() : std::filesystem::path(".");
  std::error_code error;
  if (!std::filesystem::exists(directory, error) || error) {
    throw PersistenceError("store directory does not exist: " + directory.string());
  }
  if (std::filesystem::is_directory(path, error)) {
    throw PersistenceError("store path is a directory: " + path.string());
  }

  std::random_device device;
  const std::string suffix = std::to_string(device()) + "-" + std::to_string(device());
  const std::filesystem::path temporary =
      directory / (path.filename().string() + ".tmp-" + suffix);
  {
    std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
    if (!stream) {
      throw PersistenceError("cannot create temporary store " + temporary.string());
    }
    stream.write(reinterpret_cast<const char*>(image.data()),
                 static_cast<std::streamsize>(image.size()));
    stream.flush();
    if (!stream) {
      stream.close();
      std::filesystem::remove(temporary, error);
      throw PersistenceError("cannot write temporary store " + temporary.string());
    }
  }
  std::filesystem::rename(temporary, path, error);
  if (error) {
    std::error_code cleanup_error;
    std::filesystem::remove(temporary, cleanup_error);
    throw PersistenceError("cannot replace store " + path.string() + ": " + error.message());
  }
}

DurableState read_store(const std::filesystem::path& path, const Limits& limits) {
  const std::vector<std::byte> image = read_file(path, limits);
  return decode_durable_state(image, limits);
}

PersistenceInfo inspect_store(const std::filesystem::path& path, const Limits& limits) {
  PersistenceInfo info;
  try {
    const std::vector<std::byte> image = read_file(path, limits);
    info.image_bytes = image.size();
    if (image.size() >= kHeaderBytes) {
      info.format_version =
          static_cast<std::uint32_t>(image[kMagic.size()]) |
          (static_cast<std::uint32_t>(image[kMagic.size() + 1]) << 8) |
          (static_cast<std::uint32_t>(image[kMagic.size() + 2]) << 16) |
          (static_cast<std::uint32_t>(image[kMagic.size() + 3]) << 24);
    }
    if (image.size() >= kChecksumBytes) {
      std::array<std::byte, Digest::kBytes> checksum_bytes{};
      std::copy(image.end() - kChecksumBytes, image.end(), checksum_bytes.begin());
      info.image_digest = Digest::from_bytes(checksum_bytes);
    }
    const DurableState state = decode_durable_state(image, limits);
    info.readable = true;
    info.payload_bytes = image.size() - kHeaderBytes - kChecksumBytes;
    info.record_count = state.records.size();
    info.epoch = state.epoch;
    info.policy = state.policy.generation;
    info.constraint_sets = state.constraint_sets.size();
    for (const auto& record : state.records) {
      if (record.revocation.has_value()) {
        ++info.revoked;
      }
      if (record.state == AuthorityState::AUTHORIZED ||
          record.state == AuthorityState::CONDITIONALLY_AUTHORIZED) {
        ++info.authorizing;
      }
    }
  } catch (const std::exception& error) {
    info.readable = false;
    info.problem = error.what();
  }
  return info;
}

}  // namespace path_authority
