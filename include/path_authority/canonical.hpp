// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "path_authority/constraints.hpp"
#include "path_authority/evidence.hpp"
#include "path_authority/export.hpp"
#include "path_authority/limits.hpp"
#include "path_authority/path.hpp"

namespace path_authority {

// Canonical encoding: a deterministic, self-delimiting, versioned byte
// encoding. Two semantically identical values encode to identical bytes and
// different hop order never collapses to the same encoding.
class PATH_AUTHORITY_API DecodeError : public std::runtime_error {
 public:
  explicit DecodeError(const std::string& what) : std::runtime_error(what) {}
};

class PATH_AUTHORITY_API ByteWriter {
 public:
  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void bytes(std::span<const std::byte> value);
  void length_prefixed(std::string_view value);
  void boolean(bool value) { u8(value ? 1u : 0u); }
  void digest(const Digest& value);

  const std::vector<std::byte>& data() const noexcept { return data_; }
  std::vector<std::byte> take() && { return std::move(data_); }
  std::size_t size() const noexcept { return data_.size(); }

 private:
  std::vector<std::byte> data_;
};

// Bounded reader: every read is range-checked and every length is validated
// against the configured limits before allocation.
class PATH_AUTHORITY_API ByteReader {
 public:
  ByteReader(std::span<const std::byte> data, Limits limits) : data_(data), limits_(limits) {}

  std::uint8_t u8();
  std::uint16_t u16();
  std::uint32_t u32();
  std::uint64_t u64();
  bool boolean();
  Digest digest();
  std::string length_prefixed(std::uint32_t max_bytes);
  std::span<const std::byte> fixed(std::size_t count);

  std::size_t remaining() const noexcept { return data_.size() - offset_; }
  bool at_end() const noexcept { return offset_ == data_.size(); }
  const Limits& limits() const noexcept { return limits_; }
  void require_end() const;

 private:
  void need(std::size_t count) const;
  std::span<const std::byte> data_;
  std::size_t offset_ = 0;
  Limits limits_;
};

// Canonical encoders and decoders. Every decoder is bounded, rejects trailing
// bytes and validates enumerations, identities and generations strictly.
PATH_AUTHORITY_API std::vector<std::byte> encode_path(const PathDefinition& path);
PATH_AUTHORITY_API PathDefinition decode_path(ByteReader& reader);

PATH_AUTHORITY_API std::vector<std::byte> encode_path_element(const PathElement& element);
PATH_AUTHORITY_API PathElement decode_path_element(ByteReader& reader);

PATH_AUTHORITY_API std::vector<std::byte> encode_element_ref(const ElementRef& ref);
PATH_AUTHORITY_API ElementRef decode_element_ref(ByteReader& reader);

PATH_AUTHORITY_API std::vector<std::byte> encode_constraint_set(const ConstraintSet& set);
PATH_AUTHORITY_API ConstraintSet decode_constraint_set(ByteReader& reader);

PATH_AUTHORITY_API std::vector<std::byte> encode_policy_set(const PolicySet& policy);
PATH_AUTHORITY_API PolicySet decode_policy_set(ByteReader& reader);

PATH_AUTHORITY_API std::vector<std::byte> encode_evidence_vector(const EvidenceVector& evidence);
PATH_AUTHORITY_API EvidenceVector decode_evidence_vector(ByteReader& reader);

PATH_AUTHORITY_API std::vector<std::byte> encode_capability_value(const CapabilityValue& value);
PATH_AUTHORITY_API CapabilityValue decode_capability_value(ByteReader& reader);

}  // namespace path_authority
