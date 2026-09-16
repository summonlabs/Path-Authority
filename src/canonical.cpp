// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/canonical.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string>
#include <utility>

#include "path_authority/ids.hpp"
#include "path_authority/version.hpp"

namespace path_authority {
namespace {

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4). One audited implementation shared by the semantic
// digests, the persistence integrity check and the wire frame check.
// ---------------------------------------------------------------------------
constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::uint32_t rotr(std::uint32_t value, unsigned bits) noexcept {
  return (value >> bits) | (value << (32u - bits));
}

class Sha256 {
 public:
  Sha256() { reset(); }

  void reset() noexcept {
    state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
              0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    bit_length_ = 0;
    buffer_length_ = 0;
  }

  void update(const std::byte* data, std::size_t length) noexcept {
    for (std::size_t i = 0; i < length; ++i) {
      buffer_[buffer_length_++] = static_cast<std::uint8_t>(data[i]);
      if (buffer_length_ == 64) {
        transform();
        bit_length_ += 512;
        buffer_length_ = 0;
      }
    }
  }

  std::array<std::byte, 32> finish() noexcept {
    const std::uint64_t total_bits = bit_length_ + (buffer_length_ * 8u);
    // Every index below is provably inside the 64 byte block, which keeps the
    // static analyser and the reader on the same page.
    std::size_t length = buffer_length_ < buffer_.size() ? buffer_length_ : 0;
    buffer_[length++] = 0x80u;
    if (length > 56) {
      for (std::size_t i = length; i < buffer_.size(); ++i) {
        buffer_[i] = 0x00u;
      }
      transform();
      length = 0;
    }
    for (std::size_t i = length; i < 56; ++i) {
      buffer_[i] = 0x00u;
    }
    for (std::size_t i = 0; i < 8; ++i) {
      const auto shift = static_cast<unsigned>(56 - (8 * i));
      buffer_[56 + i] = static_cast<std::uint8_t>((total_bits >> shift) & 0xffu);
    }
    buffer_length_ = 0;
    transform();

    std::array<std::byte, 32> out{};
    for (std::size_t word = 0; word < 8; ++word) {
      for (std::size_t byte_index = 0; byte_index < 4; ++byte_index) {
        const auto shift = static_cast<unsigned>(24 - (8 * byte_index));
        out[(word * 4) + byte_index] =
            static_cast<std::byte>((state_[word] >> shift) & 0xffu);
      }
    }
    return out;
  }

 private:
  void transform() noexcept {
    std::array<std::uint32_t, 64> schedule{};
    for (std::size_t i = 0; i < 16; ++i) {
      schedule[i] = (static_cast<std::uint32_t>(buffer_[i * 4]) << 24) |
                    (static_cast<std::uint32_t>(buffer_[(i * 4) + 1]) << 16) |
                    (static_cast<std::uint32_t>(buffer_[(i * 4) + 2]) << 8) |
                    (static_cast<std::uint32_t>(buffer_[(i * 4) + 3]));
    }
    for (std::size_t i = 16; i < 64; ++i) {
      const std::uint32_t s0 = rotr(schedule[i - 15], 7) ^ rotr(schedule[i - 15], 18) ^
                               (schedule[i - 15] >> 3);
      const std::uint32_t s1 = rotr(schedule[i - 2], 17) ^ rotr(schedule[i - 2], 19) ^
                               (schedule[i - 2] >> 10);
      schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (std::size_t i = 0; i < 64; ++i) {
      const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const std::uint32_t ch = (e & f) ^ ((~e) & g);
      const std::uint32_t temp1 = h + s1 + ch + kRoundConstants[i] + schedule[i];
      const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temp2 = s0 + maj;
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::uint64_t bit_length_ = 0;
  std::size_t buffer_length_ = 0;
};

char hex_digit(unsigned value) noexcept {
  return static_cast<char>(value < 10 ? ('0' + value) : ('a' + (value - 10)));
}

int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

}  // namespace

Digest Digest::from_bytes(std::array<std::byte, kBytes> bytes) noexcept {
  Digest digest;
  digest.bytes_ = bytes;
  return digest;
}

Digest sha256(std::span<const std::byte> bytes) noexcept {
  Sha256 hasher;
  hasher.update(bytes.data(), bytes.size());
  return Digest::from_bytes(hasher.finish());
}

Digest Digest::of(std::span<const std::byte> bytes) noexcept { return sha256(bytes); }

Digest Digest::of(std::string_view text) noexcept {
  return sha256(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()),
                                           text.size()));
}

std::optional<Digest> Digest::from_hex(std::string_view hex) noexcept {
  if (hex.size() != kHexLength) {
    return std::nullopt;
  }
  std::array<std::byte, kBytes> target{};
  for (std::size_t i = 0; i < kBytes; ++i) {
    const int high = hex_value(hex[i * 2]);
    const int low = hex_value(hex[(i * 2) + 1]);
    if (high < 0 || low < 0) {
      return std::nullopt;
    }
    target[i] = static_cast<std::byte>((high << 4) | low);
  }
  return from_bytes(target);
}

std::string Digest::hex() const {
  std::string text;
  text.reserve(kHexLength);
  for (std::byte value : bytes_) {
    const auto raw = static_cast<unsigned>(value);
    text.push_back(hex_digit((raw >> 4) & 0x0fu));
    text.push_back(hex_digit(raw & 0x0fu));
  }
  return text;
}

std::string Digest::short_hex(std::size_t chars) const {
  const std::string full = hex();
  return chars >= full.size() ? full : full.substr(0, chars);
}

bool Digest::is_zero() const noexcept {
  for (std::byte value : bytes_) {
    if (value != std::byte{0}) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Byte writer
// ---------------------------------------------------------------------------
void ByteWriter::u8(std::uint8_t value) { data_.push_back(static_cast<std::byte>(value)); }

void ByteWriter::u16(std::uint16_t value) {
  u8(static_cast<std::uint8_t>(value & 0xffu));
  u8(static_cast<std::uint8_t>((value >> 8) & 0xffu));
}

void ByteWriter::u32(std::uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8) {
    u8(static_cast<std::uint8_t>((value >> shift) & 0xffu));
  }
}

void ByteWriter::u64(std::uint64_t value) {
  for (int shift = 0; shift < 64; shift += 8) {
    u8(static_cast<std::uint8_t>((value >> shift) & 0xffu));
  }
}

void ByteWriter::bytes(std::span<const std::byte> value) {
  data_.insert(data_.end(), value.begin(), value.end());
}

void ByteWriter::length_prefixed(std::string_view value) {
  u32(static_cast<std::uint32_t>(value.size()));
  for (char c : value) {
    data_.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
  }
}

void ByteWriter::digest(const Digest& value) { bytes(value.bytes()); }

// ---------------------------------------------------------------------------
// Byte reader
// ---------------------------------------------------------------------------
void ByteReader::need(std::size_t count) const {
  if (count > remaining()) {
    throw DecodeError("truncated encoding: needed " + std::to_string(count) + " bytes, " +
                      std::to_string(remaining()) + " available");
  }
}

std::uint8_t ByteReader::u8() {
  need(1);
  return static_cast<std::uint8_t>(data_[offset_++]);
}

std::uint16_t ByteReader::u16() {
  std::uint16_t value = 0;
  for (int shift = 0; shift < 16; shift += 8) {
    value = static_cast<std::uint16_t>(value | (static_cast<std::uint16_t>(u8()) << shift));
  }
  return value;
}

std::uint32_t ByteReader::u32() {
  std::uint32_t value = 0;
  for (int shift = 0; shift < 32; shift += 8) {
    value |= (static_cast<std::uint32_t>(u8()) << shift);
  }
  return value;
}

std::uint64_t ByteReader::u64() {
  std::uint64_t value = 0;
  for (int shift = 0; shift < 64; shift += 8) {
    value |= (static_cast<std::uint64_t>(u8()) << shift);
  }
  return value;
}

bool ByteReader::boolean() {
  const std::uint8_t value = u8();
  if (value > 1) {
    throw DecodeError("malformed boolean encoding");
  }
  return value == 1;
}

Digest ByteReader::digest() {
  const auto raw = fixed(Digest::kBytes);
  std::array<std::byte, Digest::kBytes> target{};
  std::copy(raw.begin(), raw.end(), target.begin());
  return Digest::from_bytes(target);
}

std::span<const std::byte> ByteReader::fixed(std::size_t count) {
  need(count);
  const auto view = data_.subspan(offset_, count);
  offset_ += count;
  return view;
}

std::string ByteReader::length_prefixed(std::uint32_t max_bytes) {
  const std::uint32_t length = u32();
  if (length > max_bytes) {
    throw DecodeError("length-prefixed field exceeds the configured bound");
  }
  const auto raw = fixed(length);
  return std::string(reinterpret_cast<const char*>(raw.data()), raw.size());
}

void ByteReader::require_end() const {
  if (!at_end()) {
    throw DecodeError("trailing bytes after the end of the encoding");
  }
}

// ---------------------------------------------------------------------------
// Canonical encoders and decoders
// ---------------------------------------------------------------------------
namespace {

void require_version(ByteReader& reader) {
  const std::uint32_t version = reader.u32();
  if (version != kCanonicalEncodingVersion) {
    throw DecodeError("unsupported canonical encoding version " + std::to_string(version));
  }
}

ElementKind read_element_kind(ByteReader& reader) {
  const std::uint8_t raw = reader.u8();
  if (!is_defined_element_kind(raw)) {
    throw DecodeError("undefined element kind " + std::to_string(raw));
  }
  return static_cast<ElementKind>(raw);
}

Layer read_layer(ByteReader& reader) {
  const std::uint8_t raw = reader.u8();
  if (!is_defined_layer(raw)) {
    throw DecodeError("undefined layer " + std::to_string(raw));
  }
  return static_cast<Layer>(raw);
}

RelationType read_relation(ByteReader& reader) {
  const std::uint8_t raw = reader.u8();
  if (!is_defined_relation(raw)) {
    throw DecodeError("undefined relation type " + std::to_string(raw));
  }
  return static_cast<RelationType>(raw);
}

PathType read_path_type(ByteReader& reader) {
  const std::uint8_t raw = reader.u8();
  if (!is_defined_path_type(raw)) {
    throw DecodeError("undefined path type " + std::to_string(raw));
  }
  return static_cast<PathType>(raw);
}

DomainClassKind read_domain_class(ByteReader& reader) {
  const std::uint8_t raw = reader.u8();
  if (!is_defined_domain_class(raw)) {
    throw DecodeError("undefined failure domain class " + std::to_string(raw));
  }
  return static_cast<DomainClassKind>(raw);
}

FailureDomainConstraintKind read_domain_constraint_kind(ByteReader& reader) {
  const std::uint8_t raw = reader.u8();
  if (!is_defined_failure_domain_constraint_kind(raw)) {
    throw DecodeError("undefined failure domain constraint kind " + std::to_string(raw));
  }
  return static_cast<FailureDomainConstraintKind>(raw);
}

CapabilityValueType read_value_type(ByteReader& reader) {
  const std::uint8_t raw = reader.u8();
  if (!is_defined_capability_value_type(raw)) {
    throw DecodeError("undefined capability value type " + std::to_string(raw));
  }
  return static_cast<CapabilityValueType>(raw);
}

RequirementOp read_requirement_op(ByteReader& reader) {
  const std::uint8_t raw = reader.u8();
  if (!is_defined_requirement_op(raw)) {
    throw DecodeError("undefined requirement operator " + std::to_string(raw));
  }
  return static_cast<RequirementOp>(raw);
}

Requirement decode_requirement(ByteReader& reader, std::uint32_t depth, std::uint32_t& budget) {
  const Limits& limits = reader.limits();
  if (depth > limits.max_requirement_depth) {
    throw DecodeError("requirement nesting exceeds limits.max_requirement_depth");
  }
  if (budget == 0) {
    throw DecodeError("requirement node count exceeds limits.max_requirement_nodes");
  }
  --budget;

  Requirement requirement;
  requirement.op = read_requirement_op(reader);
  requirement.key = reader.length_prefixed(limits.max_metadata_bytes);
  const std::uint32_t value_count = reader.u32();
  if (value_count > limits.max_capability_values) {
    throw DecodeError("requirement value count exceeds limits.max_capability_values");
  }
  requirement.values.reserve(value_count);
  for (std::uint32_t i = 0; i < value_count; ++i) {
    requirement.values.push_back(decode_capability_value(reader));
  }
  const std::uint32_t child_count = reader.u32();
  if (child_count > limits.max_requirement_nodes) {
    throw DecodeError("requirement child count exceeds limits.max_requirement_nodes");
  }
  requirement.children.reserve(child_count);
  for (std::uint32_t i = 0; i < child_count; ++i) {
    requirement.children.push_back(decode_requirement(reader, depth + 1, budget));
  }
  return requirement;
}

void encode_requirement(ByteWriter& writer, const Requirement& requirement) {
  writer.u8(static_cast<std::uint8_t>(requirement.op));
  writer.length_prefixed(requirement.key);
  writer.u32(static_cast<std::uint32_t>(requirement.values.size()));
  for (const auto& value : requirement.values) {
    writer.bytes(encode_capability_value(value));
  }
  writer.u32(static_cast<std::uint32_t>(requirement.children.size()));
  for (const auto& child : requirement.children) {
    encode_requirement(writer, child);
  }
}

void encode_capability_requirement(ByteWriter& writer, const CapabilityRequirement& requirement) {
  writer.length_prefixed(requirement.entity);
  writer.length_prefixed(requirement.key.view());
  writer.boolean(requirement.fail_closed_on_unknown);
  encode_requirement(writer, requirement.expression);
}

CapabilityRequirement decode_capability_requirement(ByteReader& reader) {
  const Limits& limits = reader.limits();
  CapabilityRequirement requirement;
  requirement.entity = reader.length_prefixed(limits.max_metadata_bytes);
  const std::string key = reader.length_prefixed(limits.max_id_length);
  const auto parsed_key = CapabilityKey::from_wire(key);
  if (!parsed_key.has_value()) {
    throw DecodeError("malformed capability key");
  }
  requirement.key = *parsed_key;
  requirement.fail_closed_on_unknown = reader.boolean();
  std::uint32_t budget = limits.max_requirement_nodes;
  requirement.expression = decode_requirement(reader, 1, budget);
  std::string error;
  if (!validate_requirement(requirement.expression, limits, error)) {
    throw DecodeError("malformed capability requirement: " + error);
  }
  return requirement;
}

void encode_acceptance(ByteWriter& writer, const LinkStateAcceptance& acceptance) {
  writer.boolean(acceptance.allow_degraded);
  writer.boolean(acceptance.degraded_is_conditional);
  writer.boolean(acceptance.allow_unknown);
  writer.boolean(acceptance.unknown_is_conditional);
}

LinkStateAcceptance decode_acceptance(ByteReader& reader) {
  LinkStateAcceptance acceptance;
  acceptance.allow_degraded = reader.boolean();
  acceptance.degraded_is_conditional = reader.boolean();
  acceptance.allow_unknown = reader.boolean();
  acceptance.unknown_is_conditional = reader.boolean();
  return acceptance;
}

void encode_port_acceptance(ByteWriter& writer, const PortAdminAcceptance& acceptance) {
  writer.boolean(acceptance.allow_draining_existing);
  writer.boolean(acceptance.allow_maintenance_existing);
}

PortAdminAcceptance decode_port_acceptance(ByteReader& reader) {
  PortAdminAcceptance acceptance;
  acceptance.allow_draining_existing = reader.boolean();
  acceptance.allow_maintenance_existing = reader.boolean();
  return acceptance;
}

void encode_layers(ByteWriter& writer, const std::vector<Layer>& layers) {
  writer.u32(static_cast<std::uint32_t>(layers.size()));
  for (Layer layer : layers) {
    writer.u8(static_cast<std::uint8_t>(layer));
  }
}

std::vector<Layer> decode_layers(ByteReader& reader) {
  const std::uint32_t count = reader.u32();
  if (count > 8) {
    throw DecodeError("layer list exceeds the configured bound");
  }
  std::vector<Layer> layers;
  layers.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    layers.push_back(read_layer(reader));
  }
  return layers;
}

void encode_domain_classes(ByteWriter& writer, const std::vector<DomainClassKind>& classes) {
  writer.u32(static_cast<std::uint32_t>(classes.size()));
  for (DomainClassKind value : classes) {
    writer.u8(static_cast<std::uint8_t>(value));
  }
}

std::vector<DomainClassKind> decode_domain_classes(ByteReader& reader) {
  const std::uint32_t count = reader.u32();
  if (count > 16) {
    throw DecodeError("failure domain class list exceeds the configured bound");
  }
  std::vector<DomainClassKind> classes;
  classes.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    classes.push_back(read_domain_class(reader));
  }
  return classes;
}

}  // namespace

std::vector<std::byte> encode_path_element(const PathElement& element) {
  ByteWriter writer;
  writer.u32(kCanonicalEncodingVersion);
  writer.u8(static_cast<std::uint8_t>(element.kind));
  writer.length_prefixed(element.id);
  writer.u64(element.generation.value());
  writer.u8(static_cast<std::uint8_t>(element.layer));
  writer.u8(static_cast<std::uint8_t>(element.relation));
  return std::move(writer).take();
}

PathElement decode_path_element(ByteReader& reader) {
  require_version(reader);
  PathElement element;
  element.kind = read_element_kind(reader);
  element.id = reader.length_prefixed(reader.limits().max_id_length);
  if (!detail::valid_identity_text(element.id, reader.limits().max_id_length)) {
    throw DecodeError("malformed element identity");
  }
  const auto generation = StructuralGeneration::from_wire(reader.u64());
  if (!generation.has_value()) {
    throw DecodeError("unset structural generation");
  }
  element.generation = *generation;
  element.layer = read_layer(reader);
  element.relation = read_relation(reader);
  return element;
}

std::vector<std::byte> encode_element_ref(const ElementRef& ref) {
  ByteWriter writer;
  writer.u32(kCanonicalEncodingVersion);
  writer.u8(static_cast<std::uint8_t>(ref.kind));
  writer.length_prefixed(ref.id);
  return std::move(writer).take();
}

ElementRef decode_element_ref(ByteReader& reader) {
  require_version(reader);
  ElementRef ref;
  ref.kind = read_element_kind(reader);
  ref.id = reader.length_prefixed(reader.limits().max_id_length);
  if (!detail::valid_identity_text(ref.id, reader.limits().max_id_length)) {
    throw DecodeError("malformed element identity");
  }
  return ref;
}

std::vector<std::byte> encode_path(const PathDefinition& path) {
  ByteWriter writer;
  writer.u32(kCanonicalEncodingVersion);
  writer.u8(static_cast<std::uint8_t>(path.type));
  writer.length_prefixed(path.scope.view());
  writer.length_prefixed(path.constraint_set.view());
  writer.u64(path.generation.value());
  writer.u64(path.constraint_generation.value());
  writer.u32(static_cast<std::uint32_t>(path.hops.size()));
  for (const auto& hop : path.hops) {
    writer.u8(static_cast<std::uint8_t>(hop.kind));
    writer.length_prefixed(hop.id);
    writer.u64(hop.generation.value());
    writer.u8(static_cast<std::uint8_t>(hop.layer));
    writer.u8(static_cast<std::uint8_t>(hop.relation));
  }
  writer.boolean(path.underlying.has_value());
  if (path.underlying.has_value()) {
    writer.length_prefixed(path.underlying->path.view());
    writer.u64(path.underlying->authority_generation.value());
    writer.u16(path.underlying->nesting_depth);
  }
  return std::move(writer).take();
}

PathDefinition decode_path(ByteReader& reader) {
  const Limits& limits = reader.limits();
  require_version(reader);

  PathDefinition path;
  path.type = read_path_type(reader);
  const auto scope = ScopeId::from_wire(reader.length_prefixed(limits.max_id_length));
  if (!scope.has_value()) {
    throw DecodeError("malformed path scope");
  }
  path.scope = *scope;
  const auto constraint_set =
      ConstraintSetId::from_wire(reader.length_prefixed(limits.max_metadata_bytes));
  if (!constraint_set.has_value()) {
    throw DecodeError("malformed constraint set identity");
  }
  path.constraint_set = *constraint_set;

  const auto generation = PathGeneration::from_wire(reader.u64());
  if (!generation.has_value()) {
    throw DecodeError("unset path generation");
  }
  path.generation = *generation;
  const auto constraint_generation = ConstraintGeneration::from_wire(reader.u64());
  if (!constraint_generation.has_value()) {
    throw DecodeError("unset constraint generation");
  }
  path.constraint_generation = *constraint_generation;

  const std::uint32_t hop_count = reader.u32();
  if (hop_count > limits.max_hops) {
    throw DecodeError("hop count exceeds limits.max_hops");
  }
  path.hops.reserve(hop_count);
  for (std::uint32_t i = 0; i < hop_count; ++i) {
    PathElement hop;
    hop.kind = read_element_kind(reader);
    hop.id = reader.length_prefixed(limits.max_id_length);
    if (!detail::valid_identity_text(hop.id, limits.max_id_length)) {
      throw DecodeError("malformed element identity");
    }
    const auto element_generation = StructuralGeneration::from_wire(reader.u64());
    if (!element_generation.has_value()) {
      throw DecodeError("unset structural generation");
    }
    hop.generation = *element_generation;
    hop.layer = read_layer(reader);
    hop.relation = read_relation(reader);
    path.hops.push_back(std::move(hop));
  }

  if (reader.boolean()) {
    UnderlyingPathRef underlying;
    const auto underlying_id = PathId::from_wire(reader.length_prefixed(limits.max_metadata_bytes));
    if (!underlying_id.has_value()) {
      throw DecodeError("malformed underlying path identity");
    }
    underlying.path = *underlying_id;
    const auto underlying_generation =
        PathAuthorityGeneration::from_wire(reader.u64());
    if (!underlying_generation.has_value()) {
      throw DecodeError("unset underlying authority generation");
    }
    underlying.authority_generation = *underlying_generation;
    underlying.nesting_depth = reader.u16();
    path.underlying = underlying;
  }

  // The declared identity is derived, not encoded: it is a function of this
  // content, so it can never disagree with what was decoded.
  path.id = path.derived_id();
  reader.require_end();
  return path;
}

PathId derived_path_id(const Digest& digest) {
  return PathId::parse("path-" + digest.short_hex(32));
}

ScopeId default_scope() noexcept {
  static const ScopeId scope = ScopeId::parse("fabric");
  return scope;
}

std::vector<std::byte> encode_capability_value(const CapabilityValue& value) {
  ByteWriter writer;
  writer.u32(kCanonicalEncodingVersion);
  writer.u8(static_cast<std::uint8_t>(value.type()));
  switch (value.type()) {
    case CapabilityValueType::UNSIGNED:
      writer.u64(value.as_unsigned());
      break;
    case CapabilityValueType::SIGNED:
      writer.u64(static_cast<std::uint64_t>(value.as_signed()));
      break;
    case CapabilityValueType::BOOLEAN:
      writer.boolean(value.as_boolean());
      break;
    case CapabilityValueType::TEXT:
      writer.length_prefixed(value.as_text());
      break;
    case CapabilityValueType::VERSION: {
      const SemanticVersion version = value.as_version();
      writer.u32(version.major);
      writer.u32(version.minor);
      writer.u32(version.patch);
      break;
    }
  }
  return std::move(writer).take();
}

CapabilityValue decode_capability_value(ByteReader& reader) {
  require_version(reader);
  const CapabilityValueType type = read_value_type(reader);
  switch (type) {
    case CapabilityValueType::UNSIGNED:
      return CapabilityValue::unsigned_integer(reader.u64());
    case CapabilityValueType::SIGNED:
      return CapabilityValue::signed_integer(static_cast<std::int64_t>(reader.u64()));
    case CapabilityValueType::BOOLEAN:
      return CapabilityValue::boolean(reader.boolean());
    case CapabilityValueType::TEXT:
      return CapabilityValue::text(reader.length_prefixed(reader.limits().max_metadata_bytes));
    case CapabilityValueType::VERSION: {
      SemanticVersion version;
      version.major = reader.u32();
      version.minor = reader.u32();
      version.patch = reader.u32();
      return CapabilityValue::version(version);
    }
  }
  throw DecodeError("undefined capability value type");
}

std::vector<std::byte> encode_constraint_set(const ConstraintSet& set) {
  ByteWriter writer;
  writer.u32(kCanonicalEncodingVersion);
  writer.length_prefixed(set.id.view());
  writer.u64(set.generation.value());
  writer.length_prefixed(set.scope.view());
  writer.u32(static_cast<std::uint32_t>(set.capabilities.size()));
  for (const auto& requirement : set.capabilities) {
    encode_capability_requirement(writer, requirement);
  }
  writer.u32(static_cast<std::uint32_t>(set.failure_domains.size()));
  for (const auto& constraint : set.failure_domains) {
    writer.u8(static_cast<std::uint8_t>(constraint.kind));
    writer.length_prefixed(constraint.domain.view());
    writer.u8(static_cast<std::uint8_t>(constraint.domain_class));
    writer.u32(constraint.max_members);
    writer.boolean(constraint.peer.path.valid());
    if (constraint.peer.path.valid()) {
      writer.length_prefixed(constraint.peer.path.view());
      writer.u64(constraint.peer.authority_generation.value());
    }
    encode_domain_classes(writer, constraint.diversity_classes);
  }
  encode_acceptance(writer, set.link_state);
  encode_port_acceptance(writer, set.port_admin);
  encode_layers(writer, set.layers.allowed_layers);
  writer.boolean(set.layers.allow_loops);
  writer.u32(set.max_hops);
  return std::move(writer).take();
}

ConstraintSet decode_constraint_set(ByteReader& reader) {
  const Limits& limits = reader.limits();
  require_version(reader);

  ConstraintSet set;
  const auto id = ConstraintSetId::from_wire(reader.length_prefixed(limits.max_id_length));
  if (!id.has_value()) {
    throw DecodeError("malformed constraint set identity");
  }
  set.id = *id;
  const auto generation = ConstraintGeneration::from_wire(reader.u64());
  if (!generation.has_value()) {
    throw DecodeError("unset constraint generation");
  }
  set.generation = *generation;
  const auto scope = ScopeId::from_wire(reader.length_prefixed(limits.max_id_length));
  if (!scope.has_value()) {
    throw DecodeError("malformed constraint scope");
  }
  set.scope = *scope;

  const std::uint32_t capability_count = reader.u32();
  if (capability_count > limits.max_constraints) {
    throw DecodeError("capability constraint count exceeds limits.max_constraints");
  }
  set.capabilities.reserve(capability_count);
  for (std::uint32_t i = 0; i < capability_count; ++i) {
    set.capabilities.push_back(decode_capability_requirement(reader));
  }

  const std::uint32_t domain_count = reader.u32();
  if (domain_count > limits.max_failure_domain_refs) {
    throw DecodeError("failure domain constraint count exceeds limits.max_failure_domain_refs");
  }
  set.failure_domains.reserve(domain_count);
  for (std::uint32_t i = 0; i < domain_count; ++i) {
    FailureDomainConstraint constraint;
    constraint.kind = read_domain_constraint_kind(reader);
    const auto domain = FailureDomainId::from_wire(reader.length_prefixed(limits.max_id_length));
    if (!domain.has_value()) {
      throw DecodeError("malformed failure domain identity");
    }
    constraint.domain = *domain;
    constraint.domain_class = read_domain_class(reader);
    constraint.max_members = reader.u32();
    if (reader.boolean()) {
      const auto peer = PathId::from_wire(reader.length_prefixed(limits.max_metadata_bytes));
      if (!peer.has_value()) {
        throw DecodeError("malformed peer path identity");
      }
      constraint.peer.path = *peer;
      const auto peer_generation = PathAuthorityGeneration::from_wire(reader.u64());
      if (!peer_generation.has_value()) {
        throw DecodeError("unset peer authority generation");
      }
      constraint.peer.authority_generation = *peer_generation;
    }
    constraint.diversity_classes = decode_domain_classes(reader);
    set.failure_domains.push_back(std::move(constraint));
  }

  set.link_state = decode_acceptance(reader);
  set.port_admin = decode_port_acceptance(reader);
  set.layers.allowed_layers = decode_layers(reader);
  set.layers.allow_loops = reader.boolean();
  set.max_hops = reader.u32();
  reader.require_end();
  return set;
}

std::vector<std::byte> encode_policy_set(const PolicySet& policy) {
  ByteWriter writer;
  writer.u32(kCanonicalEncodingVersion);
  writer.u64(policy.generation.value());
  writer.length_prefixed(policy.scope.view());
  encode_acceptance(writer, policy.link_state);
  encode_port_acceptance(writer, policy.port_admin);
  writer.u32(static_cast<std::uint32_t>(policy.required_capabilities.size()));
  for (const auto& requirement : policy.required_capabilities) {
    encode_capability_requirement(writer, requirement);
  }
  encode_domain_classes(writer, policy.forbidden_domain_classes);
  encode_layers(writer, policy.forbidden_layers);
  writer.boolean(policy.allow_loops);
  writer.u32(policy.max_hops);
  writer.boolean(policy.allow_conditional_authorization);
  writer.boolean(policy.allow_unknown_link_state);
  return std::move(writer).take();
}

PolicySet decode_policy_set(ByteReader& reader) {
  const Limits& limits = reader.limits();
  require_version(reader);

  PolicySet policy;
  const auto generation = PolicyGeneration::from_wire(reader.u64());
  if (!generation.has_value()) {
    throw DecodeError("unset policy generation");
  }
  policy.generation = *generation;
  const auto scope = ScopeId::from_wire(reader.length_prefixed(limits.max_id_length));
  if (!scope.has_value()) {
    throw DecodeError("malformed policy scope");
  }
  policy.scope = *scope;
  policy.link_state = decode_acceptance(reader);
  policy.port_admin = decode_port_acceptance(reader);

  const std::uint32_t capability_count = reader.u32();
  if (capability_count > limits.max_constraints) {
    throw DecodeError("policy capability count exceeds limits.max_constraints");
  }
  policy.required_capabilities.reserve(capability_count);
  for (std::uint32_t i = 0; i < capability_count; ++i) {
    policy.required_capabilities.push_back(decode_capability_requirement(reader));
  }
  policy.forbidden_domain_classes = decode_domain_classes(reader);
  policy.forbidden_layers = decode_layers(reader);
  policy.allow_loops = reader.boolean();
  policy.max_hops = reader.u32();
  policy.allow_conditional_authorization = reader.boolean();
  policy.allow_unknown_link_state = reader.boolean();
  reader.require_end();
  return policy;
}

std::vector<std::byte> encode_evidence_vector(const EvidenceVector& evidence) {
  ByteWriter writer;
  writer.u32(kCanonicalEncodingVersion);
  writer.u32(static_cast<std::uint32_t>(evidence.entries.size()));
  for (const auto& entry : evidence.entries) {
    writer.u8(static_cast<std::uint8_t>(entry.kind));
    writer.length_prefixed(entry.subject);
    writer.u64(entry.generation);
  }
  return std::move(writer).take();
}

EvidenceVector decode_evidence_vector(ByteReader& reader) {
  const Limits& limits = reader.limits();
  require_version(reader);
  const std::uint32_t count = reader.u32();
  if (count > limits.max_dependencies_per_path) {
    throw DecodeError("evidence entry count exceeds limits.max_dependencies_per_path");
  }

  EvidenceVector evidence;
  evidence.entries.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    const std::uint8_t raw_kind = reader.u8();
    if (!is_defined_evidence_kind(raw_kind)) {
      throw DecodeError("undefined evidence kind " + std::to_string(raw_kind));
    }
    EvidenceEntry entry;
    entry.kind = static_cast<EvidenceKind>(raw_kind);
    entry.subject = reader.length_prefixed(limits.max_metadata_bytes);
    if (entry.subject.size() > limits.max_id_length + 32) {
      throw DecodeError("evidence subject exceeds the configured bound");
    }
    entry.generation = reader.u64();
    if (!evidence.entries.empty()) {
      const EvidenceEntry& previous = evidence.entries.back();
      if (!(previous < entry)) {
        throw DecodeError("evidence entries are not in canonical order");
      }
    }
    evidence.entries.push_back(std::move(entry));
  }
  reader.require_end();
  return evidence;
}

}  // namespace path_authority


