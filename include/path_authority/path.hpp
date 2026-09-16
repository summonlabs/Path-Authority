// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "path_authority/digest.hpp"
#include "path_authority/export.hpp"
#include "path_authority/ids.hpp"
#include "path_authority/limits.hpp"

namespace path_authority {

// ---------------------------------------------------------------------------
// Enumerations. All enum encodings are strictly validated on decode: an
// unknown value is rejected, never coerced to a default.
// ---------------------------------------------------------------------------
enum class ElementKind : std::uint8_t {
  ENDPOINT = 1,
  PORT = 2,
  LINK = 3,
  SWITCH = 4,
  ROUTER = 5,
  LOGICAL_HOP = 6,
  PHYSICAL_HOP = 7,
  TUNNEL = 8,
  FABRIC_BOUNDARY = 9,
  SITE_BOUNDARY = 10,
};

enum class Layer : std::uint8_t {
  PHYSICAL = 1,
  LOGICAL = 2,
  OVERLAY = 3,
  CONTROL = 4,
};

enum class RelationType : std::uint8_t {
  NONE = 0,
  FAN_OUT = 1,
  CONTAINMENT = 2,
  DEPENDENCY = 3,
  TUNNEL_UNDERLAY = 4,
};

enum class PathType : std::uint8_t {
  PHYSICAL = 1,
  LOGICAL = 2,
};

PATH_AUTHORITY_API std::string_view to_string(ElementKind value) noexcept;
PATH_AUTHORITY_API std::string_view to_string(Layer value) noexcept;
PATH_AUTHORITY_API std::string_view to_string(RelationType value) noexcept;
PATH_AUTHORITY_API std::string_view to_string(PathType value) noexcept;

PATH_AUTHORITY_API std::optional<ElementKind> element_kind_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API std::optional<Layer> layer_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API std::optional<RelationType> relation_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API std::optional<PathType> path_type_from_string(std::string_view text) noexcept;

PATH_AUTHORITY_API bool is_defined_element_kind(std::uint8_t raw) noexcept;
PATH_AUTHORITY_API bool is_defined_layer(std::uint8_t raw) noexcept;
PATH_AUTHORITY_API bool is_defined_relation(std::uint8_t raw) noexcept;
PATH_AUTHORITY_API bool is_defined_path_type(std::uint8_t raw) noexcept;

// A key onto one structural element of an external authority (Fabric Registry
// identity, Fabric Topology structure, Port Fabric port, Link State Fabric
// link). Path Authority never creates these identities.
struct PATH_AUTHORITY_API ElementRef {
  ElementKind kind = ElementKind::LINK;
  std::string id;

  friend bool operator==(const ElementRef&, const ElementRef&) = default;
  friend std::strong_ordering operator<=>(const ElementRef& lhs, const ElementRef& rhs);
  std::string render() const;
};

// One hop of a candidate path. The structural generation is the generation of
// the element the caller validated the path against; it is part of the path
// identity and is re-checked against Fabric Topology on every evaluation.
struct PATH_AUTHORITY_API PathElement {
  ElementKind kind = ElementKind::LINK;
  std::string id;
  StructuralGeneration generation;
  Layer layer = Layer::PHYSICAL;
  RelationType relation = RelationType::NONE;

  friend bool operator==(const PathElement&, const PathElement&) = default;
  ElementRef ref() const { return ElementRef{kind, id}; }
  std::string render() const;
};

// A logical path may depend on the exact authority result of an underlying
// path. Nesting is explicit, bound to a generation, depth-bounded and
// cycle-checked; logical authority is never inferred from physical authority.
struct PATH_AUTHORITY_API UnderlyingPathRef {
  PathId path;
  PathAuthorityGeneration authority_generation;
  std::uint16_t nesting_depth = 1;

  friend bool operator==(const UnderlyingPathRef&, const UnderlyingPathRef&) = default;
};

// The candidate path as supplied by the caller. Path Authority validates this
// exact sequence; it never searches for, repairs or replaces it.
struct PATH_AUTHORITY_API PathDefinition {
  PathId id;
  PathGeneration generation;
  PathType type = PathType::PHYSICAL;
  ScopeId scope;
  ConstraintSetId constraint_set;
  ConstraintGeneration constraint_generation;
  std::vector<PathElement> hops;
  std::optional<UnderlyingPathRef> underlying;

  friend bool operator==(const PathDefinition&, const PathDefinition&) = default;

  // Deterministic digest over the canonical encoding of the definition. The
  // declared id is excluded: the id is an identity *of* this content.
  Digest semantic_digest() const;
  // PathId derived from semantic_digest(); stable across processes and builds.
  PathId derived_id() const;
  // True when the declared id equals the derived id.
  bool identity_binds() const;
  std::string render() const;
};

// ---------------------------------------------------------------------------
// Shape validation: the part of legality that depends only on the path value
// itself, before any authoritative evidence is consulted.
// ---------------------------------------------------------------------------
enum class PathShapeStatus : std::uint8_t {
  VALID = 0,
  TOO_FEW_HOPS,
  TOO_MANY_HOPS,
  INVALID_IDENTITY,
  UNKNOWN_GENERATION,
  MALFORMED_ELEMENT,
  UNSUPPORTED_LAYER,
  ENDPOINT_PAIRING,
  ACCIDENTAL_LOOP,
  NESTING_DEPTH_EXCEEDED,
  INVALID_CONSTRAINT_BINDING,
  IDENTITY_MISMATCH,
  METADATA_TOO_LARGE,
};

PATH_AUTHORITY_API std::string_view to_string(PathShapeStatus status) noexcept;

struct PATH_AUTHORITY_API PathShapeResult {
  PathShapeStatus status = PathShapeStatus::VALID;
  std::string detail;
  bool ok() const noexcept { return status == PathShapeStatus::VALID; }
};

// Validates the shape of the definition under the supplied limits. Loop rules
// are explicit: physical paths reject repeated structural elements, logical
// paths reject repeated logical hops but may legitimately re-reference
// underlying structures through the explicit underlying-path binding.
PATH_AUTHORITY_API PathShapeResult validate_path_shape(const PathDefinition& path,
                                                       const Limits& limits,
                                                       bool require_identity_binding = true);

}  // namespace path_authority
