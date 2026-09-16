// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/path.hpp"

#include <algorithm>
#include <set>
#include <string>
#include <utility>

#include "path_authority/canonical.hpp"

namespace path_authority {
namespace {

std::string_view element_kind_text(ElementKind value) noexcept {
  switch (value) {
    case ElementKind::ENDPOINT: return "ENDPOINT";
    case ElementKind::PORT: return "PORT";
    case ElementKind::LINK: return "LINK";
    case ElementKind::SWITCH: return "SWITCH";
    case ElementKind::ROUTER: return "ROUTER";
    case ElementKind::LOGICAL_HOP: return "LOGICAL_HOP";
    case ElementKind::PHYSICAL_HOP: return "PHYSICAL_HOP";
    case ElementKind::TUNNEL: return "TUNNEL";
    case ElementKind::FABRIC_BOUNDARY: return "FABRIC_BOUNDARY";
    case ElementKind::SITE_BOUNDARY: return "SITE_BOUNDARY";
  }
  return "INVALID";
}

}  // namespace

std::string_view to_string(ElementKind value) noexcept { return element_kind_text(value); }

std::string_view to_string(Layer value) noexcept {
  switch (value) {
    case Layer::PHYSICAL: return "PHYSICAL";
    case Layer::LOGICAL: return "LOGICAL";
    case Layer::OVERLAY: return "OVERLAY";
    case Layer::CONTROL: return "CONTROL";
  }
  return "INVALID";
}

std::string_view to_string(RelationType value) noexcept {
  switch (value) {
    case RelationType::NONE: return "NONE";
    case RelationType::FAN_OUT: return "FAN_OUT";
    case RelationType::CONTAINMENT: return "CONTAINMENT";
    case RelationType::DEPENDENCY: return "DEPENDENCY";
    case RelationType::TUNNEL_UNDERLAY: return "TUNNEL_UNDERLAY";
  }
  return "INVALID";
}

std::string_view to_string(PathType value) noexcept {
  switch (value) {
    case PathType::PHYSICAL: return "PHYSICAL";
    case PathType::LOGICAL: return "LOGICAL";
  }
  return "INVALID";
}

std::optional<ElementKind> element_kind_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 10; ++raw) {
    const auto candidate = static_cast<ElementKind>(raw);
    if (element_kind_text(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::optional<Layer> layer_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 4; ++raw) {
    const auto candidate = static_cast<Layer>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::optional<RelationType> relation_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 0; raw <= 4; ++raw) {
    const auto candidate = static_cast<RelationType>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::optional<PathType> path_type_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 2; ++raw) {
    const auto candidate = static_cast<PathType>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_defined_element_kind(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 10; }
bool is_defined_layer(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 4; }
bool is_defined_relation(std::uint8_t raw) noexcept { return raw <= 4; }
bool is_defined_path_type(std::uint8_t raw) noexcept { return raw == 1 || raw == 2; }

std::strong_ordering operator<=>(const ElementRef& lhs, const ElementRef& rhs) {
  if (const auto cmp = lhs.kind <=> rhs.kind; cmp != 0) {
    return cmp;
  }
  return lhs.id <=> rhs.id;
}

std::string ElementRef::render() const {
  return std::string(to_string(kind)) + ":" + id;
}

std::string PathElement::render() const {
  std::string text = std::string(to_string(kind)) + ":" + id;
  text += "[" + std::string(to_string(layer)) + ",";
  text += std::to_string(generation.value()) + "]";
  return text;
}

Digest PathDefinition::semantic_digest() const { return Digest::of(encode_path(*this)); }

PathId PathDefinition::derived_id() const { return derived_path_id(semantic_digest()); }

bool PathDefinition::identity_binds() const { return id.valid() && id == derived_id(); }

std::string PathDefinition::render() const {
  std::string text;
  text += "path=" + id.str();
  text += " generation=" + std::to_string(generation.value());
  text += " type=" + std::string(to_string(type));
  text += " scope=" + scope.str();
  text += " constraints=" + constraint_set.str() + "@" +
          std::to_string(constraint_generation.value());
  text += " hops=" + std::to_string(hops.size());
  for (const auto& hop : hops) {
    text += "\n  -> " + hop.render();
  }
  if (underlying.has_value()) {
    text += "\n  under=" + underlying->path.str() + "@" +
            std::to_string(underlying->authority_generation.value());
  }
  return text;
}

std::string_view to_string(PathShapeStatus status) noexcept {
  switch (status) {
    case PathShapeStatus::VALID: return "VALID";
    case PathShapeStatus::TOO_FEW_HOPS: return "TOO_FEW_HOPS";
    case PathShapeStatus::TOO_MANY_HOPS: return "TOO_MANY_HOPS";
    case PathShapeStatus::INVALID_IDENTITY: return "INVALID_IDENTITY";
    case PathShapeStatus::UNKNOWN_GENERATION: return "UNKNOWN_GENERATION";
    case PathShapeStatus::MALFORMED_ELEMENT: return "MALFORMED_ELEMENT";
    case PathShapeStatus::UNSUPPORTED_LAYER: return "UNSUPPORTED_LAYER";
    case PathShapeStatus::ENDPOINT_PAIRING: return "ENDPOINT_PAIRING";
    case PathShapeStatus::ACCIDENTAL_LOOP: return "ACCIDENTAL_LOOP";
    case PathShapeStatus::NESTING_DEPTH_EXCEEDED: return "NESTING_DEPTH_EXCEEDED";
    case PathShapeStatus::INVALID_CONSTRAINT_BINDING: return "INVALID_CONSTRAINT_BINDING";
    case PathShapeStatus::IDENTITY_MISMATCH: return "IDENTITY_MISMATCH";
    case PathShapeStatus::METADATA_TOO_LARGE: return "METADATA_TOO_LARGE";
  }
  return "UNKNOWN";
}

namespace {

// A path terminates at an endpoint, at a logical hop, or at an explicit
// fabric or site boundary. The boundary form is what lets a host describe the
// reach of its own evidence without inventing far-side structure.
bool is_terminal_kind(ElementKind kind) noexcept {
  return kind == ElementKind::ENDPOINT || kind == ElementKind::LOGICAL_HOP ||
         kind == ElementKind::FABRIC_BOUNDARY || kind == ElementKind::SITE_BOUNDARY;
}

bool is_loop_exempt(const PathElement& element) noexcept {
  // A tunnel or boundary may legitimately be re-entered by a logical path;
  // ordinary forwarding elements may not.
  return element.kind == ElementKind::TUNNEL || element.kind == ElementKind::SITE_BOUNDARY ||
         element.kind == ElementKind::FABRIC_BOUNDARY;
}

PathShapeResult fail(PathShapeStatus status, std::string detail) {
  PathShapeResult result;
  result.status = status;
  result.detail = std::move(detail);
  return result;
}

}  // namespace

PathShapeResult validate_path_shape(const PathDefinition& path, const Limits& limits,
                                    bool require_identity_binding) {
  PathShapeResult ok;

  if (!limits.valid()) {
    return fail(PathShapeStatus::INVALID_IDENTITY, "invalid limits");
  }
  if (!path.id.valid() || !path.scope.valid() || !path.constraint_set.valid()) {
    return fail(PathShapeStatus::INVALID_IDENTITY, "path id, scope or constraint set is unset");
  }
  if (!path.generation.is_set() || !path.constraint_generation.is_set()) {
    return fail(PathShapeStatus::UNKNOWN_GENERATION,
                "path generation or constraint generation is unset");
  }
  if (!is_defined_path_type(static_cast<std::uint8_t>(path.type))) {
    return fail(PathShapeStatus::MALFORMED_ELEMENT, "undefined path type");
  }
  if (path.hops.size() < 2) {
    return fail(PathShapeStatus::TOO_FEW_HOPS, "a candidate path requires at least two hops");
  }
  if (path.hops.size() > limits.max_hops) {
    return fail(PathShapeStatus::TOO_MANY_HOPS, "hop count exceeds limits.max_hops");
  }

  for (const auto& hop : path.hops) {
    if (!is_defined_element_kind(static_cast<std::uint8_t>(hop.kind)) ||
        !is_defined_layer(static_cast<std::uint8_t>(hop.layer)) ||
        !is_defined_relation(static_cast<std::uint8_t>(hop.relation))) {
      return fail(PathShapeStatus::MALFORMED_ELEMENT, "undefined element kind, layer or relation");
    }
    if (!detail::valid_identity_text(hop.id, limits.max_id_length)) {
      return fail(PathShapeStatus::MALFORMED_ELEMENT, "malformed element identity");
    }
    if (!hop.generation.is_set()) {
      return fail(PathShapeStatus::UNKNOWN_GENERATION, "unset structural generation");
    }
  }

  if (!is_terminal_kind(path.hops.front().kind) || !is_terminal_kind(path.hops.back().kind)) {
    return fail(PathShapeStatus::ENDPOINT_PAIRING,
                "a path must begin and end at an endpoint, a logical hop or an explicit boundary");
  }
  for (std::size_t i = 1; i + 1 < path.hops.size(); ++i) {
    if (path.hops[i].kind == ElementKind::ENDPOINT) {
      return fail(PathShapeStatus::ENDPOINT_PAIRING,
                  "an endpoint may only appear at the ends of a path");
    }
  }

  if (path.type == PathType::PHYSICAL) {
    std::set<std::string> seen;
    for (const auto& hop : path.hops) {
      const std::string key = hop.ref().render();
      if (!seen.insert(key).second) {
        return fail(PathShapeStatus::ACCIDENTAL_LOOP,
                    "physical path repeats structural element " + key);
      }
    }
  } else {
    std::set<std::string> seen;
    for (const auto& hop : path.hops) {
      if (is_loop_exempt(hop)) {
        continue;
      }
      const std::string key = hop.ref().render();
      if (!seen.insert(key).second) {
        return fail(PathShapeStatus::ACCIDENTAL_LOOP,
                    "logical path repeats non-exempt element " + key);
      }
    }
  }

  if (path.underlying.has_value()) {
    if (!path.underlying->path.valid() || !path.underlying->authority_generation.is_set()) {
      return fail(PathShapeStatus::MALFORMED_ELEMENT, "malformed underlying path reference");
    }
    if (path.underlying->nesting_depth == 0 || path.underlying->nesting_depth > limits.max_nesting_depth) {
      return fail(PathShapeStatus::NESTING_DEPTH_EXCEEDED,
                  "underlying path nesting depth exceeds limits.max_nesting_depth");
    }
    if (path.underlying->path == path.id) {
      return fail(PathShapeStatus::MALFORMED_ELEMENT, "path declares itself as its own underlying path");
    }
    if (path.type != PathType::LOGICAL) {
      return fail(PathShapeStatus::MALFORMED_ELEMENT,
                  "only a logical path may bind an underlying path");
    }
  }

  if (require_identity_binding && !path.identity_binds()) {
    return fail(PathShapeStatus::IDENTITY_MISMATCH,
                "declared PathId does not match the canonical content digest");
  }

  return ok;
}

}  // namespace path_authority
