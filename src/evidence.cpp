// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/evidence.hpp"

#include <algorithm>
#include <string>
#include <utility>

#include "path_authority/canonical.hpp"
#include "path_authority/in_memory.hpp"

namespace path_authority {

TopologyView::~TopologyView() = default;
LinkStateView::~LinkStateView() = default;
PortStateView::~PortStateView() = default;
CapabilityView::~CapabilityView() = default;
FailureDomainView::~FailureDomainView() = default;
EpochAuthority::~EpochAuthority() = default;
MutableEpochAuthority::~MutableEpochAuthority() = default;
PolicyStore::~PolicyStore() = default;

bool EvidenceSources::complete() const noexcept {
  return topology != nullptr && link_state != nullptr && port_state != nullptr &&
         capability != nullptr && failure_domain != nullptr && epoch != nullptr &&
         policy != nullptr;
}

std::string_view to_string(HopLegality legality) noexcept {
  switch (legality) {
    case HopLegality::LEGAL: return "LEGAL";
    case HopLegality::UNKNOWN_ELEMENT: return "UNKNOWN_ELEMENT";
    case HopLegality::RETIRED_ELEMENT: return "RETIRED_ELEMENT";
    case HopLegality::MISSING_ADJACENCY: return "MISSING_ADJACENCY";
    case HopLegality::WRONG_DIRECTION: return "WRONG_DIRECTION";
    case HopLegality::WRONG_LAYER: return "WRONG_LAYER";
    case HopLegality::INVALID_PAIRING: return "INVALID_PAIRING";
    case HopLegality::DISCONTINUITY: return "DISCONTINUITY";
  }
  return "INVALID";
}

std::string_view to_string(LinkState state) noexcept {
  switch (state) {
    case LinkState::UNKNOWN: return "UNKNOWN";
    case LinkState::UP: return "UP";
    case LinkState::DOWN: return "DOWN";
    case LinkState::DEGRADED: return "DEGRADED";
    case LinkState::FAULTED: return "FAULTED";
    case LinkState::RETIRED: return "RETIRED";
    case LinkState::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
  }
  return "INVALID";
}

std::optional<LinkState> link_state_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 0; raw <= 6; ++raw) {
    const auto candidate = static_cast<LinkState>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_defined_link_state(std::uint8_t raw) noexcept { return raw <= 6; }

std::string_view to_string(PortAdminState state) noexcept {
  switch (state) {
    case PortAdminState::UNKNOWN: return "UNKNOWN";
    case PortAdminState::ACTIVE: return "ACTIVE";
    case PortAdminState::ADMIN_DISABLED: return "ADMIN_DISABLED";
    case PortAdminState::RETIRED: return "RETIRED";
    case PortAdminState::SUPERSEDED: return "SUPERSEDED";
    case PortAdminState::MAINTENANCE: return "MAINTENANCE";
    case PortAdminState::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case PortAdminState::DRAINING: return "DRAINING";
  }
  return "INVALID";
}

std::optional<PortAdminState> port_admin_state_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 0; raw <= 7; ++raw) {
    const auto candidate = static_cast<PortAdminState>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_defined_port_admin_state(std::uint8_t raw) noexcept { return raw <= 7; }

std::string_view to_string(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::TOPOLOGY: return "TOPOLOGY";
    case EvidenceKind::STRUCTURAL_ELEMENT: return "STRUCTURAL_ELEMENT";
    case EvidenceKind::LINK_STATE: return "LINK_STATE";
    case EvidenceKind::PORT_CONFIG: return "PORT_CONFIG";
    case EvidenceKind::CAPABILITY: return "CAPABILITY";
    case EvidenceKind::FAILURE_DOMAIN: return "FAILURE_DOMAIN";
    case EvidenceKind::POLICY: return "POLICY";
    case EvidenceKind::EPOCH: return "EPOCH";
    case EvidenceKind::CONSTRAINTS: return "CONSTRAINTS";
    case EvidenceKind::UNDERLYING_AUTHORITY: return "UNDERLYING_AUTHORITY";
  }
  return "INVALID";
}

bool is_defined_evidence_kind(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 10; }

std::strong_ordering operator<=>(const EvidenceEntry& lhs, const EvidenceEntry& rhs) {
  if (const auto cmp = lhs.kind <=> rhs.kind; cmp != 0) {
    return cmp;
  }
  return lhs.subject <=> rhs.subject;
}

std::string EvidenceEntry::render() const {
  return std::string(to_string(kind)) + ":" + subject + "@" + std::to_string(generation);
}

bool EvidenceVector::set(EvidenceKind kind, std::string subject, std::uint64_t generation,
                         const Limits& limits) {
  if (subject.size() > limits.max_id_length + 32) {
    return false;
  }
  EvidenceEntry entry{kind, std::move(subject), generation};
  const auto position =
      std::lower_bound(entries.begin(), entries.end(), entry,
                       [](const EvidenceEntry& lhs, const EvidenceEntry& rhs) { return lhs < rhs; });
  if (position != entries.end() && position->kind == entry.kind && position->subject == entry.subject) {
    position->generation = entry.generation;
    return true;
  }
  if (entries.size() >= limits.max_dependencies_per_path) {
    return false;
  }
  entries.insert(position, std::move(entry));
  return true;
}

std::optional<std::uint64_t> EvidenceVector::find(EvidenceKind kind, std::string_view subject) const {
  EvidenceEntry probe{kind, std::string(subject), 0};
  const auto position =
      std::lower_bound(entries.begin(), entries.end(), probe,
                       [](const EvidenceEntry& lhs, const EvidenceEntry& rhs) { return lhs < rhs; });
  if (position == entries.end() || position->kind != kind || position->subject != subject) {
    return std::nullopt;
  }
  return position->generation;
}

CoordinatorEpoch EvidenceVector::epoch() const {
  const auto value = find(EvidenceKind::EPOCH);
  return value.has_value() ? CoordinatorEpoch::from_value(*value) : CoordinatorEpoch{};
}

PolicyGeneration EvidenceVector::policy() const {
  const auto value = find(EvidenceKind::POLICY);
  return value.has_value() ? PolicyGeneration::from_value(*value) : PolicyGeneration{};
}

TopologyGeneration EvidenceVector::topology() const {
  const auto value = find(EvidenceKind::TOPOLOGY);
  return value.has_value() ? TopologyGeneration::from_value(*value) : TopologyGeneration{};
}

ConstraintGeneration EvidenceVector::constraint_generation() const {
  const auto value = find(EvidenceKind::CONSTRAINTS);
  return value.has_value() ? ConstraintGeneration::from_value(*value) : ConstraintGeneration{};
}

PathAuthorityGeneration EvidenceVector::underlying_authority() const {
  const auto value = find(EvidenceKind::UNDERLYING_AUTHORITY);
  return value.has_value() ? PathAuthorityGeneration::from_value(*value) : PathAuthorityGeneration{};
}

Digest EvidenceVector::digest() const { return Digest::of(encode_evidence_vector(*this)); }

bool EvidenceVector::valid() const noexcept {
  for (std::size_t i = 0; i < entries.size(); ++i) {
    if (!is_defined_evidence_kind(static_cast<std::uint8_t>(entries[i].kind))) {
      return false;
    }
    if (i != 0 && !(entries[i - 1] < entries[i])) {
      return false;
    }
  }
  return find(EvidenceKind::EPOCH).has_value() && find(EvidenceKind::POLICY).has_value();
}

std::string EvidenceVector::render() const {
  std::string text;
  for (const auto& entry : entries) {
    text += entry.render();
    text += "\n";
  }
  return text;
}

std::string EvidenceDelta::render() const {
  const std::string before_text = before.has_value() ? std::to_string(*before) : "absent";
  const std::string after_text = after.has_value() ? std::to_string(*after) : "absent";
  return std::string(to_string(kind)) + ":" + subject + " " + before_text + " -> " + after_text;
}

std::vector<EvidenceDelta> diff_evidence(const EvidenceVector& before,
                                         const EvidenceVector& after) {
  std::vector<EvidenceDelta> deltas;
  std::size_t i = 0;
  std::size_t j = 0;
  while (i < before.entries.size() || j < after.entries.size()) {
    if (i < before.entries.size() && j < after.entries.size() &&
        before.entries[i].kind == after.entries[j].kind &&
        before.entries[i].subject == after.entries[j].subject) {
      if (before.entries[i].generation != after.entries[j].generation) {
        deltas.push_back(EvidenceDelta{before.entries[i].kind, before.entries[i].subject,
                                       before.entries[i].generation, after.entries[j].generation});
      }
      ++i;
      ++j;
      continue;
    }
    const bool take_before =
        j >= after.entries.size() ||
        (i < before.entries.size() && (before.entries[i] < after.entries[j]));
    if (take_before) {
      deltas.push_back(EvidenceDelta{before.entries[i].kind, before.entries[i].subject,
                                     before.entries[i].generation, std::nullopt});
      ++i;
    } else {
      deltas.push_back(EvidenceDelta{after.entries[j].kind, after.entries[j].subject, std::nullopt,
                                     after.entries[j].generation});
      ++j;
    }
  }
  return deltas;
}

}  // namespace path_authority
