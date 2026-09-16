// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "path_authority/constraints.hpp"
#include "path_authority/digest.hpp"
#include "path_authority/export.hpp"
#include "path_authority/ids.hpp"
#include "path_authority/limits.hpp"
#include "path_authority/path.hpp"

namespace path_authority {

// ---------------------------------------------------------------------------
// Evidence views. These are the read-only seams onto the authorities that own
// the truth: Fabric Topology, Link State Fabric, Port Fabric, Fabric
// Capability Registry, Failure Domain Registry, Fabric Epoch and the policy
// store. Path Authority consumes them and never invents their content.
//
// Lifetime: views are borrowed and must outlive the runtime that references
// them. Thread safety: every method may be called concurrently from any
// thread; implementations must be internally synchronised.
// ---------------------------------------------------------------------------
struct PATH_AUTHORITY_API StructuralElementRecord {
  ElementKind kind = ElementKind::LINK;
  std::string id;
  StructuralGeneration generation;
  bool retired = false;
  bool superseded = false;
  std::string superseded_by;
};

enum class HopLegality : std::uint8_t {
  LEGAL = 0,
  UNKNOWN_ELEMENT = 1,
  RETIRED_ELEMENT = 2,
  MISSING_ADJACENCY = 3,
  WRONG_DIRECTION = 4,
  WRONG_LAYER = 5,
  INVALID_PAIRING = 6,
  DISCONTINUITY = 7,
};

PATH_AUTHORITY_API std::string_view to_string(HopLegality legality) noexcept;

struct PATH_AUTHORITY_API HopCheck {
  HopLegality legality = HopLegality::LEGAL;
  std::string detail;
  bool legal() const noexcept { return legality == HopLegality::LEGAL; }
};

class PATH_AUTHORITY_API TopologyView {
 public:
  virtual ~TopologyView();
  TopologyView() = default;
  TopologyView(const TopologyView&) = delete;
  TopologyView& operator=(const TopologyView&) = delete;

  virtual TopologyGeneration generation() const = 0;
  virtual std::optional<StructuralElementRecord> element(ElementKind kind,
                                                         std::string_view id) const = 0;
  // Structural legality of one adjacent hop pair under Fabric Topology.
  virtual HopCheck check_hop(const PathElement& from, const PathElement& to) const = 0;
};

enum class LinkState : std::uint8_t {
  UNKNOWN = 0,
  UP = 1,
  DOWN = 2,
  DEGRADED = 3,
  FAULTED = 4,
  RETIRED = 5,
  REVALIDATION_REQUIRED = 6,
};

PATH_AUTHORITY_API std::string_view to_string(LinkState state) noexcept;
PATH_AUTHORITY_API std::optional<LinkState> link_state_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API bool is_defined_link_state(std::uint8_t raw) noexcept;

struct PATH_AUTHORITY_API LinkStateRecord {
  LinkId id;
  LinkState state = LinkState::UNKNOWN;
  LinkStateGeneration generation;
};

class PATH_AUTHORITY_API LinkStateView {
 public:
  virtual ~LinkStateView();
  LinkStateView() = default;
  LinkStateView(const LinkStateView&) = delete;
  LinkStateView& operator=(const LinkStateView&) = delete;

  virtual LinkStateGeneration generation() const = 0;
  virtual std::optional<LinkStateRecord> link(std::string_view id) const = 0;
};

enum class PortAdminState : std::uint8_t {
  UNKNOWN = 0,
  ACTIVE = 1,
  ADMIN_DISABLED = 2,
  RETIRED = 3,
  SUPERSEDED = 4,
  MAINTENANCE = 5,
  REVALIDATION_REQUIRED = 6,
  DRAINING = 7,
};

PATH_AUTHORITY_API std::string_view to_string(PortAdminState state) noexcept;
PATH_AUTHORITY_API std::optional<PortAdminState> port_admin_state_from_string(std::string_view text) noexcept;
PATH_AUTHORITY_API bool is_defined_port_admin_state(std::uint8_t raw) noexcept;

struct PATH_AUTHORITY_API PortStateRecord {
  PortId id;
  PortAdminState admin = PortAdminState::UNKNOWN;
  PortConfigGeneration generation;
};

class PATH_AUTHORITY_API PortStateView {
 public:
  virtual ~PortStateView();
  PortStateView() = default;
  PortStateView(const PortStateView&) = delete;
  PortStateView& operator=(const PortStateView&) = delete;

  virtual PortConfigGeneration generation() const = 0;
  virtual std::optional<PortStateRecord> port(std::string_view id) const = 0;
};

struct PATH_AUTHORITY_API CapabilityRecord {
  std::string entity;
  CapabilityKey key;
  CapabilityValue value;
  CapabilityGeneration generation;
  // False when Fabric Capability Registry holds no current truth for this
  // (entity, key). Absence of a record is never treated as "supported".
  bool known = false;
};

// Deterministic, total evaluation of one requirement against one capability
// record. A record reported as not known yields UNKNOWN, and UNKNOWN never
// satisfies a hard requirement.
PATH_AUTHORITY_API RequirementOutcome evaluate_requirement(const Requirement& requirement,
                                                           const CapabilityRecord& record);

class PATH_AUTHORITY_API CapabilityView {
 public:
  virtual ~CapabilityView();
  CapabilityView() = default;
  CapabilityView(const CapabilityView&) = delete;
  CapabilityView& operator=(const CapabilityView&) = delete;

  virtual CapabilityGeneration generation() const = 0;
  virtual CapabilityRecord lookup(std::string_view entity, std::string_view key) const = 0;
};

struct PATH_AUTHORITY_API FailureDomainRecord {
  FailureDomainId id;
  DomainClassKind domain_class = DomainClassKind::UNKNOWN;
  // Per-domain generation owned by Failure Domain Registry. Precision matters:
  // two paths sharing a domain must not be invalidated by an unrelated domain.
  FailureDomainGeneration generation;
};

class PATH_AUTHORITY_API FailureDomainView {
 public:
  virtual ~FailureDomainView();
  FailureDomainView() = default;
  FailureDomainView(const FailureDomainView&) = delete;
  FailureDomainView& operator=(const FailureDomainView&) = delete;

  virtual FailureDomainGeneration generation() const = 0;
  virtual std::optional<FailureDomainRecord> domain(const FailureDomainId& id) const = 0;
  // Sorted, de-duplicated membership of one structural element. An empty
  // result only means "independent" when coverage_for() reports complete.
  virtual std::vector<FailureDomainId> memberships(const ElementRef& element) const = 0;
  // Whether Failure Domain Registry reports complete classification for the
  // element. Incomplete coverage never implies independence.
  virtual bool coverage_for(const ElementRef& element) const = 0;
  // Generation of the membership classification for one element.
  virtual FailureDomainGeneration membership_generation(const ElementRef& element) const = 0;
};

class PATH_AUTHORITY_API EpochAuthority {
 public:
  virtual ~EpochAuthority();
  EpochAuthority() = default;
  EpochAuthority(const EpochAuthority&) = delete;
  EpochAuthority& operator=(const EpochAuthority&) = delete;

  virtual CoordinatorEpoch current() const = 0;
};

// Epoch authority that the owning coordinator can advance. A coordinator takes
// ownership of Fabric Epoch: after a restart it consumes or advances the
// current epoch so that traffic fenced to the previous epoch is rejected.
class PATH_AUTHORITY_API MutableEpochAuthority : public EpochAuthority {
 public:
  ~MutableEpochAuthority() override;
  MutableEpochAuthority() = default;
  MutableEpochAuthority(const MutableEpochAuthority&) = delete;
  MutableEpochAuthority& operator=(const MutableEpochAuthority&) = delete;

  virtual CoordinatorEpoch advance() = 0;
  virtual void set(CoordinatorEpoch epoch) = 0;
};

class PATH_AUTHORITY_API PolicyStore {
 public:
  virtual ~PolicyStore();
  PolicyStore() = default;
  PolicyStore(const PolicyStore&) = delete;
  PolicyStore& operator=(const PolicyStore&) = delete;

  virtual PolicySet current_policy() const = 0;
};

// All evidence views a runtime consumes, as one borrowed bundle.
struct PATH_AUTHORITY_API EvidenceSources {
  const TopologyView* topology = nullptr;
  const LinkStateView* link_state = nullptr;
  const PortStateView* port_state = nullptr;
  const CapabilityView* capability = nullptr;
  const FailureDomainView* failure_domain = nullptr;
  const EpochAuthority* epoch = nullptr;
  const PolicyStore* policy = nullptr;

  bool complete() const noexcept;
};

// ---------------------------------------------------------------------------
// Evidence vector: the exact generations a decision was bound to. It is the
// basis of precise revalidation; currentness is never reduced to a timestamp.
// ---------------------------------------------------------------------------
enum class EvidenceKind : std::uint8_t {
  TOPOLOGY = 1,
  STRUCTURAL_ELEMENT = 2,
  LINK_STATE = 3,
  PORT_CONFIG = 4,
  CAPABILITY = 5,
  FAILURE_DOMAIN = 6,
  POLICY = 7,
  EPOCH = 8,
  CONSTRAINTS = 9,
  UNDERLYING_AUTHORITY = 10,
};

PATH_AUTHORITY_API std::string_view to_string(EvidenceKind kind) noexcept;
PATH_AUTHORITY_API bool is_defined_evidence_kind(std::uint8_t raw) noexcept;

struct PATH_AUTHORITY_API EvidenceEntry {
  EvidenceKind kind = EvidenceKind::TOPOLOGY;
  std::string subject;
  std::uint64_t generation = 0;

  friend bool operator==(const EvidenceEntry&, const EvidenceEntry&) = default;
  friend std::strong_ordering operator<=>(const EvidenceEntry& lhs, const EvidenceEntry& rhs);
  std::string render() const;
};

class PATH_AUTHORITY_API EvidenceVector {
 public:
  // Scalar subjects for the singleton evidence kinds.
  static constexpr std::string_view kScalarSubject = "self";

  std::vector<EvidenceEntry> entries;

  friend bool operator==(const EvidenceVector&, const EvidenceVector&) = default;

  bool set(EvidenceKind kind, std::string subject, std::uint64_t generation, const Limits& limits);
  bool set(EvidenceKind kind, std::uint64_t generation, const Limits& limits) {
    return set(kind, std::string(kScalarSubject), generation, limits);
  }
  std::optional<std::uint64_t> find(EvidenceKind kind, std::string_view subject) const;
  std::optional<std::uint64_t> find(EvidenceKind kind) const {
    return find(kind, kScalarSubject);
  }

  CoordinatorEpoch epoch() const;
  PolicyGeneration policy() const;
  TopologyGeneration topology() const;
  ConstraintGeneration constraint_generation() const;
  PathAuthorityGeneration underlying_authority() const;

  std::size_t size() const noexcept { return entries.size(); }
  Digest digest() const;
  bool valid() const noexcept;
  std::string render() const;
};

// One evidence difference. Present in both vectors unless before/after is
// absent; scalars are reported with their fixed subject.
struct PATH_AUTHORITY_API EvidenceDelta {
  EvidenceKind kind = EvidenceKind::TOPOLOGY;
  std::string subject;
  std::optional<std::uint64_t> before;
  std::optional<std::uint64_t> after;

  friend bool operator==(const EvidenceDelta&, const EvidenceDelta&) = default;
  std::string render() const;
};

// Deterministic, sorted difference between two evidence vectors.
PATH_AUTHORITY_API std::vector<EvidenceDelta> diff_evidence(const EvidenceVector& before,
                                                            const EvidenceVector& after);

}  // namespace path_authority
