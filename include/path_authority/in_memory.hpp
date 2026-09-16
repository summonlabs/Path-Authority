// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

#include "path_authority/evidence.hpp"
#include "path_authority/export.hpp"
#include "path_authority/path.hpp"

namespace path_authority {

// In-memory evidence authorities. They are used by tests, examples, the CLI
// and the synthetic fabric, and they are the reference implementation of the
// view contracts: thread-safe, no callbacks, no hidden state.
class PATH_AUTHORITY_API InMemoryTopology : public TopologyView {
 public:
  void set_generation(TopologyGeneration generation);
  TopologyGeneration generation() const override;

  void put(StructuralElementRecord record);
  void erase(ElementKind kind, std::string_view id);
  std::size_t size() const;
  std::optional<StructuralElementRecord> element(ElementKind kind,
                                                 std::string_view id) const override;

  // Legal adjacency pairs plus per-hop layer rules.
  void allow_hop(ElementRef from, ElementRef to);
  void forbid_hop(ElementRef from, ElementRef to);
  void set_layers(ElementRef from, Layer from_layer, ElementRef to, Layer to_layer);
  HopCheck check_hop(const PathElement& from, const PathElement& to) const override;

 private:
  mutable std::shared_mutex mutex_;
  TopologyGeneration generation_;
  std::map<std::string, StructuralElementRecord> elements_;
  std::map<std::string, bool> hops_;
  std::map<std::string, std::pair<Layer, Layer>> hop_layers_;
};

class PATH_AUTHORITY_API InMemoryLinkState : public LinkStateView {
 public:
  void set_generation(LinkStateGeneration generation);
  LinkStateGeneration generation() const override;
  void put(LinkId id, LinkState state, LinkStateGeneration generation);
  void erase(std::string_view id);
  std::size_t size() const;
  std::optional<LinkStateRecord> link(std::string_view id) const override;

 private:
  mutable std::shared_mutex mutex_;
  LinkStateGeneration generation_;
  std::map<std::string, LinkStateRecord> links_;
};

class PATH_AUTHORITY_API InMemoryPortState : public PortStateView {
 public:
  void set_generation(PortConfigGeneration generation);
  PortConfigGeneration generation() const override;
  void put(PortId id, PortAdminState state, PortConfigGeneration generation);
  void erase(std::string_view id);
  std::size_t size() const;
  std::optional<PortStateRecord> port(std::string_view id) const override;

 private:
  mutable std::shared_mutex mutex_;
  PortConfigGeneration generation_;
  std::map<std::string, PortStateRecord> ports_;
};
class PATH_AUTHORITY_API InMemoryCapabilityRegistry : public CapabilityView {
 public:
  void set_generation(CapabilityGeneration generation);
  CapabilityGeneration generation() const override;
  // Per-record generations are supplied by the caller because Fabric
  // Capability Registry owns them; this view never invents one.
  void put(std::string entity, CapabilityKey key, CapabilityValue value,
           CapabilityGeneration generation);
  void erase(std::string_view entity, std::string_view key);
  std::size_t size() const;
  CapabilityRecord lookup(std::string_view entity, std::string_view key) const override;

 private:
  mutable std::shared_mutex mutex_;
  CapabilityGeneration generation_;
  std::map<std::string, CapabilityRecord> records_;
};

class PATH_AUTHORITY_API InMemoryFailureDomains : public FailureDomainView {
 public:
  void set_generation(FailureDomainGeneration generation);
  FailureDomainGeneration generation() const override;
  void put(FailureDomainRecord record);
  void erase(const FailureDomainId& id);
  void add_member(const FailureDomainId& domain, ElementRef element);
  void remove_member(const FailureDomainId& domain, ElementRef element);
  void set_coverage(ElementRef element, bool complete);
  void set_membership_generation(ElementRef element, FailureDomainGeneration generation);
  std::size_t size() const;
  std::optional<FailureDomainRecord> domain(const FailureDomainId& id) const override;
  std::vector<FailureDomainId> memberships(const ElementRef& element) const override;
  bool coverage_for(const ElementRef& element) const override;
  FailureDomainGeneration membership_generation(const ElementRef& element) const override;

 private:
  mutable std::shared_mutex mutex_;
  FailureDomainGeneration generation_;
  std::map<std::string, FailureDomainRecord> domains_;
  std::map<std::string, std::vector<FailureDomainId>> members_;
  std::map<std::string, bool> coverage_;
  std::map<std::string, FailureDomainGeneration> membership_generations_;
};

class PATH_AUTHORITY_API InMemoryEpochAuthority : public MutableEpochAuthority {
 public:
  explicit InMemoryEpochAuthority(CoordinatorEpoch epoch = CoordinatorEpoch::from_value(1));
  CoordinatorEpoch current() const override;
  // Advances to the next epoch and returns it. Fails only on overflow.
  CoordinatorEpoch advance() override;
  void set(CoordinatorEpoch epoch) override;

 private:
  mutable std::mutex mutex_;
  CoordinatorEpoch epoch_;
};

class PATH_AUTHORITY_API InMemoryPolicyStore : public PolicyStore {
 public:
  void set(PolicySet policy);
  PolicySet current_policy() const override;

 private:
  mutable std::shared_mutex mutex_;
  PolicySet policy_;
};

// Owns one instance of every in-memory authority plus the shared mutable
// epoch, and hands out a consistent EvidenceSources bundle.
class PATH_AUTHORITY_API InMemoryEvidence {
 public:
  InMemoryEvidence();

  EvidenceSources sources();

  InMemoryTopology topology;
  InMemoryLinkState link_state;
  InMemoryPortState port_state;
  InMemoryCapabilityRegistry capability;
  InMemoryFailureDomains failure_domains;
  InMemoryEpochAuthority epoch;
  InMemoryPolicyStore policy;
};

// Element-key helpers shared by the index, evidence subjects and the
// in-memory authorities.
PATH_AUTHORITY_API std::string element_key(ElementKind kind, std::string_view id);
PATH_AUTHORITY_API std::string element_key(const ElementRef& ref);
PATH_AUTHORITY_API std::string capability_key(std::string_view entity, std::string_view key);

}  // namespace path_authority

