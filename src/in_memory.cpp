// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/in_memory.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace path_authority {
namespace {

std::string hop_key(const ElementRef& from, const ElementRef& to) {
  return from.render() + "->" + to.render();
}

}  // namespace

std::string element_key(ElementKind kind, std::string_view id) {
  return std::string(to_string(kind)) + ":" + std::string(id);
}

std::string element_key(const ElementRef& ref) { return element_key(ref.kind, ref.id); }

std::string capability_key(std::string_view entity, std::string_view key) {
  return std::string(entity) + "|" + std::string(key);
}

// ---------------------------------------------------------------------------
// InMemoryTopology
// ---------------------------------------------------------------------------
void InMemoryTopology::set_generation(TopologyGeneration generation) {
  const std::unique_lock lock(mutex_);
  generation_ = generation;
}

TopologyGeneration InMemoryTopology::generation() const {
  const std::shared_lock lock(mutex_);
  return generation_;
}

void InMemoryTopology::put(StructuralElementRecord record) {
  const std::unique_lock lock(mutex_);
  elements_[element_key(record.kind, record.id)] = std::move(record);
}

void InMemoryTopology::erase(ElementKind kind, std::string_view id) {
  const std::unique_lock lock(mutex_);
  elements_.erase(element_key(kind, id));
}

std::size_t InMemoryTopology::size() const {
  const std::shared_lock lock(mutex_);
  return elements_.size();
}

std::optional<StructuralElementRecord> InMemoryTopology::element(ElementKind kind,
                                                                 std::string_view id) const {
  const std::shared_lock lock(mutex_);
  const auto it = elements_.find(element_key(kind, id));
  if (it == elements_.end()) {
    return std::nullopt;
  }
  return it->second;
}

void InMemoryTopology::allow_hop(ElementRef from, ElementRef to) {
  const std::unique_lock lock(mutex_);
  hops_[hop_key(from, to)] = true;
}

void InMemoryTopology::forbid_hop(ElementRef from, ElementRef to) {
  const std::unique_lock lock(mutex_);
  hops_[hop_key(from, to)] = false;
}

void InMemoryTopology::set_layers(ElementRef from, Layer from_layer, ElementRef to,
                                  Layer to_layer) {
  const std::unique_lock lock(mutex_);
  hop_layers_[hop_key(from, to)] = {from_layer, to_layer};
}

HopCheck InMemoryTopology::check_hop(const PathElement& from, const PathElement& to) const {
  const std::shared_lock lock(mutex_);
  HopCheck check;
  const std::string from_key = element_key(from.ref());
  const std::string to_key = element_key(to.ref());
  const auto from_it = elements_.find(from_key);
  const auto to_it = elements_.find(to_key);
  if (from_it == elements_.end() || to_it == elements_.end()) {
    check.legality = HopLegality::UNKNOWN_ELEMENT;
    check.detail = "hop references an element that Fabric Topology does not hold";
    return check;
  }
  if (from_it->second.retired || to_it->second.retired) {
    check.legality = HopLegality::RETIRED_ELEMENT;
    check.detail = "hop references a retired structural element";
    return check;
  }
  if (from.kind == ElementKind::ENDPOINT && to.kind == ElementKind::ENDPOINT) {
    check.legality = HopLegality::INVALID_PAIRING;
    check.detail = "two endpoints are not directly adjacent in a physical path";
    return check;
  }
  const std::string key = from_key + "->" + to_key;
  const auto layer_it = hop_layers_.find(key);
  if (layer_it != hop_layers_.end()) {
    if (from.layer != layer_it->second.first || to.layer != layer_it->second.second) {
      check.legality = HopLegality::WRONG_LAYER;
      check.detail = "hop layer does not match the layer Fabric Topology reports for this adjacency";
      return check;
    }
  }
  const auto hop_it = hops_.find(key);
  if (hop_it != hops_.end()) {
    if (hop_it->second) {
      return check;
    }
    check.legality = HopLegality::MISSING_ADJACENCY;
    check.detail = "Fabric Topology reports no adjacency in this direction";
    return check;
  }
  if (hops_.find(to_key + "->" + from_key) != hops_.end()) {
    check.legality = HopLegality::WRONG_DIRECTION;
    check.detail = "adjacency exists only in the opposite direction";
    return check;
  }
  check.legality = HopLegality::DISCONTINUITY;
  check.detail = "the two structural elements are not directly adjacent";
  return check;
}

// ---------------------------------------------------------------------------
// InMemoryLinkState
// ---------------------------------------------------------------------------
void InMemoryLinkState::set_generation(LinkStateGeneration generation) {
  const std::unique_lock lock(mutex_);
  generation_ = generation;
}

LinkStateGeneration InMemoryLinkState::generation() const {
  const std::shared_lock lock(mutex_);
  return generation_;
}

void InMemoryLinkState::put(LinkId id, LinkState state, LinkStateGeneration generation) {
  const std::unique_lock lock(mutex_);
  LinkStateRecord record;
  record.id = id;
  record.state = state;
  record.generation = generation;
  links_[id.str()] = std::move(record);
}

void InMemoryLinkState::erase(std::string_view id) {
  const std::unique_lock lock(mutex_);
  links_.erase(std::string(id));
}

std::size_t InMemoryLinkState::size() const {
  const std::shared_lock lock(mutex_);
  return links_.size();
}

std::optional<LinkStateRecord> InMemoryLinkState::link(std::string_view id) const {
  const std::shared_lock lock(mutex_);
  const auto it = links_.find(std::string(id));
  if (it == links_.end()) {
    return std::nullopt;
  }
  return it->second;
}

// ---------------------------------------------------------------------------
// InMemoryPortState
// ---------------------------------------------------------------------------
void InMemoryPortState::set_generation(PortConfigGeneration generation) {
  const std::unique_lock lock(mutex_);
  generation_ = generation;
}

PortConfigGeneration InMemoryPortState::generation() const {
  const std::shared_lock lock(mutex_);
  return generation_;
}

void InMemoryPortState::put(PortId id, PortAdminState state, PortConfigGeneration generation) {
  const std::unique_lock lock(mutex_);
  PortStateRecord record;
  record.id = id;
  record.admin = state;
  record.generation = generation;
  ports_[id.str()] = std::move(record);
}

void InMemoryPortState::erase(std::string_view id) {
  const std::unique_lock lock(mutex_);
  ports_.erase(std::string(id));
}

std::size_t InMemoryPortState::size() const {
  const std::shared_lock lock(mutex_);
  return ports_.size();
}

std::optional<PortStateRecord> InMemoryPortState::port(std::string_view id) const {
  const std::shared_lock lock(mutex_);
  const auto it = ports_.find(std::string(id));
  if (it == ports_.end()) {
    return std::nullopt;
  }
  return it->second;
}

// ---------------------------------------------------------------------------
// InMemoryCapabilityRegistry
// ---------------------------------------------------------------------------
void InMemoryCapabilityRegistry::set_generation(CapabilityGeneration generation) {
  const std::unique_lock lock(mutex_);
  generation_ = generation;
}

CapabilityGeneration InMemoryCapabilityRegistry::generation() const {
  const std::shared_lock lock(mutex_);
  return generation_;
}

void InMemoryCapabilityRegistry::put(std::string entity, CapabilityKey key, CapabilityValue value,
                                     CapabilityGeneration generation) {
  const std::unique_lock lock(mutex_);
  CapabilityRecord record;
  record.entity = std::move(entity);
  record.key = key;
  record.value = std::move(value);
  record.generation = generation;
  record.known = true;
  records_[capability_key(record.entity, record.key.view())] = std::move(record);
}

void InMemoryCapabilityRegistry::erase(std::string_view entity, std::string_view key) {
  const std::unique_lock lock(mutex_);
  records_.erase(capability_key(entity, key));
}

std::size_t InMemoryCapabilityRegistry::size() const {
  const std::shared_lock lock(mutex_);
  return records_.size();
}

CapabilityRecord InMemoryCapabilityRegistry::lookup(std::string_view entity,
                                                    std::string_view key) const {
  const std::shared_lock lock(mutex_);
  CapabilityRecord record;
  record.entity = std::string(entity);
  record.key = CapabilityKey::parse(key);
  const auto it = records_.find(capability_key(entity, key));
  if (it == records_.end()) {
    record.known = false;
    record.generation = generation_;
    return record;
  }
  return it->second;
}

// ---------------------------------------------------------------------------
// InMemoryFailureDomains
// ---------------------------------------------------------------------------
void InMemoryFailureDomains::set_generation(FailureDomainGeneration generation) {
  const std::unique_lock lock(mutex_);
  generation_ = generation;
}

FailureDomainGeneration InMemoryFailureDomains::generation() const {
  const std::shared_lock lock(mutex_);
  return generation_;
}

void InMemoryFailureDomains::put(FailureDomainRecord record) {
  const std::unique_lock lock(mutex_);
  domains_[record.id.str()] = std::move(record);
}

void InMemoryFailureDomains::erase(const FailureDomainId& id) {
  const std::unique_lock lock(mutex_);
  domains_.erase(id.str());
  for (auto& [key, list] : members_) {
    (void)key;
    list.erase(std::remove(list.begin(), list.end(), id), list.end());
  }
}

void InMemoryFailureDomains::add_member(const FailureDomainId& domain, ElementRef element) {
  const std::unique_lock lock(mutex_);
  auto& list = members_[element_key(element)];
  if (std::find(list.begin(), list.end(), domain) == list.end()) {
    list.push_back(domain);
    std::sort(list.begin(), list.end());
  }
}

void InMemoryFailureDomains::remove_member(const FailureDomainId& domain, ElementRef element) {
  const std::unique_lock lock(mutex_);
  const auto it = members_.find(element_key(element));
  if (it == members_.end()) {
    return;
  }
  it->second.erase(std::remove(it->second.begin(), it->second.end(), domain), it->second.end());
}

void InMemoryFailureDomains::set_coverage(ElementRef element, bool complete) {
  const std::unique_lock lock(mutex_);
  coverage_[element_key(element)] = complete;
}

void InMemoryFailureDomains::set_membership_generation(ElementRef element,
                                                       FailureDomainGeneration generation) {
  const std::unique_lock lock(mutex_);
  membership_generations_[element_key(element)] = generation;
}

std::size_t InMemoryFailureDomains::size() const {
  const std::shared_lock lock(mutex_);
  return domains_.size();
}

std::optional<FailureDomainRecord> InMemoryFailureDomains::domain(const FailureDomainId& id) const {
  const std::shared_lock lock(mutex_);
  const auto it = domains_.find(id.str());
  if (it == domains_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::vector<FailureDomainId> InMemoryFailureDomains::memberships(const ElementRef& element) const {
  const std::shared_lock lock(mutex_);
  const auto it = members_.find(element_key(element));
  if (it == members_.end()) {
    return {};
  }
  return it->second;
}

bool InMemoryFailureDomains::coverage_for(const ElementRef& element) const {
  const std::shared_lock lock(mutex_);
  const auto it = coverage_.find(element_key(element));
  // Absent classification is reported as incomplete coverage: independence is
  // never inferred from absent data.
  return it != coverage_.end() && it->second;
}

FailureDomainGeneration InMemoryFailureDomains::membership_generation(
    const ElementRef& element) const {
  const std::shared_lock lock(mutex_);
  const auto it = membership_generations_.find(element_key(element));
  if (it == membership_generations_.end()) {
    return FailureDomainGeneration{};
  }
  return it->second;
}

// ---------------------------------------------------------------------------
// InMemoryEpochAuthority / InMemoryPolicyStore / InMemoryEvidence
// ---------------------------------------------------------------------------
InMemoryEpochAuthority::InMemoryEpochAuthority(CoordinatorEpoch epoch) : epoch_(epoch) {
  if (!epoch_.is_set()) {
    epoch_ = CoordinatorEpoch::from_value(1);
  }
}

CoordinatorEpoch InMemoryEpochAuthority::current() const {
  const std::lock_guard lock(mutex_);
  return epoch_;
}

CoordinatorEpoch InMemoryEpochAuthority::advance() {
  const std::lock_guard lock(mutex_);
  if (CoordinatorEpoch::can_advance(epoch_.value())) {
    epoch_ = epoch_.next();
  }
  return epoch_;
}

void InMemoryEpochAuthority::set(CoordinatorEpoch epoch) {
  const std::lock_guard lock(mutex_);
  epoch_ = epoch;
}

void InMemoryPolicyStore::set(PolicySet policy) {
  const std::unique_lock lock(mutex_);
  policy_ = std::move(policy);
}

PolicySet InMemoryPolicyStore::current_policy() const {
  const std::shared_lock lock(mutex_);
  return policy_;
}

InMemoryEvidence::InMemoryEvidence() {
  topology.set_generation(TopologyGeneration::from_value(1));
  link_state.set_generation(LinkStateGeneration::from_value(1));
  port_state.set_generation(PortConfigGeneration::from_value(1));
  capability.set_generation(CapabilityGeneration::from_value(1));
  failure_domains.set_generation(FailureDomainGeneration::from_value(1));
  PolicySet initial_policy;
  initial_policy.generation = PolicyGeneration::from_value(1);
  initial_policy.scope = default_scope();
  policy.set(initial_policy);
}

EvidenceSources InMemoryEvidence::sources() {
  EvidenceSources sources;
  sources.topology = &topology;
  sources.link_state = &link_state;
  sources.port_state = &port_state;
  sources.capability = &capability;
  sources.failure_domain = &failure_domains;
  sources.epoch = &epoch;
  sources.policy = &policy;
  return sources;
}

}  // namespace path_authority
