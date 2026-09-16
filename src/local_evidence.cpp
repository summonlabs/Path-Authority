// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/local_evidence.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "path_authority/in_memory.hpp"

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace path_authority {
namespace {

std::string sanitize_identity(std::string_view text) {
  std::string cleaned;
  cleaned.reserve(text.size());
  for (char c : text) {
    const bool allowed = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                         (c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == ':' || c == '-';
    if (allowed) {
      cleaned.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c));
    } else if (!cleaned.empty() && cleaned.back() != '-') {
      cleaned.push_back('-');
    }
  }
  while (!cleaned.empty() && cleaned.back() == '-') {
    cleaned.pop_back();
  }
  if (cleaned.empty()) {
    cleaned = "unknown";
  }
  if (!((cleaned.front() >= '0' && cleaned.front() <= '9') ||
        (cleaned.front() >= 'a' && cleaned.front() <= 'z'))) {
    cleaned.insert(cleaned.begin(), 'x');
  }
  return cleaned;
}

#if defined(_WIN32)

std::string to_utf8(const wchar_t* text) {
  if (text == nullptr) {
    return std::string();
  }
  const int required = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
  if (required <= 1) {
    return std::string();
  }
  std::string converted(static_cast<std::size_t>(required - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, text, -1, converted.data(), required, nullptr, nullptr);
  return converted;
}

std::string local_host_identity() {
  std::array<char, 256> buffer{};
  DWORD length = static_cast<DWORD>(buffer.size());
  if (GetComputerNameA(buffer.data(), &length) == 0 || length == 0) {
    return "host-unknown";
  }
  return "host-" + sanitize_identity(std::string_view(buffer.data(), length));
}

bool capture_interfaces(std::vector<LocalHostInterface>& interfaces, std::string& error) {
  ULONG size = 16 * 1024;
  std::vector<unsigned char> storage(size);
  ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                      reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()),
                                      &size);
  if (result == ERROR_BUFFER_OVERFLOW) {
    storage.resize(size);
    result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()), &size);
  }
  if (result != NO_ERROR) {
    error = "GetAdaptersAddresses failed with status " + std::to_string(result);
    return false;
  }

  for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()); adapter != nullptr;
       adapter = adapter->Next) {
    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
      continue;
    }
    if (adapter->AdapterName == nullptr) {
      continue;
    }
    LocalHostInterface entry;
    entry.identity = sanitize_identity(adapter->AdapterName);
    entry.name = to_utf8(adapter->FriendlyName);
    entry.description = to_utf8(adapter->Description);
    entry.speed_bps = adapter->TransmitLinkSpeed;
    entry.mtu = adapter->Mtu;
    entry.index = adapter->IfIndex;
    entry.operational = adapter->OperStatus == IfOperStatusUp;
    entry.admin_up = adapter->OperStatus == IfOperStatusUp;
    interfaces.push_back(std::move(entry));
  }
  return true;
}

#else

std::string local_host_identity() { return "host-unknown"; }

bool capture_interfaces(std::vector<LocalHostInterface>& interfaces, std::string& error) {
  (void)interfaces;
  error =
      "local host interface capture is implemented for Windows only; this build reports no REAL "
      "local evidence";
  return false;
}

#endif

}  // namespace

struct LocalHostFabric::Impl {
  std::string host;
  std::vector<LocalHostInterface> interfaces;
  InMemoryEvidence evidence;
};

LocalHostFabric::LocalHostFabric() : impl_(std::make_unique<Impl>()) {}

LocalHostFabric::~LocalHostFabric() = default;

LocalHostFabric::LocalHostFabric(LocalHostFabric&&) noexcept = default;

LocalHostFabric& LocalHostFabric::operator=(LocalHostFabric&&) noexcept = default;

std::optional<LocalHostFabric> LocalHostFabric::capture(std::string& error) {
  std::vector<LocalHostInterface> interfaces;
  if (!capture_interfaces(interfaces, error)) {
    return std::nullopt;
  }
  LocalHostFabric fabric;
  fabric.impl_->host = local_host_identity();
  fabric.impl_->interfaces = std::move(interfaces);

  const std::string endpoint = fabric.impl_->host + "-ep0";
  StructuralElementRecord endpoint_record;
  endpoint_record.kind = ElementKind::ENDPOINT;
  endpoint_record.id = endpoint;
  endpoint_record.generation = StructuralGeneration::from_value(1);
  fabric.impl_->evidence.topology.put(endpoint_record);

  const std::string boundary = fabric.impl_->host + "-fabric-boundary";
  StructuralElementRecord boundary_record;
  boundary_record.kind = ElementKind::FABRIC_BOUNDARY;
  boundary_record.id = boundary;
  boundary_record.generation = StructuralGeneration::from_value(1);
  fabric.impl_->evidence.topology.put(boundary_record);

  for (const auto& entry : fabric.impl_->interfaces) {
    const std::string port = "port-" + entry.identity;
    const std::string link = "link-" + entry.identity;
    StructuralElementRecord port_record;
    port_record.kind = ElementKind::PORT;
    port_record.id = port;
    port_record.generation = StructuralGeneration::from_value(1);
    fabric.impl_->evidence.topology.put(port_record);

    StructuralElementRecord link_record;
    link_record.kind = ElementKind::LINK;
    link_record.id = link;
    link_record.generation = StructuralGeneration::from_value(1);
    fabric.impl_->evidence.topology.put(link_record);

    fabric.impl_->evidence.topology.allow_hop(ElementRef{ElementKind::ENDPOINT, endpoint},
                                              ElementRef{ElementKind::PORT, port});
    fabric.impl_->evidence.topology.allow_hop(ElementRef{ElementKind::PORT, port},
                                              ElementRef{ElementKind::LINK, link});
    fabric.impl_->evidence.topology.allow_hop(ElementRef{ElementKind::LINK, link},
                                              ElementRef{ElementKind::FABRIC_BOUNDARY, boundary});

    fabric.impl_->evidence.link_state.put(
        LinkId::parse(link), entry.operational ? LinkState::UP : LinkState::DOWN,
        LinkStateGeneration::from_value(1));
    fabric.impl_->evidence.port_state.put(
        PortId::parse(port), entry.admin_up ? PortAdminState::ACTIVE : PortAdminState::ADMIN_DISABLED,
        PortConfigGeneration::from_value(1));

    fabric.impl_->evidence.capability.put(link, CapabilityKey::parse("mtu"),
                                          CapabilityValue::unsigned_integer(entry.mtu),
                                          CapabilityGeneration::from_value(1));
    fabric.impl_->evidence.capability.put(
        link, CapabilityKey::parse("speed_gbps"),
        CapabilityValue::unsigned_integer(entry.speed_bps / 1000000000ULL),
        CapabilityGeneration::from_value(1));
    fabric.impl_->evidence.capability.put(link, CapabilityKey::parse("operational"),
                                          CapabilityValue::boolean(entry.operational),
                                          CapabilityGeneration::from_value(1));
  }
  return fabric;
}

EvidenceSources LocalHostFabric::sources() const { return impl_->evidence.sources(); }

const std::vector<LocalHostInterface>& LocalHostFabric::interfaces() const noexcept {
  return impl_->interfaces;
}

std::string LocalHostFabric::host_identity() const { return impl_->host; }

std::optional<PathDefinition> LocalHostFabric::endpoint_port_path(std::size_t interface_index,
                                                                 std::string& error) const {
  if (interface_index >= impl_->interfaces.size()) {
    error = "interface index is out of range";
    return std::nullopt;
  }
  const auto& entry = impl_->interfaces[interface_index];
  const std::string endpoint = impl_->host + "-ep0";
  const std::string port = "port-" + entry.identity;
  const std::string link = "link-" + entry.identity;

  PathDefinition candidate;
  candidate.type = PathType::PHYSICAL;
  candidate.generation = PathGeneration::from_value(1);
  candidate.scope = ScopeId::parse("local-host");
  candidate.constraint_set = ConstraintSetId::parse("local-host-constraints");
  candidate.constraint_generation = ConstraintGeneration::from_value(1);
  PathElement endpoint_hop;
  endpoint_hop.kind = ElementKind::ENDPOINT;
  endpoint_hop.id = endpoint;
  endpoint_hop.generation = StructuralGeneration::from_value(1);
  PathElement port_hop;
  port_hop.kind = ElementKind::PORT;
  port_hop.id = port;
  port_hop.generation = StructuralGeneration::from_value(1);
  PathElement link_hop;
  link_hop.kind = ElementKind::LINK;
  link_hop.id = link;
  link_hop.generation = StructuralGeneration::from_value(1);
  PathElement boundary_hop;
  boundary_hop.kind = ElementKind::FABRIC_BOUNDARY;
  boundary_hop.id = impl_->host + "-fabric-boundary";
  boundary_hop.generation = StructuralGeneration::from_value(1);
  candidate.hops = {endpoint_hop, port_hop, link_hop, boundary_hop};
  candidate.id = candidate.derived_id();
  return candidate;
}

ConstraintSet LocalHostFabric::constraints() const {
  ConstraintSet set;
  set.id = ConstraintSetId::parse("local-host-constraints");
  set.generation = ConstraintGeneration::from_value(1);
  set.scope = ScopeId::parse("local-host");
  set.link_state = LinkStateAcceptance::strict();
  set.layers.allowed_layers = {Layer::PHYSICAL};
  set.max_hops = 8;
  return set;
}

std::string LocalHostFabric::describe() const {
  std::string text;
  text += "classification=REAL\n";
  text += "scope=local-host\n";
  text += "host=" + impl_->host + "\n";
  text += "interfaces=" + std::to_string(impl_->interfaces.size()) + "\n";
  for (const auto& entry : impl_->interfaces) {
    text += "interface=" + entry.identity + " name=" + entry.name +
            " operational=" + std::string(entry.operational ? "true" : "false") +
            " admin_up=" + std::string(entry.admin_up ? "true" : "false") +
            " mtu=" + std::to_string(entry.mtu) +
            " speed_bps=" + std::to_string(entry.speed_bps) + "\n";
  }
  text += "note=local host evidence only; the terminal fabric boundary marks where local\n";
  text += "note=visibility ends and it says nothing about switch fabric internals\n";
  return text;
}

}  // namespace path_authority
