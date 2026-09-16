// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "path_authority/evidence.hpp"
#include "path_authority/export.hpp"
#include "path_authority/path.hpp"

namespace path_authority {

// One captured local host interface. This is REAL evidence: the identity and
// state are read from the operating system on the machine running the
// process. It says nothing about any switch fabric.
struct PATH_AUTHORITY_API LocalHostInterface {
  std::string identity;   // stable adapter identity from the OS
  std::string name;       // human readable adapter name
  std::string description;
  std::uint64_t speed_bps = 0;
  std::uint32_t mtu = 0;
  std::uint64_t index = 0;
  bool operational = false;
  bool admin_up = false;
};

// REAL local structural evidence: endpoint -> port -> link built from the
// interfaces actually present on this host. Path Authority validates such a
// path against this evidence exactly like any other; the evidence simply
// covers one host and is reported as REAL in the scenario description.
class PATH_AUTHORITY_API LocalHostFabric {
 public:
  static std::optional<LocalHostFabric> capture(std::string& error);

  LocalHostFabric();
  ~LocalHostFabric();
  LocalHostFabric(LocalHostFabric&&) noexcept;
  LocalHostFabric& operator=(LocalHostFabric&&) noexcept;
  LocalHostFabric(const LocalHostFabric&) = delete;
  LocalHostFabric& operator=(const LocalHostFabric&) = delete;

  EvidenceSources sources() const;
  const std::vector<LocalHostInterface>& interfaces() const noexcept;
  std::string host_identity() const;
  std::string describe() const;

  // Builds the real candidate path endpoint -> port -> link for one adapter.
  std::optional<PathDefinition> endpoint_port_path(std::size_t interface_index,
                                                   std::string& error) const;
  ConstraintSet constraints() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace path_authority
