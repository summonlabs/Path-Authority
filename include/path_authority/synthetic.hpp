// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "path_authority/export.hpp"
#include "path_authority/in_memory.hpp"
#include "path_authority/runtime.hpp"

namespace path_authority {

// A synthetic leaf-spine fabric used by examples, the CLI, benchmarks and the
// distributed proofs. Every element it reports is SYNTHETIC: it is a modelling
// fixture, never evidence about a physical fabric.
class PATH_AUTHORITY_API SyntheticEnvironment {
 public:
  static std::vector<std::string> scenario_names();
  static bool scenario_exists(std::string_view name);

  explicit SyntheticEnvironment(std::string_view scenario = "simple");
  ~SyntheticEnvironment();
  SyntheticEnvironment(const SyntheticEnvironment&) = delete;
  SyntheticEnvironment& operator=(const SyntheticEnvironment&) = delete;

  const std::string& scenario() const noexcept;
  bool synthetic() const noexcept { return true; }
  std::string describe() const;

  EvidenceSources sources();

  // The candidate path this scenario evaluates. Path Authority validates it;
  // it never searches for it.
  PathDefinition path() const;
  // A second candidate used by diversity scenarios.
  PathDefinition backup_path() const;
  ConstraintSet constraints() const;
  PolicySet policy() const;

  InMemoryEvidence& evidence();
  InMemoryTopology& topology();
  InMemoryLinkState& link_state();
  InMemoryPortState& port_state();
  InMemoryCapabilityRegistry& capability();
  InMemoryFailureDomains& failure_domains();
  InMemoryEpochAuthority& epoch();
  InMemoryPolicyStore& policy_store();

  // Named element identities of the fixture, so callers can mutate exactly one
  // dependency (for example to take one link down).
  struct Elements {
    std::string endpoint_a;
    std::string endpoint_b;
    std::string port_a;
    std::string port_b;
    std::string link_a;
    std::string link_b;
    std::string link_c;
    std::string backup_link_a;
    std::string backup_link_b;
    std::string switch_a;
    std::string switch_b;
    std::string switch_c;
    std::string scope;
  };
  const Elements& elements() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// The policy set used by the synthetic fixture and the CLI when no policy is
// supplied: strict link state, conditional degraded links allowed, loops
// rejected, logical paths allowed.
PATH_AUTHORITY_API PolicySet default_policy();

}  // namespace path_authority
