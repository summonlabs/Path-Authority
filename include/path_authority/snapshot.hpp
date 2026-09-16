// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "path_authority/authority.hpp"
#include "path_authority/export.hpp"

namespace path_authority {

// An immutable view of path authority at one authority generation. Snapshots
// stay inspectable forever; they are never a source of current authority.
struct PATH_AUTHORITY_API AuthoritySnapshot {
  PathSnapshotId id;
  PathId path;
  PathGeneration path_generation;
  PathAuthorityGeneration authority_generation;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome last_outcome = EvaluationOutcome::MALFORMED_PATH;
  EvidenceVector evidence;
  ConstraintSetId constraint_set;
  ConstraintGeneration constraint_generation;
  PolicyGeneration policy;
  CoordinatorEpoch epoch;
  Digest path_digest;
  Digest authority_digest;
  // The exact candidate path this authority result is bound to.
  PathDefinition definition;
  Violation primary_violation;
  std::vector<Violation> secondary;
  std::vector<HistoryEntry> history;
  std::optional<RevocationRecord> revocation;
  PublisherId publisher;
  WorkerBootId worker_boot;
  std::uint64_t evaluations = 0;
  std::uint64_t revalidations = 0;

  // Computed against live evidence when the snapshot is produced by query();
  // false means the snapshot must not be treated as current authority.
  bool current = false;
  std::vector<EvidenceDelta> stale_dependencies;

  bool authorized() const noexcept { return is_authorizing_outcome(last_outcome); }
  Digest snapshot_digest() const;
  std::string render() const;
};

enum class AuthorityDiffKind : std::uint8_t {
  PATH_STRUCTURE = 1,
  PATH_GENERATION = 2,
  CONSTRAINT_SET = 3,
  POLICY = 4,
  EPOCH = 5,
  TOPOLOGY_BINDING = 6,
  STRUCTURAL_ELEMENT = 7,
  LINK_STATE = 8,
  PORT_CONFIG = 9,
  CAPABILITY = 10,
  FAILURE_DOMAIN = 11,
  UNDERLYING_AUTHORITY = 12,
  AUTHORITY_STATE = 13,
  AUTHORITY_GENERATION = 14,
  AUTHORITY_DIGEST = 15,
  REVOCATION = 16,
  OUTCOME = 17,
};

PATH_AUTHORITY_API std::string_view to_string(AuthorityDiffKind kind) noexcept;

struct PATH_AUTHORITY_API AuthorityDiffEntry {
  AuthorityDiffKind kind = AuthorityDiffKind::AUTHORITY_STATE;
  std::string subject;
  std::string before;
  std::string after;

  friend bool operator==(const AuthorityDiffEntry&, const AuthorityDiffEntry&) = default;
  friend std::strong_ordering operator<=>(const AuthorityDiffEntry& lhs,
                                          const AuthorityDiffEntry& rhs);
  std::string render() const;
};

// Deterministic, stably ordered difference between two snapshots.
struct PATH_AUTHORITY_API AuthorityDiff {
  PathId path;
  PathSnapshotId before;
  PathSnapshotId after;
  std::vector<AuthorityDiffEntry> entries;

  bool empty() const noexcept { return entries.empty(); }
  std::string render() const;
};

PATH_AUTHORITY_API AuthorityDiff diff_snapshots(const AuthoritySnapshot& before,
                                                const AuthoritySnapshot& after);

}  // namespace path_authority
