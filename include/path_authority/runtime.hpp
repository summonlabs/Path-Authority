// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "path_authority/authority.hpp"
#include "path_authority/evidence.hpp"
#include "path_authority/export.hpp"
#include "path_authority/limits.hpp"
#include "path_authority/snapshot.hpp"
#include "path_authority/version.hpp"

namespace path_authority {

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------
struct PATH_AUTHORITY_API EvaluationRequest {
  // Idempotency key for this mutation attempt. Replaying the same attempt with
  // identical semantic input is idempotent; reusing it with different input is
  // rejected. Excluded from the semantic digest.
  MutationAttemptId attempt;
  // When set, the caller asserts the Fabric Epoch it evaluated under. A
  // mismatch against current epoch authority is STALE_EPOCH.
  std::optional<CoordinatorEpoch> binding_epoch;
  // Compare-and-set on the committed authority generation. Excluded from the
  // semantic digest.
  std::optional<PathAuthorityGeneration> expected_authority_generation;
  // When true the declared PathId must equal the id derived from canonical
  // content.
  bool require_identity_binding = true;
  PublisherId publisher;
  WorkerBootId worker_boot;
};

struct PATH_AUTHORITY_API BatchEntry {
  PathDefinition path;
  MutationAttemptId attempt;
};

struct PATH_AUTHORITY_API RevalidationRequest {
  MutationAttemptId attempt;
  std::optional<PathAuthorityGeneration> expected_authority_generation;
  PublisherId publisher;
  WorkerBootId worker_boot;
};

struct PATH_AUTHORITY_API RevocationRequest {
  MutationAttemptId attempt;
  RevocationReason reason = RevocationReason::ADMINISTRATIVE;
  std::string explanation;
  std::string authority;
  std::optional<PathAuthorityGeneration> expected_authority_generation;
  bool durable = true;
};

// ---------------------------------------------------------------------------
// Dependency invalidation
// ---------------------------------------------------------------------------
struct PATH_AUTHORITY_API InvalidationReport {
  InvalidationCause cause = InvalidationCause::LINK_STATE_CHANGE;
  std::string subject;
  std::uint64_t generation = 0;
  std::vector<PathId> revalidation_required;
  std::vector<PathId> already_current;
  std::size_t dependents() const noexcept { return revalidation_required.size() + already_current.size(); }
  std::string render() const;
};

// ---------------------------------------------------------------------------
// Durable state. Live authority never survives a restart: recovery restores
// descriptions, revocations and generations, and requires revalidation.
// ---------------------------------------------------------------------------
struct PATH_AUTHORITY_API DurablePathRecord {
  PathDefinition definition;
  PathAuthorityGeneration authority_generation;
  AuthorityState state = AuthorityState::UNKNOWN;
  EvaluationOutcome outcome = EvaluationOutcome::MALFORMED_PATH;
  EvidenceVector evidence;
  Digest authority_digest;
  std::optional<RevocationRecord> revocation;
  std::vector<HistoryEntry> history;
  bool retired = false;
  PublisherId publisher;
  WorkerBootId worker_boot;
};

struct PATH_AUTHORITY_API DurableState {
  std::uint32_t format_version = kPersistenceFormatVersion;
  CoordinatorEpoch epoch;
  PolicySet policy;
  std::vector<ConstraintSet> constraint_sets;
  std::vector<DurablePathRecord> records;
  // Worker incarnations fenced by the coordinator. Recovered on restart so a
  // pre-restart worker boot identity can never publish again.
  std::vector<WorkerBootId> fenced;

  Digest digest() const;
};

struct PATH_AUTHORITY_API RuntimeStats {
  std::size_t paths = 0;
  std::size_t authorizing = 0;
  std::size_t revalidation_required = 0;
  std::size_t revoked = 0;
  std::size_t rejected = 0;
  std::size_t elements_indexed = 0;
  std::size_t capabilities_indexed = 0;
  std::size_t domains_indexed = 0;
  std::size_t attempts_tracked = 0;
  CoordinatorEpoch epoch;
  PolicyGeneration policy;
};

// ---------------------------------------------------------------------------
// Runtime configuration
// ---------------------------------------------------------------------------
struct PATH_AUTHORITY_API RuntimeConfig {
  Limits limits;
  // Retaining snapshots enables diff-by-id and bounded history inspection at
  // the cost of memory per path. History entries are always retained bounded.
  bool retain_snapshots = false;
  // When true, an evaluation that matches the committed semantic digest is
  // reported as IDEMPOTENT instead of re-committing.
  bool idempotent_replay = true;
};

// ---------------------------------------------------------------------------
// PathAuthorityRuntime
//
// Thread safety: all public operations are safe to call concurrently from any
// thread. Evidence views are borrowed and must outlive the runtime. Mutation
// operations are serialised internally; evaluation performs its evidence reads
// outside the state lock, so a view call never happens under it and no
// callback is ever invoked while holding a lock.
// ---------------------------------------------------------------------------
class PATH_AUTHORITY_API PathAuthorityRuntime {
 public:
  explicit PathAuthorityRuntime(EvidenceSources sources, RuntimeConfig config = {});
  PathAuthorityRuntime(EvidenceSources sources, Limits limits);
  ~PathAuthorityRuntime();

  PathAuthorityRuntime(const PathAuthorityRuntime&) = delete;
  PathAuthorityRuntime& operator=(const PathAuthorityRuntime&) = delete;
  PathAuthorityRuntime(PathAuthorityRuntime&&) = delete;
  PathAuthorityRuntime& operator=(PathAuthorityRuntime&&) = delete;

  // -- versioned inputs ----------------------------------------------------
  struct PATH_AUTHORITY_API ConstraintRegistration {
    ConstraintSetId id;
    ConstraintGeneration generation;
    bool created = false;
    std::size_t invalidated = 0;
  };
  ConstraintRegistration register_constraint_set(ConstraintSet set);
  std::optional<ConstraintSet> constraint_set(const ConstraintSetId& id) const;

  // The live policy is read from the PolicyStore view: the policy authority
  // owns policy truth, Path Authority only binds decisions to its generation.
  PolicySet policy() const;

  CoordinatorEpoch current_epoch() const;
  const Limits& limits() const noexcept;
  RuntimeStats stats() const;

  // -- evaluation ----------------------------------------------------------
  EvaluationResult evaluate(const PathDefinition& path, const EvaluationRequest& request);

  // A decision computed elsewhere and published to this runtime. Every field is
  // verified before anything is committed: the canonical path digest, the
  // constraint binding, the epoch and policy binding of the evidence vector,
  // and the recomputed semantic authority digest. A published decision can
  // never forge authority, and a stale publisher can never refresh it.
  struct PATH_AUTHORITY_API PublishedDecision {
    AuthorityState state = AuthorityState::UNKNOWN;
    EvaluationOutcome primary = EvaluationOutcome::MALFORMED_PATH;
    Violation primary_violation;
    EvidenceVector evidence;
    Digest path_digest;
    Digest authority_digest;
    Digest constraint_digest;
    std::vector<Violation> secondary;
  };
  EvaluationResult publish_decision(const PathDefinition& path, const PublishedDecision& decision,
                                    const EvaluationRequest& request);
  std::vector<EvaluationResult> evaluate_batch(const std::vector<BatchEntry>& batch,
                                               const EvaluationRequest& request);

  // -- currentness ---------------------------------------------------------
  std::optional<AuthoritySnapshot> query(const PathId& path) const;
  std::optional<AuthoritySnapshot> snapshot(const PathId& path) const;
  std::vector<AuthoritySnapshot> snapshots_all() const;
  std::vector<EvidenceDelta> stale_dependencies(const PathId& path) const;
  std::string explain(const PathId& path) const;

  // -- revalidation, revocation, retirement --------------------------------
  EvaluationResult revalidate(const PathId& path, const RevalidationRequest& request);
  EvaluationResult revoke(const PathId& path, const RevocationRequest& request);
  EvaluationResult retire(const PathId& path, const MutationAttemptId& attempt,
                          std::string_view explanation);

  // -- dependency invalidation --------------------------------------------
  InvalidationReport invalidate_link(const LinkId& link, LinkStateGeneration generation);
  InvalidationReport invalidate_port(const PortId& port, PortConfigGeneration generation);
  InvalidationReport invalidate_element(ElementKind kind, std::string_view id,
                                        StructuralGeneration generation);
  InvalidationReport invalidate_topology(TopologyGeneration generation);
  InvalidationReport invalidate_capability(std::string_view entity, const CapabilityKey& key,
                                           CapabilityGeneration generation);
  InvalidationReport invalidate_failure_domain(const FailureDomainId& domain,
                                               FailureDomainGeneration generation);
  // Membership classification of one element changed. This is the dependency
  // that "an element joined a shared risk group" invalidates.
  InvalidationReport invalidate_membership(const ElementRef& element,
                                           FailureDomainGeneration generation);
  InvalidationReport invalidate_epoch(CoordinatorEpoch epoch);
  InvalidationReport invalidate_policy(PolicyGeneration generation);
  InvalidationReport invalidate_constraints(const ConstraintSetId& id,
                                            ConstraintGeneration generation);
  InvalidationReport invalidate_underlying(const PathId& underlying,
                                           PathAuthorityGeneration generation);
  InvalidationReport invalidate_publisher(const PublisherId& publisher,
                                          const WorkerBootId& boot);

  std::vector<PathId> dependents_of_element(ElementKind kind, std::string_view id) const;
  std::vector<PathId> dependents_of_capability(std::string_view entity,
                                               const CapabilityKey& key) const;
  std::vector<PathId> dependents_of_failure_domain(const FailureDomainId& domain) const;
  std::vector<PathId> dependents_of_underlying(const PathId& underlying) const;

  // -- snapshot retention --------------------------------------------------
  std::optional<AuthoritySnapshot> retained_snapshot(const PathSnapshotId& id) const;
  std::optional<AuthorityDiff> diff(const PathSnapshotId& before,
                                    const PathSnapshotId& after) const;

  // -- persistence ---------------------------------------------------------
  DurableState export_state() const;
  // Conservative recovery: every recovered record that was authorizing becomes
  // REVALIDATION_REQUIRED at a new authority generation. Revocations, retired
  // markers and path descriptions survive. Live authority does not.
  void import_state(DurableState state);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace path_authority
