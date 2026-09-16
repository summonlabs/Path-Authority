// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "path_authority/evidence.hpp"
#include "path_authority/export.hpp"
#include "path_authority/runtime.hpp"
#include "path_authority/wire.hpp"

namespace path_authority {

// Distributed path-authority publication over real loopback TCP with the
// framed protocol in wire.hpp. The coordinator owns the Fabric Epoch, the
// worker registry, the durable store and the authoritative runtime.
struct PATH_AUTHORITY_API CoordinatorConfig {
  std::string bind_host = "127.0.0.1";
  std::uint16_t port = 0;  // 0 selects an ephemeral port
  std::filesystem::path store_path;
  bool persistence_enabled = true;
  bool persist_after_mutation = true;
  std::size_t max_connections = 64;
  std::uint32_t max_publishers = 128;
  // When set, the coordinator starts at this epoch instead of advancing the
  // recovered epoch. Lowering the epoch below a recovered one is rejected.
  CoordinatorEpoch epoch_override;
  // Required: the coordinator owns Fabric Epoch. The authority must outlive the
  // coordinator.
  MutableEpochAuthority* epoch_control = nullptr;
};

class PATH_AUTHORITY_API PathAuthorityCoordinator {
 public:
  PathAuthorityCoordinator(CoordinatorConfig config, EvidenceSources sources,
                           RuntimeConfig runtime_config = {});
  ~PathAuthorityCoordinator();

  PathAuthorityCoordinator(const PathAuthorityCoordinator&) = delete;
  PathAuthorityCoordinator& operator=(const PathAuthorityCoordinator&) = delete;

  // Recovers durable state (if configured), advances the Fabric Epoch beyond
  // the recovered one, then binds and listens.
  bool start(std::string& error);
  void stop();
  bool running() const;

  std::uint16_t port() const;
  CoordinatorEpoch epoch() const;
  PathAuthorityRuntime& runtime();
  const PathAuthorityRuntime& runtime() const;

  std::size_t worker_count() const;
  std::size_t fenced_count() const;
  std::vector<WorkerInfo> workers() const;

  // Persists the durable state atomically. Returns false with a reason when
  // the store is disabled or the write fails.
  bool persist(std::string& error);
  std::size_t recovered_records() const;
  CoordinatorEpoch recovered_epoch() const;
  std::string describe() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

struct PATH_AUTHORITY_API EvaluatorConfig {
  std::string coordinator_host = "127.0.0.1";
  std::uint16_t coordinator_port = 0;
  PublisherId publisher;
  WorkerBootId worker_boot;
  ScopeId scope;
  std::string agent = "path-authority-evaluator";
  // When false (the default) the evaluator adopts the coordinator Fabric Epoch
  // at registration, which is what a worker that follows epoch authority does.
  // When true the evaluator keeps its own pinned epoch, which is how a stale
  // publisher is modelled.
  bool pin_epoch = false;
};

// An evaluator is a real OS process role: it evaluates candidate paths against
// the evidence it can see and publishes the decision. It never owns authority.
class PATH_AUTHORITY_API PathAuthorityEvaluator {
 public:
  PathAuthorityEvaluator(EvaluatorConfig config, EvidenceSources sources,
                         RuntimeConfig runtime_config = {});
  ~PathAuthorityEvaluator();

  PathAuthorityEvaluator(const PathAuthorityEvaluator&) = delete;
  PathAuthorityEvaluator& operator=(const PathAuthorityEvaluator&) = delete;

  bool connect(std::string& error);
  bool register_worker(std::string& error);
  bool registered() const;
  CoordinatorEpoch coordinator_epoch() const;
  PolicyGeneration coordinator_policy() const;

  // Evaluates locally, then publishes. The coordinator independently verifies
  // the epoch, the worker incarnation, the attempt id and the recomputed
  // semantic digest before committing anything.
  PublishAck publish(const PathDefinition& path, const EvaluationRequest& request);
  ResultAck revalidate(const PathId& path, const RevalidationRequest& request);
  ResultAck revoke(const PathId& path, const RevocationRequest& request);
  QueryResult query(const PathId& path);
  std::vector<WorkerInfo> workers();
  bool heartbeat();

  // Local runtime used for the evaluator side of an evaluation.
  PathAuthorityRuntime& runtime();
  const EvaluatorConfig& config() const noexcept;
  std::string last_error() const;
  void disconnect();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace path_authority
