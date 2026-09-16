// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/distributed.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "path_authority/canonical.hpp"
#include "path_authority/persistence.hpp"
#include "path_authority/version.hpp"

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace path_authority {
namespace {

#if defined(_WIN32)
using socket_handle = SOCKET;
constexpr socket_handle kInvalidSocket = INVALID_SOCKET;
#else
using socket_handle = int;
constexpr socket_handle kInvalidSocket = -1;
#endif

constexpr int kSelectSliceMs = 50;

void ensure_network_initialized() {
  static std::once_flag once;
  std::call_once(once, []() {
#if defined(_WIN32)
    WSADATA data{};
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
      throw std::runtime_error("WSAStartup failed");
    }
#endif
  });
}

void close_socket(socket_handle handle) {
  if (handle == kInvalidSocket) {
    return;
  }
#if defined(_WIN32)
  closesocket(handle);
#else
  ::close(handle);
#endif
}

std::string socket_error_text() {
#if defined(_WIN32)
  return "socket error " + std::to_string(WSAGetLastError());
#else
  return std::string("socket error ") + std::strerror(errno);
#endif
}

bool send_all(socket_handle handle, const std::vector<std::byte>& bytes, std::string& error) {
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const int chunk = static_cast<int>(std::min<std::size_t>(bytes.size() - offset, 1u << 16));
    const int sent = ::send(handle, reinterpret_cast<const char*>(bytes.data() + offset), chunk, 0);
    if (sent <= 0) {
      error = "send failed: " + socket_error_text();
      return false;
    }
    offset += static_cast<std::size_t>(sent);
  }
  return true;
}

bool send_frame(socket_handle handle, const Frame& frame, const Limits& limits, std::string& error) {
  std::vector<std::byte> bytes;
  try {
    bytes = encode_frame(frame, limits);
  } catch (const std::exception& failure) {
    error = failure.what();
    return false;
  }
  return send_all(handle, bytes, error);
}

enum class ReceiveStatus { FRAME, TIMEOUT, CLOSED, FAILED };

ReceiveStatus receive_frame(socket_handle handle, const Limits& limits, Frame& frame,
                            std::string& error) {
  std::vector<std::byte> buffer;
  buffer.reserve(4096);
  std::array<std::byte, 8192> chunk{};
  for (;;) {
    std::size_t consumed = 0;
    std::string decode_error;
    const auto decoded = decode_frame(buffer, limits, consumed, decode_error);
    if (decoded.has_value()) {
      frame = *decoded;
      return ReceiveStatus::FRAME;
    }
    if (!decode_error.empty()) {
      error = decode_error;
      return ReceiveStatus::FAILED;
    }
    if (buffer.size() > static_cast<std::size_t>(limits.max_frame_bytes) + 64) {
      error = "peer frame exceeds Limits::max_frame_bytes";
      return ReceiveStatus::FAILED;
    }
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(handle, &read_set);
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = kSelectSliceMs * 1000;
    const int ready = ::select(static_cast<int>(handle) + 1, &read_set, nullptr, nullptr, &timeout);
    if (ready < 0) {
      error = "select failed: " + socket_error_text();
      return ReceiveStatus::FAILED;
    }
    if (ready == 0) {
      error.clear();
      return ReceiveStatus::TIMEOUT;
    }
    const int received = ::recv(handle, reinterpret_cast<char*>(chunk.data()),
                                static_cast<int>(chunk.size()), 0);
    if (received == 0) {
      error.clear();
      return ReceiveStatus::CLOSED;
    }
    if (received < 0) {
      error = "receive failed: " + socket_error_text();
      return ReceiveStatus::FAILED;
    }
    buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + received);
  }
}

bool resolve_host(const std::string& host, std::uint16_t port, sockaddr_in& address, std::string& error) {
  address = sockaddr_in{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  if (host.empty() || host == "localhost") {
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return true;
  }
  if (::inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
    error = "unsupported coordinator host address: " + host;
    return false;
  }
  return true;
}

bool tcp_listen(const std::string& host, std::uint16_t port, socket_handle& handle,
                std::uint16_t& bound_port, std::string& error) {
  ensure_network_initialized();
  sockaddr_in address{};
  if (!resolve_host(host, port, address, error)) {
    return false;
  }
  handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == kInvalidSocket) {
    error = "cannot create listening socket: " + socket_error_text();
    return false;
  }
  int reuse = 1;
  ::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
               sizeof(reuse));
  if (::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    error = "cannot bind " + host + ":" + std::to_string(port) + ": " + socket_error_text();
    close_socket(handle);
    handle = kInvalidSocket;
    return false;
  }
  if (::listen(handle, 16) != 0) {
    error = "cannot listen: " + socket_error_text();
    close_socket(handle);
    handle = kInvalidSocket;
    return false;
  }
  sockaddr_in actual{};
#if defined(_WIN32)
  int length = sizeof(actual);
#else
  socklen_t length = sizeof(actual);
#endif
  if (::getsockname(handle, reinterpret_cast<sockaddr*>(&actual), &length) != 0) {
    error = "cannot resolve the bound port: " + socket_error_text();
    close_socket(handle);
    handle = kInvalidSocket;
    return false;
  }
  bound_port = ntohs(actual.sin_port);
  return true;
}

bool tcp_connect(const std::string& host, std::uint16_t port, socket_handle& handle,
                 std::string& error) {
  ensure_network_initialized();
  sockaddr_in address{};
  if (!resolve_host(host, port, address, error)) {
    return false;
  }
  handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == kInvalidSocket) {
    error = "cannot create socket: " + socket_error_text();
    return false;
  }
  if (::connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    error = "cannot connect to " + host + ":" + std::to_string(port) + ": " + socket_error_text();
    close_socket(handle);
    handle = kInvalidSocket;
    return false;
  }
  int nodelay = 1;
  ::setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay),
               sizeof(nodelay));
  return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------
struct PathAuthorityCoordinator::Impl {
  struct WorkerEntry {
    PublisherId publisher;
    WorkerBootId boot;
    ScopeId scope;
    CoordinatorEpoch epoch;
    std::size_t published = 0;
    std::uint64_t connection = 0;
  };

  struct ConnectionState {
    socket_handle handle = kInvalidSocket;
    std::uint64_t id = 0;
    std::atomic<bool> finished{false};
    std::set<std::string> workers;
    std::thread thread;
  };

  Impl(CoordinatorConfig configuration, EvidenceSources source_views, RuntimeConfig runtime_configuration)
      : config(std::move(configuration)),
        sources(source_views),
        runtime(new PathAuthorityRuntime(source_views, runtime_configuration)) {}

  ~Impl() { stop(); }

  CoordinatorConfig config;
  EvidenceSources sources;
  std::unique_ptr<PathAuthorityRuntime> runtime;

  socket_handle listener = kInvalidSocket;
  std::uint16_t bound_port = 0;
  std::atomic<bool> stopping{false};
  std::thread accept_thread;

  mutable std::mutex connections_mutex;
  std::map<std::uint64_t, std::shared_ptr<ConnectionState>> connections;
  std::uint64_t next_connection_id = 1;

  mutable std::mutex worker_mutex;
  std::map<std::string, WorkerEntry> workers;
  std::set<std::string> fenced;

  std::size_t recovered_records = 0;
  CoordinatorEpoch recovered_epoch;

  const Limits& limits() const { return runtime->limits(); }

  void persist_now() {
    if (!config.persistence_enabled || config.store_path.empty() || !config.persist_after_mutation) {
      return;
    }
    std::string error;
    persist(error);
  }

  bool persist(std::string& error) {
    if (!config.persistence_enabled || config.store_path.empty()) {
      error = "persistence is disabled for this coordinator";
      return false;
    }
    try {
      DurableState state = runtime->export_state();
      {
        // Every worker incarnation registered with this coordinator is fenced
        // for the next one: its connection dies with this process, so it can
        // never be current again.
        const std::lock_guard lock(worker_mutex);
        std::set<std::string> all = fenced;
        for (const auto& [boot, entry] : workers) {
          (void)entry;
          all.insert(boot);
        }
        state.fenced.clear();
        for (const auto& boot : all) {
          const auto parsed = WorkerBootId::from_wire(boot);
          if (parsed.has_value()) {
            state.fenced.push_back(*parsed);
          }
        }
      }
      write_store(state, config.store_path, limits());
      return true;
    } catch (const std::exception& failure) {
      error = failure.what();
      return false;
    }
  }

  bool start(std::string& error) {
    if (config.epoch_control == nullptr) {
      error = "coordinator requires a mutable Fabric Epoch authority";
      return false;
    }
    if (config.persistence_enabled && !config.store_path.empty()) {
      std::error_code file_error;
      if (std::filesystem::exists(config.store_path, file_error) && !file_error) {
        try {
          DurableState state = read_store(config.store_path, limits());
          recovered_records = state.records.size();
          recovered_epoch = state.epoch;
          {
            const std::lock_guard lock(worker_mutex);
            for (const auto& boot : state.fenced) {
              fenced.insert(boot.str());
            }
          }
          runtime->import_state(std::move(state));
        } catch (const std::exception& failure) {
          error = std::string("cannot recover durable state: ") + failure.what();
          return false;
        }
      }
    }

    // Fabric Epoch ownership: a fresh coordinator consumes the new current
    // epoch, never the one its predecessor used.
    CoordinatorEpoch epoch = config.epoch_control->current();
    if (recovered_epoch.is_set() && !CoordinatorEpoch::can_advance(recovered_epoch.value())) {
      error = "recovered Fabric Epoch cannot be advanced";
      return false;
    }
    const CoordinatorEpoch recovered_next =
        recovered_epoch.is_set() ? recovered_epoch.next() : CoordinatorEpoch{};
    if (recovered_next.is_set() && recovered_next > epoch) {
      epoch = recovered_next;
    }
    if (config.epoch_override.is_set()) {
      if (recovered_next.is_set() && config.epoch_override < recovered_next) {
        error = "epoch override is lower than the recovered epoch";
        return false;
      }
      epoch = config.epoch_override;
    }
    if (!epoch.is_set()) {
      epoch = CoordinatorEpoch::from_value(1);
    }
    config.epoch_control->set(epoch);

    stopping.store(false);
    if (!tcp_listen(config.bind_host, config.port, listener, bound_port, error)) {
      return false;
    }
    accept_thread = std::thread([this]() { accept_loop(); });
    return true;
  }

  void stop() {
    if (listener == kInvalidSocket && !accept_thread.joinable()) {
      return;
    }
    stopping.store(true);
    close_socket(listener);
    listener = kInvalidSocket;
    if (accept_thread.joinable()) {
      accept_thread.join();
    }
    std::vector<std::shared_ptr<ConnectionState>> pending;
    {
      const std::lock_guard lock(connections_mutex);
      for (auto& [id, connection] : connections) {
        (void)id;
        close_socket(connection->handle);
        connection->handle = kInvalidSocket;
        pending.push_back(connection);
      }
      connections.clear();
    }
    for (auto& connection : pending) {
      if (connection->thread.joinable()) {
        connection->thread.join();
      }
    }
  }

  void reap_finished_connections() {
    std::vector<std::shared_ptr<ConnectionState>> finished;
    {
      const std::lock_guard lock(connections_mutex);
      for (auto it = connections.begin(); it != connections.end();) {
        if (it->second->finished.load()) {
          finished.push_back(it->second);
          it = connections.erase(it);
        } else {
          ++it;
        }
      }
    }
    for (auto& connection : finished) {
      if (connection->thread.joinable()) {
        connection->thread.join();
      }
    }
  }

  void accept_loop() {
    while (!stopping.load()) {
      fd_set read_set;
      FD_ZERO(&read_set);
      FD_SET(listener, &read_set);
      timeval timeout{};
      timeout.tv_sec = 0;
      timeout.tv_usec = kSelectSliceMs * 1000;
      const int ready =
          ::select(static_cast<int>(listener) + 1, &read_set, nullptr, nullptr, &timeout);
      if (stopping.load()) {
        break;
      }
      if (ready <= 0) {
        reap_finished_connections();
        continue;
      }
      const socket_handle client = ::accept(listener, nullptr, nullptr);
      if (client == kInvalidSocket) {
        if (stopping.load()) {
          break;
        }
        reap_finished_connections();
        continue;
      }
      auto connection = std::make_shared<ConnectionState>();
      connection->handle = client;
      {
        const std::lock_guard lock(connections_mutex);
        if (connections.size() >= config.max_connections) {
          close_socket(client);
          continue;
        }
        connection->id = next_connection_id++;
        connections.emplace(connection->id, connection);
      }
      connection->thread = std::thread([this, connection]() { serve_connection(connection); });
      reap_finished_connections();
    }
  }

  bool worker_registered(const WorkerBootId& boot, std::uint64_t connection_id) {
    const std::lock_guard lock(worker_mutex);
    const auto it = workers.find(boot.str());
    return it != workers.end() && it->second.connection == connection_id;
  }

  WorkerEntry worker_snapshot(const WorkerBootId& boot) {
    const std::lock_guard lock(worker_mutex);
    const auto it = workers.find(boot.str());
    if (it == workers.end()) {
      return WorkerEntry{};
    }
    return it->second;
  }

  void note_published(const WorkerBootId& boot) {
    const std::lock_guard lock(worker_mutex);
    const auto it = workers.find(boot.str());
    if (it != workers.end()) {
      it->second.published += 1;
    }
  }

  void fence_connection_workers(const ConnectionState& connection) {
    std::vector<std::pair<PublisherId, WorkerBootId>> lost;
    {
      const std::lock_guard lock(worker_mutex);
      for (const auto& boot : connection.workers) {
        const auto it = workers.find(boot);
        if (it == workers.end()) {
          continue;
        }
        lost.emplace_back(it->second.publisher, it->second.boot);
        if (fenced.size() < limits().max_publishers) {
          fenced.insert(boot);
        }
        workers.erase(it);
      }
    }
    for (const auto& [publisher, boot] : lost) {
      runtime->invalidate_publisher(publisher, boot);
    }
    if (!lost.empty()) {
      persist_now();
    }
  }

  bool send_error(socket_handle handle, std::uint16_t code, const std::string& detail) {
    ErrorMessage message;
    message.code = code;
    message.detail = detail;
    Frame frame;
    frame.type = MessageType::PROTOCOL_ERROR;
    frame.payload = encode_error_message(message);
    std::string error;
    return send_frame(handle, frame, limits(), error);
  }

  void serve_connection(const std::shared_ptr<ConnectionState>& connection) {
    for (;;) {
      if (stopping.load() || connection->handle == kInvalidSocket) {
        break;
      }
      Frame frame;
      std::string error;
      const ReceiveStatus status = receive_frame(connection->handle, limits(), frame, error);
      if (status == ReceiveStatus::TIMEOUT) {
        continue;
      }
      if (status != ReceiveStatus::FRAME) {
        break;
      }
      if (!handle_frame(connection, frame)) {
        break;
      }
    }
    fence_connection_workers(*connection);
    close_socket(connection->handle);
    connection->handle = kInvalidSocket;
    connection->finished.store(true);
  }

  bool handle_frame(const std::shared_ptr<ConnectionState>& connection, const Frame& frame) {
    switch (frame.type) {
      case MessageType::HELLO:
      case MessageType::REGISTER:
        return handle_register(connection, frame);
      case MessageType::PUBLISH:
        return handle_publish(connection, frame);
      case MessageType::REVOKE:
        return handle_revoke(connection, frame);
      case MessageType::QUERY:
        return handle_query(connection, frame);
      case MessageType::WORKERS:
        return handle_workers(connection, frame);
      case MessageType::HEARTBEAT: {
        Frame ack;
        ack.type = MessageType::HEARTBEAT_ACK;
        std::string error;
        return send_frame(connection->handle, ack, limits(), error);
      }
      case MessageType::SHUTDOWN:
        return false;
      default:
        send_error(connection->handle, 3, "unsupported message type on this connection");
        return false;
    }
  }

  bool handle_register(const std::shared_ptr<ConnectionState>& connection, const Frame& frame) {
    RegisterAck ack;
    try {
      const RegisterRequest request = decode_register_request(frame.payload, limits());
      ack.epoch = sources.epoch->current();
      ack.policy = sources.policy->current_policy().generation;
      const std::string boot = request.envelope.worker_boot.str();
      {
        const std::lock_guard lock(worker_mutex);
        if (fenced.count(boot) != 0) {
          ack.accepted = false;
          ack.detail = "worker boot identity is fenced and cannot be reused";
        } else if (workers.size() >= config.max_publishers) {
          ack.accepted = false;
          ack.detail = "coordinator reached its publisher limit";
        } else {
          WorkerEntry entry;
          entry.publisher = request.envelope.publisher;
          entry.boot = request.envelope.worker_boot;
          entry.scope = request.envelope.scope;
          entry.epoch = ack.epoch;
          entry.connection = connection->id;
          workers[boot] = entry;
          ack.accepted = true;
          ack.detail = "registered";
        }
      }
      if (ack.accepted) {
        connection->workers.insert(boot);
      }
    } catch (const std::exception& failure) {
      ack.accepted = false;
      ack.detail = std::string("malformed register request: ") + failure.what();
    }
    Frame response;
    response.type = MessageType::REGISTER_ACK;
    response.payload = encode_register_ack(ack);
    std::string error;
    return send_frame(connection->handle, response, limits(), error);
  }

  bool handle_publish(const std::shared_ptr<ConnectionState>& connection, const Frame& frame) {
    PublishAck ack;
    ack.epoch = sources.epoch->current();
    try {
      const PublishRequest request = decode_publish_request(frame.payload, limits());
      const std::string boot = request.envelope.worker_boot.str();
      {
        const std::lock_guard lock(worker_mutex);
        if (fenced.count(boot) != 0) {
          ack.accepted = false;
          ack.outcome = EvaluationOutcome::STALE_AUTHORITY;
          ack.detail = "stale worker incarnation: this boot identity is fenced";
          Frame response;
          response.type = MessageType::PUBLISH_ACK;
          response.payload = encode_publish_ack(ack);
          std::string error;
          return send_frame(connection->handle, response, limits(), error);
        }
      }
      if (!worker_registered(request.envelope.worker_boot, connection->id)) {
        ack.accepted = false;
        ack.outcome = EvaluationOutcome::STALE_AUTHORITY;
        ack.detail = "worker incarnation is not registered on this connection";
      } else {
        const WorkerEntry worker = worker_snapshot(request.envelope.worker_boot);
        EvaluationRequest evaluation;
        evaluation.attempt = request.envelope.attempt;
        evaluation.binding_epoch = request.envelope.epoch;
        evaluation.expected_authority_generation = request.expected_authority_generation;
        evaluation.publisher = request.envelope.publisher;
        evaluation.worker_boot = request.envelope.worker_boot;
        evaluation.require_identity_binding = true;
        PathAuthorityRuntime::PublishedDecision decision;
        decision.state = request.state;
        decision.primary = request.primary;
        decision.primary_violation = request.primary_violation;
        decision.evidence = request.evidence;
        decision.path_digest = request.path_digest;
        decision.authority_digest = request.authority_digest;
        decision.constraint_digest = request.constraint_digest;
        decision.secondary = request.secondary;
        const EvaluationResult result =
            runtime->publish_decision(request.path, decision, evaluation);
        ack.accepted = result.committed || result.idempotent;
        ack.outcome = result.primary;
        ack.state = result.state;
        ack.authority_generation = result.authority_generation;
        ack.authority_digest = result.authority_digest;
        ack.epoch = result.epoch;
        if (!ack.accepted) {
          ack.detail = result.secondary.empty() ? std::string("publish rejected")
                                                : result.secondary.front().render();
        } else if (result.idempotent) {
          ack.detail = "idempotent replay";
        } else {
          ack.detail = "committed";
        }
        if (ack.accepted) {
          note_published(request.envelope.worker_boot);
          persist_now();
        }
        (void)worker;
      }
    } catch (const std::exception& failure) {
      ack.accepted = false;
      ack.outcome = EvaluationOutcome::MALFORMED_PATH;
      ack.detail = std::string("malformed publish request: ") + failure.what();
    }
    Frame response;
    response.type = MessageType::PUBLISH_ACK;
    response.payload = encode_publish_ack(ack);
    std::string error;
    return send_frame(connection->handle, response, limits(), error);
  }

  bool handle_revoke(const std::shared_ptr<ConnectionState>& connection, const Frame& frame) {
    ResultAck ack;
    try {
      const RevokeRequest request = decode_revoke_request(frame.payload, limits());
      const std::string boot = request.envelope.worker_boot.str();
      {
        const std::lock_guard lock(worker_mutex);
        if (fenced.count(boot) != 0) {
          ack.accepted = false;
          ack.outcome = EvaluationOutcome::STALE_AUTHORITY;
          ack.detail = "stale worker incarnation: this boot identity is fenced";
          Frame response;
          response.type = MessageType::REVOKE_ACK;
          response.payload = encode_result_ack(ack);
          std::string error;
          return send_frame(connection->handle, response, limits(), error);
        }
      }
      if (!worker_registered(request.envelope.worker_boot, connection->id)) {
        ack.accepted = false;
        ack.outcome = EvaluationOutcome::STALE_AUTHORITY;
        ack.detail = "worker incarnation is not registered on this connection";
      } else if (request.envelope.epoch != sources.epoch->current()) {
        ack.accepted = false;
        ack.outcome = EvaluationOutcome::STALE_EPOCH;
        ack.detail = "revocation carries a stale Fabric Epoch";
      } else {
        RevocationRequest revocation;
        revocation.attempt = request.envelope.attempt;
        revocation.reason = request.reason;
        revocation.explanation = request.explanation;
        revocation.authority = request.authority;
        revocation.expected_authority_generation = request.expected_authority_generation;
        const EvaluationResult result = runtime->revoke(request.path, revocation);
        ack.accepted = result.committed || result.idempotent;
        ack.outcome = result.primary;
        ack.state = result.state;
        ack.authority_generation = result.authority_generation;
        ack.authority_digest = result.authority_digest;
        ack.epoch = sources.epoch->current();
        ack.idempotent = result.idempotent;
        ack.detail = ack.accepted ? "revoked" : "revocation rejected";
        if (ack.accepted) {
          persist_now();
        }
      }
    } catch (const std::exception& failure) {
      ack.accepted = false;
      ack.outcome = EvaluationOutcome::MALFORMED_PATH;
      ack.detail = std::string("malformed revoke request: ") + failure.what();
    }
    Frame response;
    response.type = MessageType::REVOKE_ACK;
    response.payload = encode_result_ack(ack);
    std::string error;
    return send_frame(connection->handle, response, limits(), error);
  }

  bool handle_query(const std::shared_ptr<ConnectionState>& connection, const Frame& frame) {
    QueryResult result;
    try {
      const QueryRequest request = decode_query_request(frame.payload, limits());
      const auto snapshot = runtime->query(request.path);
      result.epoch = sources.epoch->current();
      result.policy = sources.policy->current_policy().generation;
      if (snapshot.has_value()) {
        result.found = true;
        result.state = snapshot->state;
        result.outcome = snapshot->last_outcome;
        result.authority_generation = snapshot->authority_generation;
        result.authority_digest = snapshot->authority_digest;
        result.current = snapshot->current;
        result.detail = snapshot->current ? "current" : "not current";
      } else {
        result.detail = "no authority record";
      }
    } catch (const std::exception& failure) {
      result.found = false;
      result.detail = std::string("malformed query: ") + failure.what();
    }
    Frame response;
    response.type = MessageType::QUERY_RESULT;
    response.payload = encode_query_result(result);
    std::string error;
    return send_frame(connection->handle, response, limits(), error);
  }

  bool handle_workers(const std::shared_ptr<ConnectionState>& connection, const Frame&) {
    WorkersResult result;
    result.epoch = sources.epoch->current();
    {
      const std::lock_guard lock(worker_mutex);
      result.fenced = fenced.size();
      for (const auto& [boot, entry] : workers) {
        (void)boot;
        WorkerInfo info;
        info.publisher = entry.publisher;
        info.worker_boot = entry.boot;
        info.scope = entry.scope;
        info.epoch = entry.epoch;
        info.published = entry.published;
        result.workers.push_back(info);
      }
    }
    Frame response;
    response.type = MessageType::WORKERS_RESULT;
    response.payload = encode_workers_result(result);
    std::string error;
    return send_frame(connection->handle, response, limits(), error);
  }
};

PathAuthorityCoordinator::PathAuthorityCoordinator(CoordinatorConfig config, EvidenceSources sources,
                                                   RuntimeConfig runtime_config)
    : impl_(std::make_unique<Impl>(std::move(config), sources, runtime_config)) {}

PathAuthorityCoordinator::~PathAuthorityCoordinator() = default;

bool PathAuthorityCoordinator::start(std::string& error) { return impl_->start(error); }

void PathAuthorityCoordinator::stop() { impl_->stop(); }

bool PathAuthorityCoordinator::running() const {
  return impl_->listener != kInvalidSocket && !impl_->stopping.load();
}

std::uint16_t PathAuthorityCoordinator::port() const { return impl_->bound_port; }

CoordinatorEpoch PathAuthorityCoordinator::epoch() const {
  return impl_->sources.epoch->current();
}

PathAuthorityRuntime& PathAuthorityCoordinator::runtime() { return *impl_->runtime; }

const PathAuthorityRuntime& PathAuthorityCoordinator::runtime() const { return *impl_->runtime; }

std::size_t PathAuthorityCoordinator::worker_count() const {
  const std::lock_guard lock(impl_->worker_mutex);
  return impl_->workers.size();
}

std::size_t PathAuthorityCoordinator::fenced_count() const {
  const std::lock_guard lock(impl_->worker_mutex);
  return impl_->fenced.size();
}

std::vector<WorkerInfo> PathAuthorityCoordinator::workers() const {
  std::vector<WorkerInfo> result;
  const std::lock_guard lock(impl_->worker_mutex);
  for (const auto& [boot, entry] : impl_->workers) {
    (void)boot;
    WorkerInfo info;
    info.publisher = entry.publisher;
    info.worker_boot = entry.boot;
    info.scope = entry.scope;
    info.epoch = entry.epoch;
    info.published = entry.published;
    result.push_back(info);
  }
  return result;
}

bool PathAuthorityCoordinator::persist(std::string& error) { return impl_->persist(error); }

std::size_t PathAuthorityCoordinator::recovered_records() const { return impl_->recovered_records; }

CoordinatorEpoch PathAuthorityCoordinator::recovered_epoch() const {
  return impl_->recovered_epoch;
}

std::string PathAuthorityCoordinator::describe() const {
  std::string text;
  text += "role=coordinator\n";
  text += "listen=" + impl_->config.bind_host + ":" + std::to_string(impl_->bound_port) + "\n";
  text += "epoch=" + std::to_string(epoch().value()) + "\n";
  text += "recovered_records=" + std::to_string(impl_->recovered_records) + "\n";
  text += "recovered_epoch=" + std::to_string(impl_->recovered_epoch.value()) + "\n";
  text += "workers=" + std::to_string(worker_count()) + "\n";
  text += "fenced=" + std::to_string(fenced_count()) + "\n";
  text += "store=" + (impl_->config.store_path.empty() ? std::string("none")
                                                       : impl_->config.store_path.string()) +
          "\n";
  return text;
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------
struct PathAuthorityEvaluator::Impl {
  Impl(EvaluatorConfig configuration, EvidenceSources source_views, RuntimeConfig runtime_configuration)
      : config(std::move(configuration)),
        sources(source_views),
        runtime(new PathAuthorityRuntime(source_views, runtime_configuration)) {}

  ~Impl() { disconnect(); }

  EvaluatorConfig config;
  EvidenceSources sources;
  std::unique_ptr<PathAuthorityRuntime> runtime;
  socket_handle socket = kInvalidSocket;
  mutable std::mutex mutex;
  bool registered = false;
  CoordinatorEpoch epoch;
  PolicyGeneration policy;
  std::string error;

  const Limits& limits() const { return runtime->limits(); }

  bool set_error(std::string text) {
    const std::lock_guard lock(mutex);
    error = std::move(text);
    return false;
  }

  bool connect(std::string& failure) {
    const std::lock_guard lock(mutex);
    if (socket != kInvalidSocket) {
      failure = "evaluator is already connected";
      return false;
    }
    if (config.coordinator_port == 0) {
      failure = "evaluator requires a coordinator port";
      return false;
    }
    if (!config.publisher.valid() || !config.worker_boot.valid() || !config.scope.valid()) {
      failure = "evaluator requires a publisher, a worker boot id and a scope";
      return false;
    }
    std::string socket_failure;
    if (!tcp_connect(config.coordinator_host, config.coordinator_port, socket, socket_failure)) {
      failure = socket_failure;
      return false;
    }
    return true;
  }

  bool exchange(MessageType request_type, const std::vector<std::byte>& payload,
                MessageType expected_type, Frame& response) {
    Frame request;
    request.type = request_type;
    request.payload = payload;
    std::string failure;
    if (!send_frame(socket, request, limits(), failure)) {
      set_error(failure);
      return false;
    }
    for (;;) {
      Frame incoming;
      const ReceiveStatus status = receive_frame(socket, limits(), incoming, failure);
      if (status == ReceiveStatus::TIMEOUT) {
        continue;
      }
      if (status != ReceiveStatus::FRAME) {
        set_error(failure.empty() ? std::string("coordinator closed the connection") : failure);
        return false;
      }
      if (incoming.type == MessageType::PROTOCOL_ERROR) {
        const ErrorMessage message = decode_error_message(incoming.payload, limits());
        set_error("coordinator error: " + message.detail);
        return false;
      }
      if (incoming.type != expected_type) {
        set_error(std::string("unexpected response ") + std::string(to_string(incoming.type)));
        return false;
      }
      response = std::move(incoming);
      return true;
    }
  }

  WireEnvelope envelope(const MutationAttemptId& attempt) const {
    WireEnvelope value;
    value.epoch = sources.epoch->current();
    value.scope = config.scope;
    value.publisher = config.publisher;
    value.worker_boot = config.worker_boot;
    value.attempt = attempt;
    return value;
  }

  bool register_worker(std::string& failure) {
    const std::lock_guard lock(mutex);
    if (socket == kInvalidSocket) {
      failure = "evaluator is not connected";
      return false;
    }
    RegisterRequest request;
    request.envelope = envelope(MutationAttemptId{});
    request.agent = config.agent;
    Frame response;
    if (!exchange(MessageType::REGISTER, encode_register_request(request),
                  MessageType::REGISTER_ACK, response)) {
      failure = error;
      return false;
    }
    const RegisterAck ack = decode_register_ack(response.payload, limits());
    registered = ack.accepted;
    epoch = ack.epoch;
    policy = ack.policy;
    if (ack.accepted && !config.pin_epoch) {
      if (auto* mutable_epoch = dynamic_cast<MutableEpochAuthority*>(
              const_cast<EpochAuthority*>(sources.epoch));
          mutable_epoch != nullptr) {
        mutable_epoch->set(ack.epoch);
      }
    }
    if (!ack.accepted) {
      failure = ack.detail;
      return false;
    }
    return true;
  }

  bool local_only(EvaluationOutcome outcome) const {
    switch (outcome) {
      case EvaluationOutcome::MALFORMED_PATH:
      case EvaluationOutcome::RESOURCE_LIMIT:
      case EvaluationOutcome::CONSTRAINT_SET_UNKNOWN:
      case EvaluationOutcome::EVALUATION_ATTEMPT_CONFLICT:
      case EvaluationOutcome::PATH_UNKNOWN:
      case EvaluationOutcome::PATH_RETIRED:
      case EvaluationOutcome::REVOKED:
      case EvaluationOutcome::STALE_EPOCH:
        return true;
      default:
        return false;
    }
  }

  static PublishAck ack_from(const EvaluationResult& result, bool accepted, std::string detail) {
    PublishAck ack;
    ack.accepted = accepted;
    ack.outcome = result.primary;
    ack.state = result.state;
    ack.authority_generation = result.authority_generation;
    ack.epoch = result.epoch;
    ack.authority_digest = result.authority_digest;
    ack.detail = std::move(detail);
    return ack;
  }

  PublishAck publish(const PathDefinition& path, const EvaluationRequest& request) {
    const EvaluationResult local = runtime->evaluate(path, request);
    if (local_only(local.primary)) {
      return ack_from(local, false, "rejected before publication: " +
                                         std::string(to_string(local.primary)));
    }
    const auto constraints = runtime->constraint_set(path.constraint_set);
    if (!constraints.has_value()) {
      return ack_from(local, false, "the local constraint registry does not hold the bound set");
    }

    const std::lock_guard lock(mutex);
    if (socket == kInvalidSocket || !registered) {
      return ack_from(local, false, "evaluator is not registered with a coordinator");
    }
    PublishRequest message;
    message.envelope = envelope(request.attempt);
    message.path = path;
    message.state = local.state;
    message.primary = local.primary;
    message.primary_violation = local.primary_violation;
    message.evidence = local.evidence;
    message.path_digest = local.path_digest;
    message.authority_digest = local.authority_digest;
    message.constraint_digest = constraints->digest();
    message.constraint_generation = constraints->generation;
    message.secondary = local.secondary;
    message.expected_authority_generation = request.expected_authority_generation;

    Frame response;
    std::string failure;
    if (!exchange(MessageType::PUBLISH, encode_publish_request(message), MessageType::PUBLISH_ACK,
                  response)) {
      return ack_from(local, false, error);
    }
    return decode_publish_ack(response.payload, limits());
  }

  ResultAck revalidate(const PathId& path, const RevalidationRequest& request) {
    const auto snapshot = runtime->query(path);
    ResultAck ack;
    if (!snapshot.has_value()) {
      ack.accepted = false;
      ack.outcome = EvaluationOutcome::PATH_UNKNOWN;
      ack.detail = "evaluator holds no local record for this path";
      return ack;
    }
    const auto constraints = runtime->constraint_set(snapshot->constraint_set);
    if (!constraints.has_value()) {
      ack.accepted = false;
      ack.outcome = EvaluationOutcome::CONSTRAINT_SET_UNKNOWN;
      ack.detail = "the bound constraint set is not registered locally";
      return ack;
    }

    const PathDefinition path_value = snapshot->definition;
    EvaluationRequest evaluation;
    evaluation.attempt = request.attempt;
    evaluation.expected_authority_generation = request.expected_authority_generation;
    evaluation.publisher = request.publisher;
    evaluation.worker_boot = request.worker_boot;
    evaluation.require_identity_binding = true;
    const PublishAck published = publish(path_value, evaluation);
    ack.accepted = published.accepted;
    ack.outcome = published.outcome;
    ack.state = published.state;
    ack.authority_generation = published.authority_generation;
    ack.epoch = published.epoch;
    ack.authority_digest = published.authority_digest;
    ack.detail = published.detail;
    return ack;
  }

  ResultAck revoke(const PathId& path, const RevocationRequest& request) {
    const std::lock_guard lock(mutex);
    ResultAck ack;
    if (socket == kInvalidSocket || !registered) {
      ack.accepted = false;
      ack.outcome = EvaluationOutcome::STALE_AUTHORITY;
      ack.detail = "evaluator is not registered with a coordinator";
      return ack;
    }
    RevokeRequest message;
    message.envelope = envelope(request.attempt);
    message.path = path;
    message.reason = request.reason;
    message.explanation = request.explanation;
    message.authority = request.authority;
    message.expected_authority_generation = request.expected_authority_generation;
    Frame response;
    if (!exchange(MessageType::REVOKE, encode_revoke_request(message), MessageType::REVOKE_ACK,
                  response)) {
      ack.accepted = false;
      ack.detail = error;
      return ack;
    }
    return decode_result_ack(response.payload, limits());
  }

  QueryResult query(const PathId& path) {
    const std::lock_guard lock(mutex);
    QueryResult result;
    if (socket == kInvalidSocket) {
      result.detail = "evaluator is not connected";
      return result;
    }
    QueryRequest message;
    message.path = path;
    Frame response;
    if (!exchange(MessageType::QUERY, encode_query_request(message), MessageType::QUERY_RESULT,
                  response)) {
      result.detail = error;
      return result;
    }
    return decode_query_result(response.payload, limits());
  }

  std::vector<WorkerInfo> workers() {
    const std::lock_guard lock(mutex);
    std::vector<WorkerInfo> result;
    if (socket == kInvalidSocket) {
      return result;
    }
    Frame response;
    if (!exchange(MessageType::WORKERS, {}, MessageType::WORKERS_RESULT, response)) {
      return result;
    }
    return decode_workers_result(response.payload, limits()).workers;
  }

  bool heartbeat() {
    const std::lock_guard lock(mutex);
    if (socket == kInvalidSocket) {
      return false;
    }
    Frame response;
    return exchange(MessageType::HEARTBEAT, {}, MessageType::HEARTBEAT_ACK, response);
  }

  void disconnect() {
    const std::lock_guard lock(mutex);
    if (socket == kInvalidSocket) {
      return;
    }
    Frame shutdown;
    shutdown.type = MessageType::SHUTDOWN;
    std::string failure;
    send_frame(socket, shutdown, limits(), failure);
    close_socket(socket);
    socket = kInvalidSocket;
    registered = false;
  }
};

PathAuthorityEvaluator::PathAuthorityEvaluator(EvaluatorConfig config, EvidenceSources sources,
                                               RuntimeConfig runtime_config)
    : impl_(std::make_unique<Impl>(std::move(config), sources, runtime_config)) {}

PathAuthorityEvaluator::~PathAuthorityEvaluator() = default;

bool PathAuthorityEvaluator::connect(std::string& error) { return impl_->connect(error); }

bool PathAuthorityEvaluator::register_worker(std::string& error) {
  return impl_->register_worker(error);
}

bool PathAuthorityEvaluator::registered() const { return impl_->registered; }

CoordinatorEpoch PathAuthorityEvaluator::coordinator_epoch() const { return impl_->epoch; }

PolicyGeneration PathAuthorityEvaluator::coordinator_policy() const { return impl_->policy; }

PublishAck PathAuthorityEvaluator::publish(const PathDefinition& path,
                                           const EvaluationRequest& request) {
  return impl_->publish(path, request);
}

ResultAck PathAuthorityEvaluator::revalidate(const PathId& path,
                                             const RevalidationRequest& request) {
  return impl_->revalidate(path, request);
}

ResultAck PathAuthorityEvaluator::revoke(const PathId& path, const RevocationRequest& request) {
  return impl_->revoke(path, request);
}

QueryResult PathAuthorityEvaluator::query(const PathId& path) { return impl_->query(path); }

std::vector<WorkerInfo> PathAuthorityEvaluator::workers() { return impl_->workers(); }

bool PathAuthorityEvaluator::heartbeat() { return impl_->heartbeat(); }

PathAuthorityRuntime& PathAuthorityEvaluator::runtime() { return *impl_->runtime; }

const EvaluatorConfig& PathAuthorityEvaluator::config() const noexcept { return impl_->config; }

std::string PathAuthorityEvaluator::last_error() const {
  const std::lock_guard lock(impl_->mutex);
  return impl_->error;
}

void PathAuthorityEvaluator::disconnect() { impl_->disconnect(); }

}  // namespace path_authority
