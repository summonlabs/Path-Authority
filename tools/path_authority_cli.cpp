// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Focused inspection tool. Every command prints deterministic, script friendly
// output: either key=value lines (the default) or JSON with --json.
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "path_authority/path_authority.hpp"

namespace {

using namespace path_authority;

constexpr int kExitOk = 0;
constexpr int kExitUsage = 1;
constexpr int kExitRejected = 2;
constexpr int kExitDistributed = 3;

struct Options {
  std::string command;
  std::string scenario = "authorized";
  std::string store;
  std::string listen = "127.0.0.1:0";
  std::string connect = "127.0.0.1:0";
  std::string publisher = "evaluator";
  std::string boot = "boot-1";
  std::string scope = "fabric-lab";
  std::string path;
  std::string path_kind = "primary";
  std::string epoch_text;
  std::string epoch_binding;
  bool json = false;
  bool publish = false;
  bool hold = false;
  bool durable = false;
};

void usage() {
  std::cout << "path_authority " << version_string() << "\n";
  std::cout << "usage: path_authority <command> [options]\n\n";
  std::cout << "commands:\n";
  std::cout << "  version                                   print the version report\n";
  std::cout << "  scenarios                                 list synthetic scenarios\n";
  std::cout << "  evaluate     [--scenario N] [--json]      evaluate the scenario path\n";
  std::cout << "  explain      [--scenario N] [--json]      explain current authority\n";
  std::cout << "  revalidate   [--scenario N] [--json]      revalidate the scenario path\n";
  std::cout << "  local-evidence [--json]                   REAL local host evidence\n";
  std::cout << "  inspect      --store PATH [--json]        inspect a durable store\n";
  std::cout << "  coordinator  [--listen H:P] [--store P] [--scenario N] [--epoch N]\n";
  std::cout << "  evaluator    --connect H:P [--publisher P] [--boot B] [--scenario N]\n";
  std::cout << "               [--epoch N] [--publish] [--hold]\n";
  std::cout << "  query        --connect H:P --path ID      query authority at a coordinator\n";
  std::cout << "  workers      --connect H:P [--json]       list registered workers\n";
  std::cout << "  revoke       --connect H:P --path ID [--durable]\n";
  std::cout << "\nexit codes: 0 ok, 1 usage, 2 rejected, 3 distributed failure\n";
}

Options parse(int argc, char** argv) {
  Options options;
  if (argc < 2) {
    return options;
  }
  options.command = argv[1];
  for (int i = 2; i < argc; ++i) {
    const std::string argument = argv[i];
    const auto value = [&](const char* name) -> std::string {
      if (argument != name) {
        return std::string();
      }
      if (i + 1 >= argc) {
        throw std::invalid_argument(std::string("missing value for ") + name);
      }
      return argv[++i];
    };
    std::string parsed;
    if (!(parsed = value("--scenario")).empty()) {
      options.scenario = parsed;
    } else if (!(parsed = value("--store")).empty()) {
      options.store = parsed;
    } else if (!(parsed = value("--listen")).empty()) {
      options.listen = parsed;
    } else if (!(parsed = value("--connect")).empty()) {
      options.connect = parsed;
    } else if (!(parsed = value("--publisher")).empty()) {
      options.publisher = parsed;
    } else if (!(parsed = value("--boot")).empty()) {
      options.boot = parsed;
    } else if (!(parsed = value("--scope")).empty()) {
      options.scope = parsed;
    } else if (!(parsed = value("--path")).empty()) {
      options.path = parsed;
    } else if (!(parsed = value("--path-kind")).empty()) {
      options.path_kind = parsed;
    } else if (!(parsed = value("--epoch")).empty()) {
      options.epoch_text = parsed;
    } else if (!(parsed = value("--epoch-binding")).empty()) {
      options.epoch_binding = parsed;
    } else if (argument == "--json") {
      options.json = true;
    } else if (argument == "--publish") {
      options.publish = true;
    } else if (argument == "--hold") {
      options.hold = true;
    } else if (argument == "--durable") {
      options.durable = true;
    } else {
      throw std::invalid_argument("unknown option: " + argument);
    }
  }
  return options;
}

std::pair<std::string, std::uint16_t> parse_endpoint(const std::string& text) {
  const std::size_t separator = text.rfind(':');
  if (separator == std::string::npos) {
    throw std::invalid_argument("endpoint must be host:port");
  }
  const std::string host = text.substr(0, separator);
  const unsigned long port = std::stoul(text.substr(separator + 1));
  if (port > 65535) {
    throw std::invalid_argument("endpoint port is out of range");
  }
  return {host.empty() ? std::string("127.0.0.1") : host, static_cast<std::uint16_t>(port)};
}

PathDefinition select_path(const SyntheticEnvironment& environment, const std::string& kind) {
  return kind == "backup" ? environment.backup_path() : environment.path();
}

// Builds the synthetic runtime used by the single process commands.
struct InProcess {
  std::unique_ptr<SyntheticEnvironment> environment;
  std::unique_ptr<PathAuthorityRuntime> runtime;

  explicit InProcess(const std::string& scenario, bool needs_runtime) {
    if (!SyntheticEnvironment::scenario_exists(scenario)) {
      throw std::invalid_argument("unknown scenario: " + scenario);
    }
    environment = std::make_unique<SyntheticEnvironment>(scenario);
    if (needs_runtime) {
      runtime = std::make_unique<PathAuthorityRuntime>(environment->sources());
      runtime->register_constraint_set(environment->constraints());
      if (scenario == "primary-backup") {
        ConstraintSet backup = environment->constraints();
        backup.id = ConstraintSetId::parse("leaf-spine-diverse-constraints");
        runtime->register_constraint_set(backup);
      }
    }
  }
};

void print_evaluation(const EvaluationResult& result, bool json) {
  if (json) {
    std::cout << to_json(result) << "\n";
    return;
  }
  std::cout << result.render();
}

MutationAttemptId attempt(std::string_view text) { return MutationAttemptId::parse(text); }

int command_evaluate(const Options& options) {
  InProcess process(options.scenario, true);
  const PathDefinition path = select_path(*process.environment, options.path_kind);
  EvaluationRequest request;
  request.attempt = attempt("cli-evaluate-" + options.scenario);
  request.publisher = PublisherId::parse("cli");
  request.worker_boot = WorkerBootId::parse("cli-boot");
  if (!options.epoch_binding.empty()) {
    request.binding_epoch = CoordinatorEpoch::from_value(std::stoull(options.epoch_binding));
  }
  const EvaluationResult result = process.runtime->evaluate(path, request);
  print_evaluation(result, options.json);
  return result.authorizing() ? kExitOk : kExitRejected;
}

int command_explain(const Options& options) {
  InProcess process(options.scenario, true);
  const PathDefinition path = select_path(*process.environment, options.path_kind);
  EvaluationRequest request;
  request.attempt = attempt("cli-explain-" + options.scenario);
  process.runtime->evaluate(path, request);
  const std::string explanation = process.runtime->explain(path.id);
  if (options.json) {
    const auto snapshot = process.runtime->query(path.id);
    if (snapshot.has_value()) {
      std::cout << to_json(*snapshot) << "\n";
      return kExitOk;
    }
  }
  std::cout << explanation;
  return kExitOk;
}

int command_revalidate(const Options& options) {
  InProcess process(options.scenario, true);
  const PathDefinition path = select_path(*process.environment, options.path_kind);
  EvaluationRequest first;
  first.attempt = attempt("cli-revalidate-first-" + options.scenario);
  process.runtime->evaluate(path, first);
  RevalidationRequest request;
  request.attempt = attempt("cli-revalidate-" + options.scenario);
  request.publisher = PublisherId::parse("cli");
  request.worker_boot = WorkerBootId::parse("cli-boot");
  const EvaluationResult result = process.runtime->revalidate(path.id, request);
  print_evaluation(result, options.json);
  return result.authorizing() ? kExitOk : kExitRejected;
}

int command_local_evidence(const Options& options) {
  std::string error;
  const auto fabric = LocalHostFabric::capture(error);
  if (!fabric.has_value()) {
    std::cout << "classification=REAL\nresult=unavailable\nreason=" << error << "\n";
    return kExitOk;
  }
  if (!options.json) {
    std::cout << fabric->describe();
  } else {
    std::cout << "{\"classification\":\"REAL\",\"host\":\"" << fabric->host_identity()
              << "\",\"interfaces\":" << fabric->interfaces().size() << "}\n";
  }
  if (fabric->interfaces().empty()) {
    std::cout << "note=no non-loopback interface is present on this host\n";
    return kExitOk;
  }
  auto runtime = std::make_unique<PathAuthorityRuntime>(fabric->sources());
  runtime->register_constraint_set(fabric->constraints());
  std::size_t index = 0;
  for (; index < fabric->interfaces().size(); ++index) {
    if (fabric->interfaces()[index].operational) {
      break;
    }
  }
  if (index == fabric->interfaces().size()) {
    index = 0;
  }
  std::string path_error;
  const auto path = fabric->endpoint_port_path(index, path_error);
  if (!path.has_value()) {
    std::cout << "path=unavailable\nreason=" << path_error << "\n";
    return kExitOk;
  }
  EvaluationRequest request;
  request.attempt = attempt("cli-local-evidence");
  const EvaluationResult result = runtime->evaluate(*path, request);
  if (!options.json) {
    std::cout << "path=" << path->id.str() << "\n";
    std::cout << "interface=" << fabric->interfaces()[index].identity << "\n";
  }
  print_evaluation(result, options.json);
  return kExitOk;
}

int command_inspect(const Options& options) {
  if (options.store.empty()) {
    std::cerr << "inspect requires --store PATH\n";
    return kExitUsage;
  }
  const PersistenceInfo info = inspect_store(options.store, Limits::defaults());
  if (options.json) {
    std::cout << to_json(info) << "\n";
    return kExitOk;
  }
  std::cout << "store=" << options.store << "\n";
  std::cout << "readable=" << (info.readable ? "true" : "false") << "\n";
  std::cout << "format_version=" << info.format_version << "\n";
  std::cout << "image_bytes=" << info.image_bytes << "\n";
  std::cout << "payload_bytes=" << info.payload_bytes << "\n";
  std::cout << "records=" << info.record_count << "\n";
  std::cout << "epoch=" << info.epoch.value() << "\n";
  std::cout << "policy_generation=" << info.policy.value() << "\n";
  std::cout << "constraint_sets=" << info.constraint_sets << "\n";
  std::cout << "revoked=" << info.revoked << "\n";
  std::cout << "authorizing=" << info.authorizing << "\n";
  std::cout << "image_digest=" << info.image_digest.hex() << "\n";
  if (!info.readable) {
    std::cout << "problem=" << info.problem << "\n";
    return kExitRejected;
  }
  return kExitOk;
}

int command_coordinator(const Options& options) {
  if (!SyntheticEnvironment::scenario_exists(options.scenario)) {
    std::cerr << "unknown scenario: " << options.scenario << "\n";
    return kExitUsage;
  }
  auto environment = std::make_unique<SyntheticEnvironment>(options.scenario);
  CoordinatorConfig config;
  const auto [host, port] = parse_endpoint(options.listen);
  config.bind_host = host;
  config.port = port;
  config.store_path = options.store.empty() ? std::filesystem::path()
                                            : std::filesystem::path(options.store);
  config.persistence_enabled = !options.store.empty();
  config.epoch_control = &environment->epoch();
  if (!options.epoch_text.empty()) {
    config.epoch_override = CoordinatorEpoch::from_value(std::stoull(options.epoch_text));
  }

  PathAuthorityCoordinator coordinator(config, environment->sources());
  coordinator.runtime().register_constraint_set(environment->constraints());
  if (options.scenario == "primary-backup") {
    ConstraintSet backup = environment->constraints();
    backup.id = ConstraintSetId::parse("leaf-spine-diverse-constraints");
    coordinator.runtime().register_constraint_set(backup);
  }
  std::string error;
  if (!coordinator.start(error)) {
    std::cerr << "coordinator failed to start: " << error << "\n";
    return kExitDistributed;
  }
  std::cout << "role=coordinator\n";
  std::cout << "port=" << coordinator.port() << "\n";
  std::cout << "epoch=" << coordinator.epoch().value() << "\n";
  std::cout << "recovered_records=" << coordinator.recovered_records() << "\n";
  std::cout << "recovered_epoch=" << coordinator.recovered_epoch().value() << "\n";
  std::cout << "ready=true\n";
  std::cout.flush();
  while (true) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

int command_evaluator(const Options& options) {
  if (!SyntheticEnvironment::scenario_exists(options.scenario)) {
    std::cerr << "unknown scenario: " << options.scenario << "\n";
    return kExitUsage;
  }
  auto environment = std::make_unique<SyntheticEnvironment>(options.scenario);
  const bool pinned_epoch = !options.epoch_text.empty();
  if (pinned_epoch) {
    environment->epoch().set(CoordinatorEpoch::from_value(std::stoull(options.epoch_text)));
  }
  const auto [host, port] = parse_endpoint(options.connect);
  EvaluatorConfig config;
  config.coordinator_host = host;
  config.coordinator_port = port;
  config.pin_epoch = pinned_epoch;
  config.publisher = PublisherId::parse(options.publisher);
  config.worker_boot = WorkerBootId::parse(options.boot);
  config.scope = ScopeId::parse(options.scope);

  PathAuthorityEvaluator evaluator(config, environment->sources());
  evaluator.runtime().register_constraint_set(environment->constraints());
  if (options.scenario == "primary-backup") {
    ConstraintSet backup = environment->constraints();
    backup.id = ConstraintSetId::parse("leaf-spine-diverse-constraints");
    evaluator.runtime().register_constraint_set(backup);
  }
  std::string error;
  if (!evaluator.connect(error)) {
    std::cerr << "connect=failed\nreason=" << error << "\n";
    return kExitDistributed;
  }
  if (!evaluator.register_worker(error)) {
    std::cout << "register=rejected\nreason=" << error << "\n";
    std::cout.flush();
    return kExitDistributed;
  }
  std::cout << "register=accepted\n";
  std::cout << "coordinator_epoch=" << evaluator.coordinator_epoch().value() << "\n";
  std::cout.flush();

  if (options.publish) {
    const PathDefinition path = select_path(*environment, options.path_kind);
    EvaluationRequest request;
    request.attempt = attempt("publish-" + options.publisher + "-" + path.id.str().substr(0, 16));
    request.publisher = config.publisher;
    request.worker_boot = config.worker_boot;
    const PublishAck ack = evaluator.publish(path, request);
    std::cout << "path=" << path.id.str() << "\n";
    std::cout << "publish=" << (ack.accepted ? "accepted" : "rejected") << "\n";
    std::cout << "outcome=" << to_string(ack.outcome) << "\n";
    std::cout << "state=" << to_string(ack.state) << "\n";
    std::cout << "authority_generation=" << ack.authority_generation.value() << "\n";
    std::cout << "detail=" << ack.detail << "\n";
    std::cout.flush();
  }
  if (options.hold) {
    while (true) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
  evaluator.disconnect();
  return kExitOk;
}

int command_query(const Options& options) {
  const auto [host, port] = parse_endpoint(options.connect);
  EvaluatorConfig config;
  config.coordinator_host = host;
  config.coordinator_port = port;
  config.publisher = PublisherId::parse("query-client");
  config.worker_boot = WorkerBootId::parse("query-boot");
  config.scope = ScopeId::parse(options.scope);
  auto environment = std::make_unique<SyntheticEnvironment>("authorized");
  PathAuthorityEvaluator client(config, environment->sources());
  std::string error;
  if (!client.connect(error)) {
    std::cerr << "connect=failed\nreason=" << error << "\n";
    return kExitDistributed;
  }
  const QueryResult result = client.query(PathId::parse(options.path));
  if (options.json) {
    std::cout << "{\"found\":" << (result.found ? "true" : "false")
              << ",\"state\":\"" << to_string(result.state) << "\""
              << ",\"outcome\":\"" << to_string(result.outcome)
              << "\",\"authority_generation\":" << result.authority_generation.value()
              << ",\"current\":" << (result.current ? "true" : "false") << "}\n";
  } else {
    std::cout << "found=" << (result.found ? "true" : "false") << "\n";
    std::cout << "state=" << to_string(result.state) << "\n";
    std::cout << "outcome=" << to_string(result.outcome) << "\n";
    std::cout << "authority_generation=" << result.authority_generation.value() << "\n";
    std::cout << "current=" << (result.current ? "true" : "false") << "\n";
    std::cout << "detail=" << result.detail << "\n";
  }
  client.disconnect();
  return result.found ? kExitOk : kExitRejected;
}

int command_workers(const Options& options) {
  const auto [host, port] = parse_endpoint(options.connect);
  EvaluatorConfig config;
  config.coordinator_host = host;
  config.coordinator_port = port;
  config.publisher = PublisherId::parse("worker-client");
  config.worker_boot = WorkerBootId::parse("worker-boot");
  config.scope = ScopeId::parse(options.scope);
  auto environment = std::make_unique<SyntheticEnvironment>("authorized");
  PathAuthorityEvaluator client(config, environment->sources());
  std::string error;
  if (!client.connect(error)) {
    std::cerr << "connect=failed\nreason=" << error << "\n";
    return kExitDistributed;
  }
  const auto workers = client.workers();
  if (options.json) {
    std::cout << to_json(workers) << "\n";
  } else {
    std::cout << "count=" << workers.size() << "\n";
    for (const auto& worker : workers) {
      std::cout << "worker=" << worker.publisher.str() << " boot=" << worker.worker_boot.str()
                << " published=" << worker.published << "\n";
    }
  }
  client.disconnect();
  return kExitOk;
}

int command_revoke(const Options& options) {
  if (options.path.empty()) {
    std::cerr << "revoke requires --path ID\n";
    return kExitUsage;
  }
  const auto [host, port] = parse_endpoint(options.connect);
  EvaluatorConfig config;
  config.coordinator_host = host;
  config.coordinator_port = port;
  config.publisher = PublisherId::parse(options.publisher);
  config.worker_boot = WorkerBootId::parse(options.boot);
  config.scope = ScopeId::parse(options.scope);
  auto environment = std::make_unique<SyntheticEnvironment>("authorized");
  PathAuthorityEvaluator client(config, environment->sources());
  std::string error;
  if (!client.connect(error) || !client.register_worker(error)) {
    std::cerr << "connect=failed\nreason=" << error << "\n";
    return kExitDistributed;
  }
  RevocationRequest request;
  request.attempt = attempt("revoke-" + options.path.substr(0, 16));
  request.reason = RevocationReason::ADMINISTRATIVE;
  request.explanation = "administrative revocation issued through the CLI";
  request.authority = "cli";
  request.durable = options.durable;
  const ResultAck ack = client.revoke(PathId::parse(options.path), request);
  std::cout << "revoke=" << (ack.accepted ? "accepted" : "rejected") << "\n";
  std::cout << "outcome=" << to_string(ack.outcome) << "\n";
  std::cout << "authority_generation=" << ack.authority_generation.value() << "\n";
  std::cout << "detail=" << ack.detail << "\n";
  client.disconnect();
  return ack.accepted ? kExitOk : kExitRejected;
}

}  // namespace

int main(int argc, char** argv) {
  std::ios::sync_with_stdio(true);
  try {
    const Options options = parse(argc, argv);
    if (options.command.empty() || options.command == "help" || options.command == "--help") {
      usage();
      return options.command.empty() ? kExitUsage : kExitOk;
    }
    if (options.command == "version") {
      std::cout << version_report();
      return kExitOk;
    }
    if (options.command == "scenarios") {
      for (const auto& name : SyntheticEnvironment::scenario_names()) {
        std::cout << "scenario=" << name << "\n";
      }
      return kExitOk;
    }
    if (options.command == "evaluate") {
      return command_evaluate(options);
    }
    if (options.command == "explain") {
      return command_explain(options);
    }
    if (options.command == "revalidate") {
      return command_revalidate(options);
    }
    if (options.command == "local-evidence") {
      return command_local_evidence(options);
    }
    if (options.command == "inspect") {
      return command_inspect(options);
    }
    if (options.command == "coordinator") {
      return command_coordinator(options);
    }
    if (options.command == "evaluator") {
      return command_evaluator(options);
    }
    if (options.command == "query") {
      return command_query(options);
    }
    if (options.command == "workers") {
      return command_workers(options);
    }
    if (options.command == "revoke") {
      return command_revoke(options);
    }
    std::cerr << "unknown command: " << options.command << "\n";
    usage();
    return kExitUsage;
  } catch (const std::exception& error) {
    std::cerr << "error: " << error.what() << "\n";
    return kExitUsage;
  }
}
