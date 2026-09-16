// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Real process proofs: a coordinator process, evaluator processes, genuine OS
// terminations and a genuine coordinator restart with durable recovery.
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

#include "fixture.hpp"
#include "path_authority/path_authority.hpp"
#include "process_helper.hpp"

using namespace path_authority;
using pa_process::ChildProcess;

namespace {

constexpr const char* kCli = PATH_AUTHORITY_CLI_PATH;

std::filesystem::path temporary(const std::string& name) {
  return pa_test::unique_test_path(name);
}

std::string quoted(const std::filesystem::path& path) {
  return "\"" + path.string() + "\"";
}

// A CLI invocation that is expected to finish on its own.
std::string run_cli(const std::string& arguments) {
  const std::filesystem::path output = temporary("cli-output") ;
  std::string error;
  auto child = ChildProcess::start("\"" + std::string(kCli) + "\" " + arguments, output, error);
  if (!child.has_value()) {
    return std::string();
  }
  child->wait();
  return child->output();
}

bool contains(const std::string& text, const std::string& needle) {
  return text.find(needle) != std::string::npos;
}

std::string path_id_of(const std::string& scenario, const std::string& kind) {
  const std::string output =
      run_cli("evaluate --scenario " + scenario + " --path-kind " + kind);
  const std::size_t position = output.find("path=");
  if (position == std::string::npos) {
    return std::string();
  }
  const std::size_t start = position + 5;
  const std::size_t end = output.find_first_of("\r\n", start);
  return output.substr(start, end - start);
}

}  // namespace

PA_TEST(cli_reports_authorized_and_rejected_scenarios) {
  const std::string authorized = run_cli("evaluate --scenario authorized");
  PA_CHECK(contains(authorized, "outcome=AUTHORIZED"));
  PA_CHECK(contains(authorized, "state=AUTHORIZED"));
  const std::string failed = run_cli("evaluate --scenario failed-link");
  PA_CHECK(contains(failed, "outcome=LINK_DOWN"));
  PA_CHECK(contains(failed, "state=REJECTED"));
}

PA_TEST(real_worker_death_is_detected_fenced_and_recovered_by_a_fresh_worker) {
  const std::filesystem::path store = temporary("worker-death-store");
  const std::filesystem::path coordinator_output = temporary("worker-death-coordinator");
  std::string error;
  auto coordinator = ChildProcess::start(
      "\"" + std::string(kCli) + "\" coordinator --listen 127.0.0.1:0 --store " + quoted(store) +
          " --scenario primary-backup",
      coordinator_output, error);
  PA_REQUIRE(coordinator.has_value());
  const auto port = coordinator->field("port");
  PA_REQUIRE(port.has_value());
  const std::string primary_path = path_id_of("primary-backup", "primary");
  const std::string backup_path = path_id_of("primary-backup", "backup");
  PA_REQUIRE(!primary_path.empty());
  PA_REQUIRE(!backup_path.empty());

  // Evaluator A authorizes P; evaluator B authorizes Q.
  const std::filesystem::path a_output = temporary("worker-death-a");
  auto evaluator_a = ChildProcess::start(
      "\"" + std::string(kCli) + "\" evaluator --connect 127.0.0.1:" + *port +
          " --publisher evaluator-a --boot boot-a --scenario primary-backup --publish --hold",
      a_output, error);
  PA_REQUIRE(evaluator_a.has_value());
  PA_REQUIRE(evaluator_a->field("publish").has_value());
  PA_CHECK(contains(evaluator_a->output(), "publish=accepted"));

  const std::filesystem::path b_output = temporary("worker-death-b");
  auto evaluator_b = ChildProcess::start(
      "\"" + std::string(kCli) + "\" evaluator --connect 127.0.0.1:" + *port +
          " --publisher evaluator-b --boot boot-b --scenario primary-backup --path-kind backup"
          " --publish --hold",
      b_output, error);
  PA_REQUIRE(evaluator_b.has_value());
  PA_REQUIRE(evaluator_b->field("publish").has_value());
  PA_CHECK(contains(evaluator_b->output(), "publish=accepted"));

  const std::string before = run_cli("query --connect 127.0.0.1:" + *port + " --path " + primary_path);
  PA_CHECK(contains(before, "state=AUTHORIZED"));

  // Kill A as a real OS process and observe the loss through the control path.
  evaluator_a->kill_hard();
  PA_CHECK(!evaluator_a->running());
  PA_CHECK(PA_WAIT_FOR(contains(run_cli("workers --connect 127.0.0.1:" + *port), "count=1"),
                       std::chrono::seconds(30),
                       "the coordinator to observe the death of evaluator A"));

  const std::string after = run_cli("query --connect 127.0.0.1:" + *port + " --path " + primary_path);
  PA_CHECK(contains(after, "state=REVALIDATION_REQUIRED"));

  // The unrelated evaluator and its path are unaffected.
  const std::string unaffected =
      run_cli("query --connect 127.0.0.1:" + *port + " --path " + backup_path);
  PA_CHECK(contains(unaffected, "state=AUTHORIZED"));

  // A stale worker incarnation can never register again.
  const std::string stale = run_cli("evaluator --connect 127.0.0.1:" + *port +
                                    " --publisher evaluator-a --boot boot-a --scenario primary-backup");
  PA_CHECK(contains(stale, "register=rejected"));

  // A fresh incarnation re-registers and restores authority for P.
  const std::filesystem::path a2_output = temporary("worker-death-a2");
  auto evaluator_a2 = ChildProcess::start(
      "\"" + std::string(kCli) + "\" evaluator --connect 127.0.0.1:" + *port +
          " --publisher evaluator-a --boot boot-a2 --scenario primary-backup --publish --hold",
      a2_output, error);
  PA_REQUIRE(evaluator_a2.has_value());
  PA_REQUIRE(evaluator_a2->field("publish").has_value());
  PA_CHECK(contains(evaluator_a2->output(), "publish=accepted"));
  const std::string restored =
      run_cli("query --connect 127.0.0.1:" + *port + " --path " + primary_path);
  PA_CHECK(contains(restored, "state=AUTHORIZED"));

  evaluator_a2->kill_hard();
  evaluator_b->kill_hard();
  coordinator->kill_hard();
}

PA_TEST(real_coordinator_restart_recovers_conservatively_and_fences_old_traffic) {
  const std::filesystem::path store = temporary("restart-store");
  const std::filesystem::path first_output = temporary("restart-coordinator-1");
  std::string error;
  auto first = ChildProcess::start(
      "\"" + std::string(kCli) + "\" coordinator --listen 127.0.0.1:0 --store " + quoted(store) +
          " --scenario authorized",
      first_output, error);
  PA_REQUIRE(first.has_value());
  const auto first_port = first->field("port");
  PA_REQUIRE(first_port.has_value());
  const std::string path = path_id_of("authorized", "primary");
  PA_REQUIRE(!path.empty());

  const std::filesystem::path evaluator_output = temporary("restart-evaluator");
  auto evaluator = ChildProcess::start(
      "\"" + std::string(kCli) + "\" evaluator --connect 127.0.0.1:" + *first_port +
          " --publisher evaluator-a --boot boot-restart --scenario authorized --publish --hold",
      evaluator_output, error);
  PA_REQUIRE(evaluator.has_value());
  PA_REQUIRE(evaluator->field("publish").has_value());
  PA_CHECK(contains(evaluator->output(), "publish=accepted"));
  PA_CHECK(contains(run_cli("query --connect 127.0.0.1:" + *first_port + " --path " + path),
                    "state=AUTHORIZED"));

  // Kill the coordinator hard while the durable store is populated, then stop
  // the worker so the coordinator restart is the only source of live state.
  first->kill_hard();
  evaluator->kill_hard();
  PA_CHECK(std::filesystem::exists(store));
  const PersistenceInfo info = inspect_store(store, Limits::defaults());
  PA_CHECK(info.readable);
  PA_CHECK_EQ(info.record_count, std::size_t{1});
  PA_CHECK_EQ(info.authorizing, std::size_t{1});

  const std::filesystem::path second_output = temporary("restart-coordinator-2");
  auto second = ChildProcess::start(
      "\"" + std::string(kCli) + "\" coordinator --listen 127.0.0.1:0 --store " + quoted(store) +
          " --scenario authorized",
      second_output, error);
  PA_REQUIRE(second.has_value());
  const auto second_port = second->field("port");
  PA_REQUIRE(second_port.has_value());
  PA_CHECK_EQ(second->field("recovered_records").value_or("0"), std::string("1"));
  PA_CHECK_EQ(second->field("recovered_epoch").value_or("0"), std::string("1"));
  PA_CHECK_EQ(second->field("epoch").value_or("0"), std::string("2"));

  // Live authority never survives: the recovered record requires revalidation.
  const std::string recovered =
      run_cli("query --connect 127.0.0.1:" + *second_port + " --path " + path);
  PA_CHECK(contains(recovered, "state=REVALIDATION_REQUIRED"));
  PA_CHECK(contains(recovered, "current=false"));

  // A pre-restart worker incarnation is fenced across the restart.
  const std::string stale_boot = run_cli("evaluator --connect 127.0.0.1:" + *second_port +
                                         " --publisher evaluator-a --boot boot-restart"
                                         " --scenario authorized");
  PA_CHECK(contains(stale_boot, "register=rejected"));

  // Traffic bound to the retired epoch is rejected by the new coordinator.
  const std::string stale_epoch = run_cli("evaluator --connect 127.0.0.1:" + *second_port +
                                          " --publisher evaluator-c --boot boot-fresh"
                                          " --scenario authorized --epoch 1 --publish");
  PA_CHECK(contains(stale_epoch, "register=accepted"));
  PA_CHECK(contains(stale_epoch, "publish=rejected"));
  PA_CHECK(contains(stale_epoch, "outcome=STALE_EPOCH"));
  PA_CHECK(contains(stale_epoch, "state=STALE"));

  // A fresh epoch revalidates the recovered path against current evidence.
  const std::filesystem::path fresh_output = temporary("restart-evaluator-fresh");
  auto fresh = ChildProcess::start(
      "\"" + std::string(kCli) + "\" evaluator --connect 127.0.0.1:" + *second_port +
          " --publisher evaluator-d --boot boot-after-restart --scenario authorized --publish --hold",
      fresh_output, error);
  PA_REQUIRE(fresh.has_value());
  PA_REQUIRE(fresh->field("publish").has_value());
  PA_CHECK(contains(fresh->output(), "publish=accepted"));
  const std::string restored =
      run_cli("query --connect 127.0.0.1:" + *second_port + " --path " + path);
  PA_CHECK(contains(restored, "state=AUTHORIZED"));
  PA_CHECK(contains(restored, "current=true"));

  fresh->kill_hard();
  second->kill_hard();
}

PA_TEST_MAIN()
