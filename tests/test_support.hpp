// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

// Minimal, dependency-free harness. There are no framework timeouts: a hanging
// test is a defect and must be diagnosed rather than masked. Every bounded wait
// fails explicitly with a structured message when its bound is crossed.
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace pa_test {

struct Registry {
  struct Case {
    std::string name;
    std::function<void()> body;
  };
  std::vector<Case> cases;
  int failures = 0;
  int assertions = 0;
  std::string current;
};

inline Registry& registry() {
  static Registry instance;
  return instance;
}

struct CaseRegistrar {
  CaseRegistrar(std::string name, std::function<void()> body) {
    registry().cases.push_back(Registry::Case{std::move(name), std::move(body)});
  }
};

inline void fail(const std::string& file, int line, const std::string& message) {
  ++registry().failures;
  std::cout << "FAIL " << registry().current << " " << file << ":" << line << ": " << message
            << "\n";
  std::cout.flush();
}

inline void check(bool condition, const std::string& text, const std::string& file, int line) {
  ++registry().assertions;
  if (!condition) {
    fail(file, line, text);
  }
}

template <class T, class U>
inline void check_eq(const T& actual, const U& expected, const std::string& text,
                     const std::string& file, int line) {
  ++registry().assertions;
  if (!(actual == expected)) {
    std::ostringstream stream;
    stream << text;
    fail(file, line, stream.str());
  }
}

// Bounded wait with an explicit failure. Used only for cross process proofs;
// a bound crossing is a structured failed assertion, never a silent pass.
template <class Predicate>
inline bool wait_for(Predicate predicate, std::chrono::milliseconds bound,
                     const std::string& description, const std::string& file, int line) {
  const auto deadline = std::chrono::steady_clock::now() + bound;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  if (predicate()) {
    return true;
  }
  fail(file, line, "timed out waiting for " + description);
  return false;
}

inline int run_all() {
  Registry& instance = registry();
  for (auto& test_case : instance.cases) {
    instance.current = test_case.name;
    const int before = instance.failures;
    test_case.body();
    std::cout << (instance.failures == before ? "PASS " : "FAIL ") << test_case.name << "\n";
    std::cout.flush();
  }
  std::cout << "cases=" << instance.cases.size() << " assertions=" << instance.assertions
            << " failures=" << instance.failures << "\n";
  return instance.failures == 0 ? 0 : 1;
}

// Per-process and per-call unique path under the test temp root. Reusing a
// name across runs would silently reuse a stale durable store, which is a
// harness defect rather than a product behaviour.
inline std::filesystem::path unique_test_path(const std::string& name) {
  static std::mt19937_64 engine([]() {
    std::random_device device;
    return (static_cast<std::uint64_t>(device()) << 32) ^ static_cast<std::uint64_t>(device());
  }());
#if defined(_WIN32)
  const auto process = static_cast<std::uint64_t>(GetCurrentProcessId());
#else
  const auto process = static_cast<std::uint64_t>(getpid());
#endif
  static std::atomic<std::uint64_t> counter{0};
  const std::uint64_t serial = counter.fetch_add(1) + 1;
  const std::filesystem::path root(PATH_AUTHORITY_TEST_TEMP_ROOT);
  std::error_code error;
  std::filesystem::create_directories(root, error);
  return root / (name + "-" + std::to_string(process) + "-" + std::to_string(serial) + "-" +
                 std::to_string(engine() % 1000000));
}

}  // namespace pa_test

#define PA_TEST(name)                                                            \
  static void pa_test_case_##name();                                             \
  static const pa_test::CaseRegistrar pa_test_registrar_##name(#name,            \
                                                               pa_test_case_##name); \
  static void pa_test_case_##name()

#define PA_CHECK(condition) pa_test::check((condition), #condition, __FILE__, __LINE__)

#define PA_CHECK_EQ(actual, expected)                                            \
  pa_test::check_eq((actual), (expected),                                        \
                    std::string(#actual) + " == " + std::string(#expected),      \
                    __FILE__, __LINE__)

#define PA_REQUIRE(condition)      \
  do {                             \
    PA_CHECK(condition);           \
    if (!(condition)) {            \
      return;                      \
    }                             \
  } while (false)

#define PA_WAIT_FOR(predicate, bound, description) \
  pa_test::wait_for([&]() { return (predicate); }, (bound), (description), __FILE__, __LINE__)

#define PA_TEST_MAIN()      \
  int main() {              \
    return pa_test::run_all(); \
  }
