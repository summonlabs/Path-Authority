// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

// Real OS process control for the distributed proofs. Deaths performed here are
// genuine process terminations, never in-memory flags.
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <csignal>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace pa_process {

class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess() { close(); }

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ChildProcess(ChildProcess&& other) noexcept { move_from(other); }
  ChildProcess& operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
      close();
      move_from(other);
    }
    return *this;
  }

  static std::optional<ChildProcess> start(const std::string& command_line,
                                           const std::filesystem::path& output_path,
                                           std::string& error) {
    ChildProcess child;
    child.output_path_ = output_path;
#if defined(_WIN32)
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    const HANDLE output = CreateFileA(output_path.string().c_str(), GENERIC_WRITE,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (output == INVALID_HANDLE_VALUE) {
      error = "cannot create child output file";
      return std::nullopt;
    }
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = output;
    startup.hStdError = output;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION information{};
    std::vector<char> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back('\0');
    const BOOL created = CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information);
    CloseHandle(output);
    if (created == FALSE) {
      error = "cannot start child process";
      return std::nullopt;
    }
    CloseHandle(information.hThread);
    child.process_ = information.hProcess;
    child.pid_ = information.dwProcessId;
#else
    const pid_t pid = fork();
    if (pid < 0) {
      error = "cannot fork";
      return std::nullopt;
    }
    if (pid == 0) {
      const int output = ::open(output_path.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (output >= 0) {
        dup2(output, STDOUT_FILENO);
        dup2(output, STDERR_FILENO);
      }
      execl("/bin/sh", "sh", "-c", command_line.c_str(), static_cast<char*>(nullptr));
      _exit(127);
    }
    child.pid_ = pid;
#endif
    return child;
  }

  bool running() const {
#if defined(_WIN32)
    if (process_ == nullptr) {
      return false;
    }
    return WaitForSingleObject(process_, 0) == WAIT_TIMEOUT;
#else
    if (pid_ <= 0) {
      return false;
    }
    int status = 0;
    const pid_t result = waitpid(pid_, &status, WNOHANG);
    return result == 0;
#endif
  }

  // Hard termination of a live OS process: no graceful shutdown is performed.
  void kill_hard() {
#if defined(_WIN32)
    if (process_ != nullptr) {
      TerminateProcess(process_, 137);
      WaitForSingleObject(process_, INFINITE);
      CloseHandle(process_);
      process_ = nullptr;
    }
#else
    if (pid_ > 0) {
      ::kill(pid_, SIGKILL);
      int status = 0;
      waitpid(pid_, &status, 0);
      pid_ = -1;
    }
#endif
  }

  int wait() {
#if defined(_WIN32)
    if (process_ == nullptr) {
      return -1;
    }
    WaitForSingleObject(process_, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(process_, &code);
    CloseHandle(process_);
    process_ = nullptr;
    return static_cast<int>(code);
#else
    if (pid_ <= 0) {
      return -1;
    }
    int status = 0;
    waitpid(pid_, &status, 0);
    const int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    pid_ = -1;
    return code;
#endif
  }

  void close() {
    if (running()) {
      kill_hard();
    }
  }

  std::string output() const {
    std::ifstream stream(output_path_, std::ios::binary);
    std::string text;
    char chunk = 0;
    while (stream.get(chunk)) {
      text.push_back(chunk);
    }
    return text;
  }

  // Reads one "key=value" line from the child output. The caller supplies the
  // bound; crossing it is reported to the caller as a missing value.
  std::optional<std::string> field(const std::string& key,
                                   std::chrono::milliseconds bound = std::chrono::seconds(30)) {
    const std::string prefix = key + "=";
    const auto deadline = std::chrono::steady_clock::now() + bound;
    while (std::chrono::steady_clock::now() < deadline) {
      const std::string text = output();
      std::size_t position = 0;
      while ((position = text.find(prefix, position)) != std::string::npos) {
        const std::size_t start = position + prefix.size();
        const std::size_t end = text.find_first_of("\r\n", start);
        if (end != std::string::npos) {
          return text.substr(start, end - start);
        }
        position = start;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return std::nullopt;
  }

  std::filesystem::path output_path() const { return output_path_; }

 private:
  void move_from(ChildProcess& other) noexcept {
    output_path_ = std::move(other.output_path_);
#if defined(_WIN32)
    process_ = other.process_;
    pid_ = other.pid_;
    other.process_ = nullptr;
    other.pid_ = 0;
#else
    pid_ = other.pid_;
    other.pid_ = -1;
#endif
  }

  std::filesystem::path output_path_;
#if defined(_WIN32)
  void* process_ = nullptr;
  unsigned long pid_ = 0;
#else
  int pid_ = -1;
#endif
};

}  // namespace pa_process
