// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// Examples use the public library API only. This header only prints results and
// reports example failures.
#pragma once

#include <iostream>
#include <string>

#include "path_authority/path_authority.hpp"

namespace pa_example {

inline int report(const std::string& name, bool ok, const std::string& detail) {
  std::cout << (ok ? "example=" : "example-failed=") << name << "\n";
  if (!detail.empty()) {
    std::cout << detail;
  }
  return ok ? 0 : 1;
}

inline path_authority::MutationAttemptId attempt(const std::string& text) {
  return path_authority::MutationAttemptId::parse(text);
}

}  // namespace pa_example
