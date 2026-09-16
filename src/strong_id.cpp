// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/strong_id.hpp"

namespace path_authority {
namespace detail {
namespace {

bool is_alpha_numeric(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool is_body_char(char c) noexcept {
  return is_alpha_numeric(c) || c == '.' || c == '_' || c == ':' || c == '-';
}

}  // namespace

bool valid_identity_text(std::string_view text, std::size_t max_len) noexcept {
  // Identities are untrusted input. They are bounded, restricted to a single
  // unambiguous ASCII alphabet and may not begin with a separator, which also
  // makes them unusable as path fragments on any platform.
  if (text.empty() || text.size() > max_len) {
    return false;
  }
  if (!is_alpha_numeric(text.front())) {
    return false;
  }
  for (char c : text) {
    if (!is_body_char(c)) {
      return false;
    }
  }
  return true;
}

}  // namespace detail
}  // namespace path_authority
