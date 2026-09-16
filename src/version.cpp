// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/version.hpp"

namespace path_authority {
namespace {

const std::string& version_value() {
  static const std::string value =
      std::to_string(kVersionMajor) + "." + std::to_string(kVersionMinor) + "." +
      std::to_string(kVersionPatch);
  return value;
}

}  // namespace

std::string_view library_name() noexcept { return "Path Authority"; }

std::string_view version_string() noexcept { return version_value(); }

std::string version_report() {
  std::string text;
  text += "library=" + std::string(library_name()) + "\n";
  text += "version=" + version_value() + "\n";
  text += "canonical_encoding_version=" + std::to_string(kCanonicalEncodingVersion) + "\n";
  text += "digest_scheme_version=" + std::to_string(kDigestSchemeVersion) + "\n";
  text += "persistence_format_version=" + std::to_string(kPersistenceFormatVersion) + "\n";
  text += "wire_protocol_version=" + std::to_string(kWireProtocolVersion) + "\n";
  text += "rule_set_version=" + std::to_string(kRuleSetVersion) + "\n";
  return text;
}

}  // namespace path_authority
