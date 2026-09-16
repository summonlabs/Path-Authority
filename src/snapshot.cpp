// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_authority/snapshot.hpp"

#include <algorithm>
#include <string>
#include <utility>

#include "path_authority/canonical.hpp"
#include "path_authority/version.hpp"

namespace path_authority {
namespace {

AuthorityDiffKind diff_kind_for(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::TOPOLOGY: return AuthorityDiffKind::TOPOLOGY_BINDING;
    case EvidenceKind::STRUCTURAL_ELEMENT: return AuthorityDiffKind::STRUCTURAL_ELEMENT;
    case EvidenceKind::LINK_STATE: return AuthorityDiffKind::LINK_STATE;
    case EvidenceKind::PORT_CONFIG: return AuthorityDiffKind::PORT_CONFIG;
    case EvidenceKind::CAPABILITY: return AuthorityDiffKind::CAPABILITY;
    case EvidenceKind::FAILURE_DOMAIN: return AuthorityDiffKind::FAILURE_DOMAIN;
    case EvidenceKind::POLICY: return AuthorityDiffKind::POLICY;
    case EvidenceKind::EPOCH: return AuthorityDiffKind::EPOCH;
    case EvidenceKind::CONSTRAINTS: return AuthorityDiffKind::CONSTRAINT_SET;
    case EvidenceKind::UNDERLYING_AUTHORITY: return AuthorityDiffKind::UNDERLYING_AUTHORITY;
  }
  return AuthorityDiffKind::AUTHORITY_STATE;
}

std::string generation_text(std::uint64_t value) { return std::to_string(value); }

void add_entry(std::vector<AuthorityDiffEntry>& entries, AuthorityDiffKind kind,
               std::string subject, std::string before, std::string after) {
  if (before == after) {
    return;
  }
  entries.push_back(AuthorityDiffEntry{kind, std::move(subject), std::move(before), std::move(after)});
}

}  // namespace

std::string_view to_string(AuthorityDiffKind kind) noexcept {
  switch (kind) {
    case AuthorityDiffKind::PATH_STRUCTURE: return "PATH_STRUCTURE";
    case AuthorityDiffKind::PATH_GENERATION: return "PATH_GENERATION";
    case AuthorityDiffKind::CONSTRAINT_SET: return "CONSTRAINT_SET";
    case AuthorityDiffKind::POLICY: return "POLICY";
    case AuthorityDiffKind::EPOCH: return "EPOCH";
    case AuthorityDiffKind::TOPOLOGY_BINDING: return "TOPOLOGY_BINDING";
    case AuthorityDiffKind::STRUCTURAL_ELEMENT: return "STRUCTURAL_ELEMENT";
    case AuthorityDiffKind::LINK_STATE: return "LINK_STATE";
    case AuthorityDiffKind::PORT_CONFIG: return "PORT_CONFIG";
    case AuthorityDiffKind::CAPABILITY: return "CAPABILITY";
    case AuthorityDiffKind::FAILURE_DOMAIN: return "FAILURE_DOMAIN";
    case AuthorityDiffKind::UNDERLYING_AUTHORITY: return "UNDERLYING_AUTHORITY";
    case AuthorityDiffKind::AUTHORITY_STATE: return "AUTHORITY_STATE";
    case AuthorityDiffKind::AUTHORITY_GENERATION: return "AUTHORITY_GENERATION";
    case AuthorityDiffKind::AUTHORITY_DIGEST: return "AUTHORITY_DIGEST";
    case AuthorityDiffKind::REVOCATION: return "REVOCATION";
    case AuthorityDiffKind::OUTCOME: return "OUTCOME";
  }
  return "INVALID";
}

std::strong_ordering operator<=>(const AuthorityDiffEntry& lhs, const AuthorityDiffEntry& rhs) {
  if (const auto cmp = lhs.kind <=> rhs.kind; cmp != 0) {
    return cmp;
  }
  if (const auto cmp = lhs.subject <=> rhs.subject; cmp != 0) {
    return cmp;
  }
  if (const auto cmp = lhs.before <=> rhs.before; cmp != 0) {
    return cmp;
  }
  return lhs.after <=> rhs.after;
}

std::string AuthorityDiffEntry::render() const {
  std::string text = std::string(to_string(kind));
  if (!subject.empty()) {
    text += " " + subject;
  }
  text += ": " + (before.empty() ? std::string("absent") : before);
  text += " -> " + (after.empty() ? std::string("absent") : after);
  return text;
}

std::string AuthorityDiff::render() const {
  std::string text;
  text += "path=" + path.str() + "\n";
  text += "before=" + before.str() + "\n";
  text += "after=" + after.str() + "\n";
  if (entries.empty()) {
    text += "changes=0\n";
    return text;
  }
  text += "changes=" + std::to_string(entries.size()) + "\n";
  for (const auto& entry : entries) {
    text += "change=" + entry.render() + "\n";
  }
  return text;
}

Digest AuthoritySnapshot::snapshot_digest() const {
  ByteWriter writer;
  writer.u32(kDigestSchemeVersion);
  writer.length_prefixed(path.view());
  writer.u64(path_generation.value());
  writer.u64(authority_generation.value());
  writer.u8(static_cast<std::uint8_t>(state));
  writer.u16(static_cast<std::uint16_t>(last_outcome));
  writer.digest(path_digest);
  writer.digest(authority_digest);
  writer.digest(evidence.digest());
  writer.length_prefixed(constraint_set.view());
  writer.u64(constraint_generation.value());
  writer.u64(policy.value());
  writer.u64(epoch.value());
  writer.boolean(revocation.has_value());
  if (revocation.has_value()) {
    writer.u8(static_cast<std::uint8_t>(revocation->reason));
    writer.length_prefixed(revocation->explanation);
    writer.u64(revocation->generation.value());
    writer.u64(revocation->epoch.value());
    writer.length_prefixed(revocation->authority);
    writer.length_prefixed(revocation->attempt.view());
  }
  std::vector<EvaluationOutcome> codes;
  codes.reserve(secondary.size());
  for (const auto& violation : secondary) {
    codes.push_back(violation.code);
  }
  std::sort(codes.begin(), codes.end());
  writer.u32(static_cast<std::uint32_t>(codes.size()));
  for (EvaluationOutcome code : codes) {
    writer.u16(static_cast<std::uint16_t>(code));
  }
  return Digest::of(writer.data());
}

std::string AuthoritySnapshot::render() const {
  std::string text;
  text += "snapshot=" + id.str() + "\n";
  text += "path=" + path.str() + "\n";
  text += "path_generation=" + std::to_string(path_generation.value()) + "\n";
  text += "authority_generation=" + std::to_string(authority_generation.value()) + "\n";
  text += "state=" + std::string(to_string(state)) + "\n";
  text += "outcome=" + std::string(to_string(last_outcome)) + "\n";
  text += "epoch=" + std::to_string(epoch.value()) + "\n";
  text += "policy_generation=" + std::to_string(policy.value()) + "\n";
  text += "constraint_set=" + constraint_set.str() + "@" +
          std::to_string(constraint_generation.value()) + "\n";
  text += "path_digest=" + path_digest.hex() + "\n";
  text += "authority_digest=" + authority_digest.hex() + "\n";
  text += "snapshot_digest=" + snapshot_digest().hex() + "\n";
  text += "current=" + std::string(current ? "true" : "false") + "\n";
  if (!publisher.valid()) {
    text += "publisher=none\n";
  } else {
    text += "publisher=" + publisher.str() + " boot=" + worker_boot.str() + "\n";
  }
  if (revocation.has_value()) {
    text += "revocation=" + revocation->render() + "\n";
  }
  for (const auto& delta : stale_dependencies) {
    text += "stale=" + delta.render() + "\n";
  }
  for (const auto& violation : secondary) {
    text += "reason=" + violation.render() + "\n";
  }
  for (const auto& entry : history) {
    text += "history=" + entry.render() + "\n";
  }
  return text;
}

AuthorityDiff diff_snapshots(const AuthoritySnapshot& before, const AuthoritySnapshot& after) {
  AuthorityDiff diff;
  diff.path = after.path;
  diff.before = before.id;
  diff.after = after.id;
  if (before.path != after.path) {
    add_entry(diff.entries, AuthorityDiffKind::PATH_STRUCTURE, "path", before.path.str(),
              after.path.str());
  }
  add_entry(diff.entries, AuthorityDiffKind::PATH_STRUCTURE, "path_digest",
            before.path_digest.short_hex(16), after.path_digest.short_hex(16));
  add_entry(diff.entries, AuthorityDiffKind::PATH_GENERATION, "path_generation",
            generation_text(before.path_generation.value()),
            generation_text(after.path_generation.value()));
  add_entry(diff.entries, AuthorityDiffKind::CONSTRAINT_SET, "constraint_set",
            before.constraint_set.str() + "@" + generation_text(before.constraint_generation.value()),
            after.constraint_set.str() + "@" + generation_text(after.constraint_generation.value()));
  add_entry(diff.entries, AuthorityDiffKind::POLICY, "policy_generation",
            generation_text(before.policy.value()), generation_text(after.policy.value()));
  add_entry(diff.entries, AuthorityDiffKind::EPOCH, "epoch",
            generation_text(before.epoch.value()), generation_text(after.epoch.value()));
  add_entry(diff.entries, AuthorityDiffKind::AUTHORITY_STATE, "state",
            std::string(to_string(before.state)), std::string(to_string(after.state)));
  add_entry(diff.entries, AuthorityDiffKind::AUTHORITY_GENERATION, "authority_generation",
            generation_text(before.authority_generation.value()),
            generation_text(after.authority_generation.value()));
  add_entry(diff.entries, AuthorityDiffKind::AUTHORITY_DIGEST, "authority_digest",
            before.authority_digest.short_hex(16), after.authority_digest.short_hex(16));
  add_entry(diff.entries, AuthorityDiffKind::OUTCOME, "outcome",
            std::string(to_string(before.last_outcome)), std::string(to_string(after.last_outcome)));

  const std::string before_revocation =
      before.revocation.has_value() ? before.revocation->render() : std::string();
  const std::string after_revocation =
      after.revocation.has_value() ? after.revocation->render() : std::string();
  add_entry(diff.entries, AuthorityDiffKind::REVOCATION, "revocation", before_revocation,
            after_revocation);

  for (const auto& delta : diff_evidence(before.evidence, after.evidence)) {
    std::string before_text = delta.before.has_value() ? generation_text(*delta.before) : std::string();
    std::string after_text = delta.after.has_value() ? generation_text(*delta.after) : std::string();
    add_entry(diff.entries, diff_kind_for(delta.kind), delta.subject, std::move(before_text),
              std::move(after_text));
  }

  std::sort(diff.entries.begin(), diff.entries.end());
  return diff;
}

}  // namespace path_authority
