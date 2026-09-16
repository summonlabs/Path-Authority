// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
//
// REAL local evidence: identities and state read from this host. The test is
// conservative and is skipped, with an explicit note, when the host exposes no
// capturable interface.
#include <iostream>
#include <string>

#include "path_authority/path_authority.hpp"
#include "test_support.hpp"

using namespace path_authority;

PA_TEST(local_host_evidence_drives_a_real_path_evaluation) {
  std::string error;
  const auto fabric = LocalHostFabric::capture(error);
  if (!fabric.has_value()) {
    std::cout << "note: no REAL local evidence available: " << error << "\n";
    return;
  }
  PA_CHECK(!fabric->host_identity().empty());
  if (fabric->interfaces().empty()) {
    std::cout << "note: this host exposes no non-loopback interface\n";
    return;
  }

  PathAuthorityRuntime runtime(fabric->sources());
  runtime.register_constraint_set(fabric->constraints());

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
  PA_REQUIRE(path.has_value());

  EvaluationRequest request;
  request.attempt = MutationAttemptId::parse("local-evidence-attempt");
  const EvaluationResult result = runtime.evaluate(*path, request);
  PA_CHECK(result.committed);
  PA_CHECK_EQ(result.evidence.find(EvidenceKind::LINK_STATE,
                                   element_key(ElementKind::LINK, path->hops[2].id))
                     .has_value(),
              true);

  // Local authority follows local link state: taking the captured interface
  // down in the evidence must invalidate the path exactly.
  const std::string link = path->hops[2].id;
  const auto snapshot = runtime.query(path->id);
  PA_REQUIRE(snapshot.has_value());
  if (snapshot->state == AuthorityState::AUTHORIZED) {
    const InvalidationReport report = runtime.invalidate_link(
        LinkId::parse(link), LinkStateGeneration::from_value(2));
    PA_CHECK_EQ(report.revalidation_required.size(), std::size_t{1});
    const auto after = runtime.query(path->id);
    PA_REQUIRE(after.has_value());
    PA_CHECK_EQ(after->state, AuthorityState::REVALIDATION_REQUIRED);
  }
}

PA_TEST(local_evidence_describes_its_scope_conservatively) {
  std::string error;
  const auto fabric = LocalHostFabric::capture(error);
  if (!fabric.has_value()) {
    return;
  }
  const std::string description = fabric->describe();
  PA_CHECK(description.find("classification=REAL") != std::string::npos);
  PA_CHECK(description.find("local host evidence only") != std::string::npos);
  PA_CHECK(description.find("switch fabric internals") != std::string::npos);
  PA_CHECK(description.find("classification=REAL") == 0);
}

PA_TEST_MAIN()
