// Path Authority 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "path_authority/export.hpp"
#include "path_authority/strong_id.hpp"

namespace path_authority {

// ---------------------------------------------------------------------------
// Identity tags. Each tag is a distinct C++ type, so cross-domain assignment
// does not compile and cross-domain decoding is impossible by construction.
// ---------------------------------------------------------------------------
#define PATH_AUTHORITY_DEFINE_ID_TAG(TagName, DisplayName)      \
  struct TagName {                                              \
    static constexpr std::string_view name() noexcept { return DisplayName; } \
  }

PATH_AUTHORITY_DEFINE_ID_TAG(PathIdTag, "PathId");
PATH_AUTHORITY_DEFINE_ID_TAG(PathEvaluationIdTag, "PathEvaluationId");
PATH_AUTHORITY_DEFINE_ID_TAG(PathSnapshotIdTag, "PathSnapshotId");
PATH_AUTHORITY_DEFINE_ID_TAG(ConstraintSetIdTag, "ConstraintSetId");
PATH_AUTHORITY_DEFINE_ID_TAG(PublisherIdTag, "PublisherId");
PATH_AUTHORITY_DEFINE_ID_TAG(WorkerBootIdTag, "WorkerBootId");
PATH_AUTHORITY_DEFINE_ID_TAG(MutationAttemptIdTag, "MutationAttemptId");
PATH_AUTHORITY_DEFINE_ID_TAG(ScopeIdTag, "ScopeId");
PATH_AUTHORITY_DEFINE_ID_TAG(NodeIdTag, "NodeId");
PATH_AUTHORITY_DEFINE_ID_TAG(LinkIdTag, "LinkId");
PATH_AUTHORITY_DEFINE_ID_TAG(PortIdTag, "PortId");
PATH_AUTHORITY_DEFINE_ID_TAG(EndpointIdTag, "EndpointId");
PATH_AUTHORITY_DEFINE_ID_TAG(FailureDomainIdTag, "FailureDomainId");
PATH_AUTHORITY_DEFINE_ID_TAG(CapabilityKeyTag, "CapabilityKey");

PATH_AUTHORITY_DEFINE_ID_TAG(PathGenerationTag, "PathGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(PathAuthorityGenerationTag, "PathAuthorityGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(ConstraintGenerationTag, "ConstraintGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(EvidenceGenerationTag, "EvidenceGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(PolicyGenerationTag, "PolicyGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(TopologyGenerationTag, "TopologyGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(StructuralGenerationTag, "StructuralGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(LinkStateGenerationTag, "LinkStateGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(PortConfigGenerationTag, "PortConfigGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(CapabilityGenerationTag, "CapabilityGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(FailureDomainGenerationTag, "FailureDomainGeneration");
PATH_AUTHORITY_DEFINE_ID_TAG(CoordinatorEpochTag, "CoordinatorEpoch");

#undef PATH_AUTHORITY_DEFINE_ID_TAG

using PathId = StringId<PathIdTag, 96>;
using PathEvaluationId = StringId<PathEvaluationIdTag, 96>;
using PathSnapshotId = StringId<PathSnapshotIdTag, 96>;
using ConstraintSetId = StringId<ConstraintSetIdTag, 96>;
using PublisherId = StringId<PublisherIdTag, 64>;
using WorkerBootId = StringId<WorkerBootIdTag, 64>;
using MutationAttemptId = StringId<MutationAttemptIdTag, 96>;
using ScopeId = StringId<ScopeIdTag, 64>;
using NodeId = StringId<NodeIdTag, 128>;
using LinkId = StringId<LinkIdTag, 128>;
using PortId = StringId<PortIdTag, 128>;
using EndpointId = StringId<EndpointIdTag, 128>;
using FailureDomainId = StringId<FailureDomainIdTag, 128>;
using CapabilityKey = StringId<CapabilityKeyTag, 64>;

using PathGeneration = Generation<PathGenerationTag>;
using PathAuthorityGeneration = Generation<PathAuthorityGenerationTag>;
using ConstraintGeneration = Generation<ConstraintGenerationTag>;
using EvidenceGeneration = Generation<EvidenceGenerationTag>;
using PolicyGeneration = Generation<PolicyGenerationTag>;
using TopologyGeneration = Generation<TopologyGenerationTag>;
using StructuralGeneration = Generation<StructuralGenerationTag>;
using LinkStateGeneration = Generation<LinkStateGenerationTag>;
using PortConfigGeneration = Generation<PortConfigGenerationTag>;
using CapabilityGeneration = Generation<CapabilityGenerationTag>;
using FailureDomainGeneration = Generation<FailureDomainGenerationTag>;
using CoordinatorEpoch = Generation<CoordinatorEpochTag>;

// A path identity derived from canonical content: "path-" plus the leading
// 128 bits of the canonical digest. Deterministic across processes and builds.
PATH_AUTHORITY_API PathId derived_path_id(const class Digest& digest);
PATH_AUTHORITY_API ScopeId default_scope() noexcept;

}  // namespace path_authority
