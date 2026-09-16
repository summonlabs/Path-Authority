# Path Authority 1.0.0

Path Authority is the authoritative path-legality runtime of the Distributed Fabric
Infrastructure / Fabric OS stack. It answers exactly one question:

> Does this exact candidate path remain legally usable under the current
> authoritative topology, link-state, capability, failure-domain, epoch and policy
> evidence — and if not, exactly which condition invalidates it?

It consumes already-computed candidate paths. It never discovers, computes,
optimizes, selects or programs a route.

---

## 1. Systems boundary

Path Authority owns: exact path identity and canonical form, path-generation and
constraint binding, structural path validation, path authority state, legality
evaluation, path evidence binding, topology/link/port/capability/failure-domain
binding, epoch and policy currentness, administrative eligibility, deterministic
rejection reasons, revalidation, revocation, immutable authority snapshots,
authority diffs, deterministic semantic digests, reverse dependency indexes,
distributed publication with worker-incarnation fencing, conservative recovery and
bounded diagnostics.

Path Authority does not own, and never fabricates:

| Authority | Owns |
| --- | --- |
| Fabric Registry | canonical infrastructure identity |
| Fabric Topology | structural connectivity, element generations, retirement |
| Link State Fabric | dynamic link condition |
| Port Fabric | port administrative configuration |
| Fabric Capability Registry | capability truth |
| Failure Domain Registry | correlated-risk classification and coverage |
| Fabric Epoch | control-plane epoch authority |
| Path Planner | path computation |
| Bandwidth Broker / Reservation Fabric | capacity truth |
| Adaptive Routing Fabric | congestion and adaptation |
| Route Fabric | forwarding-programming lifecycle |

A path existing is not the same as the path being structurally valid, satisfying
its required constraints, or being currently authorized. Those are four separate
conditions in this runtime and they never collapse into one.

### Why path planning is separate

Path Authority validates the exact sequence it is given. If hop `L2` is stale it
reports `REJECTED because L2 is stale` and stops; the caller may then ask Path
Planner for a different candidate. There is no graph search, no "better route", no
weight, no score and no selection anywhere in this library.

### Out of scope on purpose

Capacity is not path legality: capability *speed* is a declared property, not
current available bandwidth. Congestion never becomes illegality. Route state is
never installed or chosen. No consensus protocol is implemented.

---

## 2. Path representation and authority states

A candidate path is a bounded, ordered sequence of typed structural elements
(`ENDPOINT`, `PORT`, `LINK`, `SWITCH`, `ROUTER`, `LOGICAL_HOP`, `PHYSICAL_HOP`,
`TUNNEL`, `FABRIC_BOUNDARY`, `SITE_BOUNDARY`), each carrying the structural
generation the caller validated it against, its layer and its relation type. A path
also binds its constraint set and constraint generation, its own generation, its
scope, and optionally an explicit underlying path reference.

Canonical form is a versioned, self-delimiting byte encoding. Two semantically
identical paths canonicalize identically; different hop order never collapses to the
same identity. `PathId` is derived from the canonical content digest, and the
semantic digest of a path is stable across processes and builds.

Authority states are `UNKNOWN`, `AUTHORIZED`, `CONDITIONALLY_AUTHORIZED`,
`REVALIDATION_REQUIRED`, `REJECTED`, `REVOKED`, `STALE`, `RETIRED`. Outcomes are
exactly these codes, one primary per evaluation:

`AUTHORIZED`, `IDEMPOTENT`, `CONDITIONALLY_AUTHORIZED`, `MALFORMED_PATH`,
`RESOURCE_LIMIT`, `STRUCTURALLY_INVALID`, `STALE_TOPOLOGY`, `CONSTRAINT_SET_UNKNOWN`,
`PATH_RETIRED`, `PATH_UNKNOWN`, `PORT_ADMIN_DISABLED`, `PORT_REVALIDATION_REQUIRED`,
`LINK_DOWN`, `LINK_DEGRADED`, `LINK_STATE_UNKNOWN`, `CAPABILITY_MISSING`,
`CAPABILITY_UNKNOWN`, `FAILURE_DOMAIN_VIOLATION`, `FAILURE_DOMAIN_COVERAGE_UNKNOWN`,
`STALE_EPOCH`, `STALE_AUTHORITY`, `REVALIDATION_REQUIRED`, `POLICY_REJECTED`,
`REVOKED`, `EVALUATION_ATTEMPT_CONFLICT`.

### Deterministic rejection precedence

Stages run in this fixed order (`kRuleSetVersion` covers it):

1. `DECODE` — shape, limits, constraint-set resolution (`MALFORMED_PATH`, `RESOURCE_LIMIT`, `CONSTRAINT_SET_UNKNOWN`)
2. `PATH_IDENTITY` — declared id must equal the canonical content digest
3. `PATH_RETIREMENT` — a retired path stays retired
4. `FABRIC_EPOCH` — a publisher asserting an old epoch is refused
5. `REVOCATION` — a revoked path never returns to authority
6. `STRUCTURAL_TOPOLOGY` — unknown, retired, superseded, stale-generation and non-adjacent hops
7. `BOUND_INPUT_CURRENTNESS` — underlying path authority and constraint generation binding
8. `PORT_ADMINISTRATIVE` — administrative port state, explicit DRAINING semantics
9. `LINK_STATE` — DOWN/FAULTED/RETIRED reject, DEGRADED and UNKNOWN follow explicit rules
10. `CAPABILITY` — registry truth, typed requirement trees, fail-closed on UNKNOWN
11. `FAILURE_DOMAIN` — forbidden domains, member counts, classes, coverage completeness, peer diversity
12. `POLICY` — layers, loops, effective hop bound, forbidden domain classes
13. `EXPECTED_GENERATION` — compare-and-set on the committed authority generation
14. `COMMIT` — atomic commit or exact-replay idempotency

The first hard violation in that order is the primary outcome. Every later stage
still runs to enrich diagnostics, so a path violating several constraints returns one
deterministic primary reason and a deterministic, sorted set of secondary
explanations. Diagnostic richness never changes the authoritative result.

---

## 3. Evidence vector and bindings

Every decision binds an evidence vector: topology generation, per-element structural
generations, per-link state generations, per-port configuration generations,
per-capability generations, per-domain and per-membership generations, the constraint
generation, the policy generation, the Fabric Epoch and the underlying-path authority
generation. Currentness is never reduced to one timestamp.

* **Topology** — element absence is `STRUCTURALLY_INVALID`; a moved element
  generation is `STALE_TOPOLOGY`; retired and superseded elements reject; adjacency,
  direction and layer are validated per hop.
* **Link state** — `DOWN`, `FAULTED` and `RETIRED` reject as `LINK_DOWN`.
  `DEGRADED` has no global rule: it is accepted, conditionally accepted or rejected
  strictly by the effective acceptance rules. `UNKNOWN` (including "no current
  record") fails closed unless the rules explicitly accept it.
* **Port state** — `ADMIN_DISABLED`, `RETIRED`, `SUPERSEDED` reject;
  `REVALIDATION_REQUIRED` and missing records reject; `MAINTENANCE` and `DRAINING`
  keep an existing authorization conditionally but refuse a new one.
* **Capability** — typed values (unsigned, signed, boolean, text, semantic version)
  and bounded requirement expressions (`SUPPORTS`, `MINIMUM`, `MAXIMUM`, `IN_SET`,
  `VERSION_AT_LEAST`, `RANGE_CONTAINS`, `ALL_OF`, `ANY_OF`, `NOT`) evaluated
  tri-state. `UNKNOWN` never satisfies a hard requirement. Mixed-type comparisons
  are a failure, never an implicit coercion.
* **Failure domains** — forbidden domains, maximum members per domain or class,
  excluded classes, required coverage completeness, and diversity against a supplied
  peer path across named domain classes. Incomplete coverage never implies
  independence: it rejects with `FAILURE_DOMAIN_COVERAGE_UNKNOWN`.
* **Policy** — a versioned `PolicySet` (acceptance rules, forbidden layers, forbidden
  domain classes, required capabilities, hop bound, conditional-authorization switch).
  The effective rules are the most restrictive combination of the path constraint set
  and the policy, computed deterministically.

---

## 4. Revalidation, invalidation, revocation

`revalidate(path, request)` re-evaluates the stored definition against current
evidence. An unchanged path under unchanged evidence is idempotent: the authority
generation does not advance and the result is `IDEMPOTENT`. The authority generation
advances **iff the semantic authority digest changes**, and that digest covers the
canonical path, path generation, constraint content and generation, the evidence
vector, the policy generation, the Fabric Epoch, the state and the primary outcome.

Reverse dependency indexes map element, capability, failure-domain, membership,
underlying-path, policy, epoch and constraint-set dependencies to the paths that
depend on them. `invalidate_*` marks exactly the affected paths
`REVALIDATION_REQUIRED` and reports both the paths that changed and the dependents
that were already current. Unrelated changes touch nothing.

Invalidation is monotonic: each invalidation raises an evidence watermark, and an
evaluation that was already in flight when its evidence was invalidated cannot commit
current authority — the commit is refused as stale instead.

Revocation is a different mechanism: explicit, generation-bound, reason-coded,
idempotent, durable, and distinguishable from evidence-driven invalidation. A revoked
path returns `REVOKED` forever; an invalidated path returns
`REVALIDATION_REQUIRED` and may be re-authorized once its evidence is current again.

Idempotency uses `MutationAttemptId`. Replaying the same attempt with the same
semantic input returns `IDEMPOTENT`; reusing it with different semantic input returns
`EVALUATION_ATTEMPT_CONFLICT` and mutates nothing.

---

## 5. Snapshots, digests, diffs

`query(path)` returns an immutable `AuthoritySnapshot` with the state, authority
generation, evidence vector, constraint and policy bindings, the exact candidate path,
the structured primary reason, the bounded history, the revocation record, a
deterministic snapshot digest, and a live currentness verdict with the exact
evidence deltas that make it stale. Old snapshots stay inspectable; they are never
current authority. `diff_snapshots` produces a stably ordered diff (topology binding,
link state, port state, capability, failure domain, epoch, policy, authority state and
generation transitions).

---

## 6. Persistence and recovery

Durable state is a versioned, integrity-checked, deterministically encoded image
(magic, format version, bounded payload, SHA-256 over the whole image) with atomic
replacement through a unique temporary file. Decoding is bounded and rejects empty
images, bad magic, unsupported versions, truncation, trailing bytes, checksum
failures, duplicate path identities, invalid enumerations, impossible generations,
malformed hops, excessive nesting, dangling underlying dependencies, dangling
constraint references and oversized fields.

Recovery is conservative. Persisted `AUTHORIZED` never means currently `AUTHORIZED`:
every recovered decision that carried live authority becomes `REVALIDATION_REQUIRED`
at a new authority generation. Durable path descriptions, revocations, retirements
and fenced worker incarnations survive.

---

## 7. Distributed process architecture

`PathAuthorityCoordinator` owns the Fabric Epoch, the worker registry, the durable
store and the authoritative runtime. `PathAuthorityEvaluator` is a separate OS process
role that evaluates candidate paths against the evidence it can see and publishes the
result. Publication is verified, never trusted: the coordinator recomputes the
canonical path digest, the constraint digest and the semantic authority digest from the
published components, and rejects the publish if any of them disagree, if the epoch
binding is stale, or if the worker incarnation is not registered on that connection.

The wire protocol is a framed TCP codec with explicit magic, wire version, stable
message ids, bounded payload length, reserved flags that must be zero, and a SHA-256
integrity check spanning the header and the payload. Decoding rejects undefined
enumerations, malformed identities, unset generations and trailing bytes.

Worker incarnations are fenced. When a publisher disappears — gracefully or by being
killed — its boot identity is fenced, every path it published becomes
`REVALIDATION_REQUIRED`, and the fenced set is persisted so the fence survives a
coordinator restart. A restarted coordinator consumes or advances the Fabric Epoch;
traffic bound to the old epoch and registrations from pre-restart boot identities are
rejected, and live authority is never restored from disk.

---

## 8. REAL, SYNTHETIC and UNSUPPORTED

**REAL (proven on the build host by the test suite):** real OS processes for the
coordinator, the evaluators and the CLI; real loopback TCP sockets; genuine process
terminations; a genuine coordinator restart with durable recovery; real local host
adapter identities, administrative/operational state, MTU and link speed read from the
operating system; actual persistence, corruption and recovery behaviour.

**SYNTHETIC:** every multi-switch, multi-site, optical, shared-risk and generated path
population. The synthetic fixture is a modelling fixture and is labelled as such in
its own output (`classification=SYNTHETIC`). Multi-switch path legality measured on it
is synthetic path legality, not physical fabric proof.

**UNSUPPORTED here:** physical fabrics, vendor switch internals, external routing
systems, consensus semantics, live congestion and capacity authorities. The local host
evidence covers one host: it models that host's endpoint, port, link and the boundary
of local visibility, and claims nothing about switch fabric internals.

---

## 9. Build, test, install

Requirements: CMake 3.25+, a C++20 compiler. On Windows, MSVC 19.3x with `/W4 /WX
/permissive-` is used, and AddressSanitizer is supported through `/fsanitize=address`.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Options: `PATH_AUTHORITY_BUILD_TESTS`, `PATH_AUTHORITY_BUILD_EXAMPLES`,
`PATH_AUTHORITY_BUILD_BENCHMARKS`, `PATH_AUTHORITY_BUILD_CLI`,
`PATH_AUTHORITY_WARNINGS_AS_ERRORS`, `PATH_AUTHORITY_ENABLE_ASAN`,
`PATH_AUTHORITY_ENABLE_ANALYZE` (`/analyze`), `PATH_AUTHORITY_LIBRARY_TYPE`.

Install and consume the package:

```
cmake --install build --config Release --prefix /some/prefix
find_package(PathAuthority CONFIG REQUIRED)
target_link_libraries(app PRIVATE SummonSoftwareLabs::PathAuthority)
```

The installed package exports the documented target `SummonSoftwareLabs::PathAuthority`,
a config file, a version file, the include directory and, on Windows, the required
system libraries. `tests/consumer` is an independent downstream project that builds
only against installed artifacts.

---

## 10. Command line tool

```
path_authority version
path_authority scenarios
path_authority evaluate    [--scenario NAME] [--path-kind primary|backup] [--json]
path_authority explain     [--scenario NAME] [--json]
path_authority revalidate  [--scenario NAME] [--json]
path_authority local-evidence [--json]
path_authority inspect     --store PATH [--json]
path_authority coordinator [--listen H:P] [--store PATH] [--scenario NAME] [--epoch N]
path_authority evaluator   --connect H:P [--publisher P] [--boot B] [--scenario NAME]
                           [--epoch N] [--publish] [--hold] [--path-kind KIND]
path_authority query       --connect H:P --path ID
path_authority workers     --connect H:P [--json]
path_authority revoke      --connect H:P --path ID [--durable]
```

Exit codes: `0` success, `1` usage error, `2` evaluation rejected, `3` distributed
failure. Output is deterministic and script friendly (`key=value`, or JSON with
`--json`).

---

## 11. Examples and benchmarks

Nine examples ship and all execute during closure: authorized path, link down, missing
capability, failure-domain violation, stale epoch, port disable, revalidation,
primary/backup diversity and persistence/recovery. They use the public API only.

`path_authority_benchmarks` reports measured, completed operations for authorization at
1k/10k/100k paths, query, unchanged revalidation, targeted link/capability/domain/epoch
invalidation, snapshot and digest, and persistence save/load. The populations are
SYNTHETIC and no performance guarantee is implied.

---

## 12. Thread safety, ownership, lifetime

All `PathAuthorityRuntime` operations are safe to call concurrently from any thread.
Evidence views are borrowed and must outlive the runtime; every view method may be
called concurrently and implementations must be internally synchronised. Evaluation
reads evidence outside the state lock, so no view call and no callback ever runs while
a lock is held. Snapshots, results and diffs are values: callers own them.

---

## 13. Resource limits

`Limits` bounds hop count, identity length, metadata size, constraint count, capability
values, requirement nodes and depth, failure-domain references, nesting depth, retained
paths, batch size, history, explanation entries, per-path evidence dependencies, tracked
attempts, publishers, wire frame size, store size and store records. Every bound is
enforced by the subsystem named in its comment and exercised by the test suite.

---

## 14. Genuine limitations

* Validation of fabric-scale topologies is SYNTHETIC. No physical switch fabric is
  reachable from the build host.
* The REAL local evidence covers one host and its adapters only.
* Capacity, congestion, traffic engineering, route programming, consensus and
  cross-domain identity resolution are out of scope and not implemented.
* The distributed protocol runs over loopback TCP with a single coordinator; there is
  no multi-coordinator replication and no consensus between coordinators.
* Authorization is bound to the evidence the evaluator can see; disagreement between
  an evaluator's evidence and the coordinator's authoritative evidence is surfaced as
  a rejected publication, not silently reconciled.
* No telemetry is transmitted. Path Authority emits no network traffic other than the
  explicit loopback protocol of the distributed mode.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
