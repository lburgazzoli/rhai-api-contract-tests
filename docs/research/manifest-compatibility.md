# Kubernetes manifest compatibility research

## Goal

Define a repeatable, provider-owned manifest compatibility check that compares
rendered Kubernetes objects (raw YAML, Helm, or Kustomize) against immutable
Git baselines identified by full commit SHAs, catches breaking in-place update
changes before release, and runs offline in provider CI using the same
operational conventions as the CRD check.

## Scope

### In scope

- Rendered built-in Kubernetes API objects from explicitly registered
  scenarios: raw YAML globs, local Helm charts, and local Kustomize overlays.
- In-place update compatibility: immutable fields, conditional update
  restrictions, and transition rules, source-audited against Kubernetes
  1.35–1.37.
- Manifest-level relationships: workload selector/template consistency,
  selector-based discovery (Service, PodDisruptionBudget, NetworkPolicy),
  required local references, and explicitly protected labels and resources.
- Drift visibility: label changes and object removals that cannot be proven
  breaking but may break unknown external consumers.
- Rendering integrity: pinned offline `go run` Helm/Kustomize, deterministic
  output, snapshot provenance, and safe reporting without secret disclosure.

### Out of scope

- Cluster-backed validation, admission webhook execution, live-state
  snapshots, and full API-server conformance.
- Generic CEL evaluation and CR instance immutability for custom resources.
- Cross-repository consumer discovery; external label reliance is warned
  about, never certified.
- General manifest linting, security scanning, schema validation, and API
  deprecation detection (kubeconform and Pluto are complementary tools, not
  replacements for a baseline semantic comparison).
- Beta/alpha APIs beyond explicit inventory records, and Kubernetes minors
  outside the audited 1.35–1.37 range.

## Rule authority

Every immutable-field rule is grounded in upstream Kubernetes source at exact
pinned commits:

| Minor | Tag | Commit |
|---|---|---|
| 1.35 | v1.35.10 | `ae6fece6fea92ecfcccd13af7d5f2ea8cb9b33fe` |
| 1.36 | v1.36.6 | `1b2171b110bb2a2542e1322035c6583ec86eb976` |
| 1.37 | v1.37.2 | `c50e5395f1ae2d4a2c05f28fdcc38c0916cc1a32` |

The audit inspected validators **and** registry update strategies, defaulting,
and declarative annotations. Searching only for `ValidateImmutableField` is
insufficient: whole-spec restrictions (StatefulSet in 1.35/1.36, VolumeAttachment),
ignored updates (CertificateSigningRequest), conditional rules (Service
addressing), and baseline-gated rules (ConfigMap/Secret) live outside that
helper. The machine-readable registry with per-rule source references is
`modules/manifest-compat/policy.json`; it is the single source of truth for
rule IDs, strategies, defaults, guards, and waiver eligibility.

Each scenario declares its target Kubernetes version. A patch release other
than the audited patch of its minor is reported as extrapolated coverage; an
unsupported minor fails configuration validation.

## Check inventory

### Error-severity checks (blocking in enforce mode)

Only three evidence classes may block:

1. **API rules** (`evidence: api-rule`): the declared change is provably
   rejected or rendered ineffective by the audited upstream validation and
   strategy code.
2. **Local graph rules** (`evidence: local-graph`): both sides of the
   relationship are in the same rendered set, so the regression is proven
   from the manifests alone.
3. **Declared contracts** (`evidence: declared-contract`): the provider
   explicitly declared a protected label or resource; the declaration itself
   is the contract.

#### Immutable fields (full table)

| Kind | Immutable fields | Notable exceptions |
|---|---|---|
| Deployment / DaemonSet / ReplicaSet (`apps/v1`) | `spec.selector` | Pod-template labels, images, and scaling are normal rollout behavior |
| StatefulSet (`apps/v1`) | `spec.selector`, `spec.serviceName`, `spec.podManagementPolicy` (default `OrderedReady`), `spec.volumeClaimTemplates` | 1.35/1.36 freeze the whole spec outside a mutable allowlist (replicas, ordinals, template, updateStrategy, revisionHistoryLimit, persistentVolumeClaimRetentionPolicy, minReadySeconds); 1.37 checks the four fields directly |
| ControllerRevision (`apps/v1`) | `data` | `revision` is mutable despite its misleading comment |
| Job (`batch/v1`) | `spec.selector`, `spec.completionMode` (default `NonIndexed`), `spec.podFailurePolicy`, `spec.backoffLimitPerIndex`, `spec.managedBy`, `spec.successPolicy` | Non-indexed `completions` frozen; Indexed completions may change in tandem with equal `parallelism`. Template changes are errors except the suspended-Job exception family (see warnings) |
| Pod (`v1`, direct object) | Normal-update restriction: only images, decreased/set `activeDeadlineSeconds`, added tolerations (existing toleration `tolerationSeconds` edits allowed — the validator's old-entry matching ignores that field), and removed `schedulingGates` | Applied only to direct Pod objects, never to workload templates |
| ConfigMap / Secret (`v1`) | `data`/`binaryData` (and unsetting `immutable`) **only when the baseline object set `immutable: true`** | Changing data while first setting the flag is allowed; the gate is read from the baseline |
| Secret (`v1`) | `type` (default `Opaque`) | Unconditional, independent of the immutable flag |
| RoleBinding / ClusterRoleBinding | `roleRef` | subjects mutable |
| StorageClass | `provisioner`, `parameters`, `reclaimPolicy` (default `Delete`), `volumeBindingMode` (default `Immediate`) | Other storage settings not frozen |
| CSIDriver | `spec.attachRequired` (default `true`), `spec.volumeLifecycleModes` (default `[Persistent]`) | `podInfoOnMount` mutable since 1.29 |
| VolumeAttributesClass | `driverName`, `parameters` | |
| VolumeAttachment | entire `spec` | kubelet/attacher-managed |
| CSIStorageCapacity | `nodeTopology`, `storageClassName` | capacity is controller-managed |
| CSINode | existing `spec.drivers` entries matched by name | allocatable gate-dependent (warning); add/remove not forbidden |
| RuntimeClass | `handler` | |
| PriorityClass | `value`, `preemptionPolicy` (default `PreemptLowerPriority`) | description/globalDefault mutable |
| IngressClass | `spec.controller` | parameters not frozen |
| EndpointSlice | `addressType` | endpoints/ports not intrinsically immutable |
| ResourceQuota | `spec.scopes` (set comparison) | resource limits not frozen |
| ResourceClaim / ResourceClaimTemplate (`resource.k8s.io/v1`) | entire `spec` | |
| ResourceSlice | `spec.driver`, `spec.pool.name`, `spec.nodeName` | other fields not blanket-frozen |
| CertificateSigningRequest | authored `spec` | the update is **ignored** (strategy restores the old spec), not rejected; reported as an ineffective update |
| ClusterTrustBundle (`certificates.k8s.io/v1`, 1.37) | `spec.signerName` | 1.35/1.36 serve only beta forms (inventory) |
| PodCertificateRequest (`certificates.k8s.io/v1`, 1.37) | entire `spec` | earlier beta form inventory-only |
| StorageVersionMigration (`storagemigration.k8s.io/v1`, 1.37) | entire `spec` | earlier beta form inventory-only |
| PersistentVolume | `spec.persistentVolumeSource` union, `spec.volumeMode` (default `Filesystem`) | One-time `csi.controllerExpandSecretRef` initialization allowed; `persistentVolumeReclaimPolicy` is **mutable** |
| PersistentVolumeClaim | `spec.accessModes`, `spec.selector`, `spec.dataSource`, `spec.dataSourceRef`, `spec.volumeMode` | One-time `volumeName` initialization; exact `storageClassName` beta-annotation and nil migrations allowed |
| Service | Primary `clusterIPs[0]` once set; primary IP family; `loadBalancerClass` while both types are LoadBalancer; `healthCheckNodePort` while both need Local LB health checks | ExternalName and headless transitions exempt; validated secondary-family add/remove; `type`, `selector`, `nodePort` mutable |
| IPAddress (`networking.k8s.io/v1`) | `spec.parentRef` | |
| ServiceCIDR (`networking.k8s.io/v1`) | existing `spec.cidrs` values | validated single-to-dual-stack append allowed |

#### Relationship and contract checks

- **selector-template-mismatch** (non-waivable render validation): a workload
  whose selector does not match its own pod template under Kubernetes
  matchLabels/matchExpressions semantics.
- **selector-target-lost**: an unchanged Service/PDB/NetworkPolicy selector
  that matched a baseline target template and no longer matches its candidate
  template. Value edits, label removal, added labels affecting negative
  expressions, and target disappearance all count. Reports a lost declared
  selection relationship, not an outage.
- **required-reference-lost**: a required reference whose baseline target,
  key, or port resolved locally and no longer does, per the reference
  transition table (ended reliance, retargeting, and optionality transitions
  are never false losses). In candidate validation context the same finding is
  non-waivable.
- **protected-label-changed / protected-resource-removed**: violations of
  explicitly declared protected contracts.

### Warning-severity checks (never blocking, always visible)

- **mutable-selector-changed**: a changed consumer selector silently
  re-targets traffic or policy; external consumers cannot be certified.
- **external-reference-unverified**: new or already-external unresolved
  references may be supplied by another bundle.
- **label-removed / label-value-changed**: unproven external label reliance.
- **resource-removed**: unprotected removal; generated-name rotation with
  retargeted references is not a loss, and no hash-suffix heuristics are used.
- **conditional-update-risk**: changes whose safety depends on live state or
  feature gates — PVC storage resize in either direction (failed-expansion
  recovery, `allowVolumeExpansion`), PV/PVC `volumeAttributesClassName`,
  PV `nodeAffinity`, CSINode `allocatable`, suspended-Job template
  eligibility, one-sided Job selectors, unresolved default equivalence.
- **rule-coverage-partial / patch-coverage-extrapolated / stale-exception**:
  coverage boundaries and configuration diagnostics.

### Key source-audited corrections

These facts contradict common intuition and are deliberately encoded:

- ConfigMap/Secret data immutability is gated by the **baseline's**
  `immutable: true`; a candidate cannot lift a gate the baseline never set.
- PVC size **decrease** is not universally rejected: with failed-expansion
  recovery (feature gate or prior expansion bookkeeping) a bounded reduction
  above live capacity is accepted. Live capacity is unknowable offline, so
  both resize directions warn.
- Job template updates have a real exception family for suspended,
  never-started jobs — but eligibility needs live status; missing YAML status
  is never evidence, so unresolved cases warn.
- A Service `selector` is fully mutable; its addressing fields are the
  immutable ones, and only under specific transitions.
- PV `persistentVolumeReclaimPolicy` is genuinely mutable — no rule exists
  for it.
- Direct-Pod toleration updates allow editing an existing toleration's
  `tolerationSeconds`; the validator ignores that field when matching old
  entries (verified at `validateOnlyAddedTolerations` in all three audited
  versions).
- CSR spec updates are silently ignored by the registry strategy
  (`PrepareForUpdate` restores the old spec), not rejected — findings must
  describe an ineffective update, never an API rejection.

## Rendering and graph limitations

- Rendering is offline and pinned: `go run helm.sh/helm/v4/cmd/helm@v4.3.1`
  and `go run sigs.k8s.io/kustomize/kustomize/v5@v5.8.3` only, with a
  separately prepared module cache and no network during checks. Helm's
  supported template subset rejects any `lookup` or `tpl` function use in
  chart or vendored-subchart templates, because dynamically assembled lookup
  execution cannot be excluded by determinism checks alone.
- Scenario settings (release name, namespace, kube-version, api-versions,
  set values) are identical on both sides; values-file contents, chart
  sources, and defaults come from their respective revisions.
- Findings describe **declared** in-place update compatibility and manifest
  relationships. They are not a guarantee about running endpoints, live
  admission results on distribution-specific clusters, or controller
  behavior. Server-assigned values absent from YAML (allocations, status) are
  never treated as removals or evidence.
- The selector graph covers same-namespace Service, PodDisruptionBudget, and
  NetworkPolicy top-level podSelector consumers only. NetworkPolicy peers,
  cross-namespace selectors, affinity/topology spreads, and third-party
  selectors (for example ServiceMonitor) are explicit follow-ons reported as
  partial coverage.
- Custom resources and CRD instance immutability are delegated to the CRD
  compatibility check; skipped objects are recorded, never silently passed.

## Phased roadmap

Follow-on work, explicitly out of the first delivery:

1. Custom-resource immutability via CRD `x-kubernetes-validations`
   `oldSelf` rules (CEL), and CRD-driven structural knowledge.
2. Beta/alpha API support beyond inventory records (audited per version).
3. Cross-repository consumer reliance profiles (label contracts consumed by
   other repositories).
4. Extended graph: NetworkPolicy peers, namespaceSelectors, affinity and
   topology selectors, third-party selector consumers.
5. API-version migration and deprecation detection (Pluto-style), integrated
   with the audited per-version served-API tables.
6. Optional server-side validation tier (`--dry-run=server` or envtest) for
   rules that currently warn on live-state dependencies.
7. Repository-wide scenario discovery and coverage enforcement for chart and
   overlay inventories.
