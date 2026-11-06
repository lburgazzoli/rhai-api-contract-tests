# Onboarding a provider to the manifest compatibility check

See the [onboarding checklist](README.md) for the whole path. This guide is
the detail for the manifest check, which compares the Kubernetes objects a
pull request renders (raw YAML, a local Helm chart, or a local Kustomize
overlay) against immutable Git baselines of the same repository.

The check is static and offline. It gives pull requests an early,
reproducible signal about **declared in-place update compatibility** — fields
Kubernetes rejects or ignores on update, conditional update restrictions, and
manifest-level relationships. It does not replace upgrade tests, cluster
conformance, or live-state verification.

The complete check inventory — every rule ID, kind, field path, guard,
severity, and its exact upstream Kubernetes source commit — is the
[source-audited catalogue](../../modules/manifest-compat/policy.json). This
guide does not duplicate the field list; read the catalogue for what is
checked, and the
[research notes](../research/manifest-compatibility.md) for why each rule is
shaped the way it is.

## 1. What the check can and cannot prove

Only three evidence classes produce **error-severity findings** (blocking in
enforce mode):

1. **API rules** — the change is provably rejected or rendered ineffective by
   the audited upstream validation and strategy code (Kubernetes 1.35, 1.36,
   1.37; audited patches v1.35.10, v1.36.6, v1.37.2).
2. **Local graph rules** — both sides of a relationship are in the same
   rendered set, so the regression is proven from the manifests alone (for
   example, a Service selector that no longer matches any pod template it
   used to match).
3. **Declared contracts** — the provider explicitly declared a protected
   label or resource; the declaration itself is the contract.

Everything that cannot be proven from rendered YAML alone is a **warning**,
never a block: mutable selector retargeting, label drift, unprotected
removals, external references, and conditional update risks whose safety
depends on live state or feature gates (PVC resize in either direction, PV
`nodeAffinity`, suspended-Job template eligibility, and others from the
catalogue). Two examples of why: a PVC storage decrease is not universally
rejected (failed-expansion recovery can accept a bounded reduction above
live capacity), and ConfigMap/Secret data is immutable **only when the
baseline object itself set `immutable: true`** — a candidate cannot lift a
gate the baseline never set. Live state is unknowable offline, so such
changes warn and name the missing evidence instead of guessing.

Boundaries to keep in mind:

- **Source, not live state.** Findings describe what the manifests declare.
  Server-assigned values absent from YAML (allocations, status) are never
  treated as removals or evidence.
- **Supported versions.** Each scenario declares its target Kubernetes
  version. Minors outside 1.35–1.37 fail configuration validation. A patch
  release other than the audited patch of its minor is still checked but
  reported as extrapolated coverage (`patch-coverage-extrapolated`).
- **Partial graph coverage.** The selector graph covers same-namespace
  Service, PodDisruptionBudget, and NetworkPolicy top-level pod selectors
  only. NetworkPolicy peers, cross-namespace selectors, affinity/topology
  spreads, and third-party selector consumers (ServiceMonitor and friends)
  are follow-on work; the report says so (`rule-coverage-partial`) instead of
  implying they were checked.
- **Custom resources are out of scope here.** Objects the renderer emits for
  kinds that are not built-in Kubernetes APIs are skipped and recorded in the
  scenario's `skipped` list — never silently passed. CRD compatibility is the
  [CRD check's](crd-compat.md) job.
- **No cluster, no admission.** Distribution-specific admission and webhook
  behavior cannot be reproduced offline; a passing check is not a cluster
  upgrade certificate.

Coverage and discovery claims elsewhere in this repository still mean
OpenAPI documents and CRDs. The manifest check protects exactly the scenarios
a repository declares; nothing discovers charts or overlays for you yet.

## 2. Write a `ManifestSet` descriptor

The descriptor is `.rhoai/manifests.yaml` by default
([schema](../../schemas/manifest-set.schema.json)). It names one or more
scenarios, each rendering one installation source at one target Kubernetes
version:

```yaml
apiVersion: contracts.rhoai.io/v1alpha1
kind: ManifestSet
metadata:
  name: rhods-operator
spec:
  tools:
    helmVersion: "4.3.1"        # the only supported pins; the runner
    kustomizeVersion: "5.8.3"   # rejects any other value
  scenarios:
    - id: operator-crdless      # raw YAML globs
      renderer: raw
      namespace: rhods-operator
      kubernetesVersion: 1.37.2
      sources:
        - manifests/*.yaml

    - id: helm-main             # a local chart, rendered like CI would
      renderer: helm
      namespace: rhods-operator
      kubernetesVersion: 1.36.6
      path: deploy/chart        # chart directory containing Chart.yaml
      releaseName: rhods
      valuesFiles:              # repo-relative, applied in order
        - deploy/chart/values.yaml
        - deploy/values-production.yaml
      setValues:                # string overrides, applied last
        image.tag: "2.19"
      releaseMode: upgrade      # upgrade (default) or install

    - id: kustomize-prod        # a local overlay
      renderer: kustomize
      namespace: rhods-operator
      kubernetesVersion: 1.35.10
      path: overlays/production # directory containing kustomization.yaml
```

Rules that matter:

- `namespace` is the explicit scenario namespace, applied to namespaced
  objects that do not carry their own `metadata.namespace`; it is used
  identically on the candidate and every baseline.
- Renderer settings (`releaseName`, `setValues`, `apiVersions`,
  `releaseMode`, `namespace`) are identical on both sides of every
  comparison. Chart sources, defaults, and values-file **contents** come from
  their respective revisions, so a values change shows up as a rendered
  object change — which is the point.
- Helm charts may depend only on vendored subcharts under `charts/`;
  Kustomize and Helm may reference only local paths inside the repository.
  Remote references fail closed.
- Helm templates (including vendored subcharts) may not use the `lookup` or
  `tpl` functions: they would make rendering depend on a cluster. Any use is
  a render error, not a warning.
- If your rendered set contains kinds whose scope (namespaced vs cluster) is
  not in the built-in table or your CRDs, declare `kindScopes` entries.

## 3. Prepare the pinned renderer tools (network, once)

Rendering uses pinned `go run` commands —
`helm.sh/helm/v4/cmd/helm@v4.3.1` and
`sigs.k8s.io/kustomize/kustomize/v5@v5.8.3`, the only supported pins — and
never installed Helm or Kustomize binaries. `manifest-prepare` is the only
network-enabled step: it
downloads the exact modules through Go's normal checksum verification into a
cache you choose, primes them, and re-runs each pinned `version` command
offline to prove the cache is render-ready.

```bash
# Needs Go >= 1.27 on PATH (the pinned Kustomize requires it) and network.
# The cache must live OUTSIDE any repository checkout.
python3 /path/to/api-contract-tests/cmd/contract-tests/cli.py manifest-prepare \
  --repo /path/to/your/repo \
  --manifest-set .rhoai/manifests.yaml \
  --tool-cache-dir /tmp/manifest-tools
```

The command prints provenance (module pins, observed versions, checksum
verification) and writes `prepared.json` into the cache. Re-running it
against an existing cache is safe and offline-capable.

## 4. Run the check locally (offline)

```bash
baseline_sha=$(git rev-parse <some-trusted-full-sha>)
python3 /path/to/api-contract-tests/cmd/contract-tests/cli.py manifest-check \
  --repo /path/to/your/repo \
  --manifest-set .rhoai/manifests.yaml \
  --baseline-ref "$baseline_sha" \
  --output-dir /tmp/manifest-report \
  --tool-cache-dir /tmp/manifest-tools
```

Notes:

- `--baseline-ref` accepts **full Git SHAs only**, repeat the flag for
  several baselines (each is resolved and compared independently). Mutable
  refs (`main`, tags, branches, `HEAD`) are rejected.
- `--output-dir` must not exist yet; the check never overwrites a previous
  report.
- The candidate is the **working tree** (uncommitted changes included), so
  you can run it while iterating; the report records the checked-out HEAD
  for provenance.
- `--tool-cache-dir` is required only when the selected scenarios render
  (raw-only selections need no Go at all). Pass `--scenario-id` to check one
  scenario.
- A missing, empty, or wrong-version cache fails closed with instructions to
  run `manifest-prepare`; it never silently falls back to the network or an
  installed binary. The check itself never downloads anything.

Exit codes and `report.json.status`:

| Exit | Status | Meaning |
| --- | --- | --- |
| 0 | `compatible` | Compared, no unsuppressed error findings (warnings may exist) |
| 0 | `new` | No scenario compared at any baseline (all declared new) |
| 0 | `breaking` | Error findings exist, but the run is report-only |
| 1 | `breaking` | Error findings exist and `--enforce` was passed |
| 2 | `error` | Infrastructure or integrity failure: unresolvable baseline, render failure, unusable cache, malformed descriptor |

Read `report.json`, not only the exit code. Per baseline you get a status of
`new`, `compared`, `error`, or `not-run` (blocked by an earlier failure), a
`compatible` value of `true`, `false`, or `null` — null when the baseline is
new, errored, or not run, never fabricated — plus per-scenario render
digests, object counts, inventories, skipped objects, findings, and errors.
Suppressed findings (see [exceptions](#6-protected-contracts-and-exceptions))
stay visible with their reasons; a failed baseline keeps the evidence its
successful scenarios already produced.

## 5. Baselines: compared, moved, and new

A baseline defines what is released. Whatever renders there must stay
compatible; whatever does not exist there yet is new.

**Absent inputs are never silently treated as new.** If a scenario's inputs
(chart, overlay, or raw globs) do not exist at a baseline, the check fails
closed until you declare what happened:

```yaml
scenarios:
  - id: helm-main
    # ...
    baselineCases:
      # The chart was introduced after this baseline: verified absent.
      - ref: <full-sha-of-commit-before-the-chart-existed>
        state: new
        reason: "chart introduced in #812; verified absent at this baseline"
      # The chart used to live elsewhere: compare the historical path.
      - ref: <full-sha-of-a-moved-chart>
        state: existing
        inputs:
          path: deploy/old-chart-location
```

- `state: new` requires a `reason` and must not declare `inputs`. It is an
  attestation: a false one (the inputs are actually present) fails the run
  with "must be compared, not declared new". A partially present source set
  (chart present, selected values file absent) cannot be declared new
  either.
- `state: existing` overrides the historical input locations — `path`,
  `sources`, or `valuesFiles` per renderer — so a moved chart or renamed
  values file compares against where it lived then.
- Once a baseline contains the fixtures, ordinary comparisons happen with no
  declaration at all; leftover declarations for older refs are harmless
  unused provenance.

**Empty renders have asymmetric meaning.** A candidate that renders zero
objects is a valid, successful render: every baseline object was removed,
which warns for unprotected resources and is an error only for
[protected](#6-protected-contracts-and-exceptions) ones. A baseline that
renders zero objects from present inputs, however, is an error — a
historical render must produce something to compare against.

## 6. Protected contracts and exceptions

Two declarations turn warnings into owned contracts:

```yaml
scenarios:
  - id: operator-crdless
    # ...
    protectedResources:          # removal becomes an error
      - group: apps
        kind: Deployment
        namespace: rhods-operator
        name: dashboard
    protectedLabels:             # label drift on declared keys becomes an error
      - location: /spec/template/metadata/labels
        keys: [app, app.kubernetes.io/name]
```

Edge-specific findings can be waived with a reason, but only one finding
tuple at a time — copy the resource identity and, for relational rules, the
`relatedResource` and 64-character `edgeId` verbatim from the finding being
waived:

```yaml
    exceptions:
      - ruleId: required-reference-lost
        resource: {group: "", kind: Deployment, namespace: rhods-operator, name: web}
        path: /spec/template/spec/containers/0/env/0/valueFrom/configMapKeyRef
        baselineRef: <full-sha>
        relatedResource: {group: "", kind: ConfigMap, namespace: rhods-operator, name: shared}
        edgeId: <sha256-from-the-finding>
        reason: "ConfigMap deliberately replaced by a generated equivalent (#940)"
```

Rules of the waiver mechanism:

- Suppressed findings stay in the report with their reason; suppression is
  visible, never silent.
- An exception that matches nothing at the requested baselines warns
  (`stale-exception`) so dead waivers cannot accumulate unnoticed.
- Candidate-side validation findings (for example
  `selector-template-mismatch`) are non-waivable: a chart whose own selector
  does not match its pod template is broken everywhere, not waivable per
  baseline.

Generated-name rotation (a Kustomize `configMapGenerator` hash suffix, for
example) needs no exception: the old generated object's removal is an
ordinary `resource-removed` warning and the retargeted reference is followed
to the new name. No hash-suffix heuristics are used.

## 7. Add CI (report mode first)

Call the reusable workflow, pinned to a release that contains it. The
manifest workflow is new: use the **first release that ships
`provider-manifest-check.yml`** — a placeholder is shown here until that
release is cut:

```yaml
jobs:
  manifest-contract:
    uses: red-hat-data-services/api-contract-tests/.github/workflows/provider-manifest-check.yml@v1.1.0  # TODO: replace with the first release that contains the manifest workflow
    with:
      manifest-set: .rhoai/manifests.yaml
      baseline-refs: <full-trusted-sha>        # space-separated for several
      mode: report
```

The workflow prepares the pinned tools into a runner-temp cache (the only
network-enabled step), runs the check offline, and summarizes/uploads the
report on every outcome. To check scenarios separately, add a matrix:

```yaml
  manifest-contract:
    strategy:
      fail-fast: false
      matrix:
        scenario: [helm-main, kustomize-prod]
    uses: red-hat-data-services/api-contract-tests/.github/workflows/provider-manifest-check.yml@v1.1.0  # TODO: same pin as above
    with:
      scenario-id: ${{ matrix.scenario }}
      baseline-refs: <full-trusted-sha>
      mode: report
```

Use full SHAs of commits you trust as released — typically the merge commit
of your last release — the same discipline as the
[OpenAPI baselines](openapi-compat.md#baselines).

**Moving to enforce.** Stay in report mode until findings are reviewed and
consumers agree, then change `mode: report` to `mode: enforce`. Warnings
never block in either mode; only error-severity findings do, and only in
enforce mode. Making the job required is your repository's branch-protection
decision.

**Protect the configuration.** The descriptor, baseline commits, and
exceptions are what keep the check honest. Make them code-owned (a
`CODEOWNERS` entry for `.rhoai/`), and route changes to baselines,
protected contracts, and exceptions through review by someone other than the
author — ideally including the contract working group. An exception or a
`state: new` declaration is an accepted break in writing; treat editing one
like editing the policy.

## 8. Rendering limits and failure behavior

- **Offline by construction.** During `manifest-check`, every renderer
  subprocess runs with the module proxy pointed at the prepared cache itself
  and the checksum database disabled; no network path exists. Reports and
  artifacts contain no raw rendered manifests, values, or Secret values —
  only file inventories, digests, and sanitized diagnostics.
- **Determinism is enforced.** Every render runs twice and the outputs must
  be byte-identical; non-deterministic templates fail the run.
- **Helm hooks and CRDs are skipped and recorded.** Hook-annotated objects
  and CustomResourceDefinitions emitted by `--include-crds` are excluded
  from comparison and listed in the scenario's `skipped` counts — CRDs
  belong to the [CRD check](crd-compat.md).
- **Cache failures are loud.** An unusable cache location, a toolchain older
  than the pins require (Go >= 1.26 for Helm, >= 1.27 for Kustomize), or a
  cache missing a pinned module fails with instructions, never with a
  silent pass or fallback.
- **Report state is truthful.** Unresolvable baselines are per-baseline
  `error` with a null SHA while other baselines still compare; scenarios
  blocked by an earlier failure are `not-run`; compatibility is null, never
  guessed, in exactly those cases.
