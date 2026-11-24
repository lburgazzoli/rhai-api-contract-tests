# Onboarding a provider to the openapi-compat check

Start with the [onboarding checklist](README.md) for the whole path (inventory,
descriptor, local run, coverage, CI, code owners). This guide is the detail for
the OpenAPI check itself.

This generalizes the Model Catalog pilot's original checker into a reusable
module so a second provider never needs to copy or reimplement its logic. The
initial implementation came from the
[Model Catalog pilot](https://github.com/etirelli/rhoai-api-contract-wg/commit/293feebf1e780d7ce7b34b1669f5c937fa7b6338);
this document is the generic path for the next provider.

## 1. Confirm a generator adapter covers your bundling/generation step

Candidate generation is the one part of this check that is inherently
provider-specific — every repo builds its OpenAPI document differently.
Check [`modules/openapi-compat/adapters.py`](../../modules/openapi-compat/adapters.py)
for the currently registered adapters:

- **`openapi.bundle.yq-merge`** — your repo already has a shell script that
  merges source YAML files into a bundled document using `yq` (the pattern
  Model Catalog uses with `scripts/merge_catalog_specs.sh`).
- **`openapi.static`** — your OpenAPI document is hand-maintained,
  contract-first, with no generation step.

If neither fits, a new adapter must be added to `adapters.py` and reviewed
centrally — once added, every future repo with the same build pattern reuses
it for free. Do not copy checker logic into your own repository to work
around a missing adapter.

## 2. Write a `ContractSet` descriptor

Create `.rhoai/contracts.yaml` in your repository, validated against
[`schemas/contract-set.schema.json`](../../schemas/contract-set.schema.json).
Both `check` and `coverage` reject a descriptor whose blocks have the wrong type before
doing anything else (exit 2). Writing an optional block such as `candidate:` or
`baseline:` with no value counts as the wrong type: omit the key instead. Minimal shape:

```yaml
apiVersion: contracts.rhoai.io/v1alpha1
kind: ContractSet
metadata:
  name: your-service
spec:
  contracts:
    - id: your-service-v1
      type: openapi
      declaredArtifact: api/openapi/your-service.yaml
      matchPath: "^/api/your-service/v1(/|$)"
      policy:
        oasdiffVersion: "1.33.0"
        yqVersion: "4.45.1"
        flattenAllOf: true
        severityOverrides:
          response-optional-property-removed: warn
      generator:
        adapter: openapi.bundle.yq-merge
        script: scripts/your-bundler.sh
        yqEnvVar: YQ
        sourceDir: api/openapi/src
        sourceGlobs: ["your-service.yaml", "plugins/*.yaml"]
        entrypointArg: your-service.yaml
        output: api/openapi/your-service.yaml
```

Only paths matching `matchPath` are compared; this is how you scope a check
to one bounded interface within a larger bundled document instead of
accidentally gating on every endpoint in the repo. `matchPath` is matched against
the full URL path: the document's base path plus the path (see
[Base paths](#base-paths)). A repository with no
descriptor, or a document with no `contracts:` entry naming it, is never
checked.

`severityOverrides` lets you promote an oasdiff finding (see
`oasdiff checks changelog` for the full rule catalog) above its default
severity — for example, if consumers rely on an *optional* response field,
its removal defaults to `info` in oasdiff but can be promoted to `warn` so
it surfaces as a finding.

### Several contracts in one repository

A descriptor can register more than one contract, for example one per API
version. Give each a stable `id` and its own `matchPath`; the runner and the
reusable workflow check one contract at a time (`--contract-id`), so call the
workflow once per contract (see [step 5](#5-add-ci)).

### Base paths

A document serves its `paths` below a base path: the path part of the top-level `servers`
URLs in OpenAPI 3, or `basePath` in Swagger 2.0. The runner folds that base path into the
paths before comparing, so `servers: [{url: https://api.example.com/api/v1}]` and the path
`/widgets` are `/api/v1/widgets` for `matchPath` and in the findings. This has two effects:

- **A changed base path is caught.** oasdiff ignores `servers`, so without this a change that
  moves every URL would go unnoticed; now it appears as removed paths.
- **A contract can change dialect.** A Swagger 2.0 document and the equivalent OpenAPI 3
  document have the same paths, whether the base path is in `servers` or already in the
  paths.

Server variables are replaced by their defaults. A server URL with only a host, or no
`servers` at all, has no base path, and the paths are compared as written. If the servers
have different paths (for example `/api/v1` and `/v1`), there is no single base path and
the check fails with an error naming them: make the servers agree, or move the difference
into the paths. Path- and operation-level `servers` are not considered. The report records
the folded base path in a `canonicalized` block (`base_path_prepended`) for each OpenAPI 3
document that has one.

### Swagger 2.0 documents

A contract can be a Swagger 2.0 document. Declare it like any other contract (`openapi.static`
for a committed document, or a bundle adapter). oasdiff reads OpenAPI 3 only, so the runner
converts a Swagger 2.0 baseline and candidate to OpenAPI 3 before comparing them. An OpenAPI 3
document is never converted, and a contract can move from Swagger 2.0 to OpenAPI 3 between
the baseline and the candidate.

- **Build the converter.** It is a small Go program, `cmd/swagger2openapi`, built on the same
  library family as oasdiff (`kin-openapi`), with the dependency pinned in `go.sum`:
  `go build -C <path-to-api-contract-tests>/cmd/swagger2openapi -o bin/swagger2openapi .`
  Pass it with `--swagger2openapi` or `SWAGGER2OPENAPI`. It is needed only when a Swagger 2.0
  document is compared, and the reusable workflow builds it for you.
- **`matchPath` matches `basePath` plus the path.** `basePath: /api/v1` and the path `/widgets`
  are `/api/v1/widgets`, the same as an OpenAPI 3 document with the base path in `servers`
  (see [Base paths](#base-paths)).
- **`host` and `schemes` are not compared**, like `servers` in an OpenAPI 3 document.
- **Documents that are not contracts.** A Swagger 2.0 file with no `paths` (for example the
  definitions generated for an SDK) is not an API contract: list it in `spec.exclusions`
  with a reason. A document that refers to a definition it does not contain cannot be
  converted, and the check fails naming the missing definition.
- **The report** records `dialect` and a `converted` block (including `base_path_prepended`)
  for each converted document, and the converter version under `tool_build`.

### Documents that are not contracts

Every OpenAPI document in the repository must be accounted for. If one is
deliberately outside the contract set (an internal UI API, a test fixture),
list it with a reason instead of leaving it unmentioned:

```yaml
spec:
  exclusions:
    - path: clients/ui/bff/openapi/*
      reason: Internal UI back-end-for-front-end API, not a provider contract
  contracts:
    - ...
```

`path` is a repo-relative path or glob (`*` also matches `/`). An exclusion
without a `reason` is rejected. The [coverage check](#confirm-nothing-is-left-out)
reads this list.

When every OpenAPI document in the repository is an exclusion, write
`contracts: []` (the key is still required; an omitted or blank `contracts` is
rejected): the descriptor then carries only the exclusions
(the CRD globs are still the coverage workflow's `crd-globs` input, or
`--crd-glob` locally), and coverage still fails on any document that no
exclusion matches. With no contracts, no `yqVersion` is pinned in the
descriptor; the reusable workflow passes its `yq-version` input to coverage, and
locally you must pass `--yq-version`, or coverage fails rather than run an
unverified `yq`. This is the shape for a repository whose only spec is, for
example, a `swagger.json` of definitions generated from its CRDs for an SDK —
no servable API, so no checkable contract, but the CRD checks still apply.

## 3. Install the pinned tools

```sh
GOBIN="$PWD/bin" go install github.com/oasdiff/oasdiff@<version pinned in your descriptor>
GOBIN="$PWD/bin" go install github.com/mikefarah/yq/v4@<version pinned in your descriptor>
```

If a contract is a Swagger 2.0 document, also build the converter (see
[Swagger 2.0 documents](#swagger-20-documents)).

For schema patterns using ECMAScript features that Go cannot compile, such as
lookahead or backreferences, also build the fallback validator:

```bash
go build -C <path-to-api-contract-tests>/cmd/openapi-validate -o "$PWD/bin/openapi-validate" .
```

The runner discovers it in the provider's `bin/`, or accepts `--openapi-validate`
or `OPENAPI_VALIDATE`. The reusable workflow builds it automatically. The helper
revalidates the original document; patterns remain part of the compatibility
comparison. See [ECMAScript pattern validation](../../cmd/openapi-validate/README.md).

`checker.py` rejects any other `oasdiff` or `yq` version. For `go install`
builds that print `main`, it checks the binary's embedded Go module version.

## 4. Run it locally

```bash
# Preferred: the commit the RHOAI 3.6 release was based on
baseline_sha=$(python3 <path-to-red-hat-data-services/api-contract-tests>/cmd/release-baseline/release_baseline.py \
  lookup --release 3.6 --repo <org>/<repo> --format sha)
# Fallback when the tool reports no baseline: the SHA main resolves to today
# baseline_sha=$(git rev-parse refs/remotes/<trusted-remote>/main)
python3 <path-to-red-hat-data-services/api-contract-tests>/cmd/contract-tests/cli.py check \
  --repo . \
  --contract-set .rhoai/contracts.yaml \
  --baseline-ref "$baseline_sha" \
  --output-dir /tmp/contract-report
```

Repeat `--baseline-ref` for every applicable supported-release baseline;
every supplied baseline is compared independently. Never pass `main`,
`HEAD`, or an unresolved ref — only full, resolved Git SHAs. The run is in enforce
mode by default, so a breaking finding fails it; that is what the workflows'
`mode: enforce` does.

Read `report.json.status`, not just the exit code: with `--report-only` (report mode,
not recommended) the exit code is `0` even when breaking findings are recorded.

### Baselines

Choose the repository default as described in
[Choosing a baseline](README.md#choosing-a-baseline): the commit the RHOAI 3.6
release was based on, or the SHA that `main` resolves to today when there is none.
The choice decides what the check protects, so read why it matters there first.

`--baseline-ref` (or the workflow's `baseline-refs`) is the repository default.
A contract can override it with its own `baseline` block (`refs`, a mandatory
`reason`, and optionally `artifact` when the file was later moved), and the
descriptor can carry the default as `spec.baseline.refs` instead. Precedence is
the contract's `baseline`, then `--baseline-ref`, then `spec.baseline.refs`.

- **New APIs are not failures.** If the declared artifact does not exist at a
  default baseline, the contract is reported with `status: new` for that baseline
  and nothing is compared. If every baseline predates the API, `report.json.status`
  is `new`, which is neither a pass on compatibility nor a failure. The candidate
  is still generated, checked for staleness and validated.
- **A contract's own baseline is a promise.** The artifact must exist there, or
  the check fails.
- **Moves are not silently "new".** If the artifact is absent but another OpenAPI
  document at that baseline already serves the contract's `matchPath` paths, the
  check fails and names it; set `baseline.artifact` to compare across the rename.
  A catch-all `matchPath` (omitted or `.*`) cannot tell one API from another, so it
  fails closed: if the artifact is absent and any other OpenAPI document exists at
  the baseline, the check errors instead of granting the "new" exemption. Set a
  specific `matchPath`, or `baseline.artifact` if the file was renamed.
- **Wrong versions still fail.** A baseline that has the file but no paths under
  `matchPath` is an error.

See the [checklist](README.md#choosing-a-baseline) for how to choose the baseline
and when to use an override.

### Confirm nothing is left out

```bash
python3 <path-to-red-hat-data-services/api-contract-tests>/cmd/contract-tests/cli.py coverage \
  --repo . --contract-set .rhoai/contracts.yaml \
  --yq-version 4.45.1   # required with `contracts: []`; otherwise must match policy.yqVersion
```

The check finds every OpenAPI document tracked in the repository (plus
untracked files that are not git-ignored, so it works before you commit a new
spec) and reports each as one of:

| Status | Meaning |
|---|---|
| `contract` | The document is a contract's `declaredArtifact` |
| `source` | The document is an input of a registered generator (`sourceGlobs` or `source`) |
| `excluded` | Listed in `spec.exclusions`, with the reason shown |
| `UNCOVERED` | None of the above; the check fails |

It also fails on dangling configuration (a `declaredArtifact` that is not an
OpenAPI document, a `sourceGlob` that matches nothing) and warns about stale
exclusions. For each contract it reports how many API paths fall outside
`matchPath`; that is intentional scoping and never a failure, but it makes the
scope visible to reviewers. Add `--format json` for machine-readable output,
`--report-only` to see gaps without failing, and `--crd-glob` (repeatable) to
require that every CRD manifest is matched by the glob your CRD check uses. Overlapping globs are fine; each pattern only has to match something.
`--json-output <file>` also writes the JSON report to a file whatever `--format`
prints; the reusable coverage workflow uses it to annotate each gap on the pull
request, as a warning in report mode and as an error in enforce mode.

## 5. Add CI

Call the reusable workflows from a provider workflow, for example
`.github/workflows/api-contract.yml`. Reference them by `@latest`, as in the
example below. A version tag, `@stable`, or a full commit SHA also work; never use
`main` or another branch. [Releases and pinning](../releasing.md) explains the
choices. Every job runs in `mode: enforce`, the default; keep it explicit as in the
example below.

```yaml
name: API contract

on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  api-contract:
    strategy:
      fail-fast: false
      matrix:
        contract-id: [your-service-v1, your-service-v1alpha3]
    uses: red-hat-data-services/api-contract-tests/.github/workflows/provider-openapi-check.yml@latest
    with:
      contract-set: .rhoai/contracts.yaml
      contract-id: ${{ matrix.contract-id }}
      baseline-refs: <full-git-sha>   # optional if the descriptor declares baselines
      oasdiff-version: "1.33.0"
      yq-version: "4.45.1"
      mode: enforce

  api-contract-coverage:
    uses: red-hat-data-services/api-contract-tests/.github/workflows/provider-coverage-check.yml@latest
    with:
      contract-set: .rhoai/contracts.yaml
      baseline-refs: <full-git-sha>   # optional: lets coverage flag per-contract baselines that loosen the default
      yq-version: "4.45.1"
      mode: enforce
```

Omit `contract-id` and the matrix when the descriptor registers exactly one
contract. Each contract uploads its own `contract-report-<id>` artifact.

Set `baseline-refs` in both jobs to the SHA chosen in
[Choosing a baseline](README.md#choosing-a-baseline), and note where it came from
(the tag or branch name, or "`main` on <date>") in a comment.

The workflows reject a branch or unknown tag as their own reusable-workflow ref, install exact tool
versions, and reject mutable baseline refs. A change to `baseline-refs`, to the
pinned workflow ref, or to the descriptor changes what the check protects, so
require an owner's review for those files (see the
[checklist](README.md#provider-checklist), step 7).

## 6. Register the contract with the working group

Once proven locally, register the descriptor's location (repo, path,
revision) as a pointer so baselines, consumer profiles, and support level
can be tracked centrally. A descriptor existing in a repository does not
itself make that repository part of the gated cohort; registration is a
separate, reviewed step.
