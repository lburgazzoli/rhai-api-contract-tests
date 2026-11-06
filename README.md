# api-contract-tests

Shared CI contract tests for RHOAI and ODH provider repositories, hosted at
[`red-hat-data-services/api-contract-tests`](https://github.com/red-hat-data-services/api-contract-tests).

`api-contract-tests` is the canonical home for the reusable compatibility runner,
descriptor schemas, provider workflows, and onboarding guides. Provider
repositories keep their canonical OpenAPI documents, CRDs, and behavior tests;
consumer repositories keep their reliance profiles and consumer-side tests. This
repository supplies the shared checks and result format.

## Current status

- The OpenAPI compatibility module is implemented and tested.
- The initial static CRD compatibility module is implemented and tested.
- The static Kubernetes manifest compatibility module is implemented and
  tested: rendered raw/Helm/Kustomize scenarios compared against full-SHA Git
  baselines with source-audited immutability rules. See the
  [manifest onboarding guide](docs/onboarding/manifest-compat.md).
- The coverage check (`coverage`) confirms every OpenAPI document and CRD in a
  repository is registered; `discover` inventories a repository for onboarding.
- The local runner is `cmd/contract-tests/cli.py`.
- Provider onboarding is opt-in and starts in report mode; see
  [`docs/onboarding`](docs/onboarding/README.md). Providers pin the reusable
  workflows to a release tag (`@v0.1.0`), `@stable`, `@latest` or a full commit
  SHA; see [releases and pinning](docs/releasing.md). Check each provider
  repository's workflow for whether it has been wired in yet.
- Consumer onboarding is repository-local today: the consumer owns the reliance
  profile and tests. See the [consumer guide](docs/onboarding/consumer-compat.md).
- CRD conversion, stored-object migration, and shared consumer-reliance
  verification are follow-on work.

## Quick start

From a provider repository with a `.rhoai/contracts.yaml` descriptor:

```bash
python3 /path/to/api-contract-tests/cmd/contract-tests/cli.py check \
  --repo . \
  --contract-set .rhoai/contracts.yaml \
  --baseline-ref <full-git-sha> \
  --output-dir /tmp/contract-report
```

Read `report.json.status`, not only the process exit code. Report-only mode
records breaking findings without failing the build; infrastructure and
integrity errors still fail closed.

Every check pins `oasdiff` and `yq` in the provider descriptor and resolves
each baseline to a full Git SHA. Mutable refs such as `main`, `HEAD`, tags,
and branches are rejected.

Before relying on the check, confirm every OpenAPI document in the repository
is registered (or excluded with a reason):

```bash
python3 /path/to/api-contract-tests/cmd/contract-tests/cli.py coverage --repo .
```

New to the repository? `discover --repo .` inventories its OpenAPI documents
and CRDs and suggests a contract for each.

For a provider with committed CRD manifests:

```bash
python3 /path/to/api-contract-tests/cmd/contract-tests/cli.py crd-check \
  --repo . \
  --crd-glob 'config/crd/**/*.yaml' \
  --baseline-ref <full-git-sha> \
  --output-dir /tmp/crd-contract-report
```

See [CRD onboarding](docs/onboarding/crd-compat.md) for the initial static
policy and the remaining cluster-backed follow-on work.

For a provider that installs through raw manifests, Helm, or Kustomize:

```bash
# Once, with network: fetch the pinned renderer tools into a cache outside
# any checkout (needs Go >= 1.27 on PATH).
python3 /path/to/api-contract-tests/cmd/contract-tests/cli.py manifest-prepare \
  --repo . --manifest-set .rhoai/manifests.yaml --tool-cache-dir /tmp/manifest-tools

# Offline, on every change:
python3 /path/to/api-contract-tests/cmd/contract-tests/cli.py manifest-check \
  --repo . \
  --manifest-set .rhoai/manifests.yaml \
  --baseline-ref <full-git-sha> \
  --output-dir /tmp/manifest-report \
  --tool-cache-dir /tmp/manifest-tools
```

See the [manifest onboarding guide](docs/onboarding/manifest-compat.md) for
scenario descriptors, baseline declarations, and report semantics.

For the consumer side, start with the
[consumer onboarding guide](docs/onboarding/consumer-compat.md).

## Repository layout

```text
.
├── cmd/contract-tests/       # Local runner
├── modules/openapi-compat/   # OpenAPI compatibility engine
├── modules/crd-compat/       # Static CRD compatibility engine
├── modules/manifest-compat/  # Kubernetes manifest compatibility engine
├── modules/coverage/         # Coverage check and repository discovery
├── schemas/                  # ContractSet and ManifestSet descriptor schemas
├── .claude/skills/           # Assistant skills for provider and consumer onboarding
├── docs/
│   ├── architecture.md       # Ownership and enforcement model
│   ├── onboarding/           # Provider and consumer onboarding checklists and guides
│   ├── releasing.md          # Pinning options and the release process
│   └── research/             # CRD and follow-on research
└── .github/workflows/        # CI and provider workflows
```

## Ownership model

- Provider repositories own canonical contracts and provider behavior tests.
- Consumer repositories own their reliance profiles.
- This repository owns shared checks, schemas, workflows, policy, and the pointer registry.

## Development

```bash
python3 -m pip install -r requirements-dev.txt
OASDIFF=/path/to/oasdiff YQ=/path/to/yq python3 -m pytest modules/openapi-compat/tests modules/crd-compat/tests modules/coverage/tests cmd/action-pins/tests cmd/workflow-steps/tests modules/manifest-compat/tests -v
```

The manifest module's real-renderer integration tests are excluded from that
invocation (they need a prepared Go tool cache); the repository-root
`pytest.ini` registers the `manifest_renderers` marker and excludes it by
default. Run them explicitly after preparing the cache, as described in the
[module README](modules/manifest-compat/README.md#tests).

CI also lints the workflows with [actionlint](https://github.com/rhysd/actionlint)
v1.7.12 (settings in `.github/actionlint.yaml`) and checks that every action's
pinned SHA is the commit its `# vX.Y.Z` comment names:

```bash
GOBIN="$PWD/bin" go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
bin/actionlint
python3 cmd/action-pins/check_action_pins.py
```

The runner and modules are type-checked with mypy (settings in `mypy.ini`). Each
module directory has its own `checker.py`, so check one file at a time:

```bash
for file in cmd/contract-tests/cli.py modules/*/*.py; do python3 -m mypy "$file"; done
```

The provider workflows keep their logic in `cmd/workflow-steps/steps.py`
(tested by `cmd/workflow-steps/tests`); the YAML only wires steps together. The
`Workflow self-test` workflow (`.github/workflows/self-test.yml`) runs every
provider workflow end to end on every pull request, against the fixture
provider in [`selftest/`](selftest/README.md).

The test suite requires `oasdiff` v1.33.0 and `yq` v4.45.1:

```bash
GOBIN="$PWD/bin" go install github.com/oasdiff/oasdiff@v1.33.0
GOBIN="$PWD/bin" go install github.com/mikefarah/yq/v4@v4.45.1
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
