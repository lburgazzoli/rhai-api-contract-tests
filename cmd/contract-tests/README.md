# contract-tests local runner

A thin CLI over the [`openapi-compat`](../../modules/openapi-compat/),
[`crd-compat`](../../modules/crd-compat/),
[`manifest-compat`](../../modules/manifest-compat/), and
[`coverage`](../../modules/coverage/) modules.

```bash
python3 cmd/contract-tests/cli.py check \
  --repo /path/to/provider/checkout \
  --contract-set .rhoai/contracts.yaml \
  --baseline-ref <full-git-sha> \
  --output-dir /tmp/contract-report \
  [--contract-id <id>] [--enforce] [--oasdiff <path>] [--yq <path>]
```

`--baseline-ref` is the repository default and is optional when the descriptor
declares `spec.baseline.refs` or the contract its own `baseline`. An API absent
at a default baseline is reported as `new`, not a failure; see
[`docs/onboarding`](../../docs/onboarding/README.md#choosing-a-baseline).

The same command runs locally and in CI — there is no separate "CI mode" —
so a result is always reproducible without a cluster. See
[`docs/onboarding/openapi-compat.md`](../../docs/onboarding/openapi-compat.md).

CRD checks use:

```bash
python3 cmd/contract-tests/cli.py crd-check \
  --repo /path/to/provider/checkout \
  --crd-glob 'config/crd/**/*.yaml' \
  --baseline-ref <full-git-sha> \
  --output-dir /tmp/crd-contract-report \
  [--enforce]
```

See [`docs/onboarding/crd-compat.md`](../../docs/onboarding/crd-compat.md).
Coverage and discovery:

```bash
# Fail if an OpenAPI document (or, with --crd-glob, a CRD) is not registered.
python3 cmd/contract-tests/cli.py coverage \
  --repo /path/to/provider/checkout \
  [--contract-set .rhoai/contracts.yaml] [--crd-glob 'config/crd/**/*.yaml'] \
  [--baseline-ref <full-sha>] \
  [--format text|json] [--report-only] [--yq <path>]

# Inventory a repository and suggest contract shapes; needs no descriptor.
python3 cmd/contract-tests/cli.py discover --repo /path/to/provider/checkout [--format text|json]
```

`coverage` exits 0 when everything is accounted for, 1 when it finds gaps (0 with
`--report-only`), and 2 on an integrity error such as an unparseable descriptor,
an exclusion without a reason, or an unpinned `yq`.

Kubernetes manifest checks (see the
[manifest onboarding guide](../../docs/onboarding/manifest-compat.md)).
Preparation is the only network-enabled step and needs Go >= 1.27 on PATH; the
check itself is offline:

```bash
# Once per cache location, with network: fetch and verify the pinned go-run
# Helm/Kustomize modules. The cache must live outside any repository checkout.
python3 cmd/contract-tests/cli.py manifest-prepare \
  --repo /path/to/provider/checkout \
  --manifest-set .rhoai/manifests.yaml \
  --tool-cache-dir /tmp/manifest-tools

# Offline, on every change. --tool-cache-dir is required only when the
# selected scenarios render (raw-only selections need no Go).
python3 cmd/contract-tests/cli.py manifest-check \
  --repo /path/to/provider/checkout \
  --manifest-set .rhoai/manifests.yaml \
  --baseline-ref <full-git-sha> [--baseline-ref <full-git-sha> ...] \
  --output-dir /tmp/manifest-report \
  [--tool-cache-dir /tmp/manifest-tools] [--scenario-id <id>] [--enforce]
```

`manifest-check` exits 0 for `compatible` and `new` (and for `breaking`
findings without `--enforce`), 1 for `breaking` findings with `--enforce`,
and 2 on integrity errors such as an unresolvable baseline, a render
failure, or a missing tool cache. Baselines must be full Git SHAs; scenario
inputs absent at a baseline fail closed until declared in a `baselineCases`
entry.

`protobuf-compat` and additional contract types are follow-on work.
