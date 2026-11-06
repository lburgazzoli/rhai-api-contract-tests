# manifest-compat

Static Kubernetes manifest compatibility for provider pull requests. Renders
the provider's declared installation sources — raw YAML, a local Helm chart,
or a local Kustomize overlay — with pinned tools and compares the rendered
objects against immutable Git baselines identified by full commit SHAs.

The check detects declared in-place update compatibility: immutable fields,
conditional update restrictions, transition rules, and manifest-level
relationships (selectors, required references, protected labels and
resources). It does **not** validate against a cluster, execute admission
webhooks, or read live state; see
[docs/research/manifest-compatibility.md](../../docs/research/manifest-compatibility.md)
for the full scope and the follow-on roadmap.

## Source of truth

- [`policy.json`](policy.json) — the complete finding-ID registry (85 rules,
  15 families): stable IDs, kinds, field paths, strategies, guards,
  severity/evidence, and waiver eligibility. Every immutable-field rule cites
  the exact upstream Kubernetes commit it was audited from (minors 1.35, 1.36,
  1.37; audited patches v1.35.10, v1.36.6, v1.37.2). This file is the only
  field catalogue; no other list is maintained.
- [`schemas/manifest-set.schema.json`](../../schemas/manifest-set.schema.json)
  — the `ManifestSet` descriptor schema.
- [`docs/onboarding/manifest-compat.md`](../../docs/onboarding/manifest-compat.md)
  — the provider onboarding guide (local runs, baselines, CI, report
  semantics).

## Layout

| File | Purpose |
| --- | --- |
| `checker.py` | Run orchestration, report assembly, CLI entry (`manifest-prepare`, `manifest-check` via `cmd/contract-tests/cli.py`) |
| `config.py` | `ManifestSet` loading and validation |
| `renderers.py` | Pinned offline rendering (`go run` Helm/Kustomize), snapshots, tool-cache preparation |
| `normalizer.py` | Rendered-output parsing and structural normalization |
| `policies_*.py` | Field and transition rules per API family (workloads, storage/Service, resources) |
| `relationships.py` | Selector and reference graph rules |
| `policy.json` | The finding-ID registry and audited-version metadata |

## Rendering model

Renders run through `go run helm.sh/helm/v4/cmd/helm@v4.3.1` and
`go run sigs.k8s.io/kustomize/kustomize/v5@v5.8.3` — never installed
binaries. `manifest-prepare` is the only network-enabled step: it fetches and
checksum-verifies the exact modules into a caller-selected cache outside the
provider checkout and proves the cache renders offline. `manifest-check` then
renders strictly offline, with the module proxy pointed at the prepared cache
itself, and fails closed on a missing or unusable cache. Helm templates may
not use `lookup` or `tpl`; every render runs twice and must be
byte-deterministic. Helm hook objects and CustomResourceDefinitions are
skipped and recorded (CRDs belong to the CRD compatibility check).

## Tests

```bash
# Offline unit/regression suites (no Go toolchain or cache needed).
python3 -m pytest modules/manifest-compat/tests -v

# Real-renderer integration group: needs Go >= 1.27 on PATH and a cache
# prepared by manifest-prepare; fails (never skips) when either is missing.
python3 cmd/contract-tests/cli.py manifest-prepare --repo . \
  --manifest-set selftest/manifests.yaml --tool-cache-dir /tmp/manifest-tools
MANIFEST_RENDERERS_CACHE=/tmp/manifest-tools \
  python3 -m pytest modules/manifest-compat/tests/test_renderer_integration.py \
  -m manifest_renderers -v
```

The `manifest_renderers` marker is registered in the repository-root
`pytest.ini` and excluded from ordinary runs; CI runs it in a dedicated job.
