# api-contract-tests architecture

## Purpose

`api-contract-tests` provides shared, reproducible compatibility checks that run in
provider pull-request CI. It does not become a second source of truth for
provider contracts.

## Ownership

| Responsibility | Owner |
|---|---|
| Canonical OpenAPI document, CRD, or protobuf source | Provider repository |
| Provider behavior and upgrade tests | Provider team |
| Consumer reliance profile | Consumer repository |
| Shared compatibility policy, schemas, runner, and workflows | `api-contract-tests` |
| Supported release matrix | Productization |

## Provider pull-request flow

1. Check out the provider pull request.
2. Generate a fresh candidate contract using a registered adapter and pinned tools.
3. Require rolling and supported-release baselines as full Git SHAs. A baseline defines what is released: an API that does not exist at the default baseline is new and not compared, while a contract's own baseline is explicit and must contain it.
4. Verify baseline artifact digests.
5. Run the compatibility check and consumer-profile verification.
6. Confirm the descriptor accounts for every OpenAPI document and CRD in the repository (the coverage check), so a new spec cannot stay outside the gate unnoticed.
7. Publish a machine-readable report with candidate, baseline, policy, and tool provenance.
8. Advance the rolling baseline only after merge through a trusted workflow.

## Enforcement modes

- **Report-only:** compatibility findings are recorded but do not fail the pull request.
- **Enforce:** breaking findings fail the pull request.

Infrastructure and integrity failures fail closed in both modes. Missing
baselines, digest mismatches, mutable baseline refs, malformed descriptors,
unpinned tools, and missing required results must not produce a silent pass.

## Current and follow-on contract types

- OpenAPI compatibility is implemented.
- Static CRD compatibility is implemented.
- Static Kubernetes manifest compatibility is implemented: rendered
  raw/Helm/Kustomize scenarios compared against full-SHA Git baselines, with
  immutable-field and relationship rules source-audited against Kubernetes
  1.35–1.37. Custom resources stay the CRD check's responsibility.
- CRD conversion, stored-object migration, and consumer-reliance checks are follow-on work.
- Protobuf and additional contract types are follow-on work.

Consumer repositories can record their reliance profile and consumer-side tests
now using the [consumer onboarding guide](onboarding/consumer-compat.md); shared
consumer-profile verification is the follow-on automation.
