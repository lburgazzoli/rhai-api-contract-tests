# Onboarding a consumer to API contract checks

Start with the [onboarding overview](README.md). This guide covers the consumer
side of a provider/consumer API relationship: the behavior a consumer relies on,
the tests that prove that reliance, and the CI that reports drift early.

> **Current status.** Consumer reliance checks are repository-local today. The
> shared runner and reusable workflows verify provider contracts; they do not yet
> load or verify a consumer reliance profile. This guide defines the record and
> tests the consumer owns so the follow-on shared verifier can adopt them without
> another discovery pass.

## What the consumer owns

| Piece | Where it lives in your repository | Purpose |
|---|---|---|
| Reliance profile | `.rhoai/consumer-profile.yaml` (proposed) | Names the provider contract, the operations/fields/statuses the consumer uses, and the tests that prove it |
| Consumer contract tests | Existing test tree, for example `contract-tests/` | Exercises the consumer boundary and validates the provider response against the contract plus explicit behavior assertions |
| CI job | `.github/workflows/` | Runs the tests on consumer changes and provider syncs in report mode |
| Registration | Working-group review | Links the provider contract, consumer profile, tests, owner, and support level |

The provider keeps the canonical OpenAPI document and provider behavior tests.
The consumer must not copy the provider schema into its repository or take over
provider tests. Both sides use the provider artifact by reference.

## 1. Identify the provider contract

Record the provider boundary before writing tests:

- provider repository and owner;
- contract ID and declared artifact path from the provider's
  `.rhoai/contracts.yaml`;
- API version and support level the consumer is claiming;
- immutable provider baseline: a full Git SHA and, where available, the artifact
  digest;
- the consumer entry point that calls the provider (BFF client, SDK, adapter, or
  service client).

If the provider has not registered a contract, stop here and ask the provider to
follow the [provider onboarding checklist](openapi-compat.md). Do not create a
consumer profile against an unregistered document; the profile would have no
stable contract ID or baseline to refer to.

### Choosing the provider reference

Use a full SHA for the recorded baseline and for evidence attached to a review.
Testing against the provider's `main` is useful as a drift signal, but it is not
a reproducible baseline and must not be recorded as one. When the consumer needs
to support several provider releases, record each release baseline separately.

## 2. Inventory the consumer's reliance

The profile must describe what the consumer actually uses, not everything the
provider publishes. Search the consumer repository for:

- provider URL paths, route constants, generated clients, and operation IDs;
- request parameters, headers, authentication assumptions, and pagination;
- response fields and envelopes the code reads;
- status codes, error shapes, and retry/fallback behavior;
- ordering, defaulting, empty-result, not-found, and authorization behavior that
  the consumer's tests or code depend on.

Use code and tests as evidence. Do not infer reliance from an OpenAPI schema
alone: a field can exist in the contract without the consumer reading it, and a
consumer can rely on behavior that the schema cannot express.

Record unknowns explicitly. An unknown is a coverage gap to resolve with the
provider owner, not an assumption to encode into the profile.

### Reliance table

Review this table with the consumer owner and provider representative before
writing the profile:

| Operation | Request surface | Response surface | Status/behavior | Consumer evidence |
|---|---|---|---|---|
| `listCatalogModels` | `GET /models`, `namespace`, `pageSize` | `data.items`, `data.size`, `data.nextPageToken` | `200` empty list; `400` missing namespace | BFF client and list page tests |
| `getCatalogModel` | `GET /models/{name}` | `data.name`, `data.labels` | `200`, `404` | Detail page fixture |

## 3. Write the reliance profile

Keep the profile in the consumer repository so it is reviewed with the consumer
code. This is the proposed shape; the shared runner does not consume it yet.

```yaml
apiVersion: contracts.rhoai.io/v1alpha1
kind: ConsumerReliance
metadata:
  name: dashboard-model-catalog
spec:
  consumer:
    repository: opendatahub-io/odh-dashboard
    owner: Dashboard
    supportLevel: supported
  provider:
    repository: opendatahub-io/model-registry
    contractId: model-catalog-v1
    artifact: api/openapi/catalog-v1.yaml
    baseline:
      ref: <full-git-sha>
      digest: <artifact-digest>
  reliance:
    operations:
      - operationId: listCatalogModels
        method: GET
        path: /api/model_catalog/v1/models
        parameters: [namespace, filterQuery, pageSize, nextPageToken]
        statusCodes: [200, 400]
        responseFields:
          - /data/items
          - /data/size
          - /data/pageSize
          - /data/nextPageToken
        behavior:
          - An empty result is 200 with an empty data.items list.
          - A missing namespace is a 400 response.
  tests:
    command: pnpm --filter @odh-dashboard/model-registry test:contract
    paths:
      - packages/model-registry/contract-tests/__tests__/testModelCatalogContract.test.ts
```

Use stable, human-readable operation and field names. A path such as
`/data/items` is a JSON pointer into the response; document the response
envelope when the provider uses one. If the consumer relies on several provider
contracts, give each relationship its own profile and baseline.

## 4. Add consumer contract tests

Consumer tests prove the consumer's assumptions through its real boundary. Use
the consumer's existing test framework and harness; do not add a second test
runner just for contracts.

The tests should:

- exercise the consumer entry point that calls the provider, not a hand-written
  HTTP call that bypasses the client;
- validate the response against the provider's OpenAPI document where the
  contract has a schema;
- assert the concrete fields, envelope, status codes, and behavior recorded in
  the reliance profile, independently of the schema;
- cover success, empty results, not-found, validation errors, pagination, and
  authorization cases the consumer actually handles;
- avoid asserting provider internals, undocumented response members, or
  behavior the consumer does not use.

### Dashboard reference implementation

The Dashboard Model Registry package already implements this pattern:

- harness: [`packages/contract-tests`](https://github.com/opendatahub-io/odh-dashboard/tree/main/packages/contract-tests);
- catalog tests: [`testModelCatalogContract.test.ts`](https://github.com/opendatahub-io/odh-dashboard/blob/main/packages/model-registry/contract-tests/__tests__/testModelCatalogContract.test.ts);
- local command:

  ```bash
  pnpm --filter @odh-dashboard/model-registry test:contract
  ```

- CI: [`.github/workflows/model-registry-contract.yml`](https://github.com/opendatahub-io/odh-dashboard/blob/main/.github/workflows/model-registry-contract.yml).

That workflow combines the shared provider OpenAPI check with a consumer-owned
job that runs the BFF contract tests against the upstream provider's current
OpenAPI document. The upstream job is a drift signal; the shared OpenAPI check
is the provider-side compatibility check.

## 5. Run against a pinned provider

For local evidence, check out the provider at the baseline SHA and point the
consumer tests at that checkout. Record the provider SHA, test command, tool
versions, and result next to the review or pull request.

If the consumer harness supports overriding the provider OpenAPI path or BFF
path (the Dashboard harness does), run the same tests twice:

1. **Baseline run:** provider at the recorded full SHA. This is the result that
   belongs in the profile or review evidence.
2. **Drift run:** provider `main`, with the resolved SHA printed in the log. A
   failure here is an early warning to discuss with the provider owner; it is not
   a reason to weaken the consumer assertions.

Do not use a branch name, tag, or `HEAD` as the recorded baseline. The provider
runner already rejects those refs; the consumer profile should follow the same
rule.

## 6. Add CI in report mode

Run the consumer tests when consumer code, the reliance profile, the tests, or a
provider sync changes. Keep the job in report mode until the findings and the
support level are reviewed.

If the job calls a reusable workflow from `api-contract-tests`, pin it to a
release tag such as `@v0.1.0`, `@stable`, or `@latest`, or to a full commit SHA.
Never use a branch. [Releases and pinning](../releasing.md) explains the
trade-offs. `@latest` follows the current release automatically; a version tag is
the default when the check is enforced.

This is the shape for a new consumer relationship. The Dashboard Model Registry
job uses the same wiring with `mode: enforce`, because that relationship has
already been reviewed and adopted.

```yaml
jobs:
  openapi:
    name: OpenAPI compatibility vs PR base
    uses: red-hat-data-services/api-contract-tests/.github/workflows/provider-openapi-check.yml@latest
    with:
      contract-set: packages/model-registry/.rhoai/contracts.yaml
      contract-id: model-registry-bff-model-catalog-v1
      baseline-refs: ${{ github.event.pull_request.base.sha }}
      mode: report

  upstream-main:
    name: BFF contract vs upstream main
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-sha>
      - run: pnpm --filter @odh-dashboard/model-registry test:contract
```

The consumer job must not require a cluster or a full end-to-end deployment.
Keep full Dashboard E2E and provider PR gates separate: provider changes should
get bounded, reproducible feedback, not a dependency on the consumer's entire
deployment stack.

## 7. Register the relationship with the working group

Once the profile and tests pass locally, provide the working group with:

- provider repository, contract ID, artifact path, and baseline SHA/digest;
- consumer repository, profile path, test command, and CI workflow;
- consumer and provider owners;
- support level and the provider releases the consumer claims to support;
- known gaps, exclusions, and behavior that is not covered by tests.

A profile in a consumer repository does not by itself make the relationship part
of an enforced cohort. Registration and enforcement are separate, reviewed
decisions. Start in report mode and move to enforce only after the provider and
consumer owners agree on the policy and the findings are reviewed.

## 8. Maintain the relationship

- Update the profile when the consumer starts or stops using an operation, field,
  status code, or behavior.
- Treat removal or narrowing of a relied-on operation, field, status, or
  semantic behavior as breaking, even when the provider labels it optional.
- Watch for provider `Deprecation` and `Sunset` headers and migration records;
  confirm the consumer's migration date before removal.
- Keep the profile, tests, and workflow code-owned so a baseline or assertion
  change needs an owner's review.
- Additive provider changes (new optional fields or operations) should not
  require a consumer change; verify that the tests still pass rather than
  broadening assertions to cover unused API surface.

## Definition of done

- [ ] Provider contract ID, artifact, owner, and full-SHA baseline are recorded.
- [ ] The reliance table names every operation, parameter, response field,
  status code, and behavior the consumer uses.
- [ ] The profile is committed in the consumer repository and reviewed by the
  consumer and provider owners.
- [ ] Consumer tests exercise the real consumer boundary and assert the profile's
  fields, statuses, and behavior.
- [ ] The baseline run is green and records the provider SHA and test command.
- [ ] CI runs in report mode on consumer changes and provider syncs.
- [ ] Known gaps and exclusions are explicit.
- [ ] The relationship is registered with the working group.

## Boundaries

- Do not copy provider schemas, generated documents, or behavior tests into the
  consumer repository.
- Do not make a provider pull request depend on consumer end-to-end tests.
- Do not use mutable provider refs for release evidence.
- Do not replace schema-aware consumer assertions with a path-existence check;
  removed fields and narrowed values must be detectable.
- Do not describe the consumer job as a promotion gate until the provider and
  consumer owners explicitly move it to enforce mode.
