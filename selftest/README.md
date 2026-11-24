# Workflow self-test fixtures

A minimal provider used by `.github/workflows/self-test.yml`. On every pull
request and push to `main`, the self-test calls each provider workflow with
`uses: ./.github/workflows/...`, so a change to a workflow runs end to end on its
own pull request instead of first running when a provider bumps its pin.

| File | Used by |
| --- | --- |
| `contracts.yaml` | OpenAPI and coverage checks (ContractSet descriptor) |
| `openapi/widgets.yaml` | OpenAPI check (`openapi.static` contract) |
| `openapi/gadgets.swagger.json` | OpenAPI check of a Swagger 2.0 contract (converted to OpenAPI 3 first) |
| `crd/widgets.yaml` | CRD and coverage checks |
| `manifests.yaml` | Manifest check (ManifestSet descriptor) |
| `manifests/raw/`, `manifests/helm/`, `manifests/kustomize/` | Manifest check scenarios: raw YAML, a Helm chart with a vendored dependency and selected values, and a Kustomize base/overlay with a generated ConfigMap reference |

The widgets response includes an ECMAScript lookahead pattern, exercising the
OpenAPI validator fallback in the reusable workflow.

Each check compares against the pull request's base commit (or the previous
`main` commit on push), so the self-test fails if a pull request makes a breaking
change to these fixtures. Change them only in compatible ways, or update the
baseline expectations in the same pull request. The manifest check passes its
exact event baseline to the reusable workflow's `allow-missing-baseline-refs`
input, so an event baseline that predates the fixtures is classified new with
no descriptor declaration: the manifest descriptor carries no per-ref
`baselineCases` to keep current. The kustomize renderer fixture CRD under
`modules/manifest-compat/tests/fixtures/` is deliberate test data, not a
served API of this repository; the coverage job excludes it through the
CRD-exclusion facility (`crd-exclude-globs`), and the OpenAPI renderer
fixture through the ContractSet's `exclusions`.

A local call has no SHA to pin, so the workflows' pin requirement is waived when
the caller is this repository (see `require_pinned_ref` in
`cmd/workflow-steps/steps.py`). Providers are different repositories and must
still pin by release tag, such as `@latest`, or full commit SHA (see
[releases and pinning](../docs/releasing.md)).
