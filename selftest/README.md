# Workflow self-test fixtures

A minimal provider used by `.github/workflows/self-test.yml`. On every pull
request and push to `main`, the self-test calls each provider workflow with
`uses: ./.github/workflows/...`, so a change to a workflow runs end to end on its
own pull request instead of first running when a provider bumps its pin.

| File | Used by |
| --- | --- |
| `contracts.yaml` | OpenAPI and coverage checks (ContractSet descriptor) |
| `openapi/widgets.yaml` | OpenAPI check (`openapi.static` contract) |
| `crd/widgets.yaml` | CRD and coverage checks |
| `manifests.yaml` | Manifest check (ManifestSet descriptor) |
| `manifests/raw/`, `manifests/helm/`, `manifests/kustomize/` | Manifest check scenarios: raw YAML, a Helm chart with a vendored dependency and selected values, and a Kustomize base/overlay with a generated ConfigMap reference |

Each check compares against the pull request's base commit (or the previous
`main` commit on push), so the self-test fails if a pull request makes a breaking
change to these fixtures. Change them only in compatible ways, or update the
baseline expectations in the same pull request. The manifest descriptor's
`baselineCases` declare the fixture-introduction refs as explicitly new (with
verified reasons); update those declarations only after verifying absence at
the new event refs.

A local call has no SHA to pin, so the workflows' pin requirement is waived when
the caller is this repository (see `require_pinned_ref` in
`cmd/workflow-steps/steps.py`). Providers are different repositories and must
still pin by full commit SHA or release tag (see
[releases and pinning](../docs/releasing.md)).
