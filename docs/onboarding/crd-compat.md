# Onboarding a provider to the CRD compatibility check

See the [onboarding checklist](README.md) for the whole path. This guide is the
detail for the CRD check.

The CRD check compares CustomResourceDefinition YAML files in a provider pull
request against immutable Git baselines. It initially detects:

- removed CRDs and API versions;
- served or storage-version changes;
- removed schema properties;
- newly required properties;
- type changes, enum narrowing, and default changes.

A field marked `x-kubernetes-int-or-string` that is narrowed to a single
`type: integer` or `type: string` is reported as a type change: such a field
has no top-level type, so losing one of its two alternatives is otherwise
invisible to the check. The detection is keyed on the marker, not on the
union's composition. Union composition without the marker, general
`anyOf`/`oneOf`/`allOf` changes, and `x-kubernetes-validations` (CEL) rule
changes are not compared: a compatible report is a static schema signal, not a
full compatibility guarantee.

The check is static and does not replace conversion, admission, or upgrade
tests. It gives provider pull requests an early, reproducible compatibility
signal without a cluster.

## Add the reusable workflow

Reference the workflow by `@latest` (a version tag, `stable` or a full commit SHA
also work; see [releases and pinning](../releasing.md)); never by a branch:

```yaml
jobs:
  crd-contract:
    uses: red-hat-data-services/api-contract-tests/.github/workflows/provider-crd-check.yml@latest
    with:
      crd-glob: config/crd/**/*.yaml
      baseline-refs: <full-git-sha>
      mode: enforce
```

Set `baseline-refs` to the SHA chosen in
[Choosing a baseline](README.md#choosing-a-baseline): the commit the RHOAI 3.6
release was based on, or the SHA that `main` resolves to today when there is none.
Note where it came from in a comment next to the input.

Use `mode: enforce`, the default; keep it explicit as in the example. If the first run fails because the repository already broke its
baseline, fix the break or revisit the baseline; do not fall back to `report`.

## Run locally

```bash
# Preferred: the commit the RHOAI 3.6 release was based on
baseline_sha=$(python3 <path-to-red-hat-data-services/api-contract-tests>/cmd/release-baseline/release_baseline.py \
  lookup --release 3.6 --repo <org>/<repo> --format sha)
# Fallback when the tool reports no baseline: the SHA main resolves to today
# baseline_sha=$(git rev-parse refs/remotes/<trusted-remote>/main)
python3 <path-to-red-hat-data-services/api-contract-tests>/cmd/contract-tests/cli.py crd-check \
  --repo . \
  --crd-glob 'config/crd/**/*.yaml' \
  --baseline-ref "$baseline_sha" \
  --output-dir /tmp/crd-contract-report
```

Baselines must be full Git SHAs. Mutable refs such as `main`, tags, and branches
are rejected.

## New CRDs

A CRD that exists in the pull request but not in the baseline is new and is not
compared. When the baseline has no CRD manifests at all, the check reports
`status: new` and does not fail. If the baseline has CRD manifests but none match
your glob, that is a configuration error and still fails.

## The same CRD in several files

A provider may ship one CRD in more than one place, for example a copy per
kustomize overlay. Identical copies are accepted and compared once. If two files
matched by the glob define the same CRD (same group and kind) differently, the
check fails with a configuration error naming both files, because otherwise only
one copy would be compared and a breaking change in the other could go unnoticed.
Keep the copies identical (ideally generated from one source), or narrow the glob
to one of them.

## Confirm every CRD is covered

The glob decides which manifests are compared, so a CRD that moves or is added
outside it silently leaves the check. Run the coverage check with the same
glob:

```bash
python3 <path-to-red-hat-data-services/api-contract-tests>/cmd/contract-tests/cli.py coverage \
  --repo . --contract-set .rhoai/contracts.yaml --crd-glob 'config/crd/**/*.yaml'
```

Every CRD manifest must match a `--crd-glob` (repeat the flag when you use
several), and every glob must match at least one manifest. Kustomize patches
that merely say `kind: CustomResourceDefinition` (conversion-webhook or
CA-injection patches) are not CRD manifests and are ignored. CRDs that are
deliberately not checked, such as mocked CRDs used as test data, are named with
`--crd-exclude <glob>`; keep the reason in a comment next to the workflow
input so reviewers can read it.

A repository that ships only CRDs has no descriptor. In that case `coverage`
runs in CRD-only mode: pass `--crd-glob` and it checks just the CRD globs. If
the repository also has OpenAPI documents, it needs a descriptor as usual;
when none of them is a contract (for example a `swagger.json` of definitions
generated from the CRDs for an SDK), register each one under
`spec.exclusions` and leave `spec.contracts` empty — coverage accepts an
exclusion-only descriptor and still fails on any document no exclusion
matches.

## Follow-on work

The static schema check is intentionally the first CRD increment. Conversion,
stored-object migration, and consumer-reliance profiles require bounded
`envtest` scenarios and remain follow-on work.
