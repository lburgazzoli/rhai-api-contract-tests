# ECMAScript pattern validation

`oasdiff validate` uses Go's regular expression engine, which rejects valid
ECMAScript constructs such as lookahead and backreferences in OpenAPI schema
patterns. `openapi-validate` is the fallback for that specific validation error.

It reloads the original document with external references disabled and runs
kin-openapi's full validation with an ECMAScript-mode `regexp2` compiler. The
kin-openapi and oasdiff versions match oasdiff v1.33.0. Findings use oasdiff's
severity mapping, so examples remain informational and invalid defaults remain
warnings. Regex execution errors fail the tool.

The runner keeps other findings from the initial oasdiff validation, records the
helper's versions in `report.json`, and compares the original patterns. No
schema patterns or constraints are removed to make validation pass.

```bash
go build -C cmd/openapi-validate -o "$PWD/bin/openapi-validate" .
go test -C cmd/openapi-validate ./...
```

The reusable OpenAPI workflow builds the helper automatically. For a local
run, place it in the provider's `bin/` directory or pass its path through
`--openapi-validate` or `OPENAPI_VALIDATE`. It is needed only when oasdiff
reports `schema-pattern-regex-invalid`; a missing helper fails the check.

As a standalone command, `openapi-validate <document.yaml|document.json>` emits
a JSON findings array. Exit codes are 0 for no error-level findings, 1 for an
invalid contract, and 2 for an execution or loading failure. `--version` lists
the pinned libraries.
