"""Generic OpenAPI compatibility engine (the openapi-compat module).

Loads a provider's ContractSet descriptor (see ../../schemas/contract-set.schema.json),
generates a fresh candidate using the descriptor's declared generator adapter
(adapters.py), resolves every baseline by exact Git SHA, and runs pinned
oasdiff checks scoped to the selected contract. Swagger 2.0 documents are converted to
OpenAPI 3 first (see convert_swagger2), because oasdiff reads OpenAPI 3 only.

This module is provider-agnostic: no Model Catalog-specific paths, tool
versions, or bundling scripts live here. All of that comes from the
provider's own .rhoai/contracts.yaml.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

_HERE = Path(__file__).resolve().parent

# A parsed YAML or JSON mapping: a descriptor, a contract entry, or the report.
Document = dict[str, Any]


def _load_adapters() -> ModuleType:
    spec = importlib.util.spec_from_file_location("openapi_compat_adapters", _HERE / "adapters.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {_HERE / 'adapters.py'}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapters = _load_adapters()


class CheckError(Exception):
    """The comparison could not be completed reliably."""


def command(
    args: Sequence[str | Path], *, cwd: Path, env: Mapping[str, str] | None = None, check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [str(arg) for arg in args], cwd=cwd, env=env,
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"Cannot run {args[0]}: {error}") from error
    if check and result.returncode:
        raise CheckError(f"{args[0]} failed: {result.stderr or result.stdout}")
    return result


def tool_path(name: str, explicit: str | None, repo: Path) -> Path:
    candidate: str | Path | None
    if explicit:
        candidate = shutil.which(explicit) or explicit
    elif (repo / "bin" / name).is_file():
        candidate = repo / "bin" / name
    else:
        candidate = shutil.which(name)
    if not candidate or not Path(candidate).is_file() or not os.access(candidate, os.X_OK):
        raise CheckError(f"Missing executable {name}; pin it under bin/ or pass an explicit path")
    return Path(candidate).resolve()


def verify_oasdiff(binary: Path, version: str, cwd: Path) -> str:
    output = command([binary, "--version"], cwd=cwd).stdout.strip()
    if output in (f"oasdiff version {version}", f"oasdiff version v{version}"):
        return output
    # go install leaves build.Version as 'main'. Check its embedded module
    # version instead of accepting an unversioned development build.
    build_info = command(["go", "version", "-m", binary], cwd=cwd).stdout
    for line in build_info.splitlines():
        fields = line.split()
        if fields[:3] == ["mod", "github.com/oasdiff/oasdiff", f"v{version}"]:
            return f"{output}; module v{version}"
    raise CheckError(f"Expected oasdiff v{version}, got {output!r}")


def verify_yq(binary: Path, version: str, cwd: Path) -> str:
    output = command([binary, "--version"], cwd=cwd).stdout.strip()
    if re.search(rf"(?:^|\s)version v{re.escape(version)}(?:\s|$)", output):
        return output
    build_info = command(["go", "version", "-m", binary], cwd=cwd).stdout
    for line in build_info.splitlines():
        fields = line.split()
        if fields[:3] == ["mod", "github.com/mikefarah/yq/v4", f"v{version}"]:
            return f"{output}; module v{version}"
    raise CheckError(f"Expected yq v{version}, got {output!r}")


def validate_baseline_ref(ref: str) -> None:
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", ref) is None:
        raise CheckError(
            f"Baseline revision {ref!r} must be a full 40- or 64-character Git SHA; "
            "mutable refs such as main, HEAD, tags, and branches are not accepted"
        )


def resolve_commit(repo: Path, ref: str) -> str:
    result = command(
        ["git", "--no-replace-objects", "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
        cwd=repo, check=False,
    )
    sha = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"[0-9a-f]{40,64}", sha):
        raise CheckError(f"Cannot resolve baseline revision {ref!r}; fetch the trusted revision first")
    return sha


def digest(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parse_document(yq: Path, path: Path, cwd: Path) -> Any:
    """Parse a YAML or JSON OpenAPI or Swagger document."""
    try:
        return json.loads(command([yq, "eval", "-o=json", ".", str(path)], cwd=cwd).stdout)
    except json.JSONDecodeError as error:
        raise CheckError(f"Cannot parse {Path(path).name}: {error}") from error


def is_swagger2(document: Any) -> bool:
    """True for a Swagger 2.0 document.

    ``swagger: 2.0`` written without quotes parses as a number, so both forms count.
    """
    return isinstance(document, dict) and str(document.get("swagger", "")).strip() in ("2", "2.0")


def swagger_base_path(document: Any) -> str:
    """A Swagger 2.0 basePath as a path prefix without a trailing slash; empty for none or ``/``."""
    base = document.get("basePath") if isinstance(document, dict) else None
    if not isinstance(base, str) or base.strip() in ("", "/"):
        return ""
    return "/" + base.strip().strip("/")


def _normalize_base_path(path: str) -> str:
    path = path.strip().strip("/")
    return "/" + path if path else ""


def openapi3_base_path(document: Any) -> str:
    """The URL path an OpenAPI 3 document's top-level ``servers`` share; empty for none or ``/``.

    Server variables are replaced by their defaults, and only the path part of a server URL
    counts: ``https://example.com:8443/api/v1`` and ``/api/v1`` both give ``/api/v1``. Servers
    that disagree on the path have no single base path, which is an error: comparing either
    one could report every route as removed. Path- and operation-level ``servers`` are not
    considered.
    """
    servers = document.get("servers") if isinstance(document, dict) else None
    if not isinstance(servers, list):
        return ""
    bases: dict[str, str] = {}
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            continue
        url = server["url"]
        variables = server.get("variables")
        for name, variable in (variables.items() if isinstance(variables, dict) else ()):
            if isinstance(variable, dict) and "default" in variable:
                url = url.replace("{" + str(name) + "}", str(variable["default"]))
        path = urllib.parse.urlsplit(url).path if "://" in url or url.startswith("//") else url.split("?")[0]
        bases.setdefault(_normalize_base_path(path), server["url"])
    if len(bases) > 1:
        listed = ", ".join(repr(url) for url in bases.values())
        raise CheckError(
            f"The servers in this OpenAPI 3 document have different URL paths ({listed}), so it has no single "
            "base path to compare its paths under. Make every server use the same path, or move the "
            "difference into the paths"
        )
    return next(iter(bases), "")


def base_path(document: Any) -> str:
    """The path prefix a document serves its ``paths`` below, in either dialect."""
    return swagger_base_path(document) if is_swagger2(document) else openapi3_base_path(document)


def effective_paths(document: Any) -> list[str]:
    """The URL paths a document serves, which is what a contract's matchPath is matched against.

    Both dialects serve their ``paths`` below a base path: ``basePath`` in Swagger 2.0, the path
    of the ``servers`` URLs in OpenAPI 3. The base path is part of the path, so a document keeps
    the same effective paths when it moves from one dialect to the other. Prepending it also
    makes a changed base path visible to oasdiff as removed paths: oasdiff ignores ``servers``
    (and so ``basePath`` after conversion), so it would otherwise miss a change that moves
    every URL.
    """
    paths = document.get("paths") if isinstance(document, dict) else None
    if not isinstance(paths, dict):
        return []
    prefix = base_path(document)
    return [prefix + name for name in paths if isinstance(name, str)]


def document_serves(document: Any, pattern: str) -> bool:
    return any(re.match(pattern, name) for name in effective_paths(document))


def spec_has_paths(yq: Path, path: Path, cwd: Path, pattern: str) -> bool:
    return document_serves(parse_document(yq, path, cwd), pattern)


def convert_swagger2(document: Any, source: Path, dest: Path, converter: Path, cwd: Path) -> Document:
    """Write an OpenAPI 3 conversion of a Swagger 2.0 document and describe it for the report.

    oasdiff reads OpenAPI 3 only. The conversion is done by the swagger2openapi tool built
    from cmd/swagger2openapi, which uses the same library family as oasdiff. The Swagger
    basePath is folded into the path keys first (see effective_paths). A document that cannot
    be converted, for example one with a dangling reference, is an error, never a partial result.
    """
    paths = document.get("paths") or {}
    if not isinstance(paths, dict):
        raise CheckError(f"Cannot convert {source.name}: paths must be a mapping")
    prefix = swagger_base_path(document)
    prepared = {key: value for key, value in document.items() if key != "basePath"}
    prepared["swagger"] = "2.0"
    prepared["paths"] = {prefix + name: item for name, item in paths.items()}
    staged = dest.parent / f"{dest.name}.input.json"
    staged.write_text(json.dumps(prepared, indent=2) + "\n", encoding="utf-8")
    result = command([converter, staged], cwd=cwd, check=False)
    if result.returncode:
        raise CheckError(
            f"Cannot convert the Swagger 2.0 document {source.name} to OpenAPI 3: "
            f"{(result.stderr or result.stdout).strip()}"
        )
    dest.write_text(result.stdout, encoding="utf-8")
    return {"from": "swagger-2.0", "to": "openapi-3", "base_path_prepended": prefix or None,
            "file": dest.name, "sha256": digest(dest)}


def canonicalize_openapi3(document: Any, source: Path, dest: Path) -> Document | None:
    """Write a copy of an OpenAPI 3 document with its servers' base path folded into the paths.

    This puts it in the same path space as a converted Swagger 2.0 document (see effective_paths),
    so a contract can move between dialects, and a changed servers path shows up as removed
    paths. Returns None, and writes nothing, when the document has no base path to fold.
    """
    prefix = openapi3_base_path(document)
    if not prefix:
        return None
    paths = document.get("paths") or {}
    if not isinstance(paths, dict):
        raise CheckError(f"Cannot read {source.name}: paths must be a mapping")
    prepared = dict(document)
    prepared["paths"] = {prefix + name: item for name, item in paths.items()}
    dest.write_text(json.dumps(prepared, indent=2) + "\n", encoding="utf-8")
    return {"base_path_prepended": prefix, "file": dest.name, "sha256": digest(dest)}


def prepare_for_comparison(document: Any, source: Path, stem: str, output: Path,
                           converter: Any) -> tuple[Path, str, Document | None, Document | None]:
    """The file oasdiff compares for one document: a conversion, a canonical copy, or the source.

    Returns ``(compare_file, dialect, converted, canonicalized)``.
    """
    if is_swagger2(document):
        dest = output / f"{stem}.openapi3.json"
        return dest, "swagger-2.0", convert_swagger2(document, source, dest, converter(), output), None
    dest = output / f"{stem}.canonical.json"
    canonicalized = canonicalize_openapi3(document, source, dest)
    return (dest if canonicalized else source), "openapi-3", None, canonicalized


def findings(result: subprocess.CompletedProcess[str], operation: str, *, tool: str = "oasdiff") -> list[Document]:
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CheckError(f"{tool} {operation} returned invalid JSON: {result.stderr or result.stdout}") from error
    if parsed is None:
        parsed = []
    if not isinstance(parsed, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("id"), str)
        or not isinstance(item.get("text"), str) or not isinstance(item.get("level"), int)
        for item in parsed
    ):
        raise CheckError(f"{tool} {operation} returned malformed findings")
    if result.returncode not in (0, 1) or (result.returncode == 1 and not parsed):
        raise CheckError(f"{tool} {operation} failed: {result.stderr or result.stdout}")
    return parsed


def validate_spec(binary: Path, policy: Path, path: Path, cwd: Path,
                  get_validator: Callable[[], Path]) -> list[Document]:
    result = command(
        [binary, "validate", "--config", policy, "--allow-external-refs=false",
         "--fail-on", "ERR", "--format", "json", path], cwd=cwd, check=False,
    )
    records = findings(result, "validate")
    if result.returncode == 1 and any(item["id"] == "schema-pattern-regex-invalid" for item in records):
        # Go's regexp engine cannot compile valid ECMAScript constructs such as
        # lookahead and backreferences. Revalidate the original document with
        # the same kin-openapi library and an ECMAScript compiler. Never strip
        # patterns from the documents used for validation or comparison.
        result = command([get_validator(), path], cwd=cwd, check=False)
        fallback = findings(result, "validate", tool="openapi-validate")
        records = [item for item in records if item["id"] != "schema-pattern-regex-invalid"] + fallback
    if result.returncode or any(item["level"] >= 3 for item in records):
        raise CheckError(f"Invalid OpenAPI contract {Path(path).name}: {json.dumps(records)}")
    return records


def load_descriptor(path: Path, yq: Path, cwd: Path) -> Document:
    if not Path(path).is_file():
        raise CheckError(f"Descriptor not found: {path}")
    raw = command([yq, "eval", "-o=json", ".", str(path)], cwd=cwd).stdout
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CheckError(f"Cannot parse descriptor {path}: {error}") from error
    if not isinstance(data, dict) or data.get("kind") != "ContractSet":
        raise CheckError(f"{path} is not a ContractSet descriptor (missing kind: ContractSet)")
    try:
        validate_descriptor(data)
    except CheckError as error:
        raise CheckError(f"{path}: {error}") from error
    return data


_ABSENT = object()


def _optional(mapping: Document, key: str, kind: type, what: str) -> Any:
    """``mapping[key]`` when present; it must be a ``kind``. An explicit null is not absent."""
    value = mapping.get(key, _ABSENT)
    if value is _ABSENT:
        return None
    if not isinstance(value, kind):
        raise CheckError(f"{what} must be a {'mapping' if kind is dict else 'list'}")
    return value


def validate_descriptor(descriptor: Document) -> None:
    """Check the descriptor's shape once, for every command, as schemas/contract-set.schema.json types it.

    Covers what the commands dereference: ``spec``, ``spec.contracts`` and each contract,
    each contract's ``policy`` (with its pinned tool versions), and the optional
    ``candidate``, ``baseline``, ``generator``, ``severityOverrides`` and ``exclusions``
    blocks. An optional block may be omitted, but a present one, including null or another
    falsy value, must have the schema's type. Semantic rules (full Git SHAs, reasons,
    registered adapters, exclusion entries) stay with the code that applies them, which
    gives more specific errors. modules/coverage/tests/test_schema.py keeps this in step
    with the schema.
    """
    spec = descriptor.get("spec")
    if not isinstance(spec, dict):
        raise CheckError("spec must be a mapping")
    candidate = _optional(spec, "candidate", dict, "spec.candidate")
    if candidate is not None:
        _optional(candidate, "generator", dict, "spec.candidate.generator")
    _optional(spec, "baseline", dict, "spec.baseline")
    _optional(spec, "exclusions", list, "spec.exclusions")
    contracts = spec.get("contracts")
    if not isinstance(contracts, list):
        raise CheckError(
            "spec.contracts is required and must be a list of contracts "
            "(use `contracts: []` for a descriptor with only exclusions)")
    for index, contract in enumerate(contracts):
        if not isinstance(contract, dict):
            raise CheckError(f"spec.contracts[{index}] must be a mapping")
        name = f"contract {contract['id']}" if isinstance(contract.get("id"), str) else f"spec.contracts[{index}]"
        _optional(contract, "generator", dict, f"{name}: generator")
        _optional(contract, "baseline", dict, f"{name}: baseline")
        policy = contract.get("policy")
        if not isinstance(policy, dict):
            raise CheckError(f"{name}: policy must be a mapping with oasdiffVersion and yqVersion")
        for pin in ("oasdiffVersion", "yqVersion"):
            if not isinstance(policy.get(pin), str) or not policy[pin]:
                raise CheckError(f"{name}: policy.{pin} must be a quoted version string, e.g. \"4.45.1\"")
        _optional(policy, "severityOverrides", dict, f"{name}: policy.severityOverrides")


def select_contract(descriptor: Document, contract_id: str | None) -> Document:
    contracts = descriptor["spec"]["contracts"]
    if not contracts:
        raise CheckError("Descriptor declares no contracts")
    if contract_id is None:
        if len(contracts) != 1:
            raise CheckError("Descriptor registers multiple contracts; --contract-id is required")
        return contracts[0]
    matches = [c for c in contracts if c.get("id") == contract_id]
    if len(matches) != 1:
        raise CheckError(f"Contract id {contract_id!r} not found or not unique in descriptor")
    return matches[0]


def contract_baselines(
    args: argparse.Namespace, descriptor: Document, contract: Document,
) -> tuple[list[tuple[str, str]], str | None, bool]:
    """Resolve which baselines a contract is compared against, and where they came from.

    Precedence: the contract's own ``baseline`` block, then ``--baseline-ref`` (the
    repository default, normally supplied by the workflow), then ``spec.baseline``
    in the descriptor. A contract's own baseline is an explicit promise that the
    artifact exists there; the repository default is not.
    """
    contract_id = contract.get("id")
    block = contract.get("baseline")
    if block is not None:
        refs = block.get("refs")
        reason = block.get("reason")
        artifact = block.get("artifact")
        if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) for ref in refs):
            raise CheckError(f"Contract {contract_id!r}: baseline.refs must be a non-empty list of full Git SHAs")
        if not isinstance(reason, str) or not reason.strip():
            raise CheckError(
                f"Contract {contract_id!r}: baseline needs a 'reason'; a per-contract baseline "
                "without a recorded justification is not accepted"
            )
        if artifact is not None and (not isinstance(artifact, str) or not artifact):
            raise CheckError(f"Contract {contract_id!r}: baseline.artifact must be a repo-relative path")
        return [(ref, "contract") for ref in refs], artifact, True
    if args.baseline_ref:
        return [(ref, "default") for ref in args.baseline_ref], None, False
    refs = descriptor["spec"].get("baseline", {}).get("refs")
    if isinstance(refs, list) and refs and all(isinstance(ref, str) for ref in refs):
        return [(ref, "default") for ref in refs], None, False
    raise CheckError(
        f"Contract {contract_id!r} has no baseline: pass --baseline-ref, or declare "
        "spec.baseline.refs or contract baseline.refs in the descriptor"
    )


def exists_at(repo: Path, sha: str, relative: str) -> bool:
    result = command(["git", "--no-replace-objects", "cat-file", "-e", f"{sha}:{relative}"], cwd=repo, check=False)
    return result.returncode == 0


def find_moved_artifact(
    repo: Path, sha: str, match_path: str | None, yq: Path, workdir: Path, skip: str,
) -> tuple[str | None, bool]:
    """Find an OpenAPI document at the baseline that may be this contract's earlier self.

    Used when the declared artifact is absent: if the API existed under another
    name, calling it "new" would silently drop its protection.

    Returns ``(path, catch_all)``. With a specific matchPath, a document counts only
    if it already serves paths matching it. A catch-all matchPath cannot tell one API
    from another, so any other OpenAPI document at the baseline is returned and the
    caller must fail closed rather than grant the "new" exemption.
    """
    result = command(
        ["git", "--no-replace-objects", "grep", "-l", "-I", "-E",
         "-e", r"^(openapi|swagger)[[:space:]]*:", "-e", r'"(openapi|swagger)"[[:space:]]*:',
         sha, "--", "*.yaml", "*.yml", "*.json"],
        cwd=repo, check=False,
    )
    catch_all = match_path in (None, "", ".*")
    prefix = f"{sha}:"
    for line in result.stdout.splitlines():
        relative = line[len(prefix):] if line.startswith(prefix) else line
        if relative == skip:
            continue
        if catch_all or match_path is None:
            return relative, True
        probe = Path(workdir) / "moved-probe.yaml"
        raw = command(["git", "--no-replace-objects", "show", f"{sha}:{relative}"], cwd=repo, check=False)
        if raw.returncode:
            continue
        probe.write_text(raw.stdout, encoding="utf-8")
        try:
            if spec_has_paths(yq, probe, workdir, match_path):
                return relative, False
        except CheckError:
            continue
    return None, False


def check_compatibility(args: argparse.Namespace, output: Path, report: Document) -> int:
    repo = args.repo.resolve()
    oasdiff = tool_path("oasdiff", args.oasdiff, repo)
    yq = tool_path("yq", args.yq, repo)
    for ref in args.baseline_ref or []:
        validate_baseline_ref(ref)

    descriptor = load_descriptor(repo / args.contract_set, yq, repo)
    contract = select_contract(descriptor, args.contract_id)
    contract_id = contract.get("id")
    if contract.get("type") != "openapi":
        raise CheckError(f"Contract {contract_id!r} is type {contract.get('type')!r}; openapi-compat only handles 'openapi'")

    declared_artifact = contract.get("declaredArtifact")
    match_path = contract.get("matchPath", ".*")
    policy = contract["policy"]  # validate_descriptor guarantees both pins
    oasdiff_version = policy["oasdiffVersion"]
    yq_version = policy["yqVersion"]
    if not declared_artifact:
        raise CheckError(f"Contract {contract_id!r} must declare declaredArtifact")
    severity_overrides = policy.get("severityOverrides", {})
    flatten_allof = policy.get("flattenAllOf", True)

    report["contract_id"] = contract_id
    report["tool_build"] = {
        "oasdiff": verify_oasdiff(oasdiff, oasdiff_version, output),
        "yq": verify_yq(yq, yq_version, output),
    }

    # Explicit, locked-down policy prevents a provider-local .oasdiff file or
    # environment config from silently suppressing findings. No uploads.
    policy_file = output / "oasdiff-policy.json"
    policy_file.write_text("{}\n", encoding="utf-8")
    levels_file = output / "oasdiff-levels.txt"
    levels_file.write_text("".join(f"{rule} {level}\n" for rule, level in severity_overrides.items()), encoding="utf-8")
    report["policy"] = {
        "config_file": policy_file.name, "config_sha256": digest(policy_file),
        "severity_file": levels_file.name, "severity_sha256": digest(levels_file),
        "severity_overrides": severity_overrides, "fail_on": "WARN", "match_path": match_path,
    }

    converter: list[Path] = []
    validator: list[Path] = []

    def get_validator() -> Path:
        if not validator:
            try:
                path = tool_path("openapi-validate", getattr(args, "openapi_validate", None), repo)
            except CheckError as error:
                raise CheckError(
                    "This document needs ECMAScript pattern validation. Build the helper with "
                    "`go build -C <api-contract-tests>/cmd/openapi-validate -o <provider>/bin/openapi-validate .` "
                    "or pass --openapi-validate (see docs/onboarding/openapi-compat.md)"
                ) from error
            report["tool_build"]["openapi_validate"] = command([path, "--version"], cwd=output).stdout.strip()
            validator.append(path)
        return validator[0]

    def get_converter() -> Path:
        """Find the Swagger 2.0 converter once, and only when a Swagger 2.0 document needs it."""
        if not converter:
            try:
                path = tool_path("swagger2openapi", getattr(args, "swagger2openapi", None), repo)
            except CheckError as error:
                raise CheckError(
                    "A Swagger 2.0 document needs the swagger2openapi converter, and it was not found. Build it "
                    "with `go build -C <api-contract-tests>/cmd/swagger2openapi -o <provider>/bin/swagger2openapi .` "
                    "or pass --swagger2openapi (see docs/onboarding/openapi-compat.md)"
                ) from error
            report["tool_build"]["swagger2openapi"] = command([path, "--version"], cwd=output).stdout.strip()
            converter.append(path)
        return converter[0]

    baselines, baseline_artifact, explicit = contract_baselines(args, descriptor, contract)
    for ref, _ in baselines:
        validate_baseline_ref(ref)
    baseline_path = baseline_artifact or declared_artifact
    for ref, source in baselines:
        sha = resolve_commit(repo, ref)
        if not exists_at(repo, sha, baseline_path):
            if explicit:
                raise CheckError(
                    f"Contract {contract_id!r} names baseline {sha} explicitly, but {baseline_path} "
                    "does not exist there; fix the baseline, or set baseline.artifact if the file was moved"
                )
            moved, catch_all = find_moved_artifact(repo, sha, match_path, yq, output, baseline_path)
            if moved and catch_all:
                raise CheckError(
                    f"{declared_artifact} does not exist at baseline {sha}, but {moved} does, and contract "
                    f"{contract_id!r} has a catch-all matchPath, so it cannot tell whether the API is new or "
                    f"was renamed. Set a specific matchPath, or declare baseline: {{refs: [{sha}], "
                    f"artifact: {moved}, reason: ...}} if it was renamed"
                )
            if moved:
                raise CheckError(
                    f"{declared_artifact} does not exist at baseline {sha}, but {moved} there already serves "
                    f"paths matching {match_path!r}: the artifact was moved or renamed. Declare "
                    f"baseline: {{refs: [{sha}], artifact: {moved}, reason: ...}} on contract {contract_id!r}"
                )
            report["baselines"].append({
                "ref": ref, "sha": sha, "source": source, "status": "new",
                "reason": f"{baseline_path} does not exist at this baseline; the API is new relative to it, so there is nothing to compare",
            })
            continue
        baseline = output / f"baseline-{sha}.yaml"
        raw = command(["git", "--no-replace-objects", "show", f"{sha}:{baseline_path}"], cwd=repo).stdout
        baseline.write_text(raw, encoding="utf-8")
        baseline_document = parse_document(yq, baseline, output)
        if not document_serves(baseline_document, match_path):
            raise CheckError(f"Baseline {ref!r} has no paths matching {match_path!r}; wrong API/version")
        compare_file, dialect, converted, canonicalized = prepare_for_comparison(
            baseline_document, baseline, f"baseline-{sha}", output, get_converter)
        validation = validate_spec(oasdiff, policy_file, compare_file, output, get_validator)
        entry: Document = {
            "ref": ref, "sha": sha, "source": source, "status": "compared", "file": baseline.name,
            "sha256": digest(baseline), "dialect": dialect,
            "compare_file": compare_file.name, "validation_findings": validation,
        }
        if converted:
            entry["converted"] = converted
        if canonicalized:
            entry["canonicalized"] = canonicalized
        report["baselines"].append(entry)

    candidate = output / "candidate.yaml"
    generator = contract.get("generator") or descriptor["spec"].get("candidate", {}).get("generator")
    if not generator or "adapter" not in generator:
        raise CheckError(f"Contract {contract_id!r} has no generator.adapter declared")
    try:
        adapters.generate(generator["adapter"], repo, generator, yq, candidate)
    except adapters.AdapterError as error:
        raise CheckError(str(error)) from error
    report["candidate"] = {
        "head": resolve_commit(repo, "HEAD"), "file": candidate.name, "sha256": digest(candidate),
    }
    if candidate.read_bytes() != (repo / declared_artifact).read_bytes():
        raise CheckError(f"Stale committed {declared_artifact}; regenerate it before committing")
    candidate_document = parse_document(yq, candidate, output)
    candidate_compare, dialect, converted, canonicalized = prepare_for_comparison(
        candidate_document, candidate, "candidate", output, get_converter)
    report["candidate"]["dialect"] = dialect
    if converted:
        report["candidate"]["converted"] = converted
    if canonicalized:
        report["candidate"]["canonicalized"] = canonicalized
    report["candidate"]["compare_file"] = candidate_compare.name
    report["candidate"]["validation_findings"] = validate_spec(oasdiff, policy_file, candidate_compare, output, get_validator)

    breaking = False
    compared = [baseline for baseline in report["baselines"] if baseline["status"] == "compared"]
    for baseline in compared:
        cmd: list[str | Path] = [oasdiff, "breaking", "--config", policy_file, "--allow-external-refs=false",
               "--severity-levels", levels_file]
        if flatten_allof:
            cmd.append("--flatten-allof")
        if match_path and match_path != ".*":
            cmd.extend(["--match-path", match_path])
        cmd.extend(["--fail-on", "WARN", "--format", "json", output / baseline["compare_file"], candidate_compare])
        result = command(cmd, cwd=output, check=False)
        baseline["findings"] = findings(result, "breaking")
        baseline["compatible"] = result.returncode == 0
        breaking = breaking or not baseline["compatible"]
    if not compared:
        # Every baseline predates this API. Not a pass on compatibility, and not a failure.
        report["status"] = "new"
    else:
        report["status"] = "breaking" if breaking else "compatible"
    return 1 if breaking and args.enforce else 0


def run_check(args: argparse.Namespace) -> int:
    output = args.output_dir.resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        print(f"Cannot create new output directory: {error}", file=sys.stderr)
        return 2
    report: Document = {
        "status": "error", "mode": "enforce" if args.enforce else "report-only",
        "contract_set": str(args.contract_set), "baselines": [], "errors": [],
    }
    try:
        code = check_compatibility(args, output, report)
    except (CheckError, OSError, ValueError) as error:
        report["errors"].append(str(error))
        print(str(error), file=sys.stderr)
        code = 2
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    label = report.get("contract_id", str(args.contract_set))
    print(f"{label}: {report['status']} ({report['mode']}); report: {output / 'report.json'}")
    return code
