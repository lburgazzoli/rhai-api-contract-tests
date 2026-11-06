"""Manifest compatibility check orchestration.

Owns the ``manifest-prepare`` and ``manifest-check`` flows: descriptor and
baseline validation, candidate/baseline snapshots and rendering, policy
comparison across the four family modules, candidate validation, candidate-edge
correlation, exception application, aggregate statuses, and safe report
publication. The CLI adds loaders and subparsers only.

Design invariants (standing policy):

- Candidate configuration drives scenario definitions on both sides; baseline
  revisions are exact Git blobs and need no historical descriptor.
- Every requested baseline stays in the report whatever else failed; missing
  provenance is ``null``, never fabricated.
- Suppression never deletes evidence: matched findings keep their severity and
  gain ``suppressed``/``suppressed_reason``.
- Reports contain digests and identities, never rendered manifests, values, or
  Secret contents; temporary snapshots are cleaned on every path.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

_MODULE_DIR = Path(__file__).resolve().parent
POLICY_PATH = _MODULE_DIR / "policy.json"

# Rule IDs owned by the checker itself rather than a comparison module.
_CHECKER_RULE_IDS = frozenset({"patch-coverage-extrapolated", "stale-exception"})
# Cross-cutting catalogue rows that several field modules emit per object
# (partial coverage of unaudited versions; conditional live-state risks).
_CROSS_CUTTING_RULE_IDS = frozenset({"rule-coverage-partial", "conditional-update-risk"})


class CheckError(Exception):
    """A configuration, baseline, integrity, rendering, or output failure."""


def _load_sibling(name: str, filename: str) -> ModuleType:
    """Load a sibling module once under a stable registered name."""
    registered = f"manifest_compat_{name}"
    module = sys.modules.get(registered)
    if module is not None:
        return module
    path = _MODULE_DIR / filename
    spec = importlib.util.spec_from_file_location(registered, path)
    if spec is None or spec.loader is None:
        raise CheckError(f"Cannot load sibling module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[registered] = module
    spec.loader.exec_module(module)
    return module


def _modules() -> dict[str, ModuleType]:
    return {
        "config": _load_sibling("config", "config.py"),
        "normalizer": _load_sibling("normalizer", "normalizer.py"),
        "renderers": _load_sibling("renderers", "renderers.py"),
        "workloads": _load_sibling("workloads", "policies_workloads.py"),
        "resources": _load_sibling("resources", "policies_resources.py"),
        "storage_service": _load_sibling("storage_service", "policies_storage_service.py"),
        "relationships": _load_sibling("relationships", "relationships.py"),
    }


def load_catalogue() -> dict[str, Any]:
    """Load the rule registry shipped beside this module."""
    try:
        catalogue = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CheckError(f"Cannot read policy catalogue {POLICY_PATH}: {error}") from error
    if not isinstance(catalogue, dict) or not isinstance(catalogue.get("rules"), list):
        raise CheckError("Policy catalogue is malformed")
    return catalogue


# --- Registry / handler coverage ----------------------------------------------

def verify_handler_coverage(catalogue: dict[str, Any], modules: Mapping[str, ModuleType]) -> list[str]:
    """Verify every active catalogue rule has exactly one implemented owner.

    Kind-bearing rules must resolve through their family module's
    (group, kind) dispatch table — a comma-separated catalogue ``kind`` value
    (for example ``"Service, PodDisruptionBudget, NetworkPolicy"``) must
    resolve every listed kind. Graph rules (selectors, references, drift,
    protection) belong to the relationships module regardless of their kind
    list; kindless cross-cutting coverage/risk rows are emitted by the field
    modules per object. Returns a list of problems (empty when coverage is
    complete).
    """
    workloads = modules["workloads"]
    resources = modules["resources"]
    storage_service = modules["storage_service"]
    relationships = modules["relationships"]

    workload_kinds: frozenset[str] = workloads.WORKLOAD_KINDS
    resource_handlers: Mapping[tuple[str, str], Any] = resources.HANDLERS
    storage_handlers: Mapping[tuple[str, str], Any] = storage_service._HANDLERS  # noqa: SLF001
    relationship_ids: frozenset[str] = frozenset(relationships._RULES)  # noqa: SLF001

    def field_owners(group: str, kind: str) -> list[str]:
        owners = []
        if kind in workload_kinds:
            owners.append("policies_workloads")
        if (group, kind) in resource_handlers:
            owners.append("policies_resources")
        if (group, kind) in storage_handlers:
            owners.append("policies_storage_service")
        return owners

    problems: list[str] = []
    for rule in catalogue["rules"]:
        if rule.get("status") != "active":
            continue
        rule_id = rule.get("id", "<missing>")
        group, kind = rule.get("group") or "", rule.get("kind") or ""
        if rule_id in _CHECKER_RULE_IDS or rule_id in _CROSS_CUTTING_RULE_IDS:
            continue
        if rule_id in relationship_ids:
            # Graph rule: owned by the relationships module whatever its
            # catalogue kind list says; field handlers for the same kinds
            # implement different rules and are not in conflict.
            continue
        if not kind:
            problems.append(f"active kindless rule {rule_id!r} has no owning module")
            continue
        for entry in kind.split(","):
            single = entry.strip()
            if not single:
                continue
            owners = field_owners(group, single)
            if len(owners) == 0:
                problems.append(
                    f"active rule {rule_id!r} for {group or 'core'}/{single} has no handler module"
                )
            elif len(owners) > 1:
                problems.append(
                    f"active rule {rule_id!r} for {group or 'core'}/{single} is claimed by "
                    f"{', '.join(owners)}"
                )
    return problems


# --- Small shared helpers -------------------------------------------------------

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolve_commit(repo: Path, ref: str) -> str:
    """Resolve a ref to a commit OID without replacing objects (CRD convention)."""
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
            cwd=repo, capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError(f"Cannot resolve ref {ref!r} in {repo}: {error}") from error
    if result.returncode or not result.stdout.strip():
        raise CheckError(f"Cannot resolve baseline ref {ref!r} to a commit in {repo}")
    return result.stdout.strip()


def _identity_tuple(identity: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(identity.get("group") or ""),
        str(identity.get("kind") or ""),
        str(identity.get("namespace") or ""),
        str(identity.get("name") or ""),
    )


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
        resource = _identity_tuple(finding.get("resource") or {})
        related = finding.get("related_resource")
        related_key = _identity_tuple(related) if isinstance(related, dict) else ("", "", "", "")
        return (
            finding.get("id") or "", resource, finding.get("path") or "", related_key,
            finding.get("edge_id") or "", finding.get("candidate_edge_id") or "",
            finding.get("text") or "",
        )

    return sorted(findings, key=sort_key)


def _scenario_inventory(records: Sequence[Mapping[str, Any]],
                        scenario: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Records selected as this scenario's renderer inputs (file + digest only)."""
    renderer = scenario.get("renderer")
    selected: list[dict[str, Any]] = []
    for record in records:
        file = str(record.get("file") or "")
        if renderer == "raw":
            patterns = scenario.get("sources") or []
            if any(fnmatch.fnmatchcase(file, pattern) for pattern in patterns):
                selected.append({"file": file, "sha256": record.get("sha256")})
        else:
            prefix = str(scenario.get("path") or "").strip("/") + "/"
            if file.startswith(prefix):
                selected.append({"file": file, "sha256": record.get("sha256")})
    selected.sort(key=lambda entry: entry["file"])
    return selected


def _inventory_records(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Project snapshot records to stable, safe provenance entries.

    Snapshot records carry absolute paths inside the (deleted) temporary work
    root; reports must stay deterministic and never reference them, so only
    the repository-relative file, its digest, and any hazard name survive.
    """
    entries: list[dict[str, Any]] = []
    for record in records:
        entry: dict[str, Any] = {"file": str(record.get("file") or "")}
        if "sha256" in record:
            entry["sha256"] = record["sha256"]
        if "hazard" in record:
            entry["hazard"] = record["hazard"]
        entries.append(entry)
    entries.sort(key=lambda item: item["file"])
    return entries


def _effective_baseline_scenario(scenario: Mapping[str, Any],
                                 case: Mapping[str, Any] | None) -> dict[str, Any]:
    """Apply a baselineCase's input overrides onto the candidate scenario."""
    effective = dict(scenario)
    inputs = case.get("inputs") if case is not None else None
    if isinstance(inputs, Mapping):
        for key in ("path", "sources", "valuesFiles"):
            if key in inputs:
                effective[key] = inputs[key]
    return effective


def _case_for(scenario: Mapping[str, Any], ref: str) -> dict[str, Any] | None:
    for case in scenario.get("baselineCases") or []:
        if isinstance(case, Mapping) and case.get("ref") == ref:
            return dict(case)
    return None


def _patch_extrapolation_finding(scenario: Mapping[str, Any],
                                 catalogue: dict[str, Any]) -> dict[str, Any] | None:
    """Warn when a scenario targets a patch other than the audited patch.

    ``kubernetes.audited_sources`` maps each supported minor to its audited
    ``{tag, commit}``; the audited patch is read from the tag (for example
    ``v1.35.10``). A scenario version outside the supported minors never
    reaches this check (configuration validation rejects it first).
    """
    sources = catalogue.get("kubernetes", {}).get("audited_sources") or {}
    version = str(scenario.get("kubernetesVersion") or "")
    parts = version.split(".")
    if len(parts) != 3:
        return None
    minor, patch = f"{parts[0]}.{parts[1]}", parts[2]
    entry = sources.get(minor)
    if not isinstance(entry, Mapping):
        return None
    tag_parts = str(entry.get("tag") or "").split(".")
    audited_patch = tag_parts[2] if len(tag_parts) == 3 else None
    if audited_patch is None or audited_patch == patch:
        return None
    rule = _rule_by_id(catalogue, "patch-coverage-extrapolated")
    return {
        "id": "patch-coverage-extrapolated",
        "path": "",
        "text": (
            f"scenario {scenario.get('id')!r} targets Kubernetes {version}; rules were audited at "
            f"{minor}.{audited_patch}, so coverage is extrapolated from the audited patch"
        ),
        "severity": rule["severity"],
        "scenario": scenario.get("id"),
        "resource": {
            "group": "", "kind": "", "namespace": str(scenario.get("namespace") or ""),
            "name": str(scenario.get("id") or ""),
        },
        "classification": rule["classification"],
        "evidence": rule["evidence"],
    }


def _rule_by_id(catalogue: dict[str, Any], rule_id: str) -> dict[str, Any]:
    for rule in catalogue["rules"]:
        if rule.get("id") == rule_id:
            return rule
    raise CheckError(f"catalogue is missing rule {rule_id!r}")


def _stale_exception_finding(exception: Mapping[str, Any], ref: str,
                             catalogue: dict[str, Any]) -> dict[str, Any]:
    rule = _rule_by_id(catalogue, "stale-exception")
    resource = exception.get("resource")
    if not isinstance(resource, Mapping):
        resource = {}
    return {
        "id": "stale-exception",
        "path": str(exception.get("path") or ""),
        "text": (
            f"exception for rule {exception.get('ruleId')!r} at baseline {ref} matched no finding; "
            "remove it or narrow the change it described"
        ),
        "severity": rule["severity"],
        "scenario": None,
        "resource": dict(resource),
        "classification": rule["classification"],
        "evidence": rule["evidence"],
    }


# --- Comparison assembly --------------------------------------------------------

def _compare_scenario(baseline_map: dict[str, Any], candidate_map: dict[str, Any],
                      scenario: dict[str, Any], catalogue: dict[str, Any],
                      modules: Mapping[str, ModuleType]) -> list[dict[str, Any]]:
    """Run all four family comparisons for one scenario and sort the union."""
    findings: list[dict[str, Any]] = []
    for module in (modules["workloads"], modules["resources"],
                   modules["storage_service"], modules["relationships"]):
        findings.extend(module.compare(baseline_map, candidate_map, scenario, catalogue))
    registered = {str(rule["id"]) for rule in catalogue["rules"]}
    for finding in findings:
        rule_id = finding.get("id")
        if not isinstance(rule_id, str) or rule_id not in registered:
            raise CheckError(f"comparison module emitted unregistered rule id {rule_id!r}")
    return _sort_findings(findings)


def _correlate_candidate_edges(baseline_findings: list[dict[str, Any]],
                               candidate_findings: Sequence[dict[str, Any]],
                               ref: str, sha: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Absorb comparison duplicates of already-reported candidate findings.

    Returns (retained findings, absorbed findings, association links);
    absorbed findings are removed from the retained list so each failing
    logical slot is reported exactly once. Retained candidate findings
    gain ``baseline_associations`` entries carrying the original baseline
    edge ID/pointers; each affected baseline gains an
    ``associated_candidate_findings`` link using the retained candidate
    edge ID.
    """
    candidate_index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for finding in candidate_findings:
        edge_id = finding.get("edge_id")
        if isinstance(edge_id, str):
            candidate_index[(str(finding.get("scenario")), str(finding.get("id")), edge_id)] = finding

    absorbed: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    retained: list[dict[str, Any]] = []
    for finding in baseline_findings:
        candidate_edge_id = finding.get("candidate_edge_id")
        key = (str(finding.get("scenario")), str(finding.get("id")), str(candidate_edge_id))
        match = candidate_index.get(key) if isinstance(candidate_edge_id, str) else None
        if (
            match is not None
            and _identity_tuple(finding.get("resource") or {})
            == _identity_tuple(match.get("resource") or {})
            and _identity_tuple(finding.get("related_resource") or {})
            == _identity_tuple(match.get("related_resource") or {})
        ):
            associations = match.setdefault("baseline_associations", [])
            associations.append({
                "ref": ref,
                "sha": sha,
                "edge_id": finding.get("edge_id"),
                "path": finding.get("path"),
                "related_path": finding.get("related_path"),
            })
            links.append({
                "scenario": match.get("scenario"),
                "id": match.get("id"),
                "edge_id": match.get("edge_id"),
            })
            absorbed.append(finding)
        else:
            retained.append(finding)
    return retained, absorbed, links


def _exception_matches(exception: Mapping[str, Any], finding: Mapping[str, Any],
                       relational: bool) -> bool:
    if finding.get("id") != exception.get("ruleId"):
        return False
    if _identity_tuple(finding.get("resource") or {}) != _identity_tuple(exception.get("resource") or {}):
        return False
    if finding.get("path") != exception.get("path"):
        return False
    if relational:
        return (
            _identity_tuple(finding.get("related_resource") or {})
            == _identity_tuple(exception.get("relatedResource") or {})
            and finding.get("edge_id") == exception.get("edgeId")
        )
    return True


def _apply_exceptions(baseline_findings: list[dict[str, Any]], absorbed: Sequence[dict[str, Any]],
                      scenario: Mapping[str, Any], ref: str, catalogue: dict[str, Any],
                      rules: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Suppress exactly-matched findings; warn on stale requested-baseline exceptions.

    An exception whose tuple matches an absorbed comparison finding is an
    invalid attempt to waive candidate validation and fails the run.
    """
    appended: list[dict[str, Any]] = []
    for exception in scenario.get("exceptions") or []:
        if not isinstance(exception, Mapping) or exception.get("baselineRef") != ref:
            continue
        rule = rules.get(str(exception.get("ruleId")))
        relational = bool(rule and rule.get("relational"))
        matched = False
        for finding in baseline_findings:
            if finding.get("suppressed"):
                continue
            if _exception_matches(exception, finding, relational):
                finding["suppressed"] = True
                finding["suppressed_reason"] = exception.get("reason")
                matched = True
                break
        if matched:
            continue
        for finding in absorbed:
            if _exception_matches(exception, finding, relational):
                raise CheckError(
                    f"scenario {scenario.get('id')!r}: exception for rule {exception.get('ruleId')!r} "
                    f"at baseline {ref} targets a candidate-validation finding (already reported "
                    "under candidate_findings); candidate validation cannot be waived"
                )
        appended.append(_stale_exception_finding(exception, ref, catalogue))
    return appended


# --- Report assembly ------------------------------------------------------------

def _baseline_status(scenarios: Mapping[str, Mapping[str, Any]]) -> str:
    statuses = [str(entry.get("status")) for entry in scenarios.values()]
    if any(status == "error" for status in statuses):
        return "error"
    if any(status == "not-run" for status in statuses):
        return "not-run"
    if statuses and all(status == "new" for status in statuses):
        return "new"
    return "compared"


def _finalize_report(report: dict[str, Any], enforce: bool) -> int:
    """Compute aggregate status, compatibility, and the exit code."""
    errors = bool(report.get("errors"))
    candidate_error = any(
        entry.get("status") == "error"
        for entry in (report.get("candidate", {}) or {}).get("scenarios", {}).values()
    )
    baseline_error = any(baseline.get("status") == "error" for baseline in report["baselines"])

    def unsuppressed_errors(findings: Sequence[Mapping[str, Any]]) -> bool:
        return any(
            finding.get("severity") == "error" and not finding.get("suppressed")
            for finding in findings
        )

    breaking_findings = any(unsuppressed_errors(baseline.get("findings") or []) for baseline in report["baselines"])
    candidate_findings = report.get("candidate_findings") or []
    breaking_findings = breaking_findings or unsuppressed_errors(candidate_findings)

    compared_any = any(
        str(entry.get("status")) == "compared"
        for baseline in report["baselines"]
        for entry in (baseline.get("scenarios") or {}).values()
    )

    if errors or candidate_error or baseline_error:
        report["status"] = "error"
        code = 2
    elif breaking_findings:
        report["status"] = "breaking"
        code = 1 if enforce else 0
    elif not compared_any:
        report["status"] = "new"
        code = 0
    else:
        report["status"] = "compatible"
        code = 0

    compared_scenarios_by_ref: dict[str, set[str]] = {}
    for baseline in report["baselines"]:
        compared_scenarios_by_ref[str(baseline.get("ref"))] = {
            scenario_id for scenario_id, entry in (baseline.get("scenarios") or {}).items()
            if str(entry.get("status")) == "compared"
        }
    active_candidate_errors: dict[str, list[dict[str, Any]]] = {}
    for finding in candidate_findings:
        if finding.get("severity") == "error":
            active_candidate_errors.setdefault(str(finding.get("scenario")), []).append(dict(finding))
    for baseline in report["baselines"]:
        if baseline.get("status") != "compared":
            continue
        compared = compared_scenarios_by_ref.get(str(baseline.get("ref")), set())
        incompatible = unsuppressed_errors(baseline.get("findings") or []) or any(
            scenario_id in compared and findings
            for scenario_id, findings in active_candidate_errors.items()
        )
        baseline["compatible"] = not incompatible
    return code


def _write_report(output: Path, report: dict[str, Any]) -> None:
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _print_summary(report: dict[str, Any], output: Path) -> None:
    label = report.get("manifest_set") or "manifests"
    counts: dict[str, int] = {}
    for baseline in report["baselines"]:
        counts[baseline.get("status", "unknown")] = counts.get(baseline.get("status", "unknown"), 0) + 1
    summary = ", ".join(f"{count} {status}" for status, count in sorted(counts.items())) or "no baselines"
    print(f"{label}: {report['status']} ({report['mode']}); baselines: {summary}; report: {output / 'report.json'}")


# --- Commands -------------------------------------------------------------------

def run_prepare(args: argparse.Namespace) -> int:
    """Prepare the pinned renderer modules in the selected cache (network-enabled)."""
    try:
        catalogue = load_catalogue()
        modules = _modules()
        problems = verify_handler_coverage(catalogue, modules)
        if problems:
            raise CheckError("policy catalogue handler coverage is incomplete: " + "; ".join(problems))
        config_data = modules["config"].load_config(args.repo, args.manifest_set, args.scenario_id)
        modules["config"].validate_context(config_data, args.repo, [], catalogue)
        provenance = modules["renderers"].prepare_tools(config_data, args.tool_cache_dir)
    except Exception as error:  # noqa: BLE001 - CLI boundary reports every failure as exit 2
        print(f"manifest-prepare: {error}", file=sys.stderr)
        return 2
    print(json.dumps(provenance, indent=2, sort_keys=True))
    return 0


def run_check(args: argparse.Namespace) -> int:
    """Run the offline manifest compatibility check and publish the report."""
    output = Path(args.output_dir).resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        print(f"Cannot create new output directory: {error}", file=sys.stderr)
        return 2

    baseline_refs: list[str] = list(args.baseline_ref)
    report: dict[str, Any] = {
        "status": "error",
        "mode": "enforce" if args.enforce else "report-only",
        "manifest_set": str(args.manifest_set),
        "policy_version": None,
        "tools": {},
        "candidate": None,
        "candidate_findings": [],
        "baselines": [
            {"ref": ref, "sha": None, "status": "not-run", "scenarios": {},
             "findings": [], "associated_candidate_findings": [], "errors": [],
             "compatible": None}
            for ref in baseline_refs
        ],
        "errors": [],
    }

    work_root: Path | None = None
    try:
        catalogue = load_catalogue()
        report["policy_version"] = catalogue.get("policy_version")
        modules = _modules()
        problems = verify_handler_coverage(catalogue, modules)
        if problems:
            raise CheckError("policy catalogue handler coverage is incomplete: " + "; ".join(problems))
        rules = {str(rule["id"]): rule for rule in catalogue["rules"]}
        config_module = modules["config"]

        config_data = config_module.load_config(args.repo, args.manifest_set, args.scenario_id)
        config_module.validate_context(config_data, args.repo, baseline_refs, catalogue)
        scenarios: list[dict[str, Any]] = list(config_data["scenarios"])
        report["tools"] = dict(config_data.get("tools") or {})

        work_root = Path(tempfile.mkdtemp(prefix="manifest-check-"))

        # --- candidate side ---
        head = _resolve_commit(Path(args.repo), "HEAD")
        descriptor = Path(args.manifest_set)
        if not descriptor.is_absolute():
            descriptor = Path(args.repo) / descriptor
        candidate_records = modules["renderers"].snapshot_candidate(Path(args.repo), work_root / "candidate")

        candidate_scenarios: dict[str, dict[str, Any]] = {}
        candidate_maps: dict[str, dict[str, Any]] = {}
        cache_dir = args.tool_cache_dir
        for scenario in scenarios:
            scenario_id = str(scenario.get("id"))
            entry: dict[str, Any] = {
                "status": "not-run", "render_digest": None, "object_count": None,
                "coverage": None, "skipped": [], "inventory": [], "errors": [],
            }
            candidate_scenarios[scenario_id] = entry
            entry["inventory"] = _scenario_inventory(candidate_records, scenario)
            try:
                content = modules["renderers"].render(candidate_records, scenario, cache_dir)
                normalized = modules["normalizer"].normalize(
                    content, f"candidate:{scenario_id}", scenario
                )
            except Exception as error:  # renderer/normalizer integrity failure
                entry["status"] = "error"
                entry["errors"].append(str(error))
                continue
            entry["status"] = "ready"
            entry["render_digest"] = digest(content)
            entry["object_count"] = normalized["coverage"]["object_count"]
            entry["coverage"] = normalized["coverage"]
            entry["skipped"] = normalized["skipped"]
            candidate_maps[scenario_id] = normalized

        candidate_findings: list[dict[str, Any]] = []
        for scenario in scenarios:
            scenario_id = str(scenario.get("id"))
            if candidate_scenarios[scenario_id]["status"] != "ready":
                continue
            for finding in modules["relationships"].validate_candidate(
                candidate_maps[scenario_id], scenario
            ):
                if str(finding.get("id")) not in rules:
                    raise CheckError(f"candidate validation emitted unregistered rule id {finding.get('id')!r}")
                candidate_findings.append(finding)
            extrapolation = _patch_extrapolation_finding(scenario, catalogue)
            if extrapolation is not None:
                candidate_findings.append(extrapolation)
        report["candidate"] = {
            "head": head,
            "config_sha256": digest(descriptor.read_bytes()),
            "inventory": _inventory_records(candidate_records),
            "scenarios": candidate_scenarios,
        }
        report["candidate_findings"] = _sort_findings(candidate_findings)

        # --- baseline side ---
        for index, ref in enumerate(baseline_refs):
            baseline = report["baselines"][index]
            try:
                sha = _resolve_commit(Path(args.repo), ref)
            except CheckError as error:
                baseline["status"] = "error"
                baseline["sha"] = None
                baseline["errors"] = [str(error)]
                report["errors"].append(f"baseline {ref}: {error}")
                continue
            baseline["sha"] = sha
            baseline_dest = work_root / f"baseline-{index}"
            try:
                baseline_records = modules["renderers"].snapshot_baseline(Path(args.repo), sha, baseline_dest)
            except Exception as error:
                baseline["status"] = "error"
                baseline["errors"] = [str(error)]
                report["errors"].append(f"baseline {ref}: {error}")
                continue

            flattened: list[dict[str, Any]] = []
            links: list[dict[str, Any]] = []
            baseline_scenarios: dict[str, dict[str, Any]] = {}
            try:
                for scenario in scenarios:
                    scenario_id = str(scenario.get("id"))
                    entry = {
                        "status": "not-run", "reason": None, "digest": None,
                        "object_count": None, "inventory": [], "errors": [],
                    }
                    baseline_scenarios[scenario_id] = entry
                    if candidate_scenarios[scenario_id]["status"] != "ready":
                        entry["reason"] = "blocked: candidate scenario did not render"
                        continue
                    case = _case_for(scenario, ref)
                    effective = _effective_baseline_scenario(scenario, case)
                    entry["inventory"] = _scenario_inventory(baseline_records, effective)
                    try:
                        content = modules["renderers"].render(baseline_records, effective, cache_dir)
                    except modules["renderers"].MissingInputError as error:
                        if case is not None and case.get("state") == "new":
                            if error.matched:
                                entry["status"] = "error"
                                entry["errors"].append(
                                    f"baseline {ref} declares scenario {scenario_id!r} new but some "
                                    f"inputs are present ({', '.join(sorted(error.matched))}); a partially "
                                    "missing source set cannot be declared new"
                                )
                            else:
                                entry["status"] = "new"
                                entry["reason"] = str(case.get("reason"))
                        else:
                            entry["status"] = "error"
                            entry["errors"].append(
                                f"scenario {scenario_id!r} inputs are absent at baseline {ref}; declare "
                                "an explicit new baselineCase only after verifying absence"
                            )
                        continue
                    except Exception as error:
                        entry["status"] = "error"
                        entry["errors"].append(str(error))
                        continue
                    if case is not None and case.get("state") == "new":
                        entry["status"] = "error"
                        entry["errors"].append(
                            f"baseline {ref} declares scenario {scenario_id!r} new but its inputs are "
                            "present; a present historical input must be compared, not declared new"
                        )
                        continue
                    normalized = modules["normalizer"].normalize(content, f"baseline:{scenario_id}", effective)
                    if normalized["coverage"]["object_count"] == 0:
                        entry["status"] = "error"
                        entry["errors"].append(
                            f"scenario {scenario_id!r} renders zero objects at baseline {ref}; a present "
                            "historical input cannot be empty"
                        )
                        continue
                    entry["digest"] = digest(content)
                    entry["object_count"] = normalized["coverage"]["object_count"]
                    findings = _compare_scenario(
                        normalized, candidate_maps[scenario_id], scenario, catalogue, modules
                    )
                    findings, absorbed, scenario_links = _correlate_candidate_edges(
                        findings, report["candidate_findings"], ref, sha
                    )
                    stale = _apply_exceptions(
                        findings, absorbed, scenario, ref, catalogue, rules
                    )
                    for finding in findings:
                        finding["baseline_ref"] = ref
                        finding["baseline_sha"] = sha
                    for finding in stale:
                        finding["scenario"] = scenario_id
                        finding["baseline_ref"] = ref
                        finding["baseline_sha"] = sha
                    flattened.extend(findings)
                    flattened.extend(stale)
                    links.extend(scenario_links)
                    entry["status"] = "compared"
            finally:
                shutil.rmtree(baseline_dest, ignore_errors=True)

            baseline["scenarios"] = baseline_scenarios
            baseline["findings"] = _sort_findings(flattened)
            baseline["associated_candidate_findings"] = links
            baseline["status"] = _baseline_status(baseline_scenarios)
            if baseline["status"] == "error":
                for entry in baseline_scenarios.values():
                    report["errors"].extend(
                        f"baseline {ref} scenario error: {message}" for message in entry.get("errors", [])
                    )
    except (CheckError, OSError, ValueError) as error:
        report["errors"].append(str(error))
        print(str(error), file=sys.stderr)
    except Exception as error:  # noqa: BLE001 - integrity boundary: renderer/policy failures
        report["errors"].append(f"{type(error).__name__}: {error}")
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
    finally:
        if work_root is not None:
            shutil.rmtree(work_root, ignore_errors=True)

    code = _finalize_report(report, bool(args.enforce))
    _write_report(output, report)
    _print_summary(report, output)
    return code
