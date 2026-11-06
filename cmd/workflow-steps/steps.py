#!/usr/bin/env python3
"""Steps of the provider workflows, kept out of the YAML so they can be tested.

Each provider workflow (.github/workflows/provider-*.yml) checks out this
repository at its own commit and calls one subcommand per step. Inputs arrive as
environment variables, exactly as the workflow passes them:

    steps.py require-pinned-ref       WORKFLOW_REF, WORKFLOW_SHA, WORKFLOW_REPOSITORY, CALLER_REPOSITORY
    steps.py run {openapi,crd,coverage,manifest}
                                      MODE, BASELINE_REFS, and per check: CONTRACT_SET,
                                      CONTRACT_ID, CRD_GLOB, CRD_GLOBS, CRD_EXCLUDE_GLOBS,
                                      MANIFEST_SET, SCENARIO_ID, TOOL_CACHE_DIR
    steps.py prepare manifest         MANIFEST_SET, SCENARIO_ID, TOOL_CACHE_DIR
                                      (the only network-enabled step: populates the pinned
                                      go-run renderer cache that run manifest reuses offline)
    steps.py summarize {openapi,crd,manifest}
                                      report at .contract-report/report.json
    steps.py annotate-coverage        MODE, report at $RUNNER_TEMP/coverage.json

Markdown goes to the job summary ($GITHUB_STEP_SUMMARY; stdout when unset).
Workflow commands (::error:: and friends) go to stdout.

This runs on the runner's system Python, so it uses the standard library only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, TextIO

CLI = Path(__file__).resolve().parents[1] / "contract-tests" / "cli.py"
FULL_SHA = re.compile(r"[0-9a-f]{40}")
# Release tags a caller may pin the provider workflows to; see docs/releasing.md.
VERSION_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
FLOATING_TAGS = ("stable", "latest")
REPORT = Path(".contract-report") / "report.json"

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class InputError(Exception):
    """A workflow input is invalid; the step fails before running any check."""


def escape(text: str) -> str:
    # Workflow-command data must not carry raw %, CR or LF.
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def command(level: str, message: str, title: str | None = None) -> str:
    properties = f" title={escape(title)}" if title else ""
    return f"::{level}{properties}::{escape(message)}"


def release_tag(ref: str) -> str | None:
    """The tag name if ref names a release tag this repository publishes, else None.

    Accepts the full form (refs/tags/v1.2.3) and the bare name (v1.2.3), because the
    caller's spelling is what reaches job.workflow_ref. Only release names are
    accepted, so a branch never passes: refs/heads/... is never a tag, and a bare
    name is accepted only if it is one this repository reserves for tags.
    """
    name = ref.removeprefix("refs/tags/")
    if VERSION_TAG.fullmatch(name) or name in FLOATING_TAGS:
        return name
    return None


def require_pinned_ref(env: Mapping[str, str]) -> tuple[int, str]:
    """Require callers to name this workflow by a full commit SHA or a release tag.

    job.workflow_sha is always the resolved commit, even when the caller wrote a
    branch or tag, so it cannot show how the caller pinned. job.workflow_ref ends
    with the ref the caller wrote after '@'. Accepted there:

    - a full commit SHA, which must be the commit that is running;
    - a version tag, vX.Y.Z, which the release process never moves;
    - a floating tag (stable, latest), which the release process moves on purpose.

    Branches, short SHAs and any other tag fail. For a tag, the notice records the
    commit it resolved to, so a run can be traced to the exact code it used.

    The exception is this repository calling its own workflows with
    ``uses: ./.github/workflows/...`` (the self-test). A local call has no SHA to
    pin, and it always runs the workflow from the caller's own commit. A provider is
    a different repository, so it can never match.
    """
    workflow_ref = env.get("WORKFLOW_REF", "")
    workflow_sha = env.get("WORKFLOW_SHA", "")
    workflow_repository = env.get("WORKFLOW_REPOSITORY", "")
    if workflow_repository and workflow_repository == env.get("CALLER_REPOSITORY"):
        return 0, command("notice", f"{workflow_repository} is calling its own workflow; pinning is not required: {workflow_ref}")
    pinned = workflow_ref.rpartition("@")[2]
    if FULL_SHA.fullmatch(pinned) and pinned == workflow_sha:
        return 0, ""
    tag = release_tag(pinned)
    if tag in FLOATING_TAGS:
        return 0, command("notice", f"Pinned to floating tag {tag}, which moves with each release; this run used commit {workflow_sha}")
    if tag:
        return 0, command("notice", f"Pinned to release tag {tag} (commit {workflow_sha})")
    return 2, command(
        "error",
        f"Call this workflow by a full commit SHA, a release tag (vX.Y.Z) or a floating tag "
        f"({', '.join(FLOATING_TAGS)}), not a branch or other ref: {workflow_ref}",
    )


def _mode(env: Mapping[str, str]) -> str:
    mode = env.get("MODE", "report")
    if mode not in ("report", "enforce"):
        raise InputError(f"mode must be report or enforce, not {mode!r}")
    return mode


def _baseline_args(env: Mapping[str, str]) -> list[str]:
    args = []
    for ref in env.get("BASELINE_REFS", "").split():
        if FULL_SHA.fullmatch(ref) is None:
            raise InputError(f"Baseline refs must be full 40-character Git SHAs: {ref}")
        args += ["--baseline-ref", ref]
    return args


def _required_baseline_args(env: Mapping[str, str]) -> list[str]:
    if not env.get("BASELINE_REFS", "").split():
        raise InputError("baseline-refs is required")
    return _baseline_args(env)


def _manifest_set(env: Mapping[str, str]) -> str:
    """The ManifestSet descriptor path, defaulting to .rhoai/manifests.yaml."""
    manifest_set = (env.get("MANIFEST_SET") or "").strip() or ".rhoai/manifests.yaml"
    path = PurePosixPath(manifest_set)
    if path.is_absolute() or ".." in path.parts:
        raise InputError(f"manifest-set must be a repository-relative path, not {manifest_set!r}")
    return manifest_set


def _scenario_id(env: Mapping[str, str]) -> str | None:
    scenario_id = (env.get("SCENARIO_ID") or "").strip()
    if not scenario_id:
        return None
    if any(character.isspace() for character in scenario_id):
        raise InputError(f"scenario-id must name exactly one scenario, not {scenario_id!r}")
    return scenario_id


def _tool_cache_dir(env: Mapping[str, str], workspace: Path, *, required: bool) -> Path | None:
    """The renderer tool cache location, which must stay outside the checkout.

    The candidate snapshot scans untracked checkout files, so a cache inside
    the workspace would corrupt every comparison; keep it in $RUNNER_TEMP.
    """
    raw = (env.get("TOOL_CACHE_DIR") or "").strip()
    if not raw:
        if required:
            raise InputError("tool-cache-dir is required for manifest preparation")
        return None
    base = Path(raw) if Path(raw).is_absolute() else workspace / raw
    cache = Path(os.path.abspath(str(base)))
    checkout = Path(os.path.abspath(str(workspace)))
    if cache == checkout or checkout in cache.parents:
        raise InputError(
            "tool cache must live outside the provider checkout so it is never scanned as "
            f"repository content: {raw!r}"
        )
    return cache


def check_args(check: str, env: Mapping[str, str], workspace: Path) -> list[str]:
    """The cli.py arguments for one check, built from the workflow's inputs.

    Space-separated inputs are split on whitespace and never glob-expanded; the
    checkers expand CRD globs themselves.
    """
    mode = _mode(env)
    report_dir = str(workspace / ".contract-report")
    if check == "openapi":
        args = ["check", "--repo", str(workspace), "--contract-set", env.get("CONTRACT_SET", ""),
                "--output-dir", report_dir]
        if env.get("CONTRACT_ID"):
            args += ["--contract-id", env["CONTRACT_ID"]]
        args += _baseline_args(env)
        return args + (["--enforce"] if mode == "enforce" else [])
    if check == "crd":
        if not env.get("CRD_GLOB"):
            raise InputError("crd-glob is required")
        args = ["crd-check", "--repo", str(workspace), "--crd-glob", env["CRD_GLOB"], "--output-dir", report_dir]
        args += _baseline_args(env)
        return args + (["--enforce"] if mode == "enforce" else [])
    if check == "coverage":
        args = ["coverage", "--repo", str(workspace), "--contract-set", env.get("CONTRACT_SET", "")]
        for glob in env.get("CRD_GLOBS", "").split():
            args += ["--crd-glob", glob]
        for glob in env.get("CRD_EXCLUDE_GLOBS", "").split():
            args += ["--crd-exclude", glob]
        args += _baseline_args(env)
        if mode == "report":
            args.append("--report-only")
        # The JSON copy stays outside the checkout so it is never scanned as a repository file.
        return args + ["--json-output", str(coverage_report(env))]
    if check == "manifest":
        args = ["manifest-check", "--repo", str(workspace), "--manifest-set", _manifest_set(env)]
        scenario_id = _scenario_id(env)
        if scenario_id:
            args += ["--scenario-id", scenario_id]
        args += _required_baseline_args(env)
        args += ["--output-dir", report_dir]
        cache = _tool_cache_dir(env, workspace, required=False)
        if cache is not None:
            args += ["--tool-cache-dir", str(cache)]
        # Rendering is strictly offline; the cache was prepared by `prepare manifest`.
        return args + (["--enforce"] if mode == "enforce" else [])
    raise InputError(f"unknown check {check!r}")


def prepare_args(check: str, env: Mapping[str, str], workspace: Path) -> list[str]:
    """The cli.py arguments for one preparation step (network-enabled)."""
    if check == "manifest":
        args = ["manifest-prepare", "--repo", str(workspace), "--manifest-set", _manifest_set(env)]
        scenario_id = _scenario_id(env)
        if scenario_id:
            args += ["--scenario-id", scenario_id]
        return args + ["--tool-cache-dir", str(_tool_cache_dir(env, workspace, required=True))]
    raise InputError(f"unknown check {check!r}")


def coverage_report(env: Mapping[str, str]) -> Path:
    return Path(env.get("RUNNER_TEMP", ".")) / "coverage.json"


def run_check(check: str, env: Mapping[str, str], workspace: Path, runner: Runner = subprocess.run) -> int:
    try:
        args = check_args(check, env, workspace)
    except InputError as error:
        print(command("error", str(error)))
        return 2
    if check != "coverage":
        return runner([sys.executable, str(CLI), *args], check=False).returncode
    # The coverage text goes to the job log and the job summary.
    result = runner([sys.executable, str(CLI), *args], check=False, stdout=subprocess.PIPE, text=True)
    print(result.stdout, end="")
    with summary_stream(env) as summary:
        summary.write(result.stdout)
    return result.returncode


def run_prepare(check: str, env: Mapping[str, str], workspace: Path, runner: Runner = subprocess.run) -> int:
    """Run one preparation step; input problems fail before anything downloads."""
    try:
        args = prepare_args(check, env, workspace)
    except InputError as error:
        print(command("error", str(error)))
        return 2
    return runner([sys.executable, str(CLI), *args], check=False).returncode


@contextmanager
def summary_stream(env: Mapping[str, str]) -> Iterator[TextIO]:
    """The job summary file, or stdout outside GitHub Actions."""
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        yield sys.stdout
        return
    with open(path, "a", encoding="utf-8") as stream:
        yield stream


def _findings(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [item for baseline in report.get("baselines", []) for item in baseline.get("findings", [])]


def _md(text: Any) -> str:
    """Escape untrusted text for inline Markdown (cells and bullet text)."""
    return str(text).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _resource(resource: Mapping[str, Any]) -> str:
    kind = str(resource.get("kind") or "?")
    name = str(resource.get("name") or "?")
    namespace = str(resource.get("namespace") or "")
    where = f"{kind} {name}"
    return f"{where} ({namespace})" if namespace else where


def _manifest_finding_line(finding: Mapping[str, Any]) -> str:
    line = (f"- scenario `{_md(finding.get('scenario', ''))}`: `{finding.get('id', '?')}` "
            f"({finding.get('severity', '?')}) at `{_md(finding.get('path', ''))}` on "
            f"{_md(_resource(finding.get('resource') or {}))}")
    related = finding.get("related_resource")
    if related:
        line += f" relating to {_md(_resource(related))}"
    return f"{line} — {_md(finding.get('text', ''))}"


def _manifest_compatibility(baseline: Mapping[str, Any]) -> str:
    """A truthful compatibility label; null is never coerced to yes or no."""
    if baseline.get("compatible") is True:
        return "yes"
    if baseline.get("compatible") is False:
        return "no"
    status = baseline.get("status")
    if status == "new":
        return "untested (new)"
    if status == "error":
        return "incomplete (error)"
    if status == "compared":
        return "incomplete (comparison unfinished)"
    return "incomplete (not run)"


def summarize_manifest(report: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """Markdown lines and workflow-command lines for a manifest report.

    Candidate validation findings are counted once globally and their baseline
    associations are shown separately; a completed baseline whose only failure
    is an associated candidate finding displays as incompatible, never as a
    pass. Unavailable provenance stays visible instead of being dropped.
    """
    mode = report.get("mode", "unknown mode")
    status = report.get("status", "error")
    manifest_set = str(report.get("manifest_set", "unknown manifest set"))
    heading = f"Manifest compatibility: {_md(manifest_set)}"
    prefix = f"Manifest compatibility: {manifest_set}"

    candidate_findings = list(report.get("candidate_findings") or [])
    baselines = list(report.get("baselines") or [])
    baseline_findings = _findings(report)
    active = [item for item in baseline_findings if not item.get("suppressed")]
    suppressed = [item for item in baseline_findings if item.get("suppressed")]
    errors = [str(error) for error in report.get("errors", [])]
    errors += [str(error) for baseline in baselines for error in baseline.get("errors", [])]
    breaking = [item for item in active + candidate_findings if item.get("severity") == "error"]
    warnings = [item for item in active + candidate_findings if item.get("severity") == "warn"]
    # Candidate findings are listed once in their own section (with their
    # baseline associations); these sections list only baseline comparison
    # findings so no logical finding appears twice.
    baseline_breaking = [item for item in active if item.get("severity") == "error"]
    baseline_warnings = [item for item in active if item.get("severity") == "warn"]
    coverage = [item for item in baseline_warnings if item.get("classification") in ("coverage", "risk")]
    other_warnings = [item for item in baseline_warnings
                      if item.get("classification") not in ("coverage", "risk")]

    lines = [
        f"## {heading}",
        "",
        f"- **Mode:** {mode}",
        f"- **Result:** {status}",
        f"- **Candidate validation findings:** {len(candidate_findings)}",
        f"- **Baseline comparison findings:** {len(active)} active, {len(suppressed)} suppressed",
        f"- **Warnings:** {len(warnings)}",
    ]
    if report.get("policy_version"):
        lines.append(f"- **Policy version:** `{report['policy_version']}`")

    scenarios = (report.get("candidate") or {}).get("scenarios") or {}
    if scenarios:
        lines += ["", "### Candidate scenarios", "",
                  "| Scenario | Status | Objects | Errors |", "| --- | --- | --- | --- |"]
        for scenario_id in sorted(scenarios):
            entry = scenarios[scenario_id] or {}
            objects = entry.get("object_count")
            lines.append(f"| `{_md(scenario_id)}` | {entry.get('status', 'unknown')} | "
                         f"{'unknown' if objects is None else objects} | "
                         f"{len(entry.get('errors') or [])} |")

    if candidate_findings:
        lines += ["", "### Candidate validation findings", "",
                  "Validated on the candidate alone, so they apply to every baseline; each "
                  "logical finding is listed once with its baseline associations.", ""]
        for finding in candidate_findings:
            lines.append(_manifest_finding_line(finding))
            for association in finding.get("baseline_associations") or []:
                lines.append(f"  - baseline `{_md(association.get('ref', ''))}` at "
                             f"`{_md(association.get('path', ''))}`")

    lines += ["", "### Baselines", "",
              "| Ref | SHA | Status | Compatible | Active findings | Linked candidate findings |",
              "| --- | --- | --- | --- | --- | --- |"]
    for baseline in baselines:
        findings = baseline.get("findings") or []
        suppressed_count = len([item for item in findings if item.get("suppressed")])
        findings_label = str(len(findings) - suppressed_count)
        if suppressed_count:
            findings_label += f" (+{suppressed_count} suppressed)"
        sha = baseline.get("sha")
        lines.append(f"| `{_md(baseline.get('ref', ''))}` | `{sha or 'unresolved'}` | "
                     f"{baseline.get('status', 'unknown')} | {_manifest_compatibility(baseline)} | "
                     f"{findings_label} | {len(baseline.get('associated_candidate_findings') or [])} |")

    scenario_rows = [(baseline, scenario_id, (baseline.get("scenarios") or {}).get(scenario_id) or {})
                     for baseline in baselines
                     for scenario_id in sorted(baseline.get("scenarios") or {})]
    if scenario_rows:
        lines += ["", "### Baseline scenarios", "",
                  "| Baseline | Scenario | Status | Objects | Detail |", "| --- | --- | --- | --- | --- |"]
        for baseline, scenario_id, entry in scenario_rows:
            detail = "; ".join(str(error) for error in entry.get("errors") or [])
            detail = detail or str(entry.get("reason") or "")
            objects = entry.get("object_count")
            lines.append(f"| `{_md(baseline.get('ref', ''))}` | `{_md(scenario_id)}` | "
                         f"{entry.get('status', 'unknown')} | "
                         f"{'unknown' if objects is None else objects} | {_md(detail)} |")

    if breaking:
        lines += ["", "### Breaking findings", "",
                  "Baseline comparison findings with error severity; candidate validation "
                  "findings above also fail enforcement.", ""]
        lines += [_manifest_finding_line(item) for item in baseline_breaking]

    if suppressed:
        lines += ["", "### Suppressed findings (waived exceptions)", ""]
        for item in suppressed:
            lines.append(f"- scenario `{_md(item.get('scenario', ''))}`: `{item.get('id', '?')}` at "
                         f"`{_md(item.get('path', ''))}` — waived: "
                         f"{_md(item.get('suppressed_reason') or 'no reason recorded')} "
                         f"(severity stays {item.get('severity', '?')})")

    if coverage:
        lines += ["", "### Coverage limitations", ""]
        lines += [_manifest_finding_line(item) for item in coverage]

    if other_warnings:
        lines += ["", "### Warnings", ""]
        lines += [_manifest_finding_line(item) for item in other_warnings]

    if errors:
        lines += ["", "### Errors", ""]
        lines += [f"- {_md(error)}" for error in errors]

    commands = []
    if status == "breaking":
        message = (f"{prefix}: {status} ({mode}); {len(breaking)} breaking findings, "
                   f"{len(warnings)} warnings. Download the manifest-contract-report artifact for details.")
        commands.append(command("warning" if mode == "report-only" else "error", message))
    elif status == "error":
        joined = "; ".join(errors) or "unknown error"
        commands.append(command("error", f"{prefix}: {status} ({mode}); {joined}"))
    else:
        commands.append(command("notice", f"{prefix}: {status} ({mode}); {len(candidate_findings)} "
                                          f"candidate findings, {len(active)} baseline findings, "
                                          f"{len(warnings)} warnings."))
    return lines, commands


def summarize(check: str, report: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """Markdown summary lines and workflow-command lines for a compatibility report."""
    if check == "manifest":
        return summarize_manifest(report)
    mode = report.get("mode", "unknown mode")
    status = report.get("status", "error")
    findings = _findings(report)
    if check == "crd":
        label = report.get("crd_glob", "unknown glob")
        heading, prefix = f"CRD compatibility: {label}", "CRD compatibility"
    else:
        label = report.get("contract_id", report.get("contract_set", "unknown contract"))
        heading, prefix = f"OpenAPI compatibility: {label}", label

    lines = [f"## {heading}", "", f"- **Mode:** {mode}", f"- **Result:** {status}", f"- **Findings:** {len(findings)}"]
    if check == "openapi":
        lines += ["", "| Baseline | Source | Compatible | Findings |", "| --- | --- | --- | --- |"]
        for baseline in report.get("baselines", []):
            if baseline.get("status") == "new":
                compatible = "new (not in baseline)"
            else:
                compatible = "yes" if baseline.get("compatible") else "no"
            lines.append(f"| `{baseline.get('sha', 'unknown')}` | {baseline.get('source', 'default')} | "
                         f"{compatible} | {len(baseline.get('findings', []))} |")
        if status == "new":
            lines += ["", "This API does not exist at any baseline yet, so nothing was compared. "
                          "It becomes protected once a baseline that contains it is adopted."]

    commands = []
    if status == "breaking":
        message = (f"{prefix}: {status} ({mode}); {len(findings)} breaking findings. "
                   "Download the contract-report artifact for details.")
        commands.append(command("warning" if mode == "report-only" else "error", message))
        lines += ["", "### Breaking findings", ""]
        for item in findings:
            text = str(item.get("text", "")).replace("|", "\\|")
            where = f"{item.get('operation', '')} {item.get('path', '')}".strip()
            lines.append(f"- `{where}` — {text}")
    elif status == "error":
        errors = "; ".join(report.get("errors", [])) or "unknown error"
        commands.append(command("error", f"{prefix}: {status} ({mode}); {errors}"))
    else:
        commands.append(command("notice", f"{prefix}: {status} ({mode}); {len(findings)} findings."))
    return lines, commands


def summarize_report(check: str, env: Mapping[str, str], report_path: Path = REPORT) -> int:
    names = {"crd": "CRD compatibility check", "manifest": "Manifest compatibility check"}
    name = names.get(check, "Compatibility check")
    if not report_path.is_file():
        print(command("error", f"{name} did not produce {report_path.name}"))
        return 1
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(command("error", f"{name} produced an unreadable {report_path.name}: {error}"))
        return 1
    lines, commands = summarize(check, report)
    with summary_stream(env) as summary:
        summary.write("\n".join(lines) + "\n")
    print("\n".join(commands))
    return 0


def coverage_annotations(report: Mapping[str, Any] | None, mode: str) -> list[str]:
    if report is None:
        return [command("error", "The coverage check did not produce a report", title="API contract coverage")]
    # Report mode keeps the job green, so a warning is the only signal on the pull request.
    level = "error" if mode == "enforce" else "warning"
    lines = [command(level, text, title="API contract coverage gap") for text in report.get("problems", [])]
    lines += [command("error", text, title="API contract coverage error") for text in report.get("errors", [])]
    return lines


def annotate_coverage(env: Mapping[str, str]) -> int:
    path = coverage_report(env)
    report = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    for line in coverage_annotations(report, env.get("MODE", "report")):
        print(line)
    # Never fails the job: the coverage step's exit code already decides that.
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="step", required=True)
    subparsers.add_parser("require-pinned-ref")
    subparsers.add_parser("run").add_argument("check", choices=("openapi", "crd", "coverage", "manifest"))
    subparsers.add_parser("prepare").add_argument("check", choices=("manifest",))
    subparsers.add_parser("summarize").add_argument("check", choices=("openapi", "crd", "manifest"))
    subparsers.add_parser("annotate-coverage")
    args = parser.parse_args(argv)

    env = os.environ
    if args.step == "require-pinned-ref":
        code, message = require_pinned_ref(env)
        if message:
            print(message)
        return code
    if args.step == "run":
        return run_check(args.check, env, Path.cwd())
    if args.step == "prepare":
        return run_prepare(args.check, env, Path.cwd())
    if args.step == "summarize":
        return summarize_report(args.check, env)
    return annotate_coverage(env)


if __name__ == "__main__":
    sys.exit(main())
