"""Tests for the provider workflow steps (cmd/workflow-steps/steps.py)."""

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "cmd" / "workflow-steps" / "steps.py"

spec = importlib.util.spec_from_file_location("workflow_steps", MODULE)
steps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(steps)


SHA = "a" * 40
OTHER = "b" * 40
WORKSPACE = Path("/work/provider")


# require-pinned-ref

def pinned_env(ref, sha=SHA, repository="red-hat-data-services/api-contract-tests", caller="org/provider"):
    return {
        "WORKFLOW_REF": f"{repository}/.github/workflows/provider-crd-check.yml@{ref}",
        "WORKFLOW_SHA": sha, "WORKFLOW_REPOSITORY": repository, "CALLER_REPOSITORY": caller,
    }


def test_provider_pinned_by_sha_passes():
    assert steps.require_pinned_ref(pinned_env(SHA)) == (0, "")


@pytest.mark.parametrize("ref", ["v0.1.0", "refs/tags/v0.1.0", "v12.0.3", "refs/tags/v1.10.0"])
def test_provider_pinned_by_version_tag_passes(ref):
    code, message = steps.require_pinned_ref(pinned_env(ref))
    assert code == 0
    tag = ref.removeprefix("refs/tags/")
    assert message == f"::notice::Pinned to release tag {tag} (commit {SHA})"


@pytest.mark.parametrize("ref", ["stable", "latest", "refs/tags/stable", "refs/tags/latest"])
def test_provider_pinned_by_floating_tag_passes_and_records_the_commit(ref):
    code, message = steps.require_pinned_ref(pinned_env(ref))
    assert code == 0
    assert message.startswith("::notice::Pinned to floating tag ")
    assert message.endswith(f"this run used commit {SHA}")


@pytest.mark.parametrize("ref", [
    "main", "refs/heads/main", "refs/heads/v1.0.0", "refs/heads/stable", SHA[:12],
    "v1", "v1.2", "v1.2.3-rc.1", "1.2.3", "v01.2.3", "refs/tags/v1", "refs/tags/release", "Stable",
])
def test_provider_pinned_by_branch_or_other_ref_fails(ref):
    code, message = steps.require_pinned_ref(pinned_env(ref))
    assert code == 2
    assert message.startswith("::error::Call this workflow by a full commit SHA, a release tag (vX.Y.Z)")


def test_sha_that_is_not_the_running_commit_fails():
    assert steps.require_pinned_ref(pinned_env(OTHER))[0] == 2


def test_self_test_call_from_this_repository_is_exempt():
    env = pinned_env("refs/pull/8/merge", caller="red-hat-data-services/api-contract-tests")
    code, message = steps.require_pinned_ref(env)
    assert code == 0
    assert message.startswith("::notice::red-hat-data-services/api-contract-tests is calling its own workflow")


def test_missing_repositories_do_not_count_as_a_self_call():
    env = pinned_env("main", repository="", caller="")
    assert steps.require_pinned_ref(env)[0] == 2


# run: building cli.py arguments from workflow inputs

def test_openapi_args():
    env = {"MODE": "enforce", "CONTRACT_SET": ".rhoai/contracts.yaml", "CONTRACT_ID": "svc-v1",
           "BASELINE_REFS": f"{SHA} {OTHER}"}
    assert steps.check_args("openapi", env, WORKSPACE) == [
        "check", "--repo", "/work/provider", "--contract-set", ".rhoai/contracts.yaml",
        "--output-dir", "/work/provider/.contract-report", "--contract-id", "svc-v1",
        "--baseline-ref", SHA, "--baseline-ref", OTHER, "--enforce",
    ]


def test_openapi_args_without_contract_id_or_baselines_in_report_mode():
    env = {"MODE": "report", "CONTRACT_SET": "c.yaml", "CONTRACT_ID": "", "BASELINE_REFS": ""}
    assert steps.check_args("openapi", env, WORKSPACE) == [
        "check", "--repo", "/work/provider", "--contract-set", "c.yaml", "--output-dir", "/work/provider/.contract-report",
    ]


def test_crd_args():
    env = {"MODE": "report", "CRD_GLOB": "config/crd/**/*.yaml", "BASELINE_REFS": SHA}
    assert steps.check_args("crd", env, WORKSPACE) == [
        "crd-check", "--repo", "/work/provider", "--crd-glob", "config/crd/**/*.yaml",
        "--output-dir", "/work/provider/.contract-report", "--baseline-ref", SHA,
    ]


def test_crd_glob_is_required():
    with pytest.raises(steps.InputError, match="crd-glob is required"):
        steps.check_args("crd", {"MODE": "report", "CRD_GLOB": "", "BASELINE_REFS": SHA}, WORKSPACE)


def test_coverage_args_keep_globs_unexpanded():
    env = {"MODE": "report", "CONTRACT_SET": ".rhoai/contracts.yaml", "CRD_GLOBS": "config/crd/*.yaml  config/overlays/**/*.yaml",
           "CRD_EXCLUDE_GLOBS": "test/*", "BASELINE_REFS": "", "RUNNER_TEMP": "/runner/tmp"}
    assert steps.check_args("coverage", env, WORKSPACE) == [
        "coverage", "--repo", "/work/provider", "--contract-set", ".rhoai/contracts.yaml",
        "--crd-glob", "config/crd/*.yaml", "--crd-glob", "config/overlays/**/*.yaml", "--crd-exclude", "test/*",
        "--report-only", "--json-output", "/runner/tmp/coverage.json",
    ]


def test_coverage_in_enforce_mode_is_not_report_only():
    env = {"MODE": "enforce", "CONTRACT_SET": "c.yaml", "RUNNER_TEMP": "/t"}
    assert "--report-only" not in steps.check_args("coverage", env, WORKSPACE)


@pytest.mark.parametrize("check", ["openapi", "crd", "coverage", "manifest"])
def test_invalid_mode_is_rejected(check):
    env = {"MODE": "strict", "CONTRACT_SET": "c.yaml", "CRD_GLOB": "x", "BASELINE_REFS": SHA}
    with pytest.raises(steps.InputError, match="mode must be report or enforce"):
        steps.check_args(check, env, WORKSPACE)


@pytest.mark.parametrize("check", ["openapi", "crd", "coverage", "manifest"])
def test_mutable_baseline_ref_is_rejected(check):
    env = {"MODE": "report", "CONTRACT_SET": "c.yaml", "CRD_GLOB": "x", "BASELINE_REFS": f"{SHA} main"}
    with pytest.raises(steps.InputError, match="full 40-character Git SHAs: main"):
        steps.check_args(check, env, WORKSPACE)


def test_run_check_reports_invalid_input_as_an_error_without_running(capsys):
    def runner(*args, **kwargs):
        raise AssertionError("the checker must not run")

    assert steps.run_check("crd", {"MODE": "strict", "CRD_GLOB": "x"}, WORKSPACE, runner) == 2
    assert capsys.readouterr().out.startswith("::error::mode must be report or enforce")


def test_run_check_passes_the_checker_exit_code_through():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1)

    assert steps.run_check("crd", {"MODE": "enforce", "CRD_GLOB": "x", "BASELINE_REFS": SHA}, WORKSPACE, runner) == 1
    assert calls[0][1] == str(steps.CLI)
    assert calls[0][2] == "crd-check"


def test_run_coverage_copies_its_output_to_the_job_summary(tmp_path, capsys):
    summary = tmp_path / "summary.md"

    def runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="Result: complete\n")

    env = {"MODE": "report", "CONTRACT_SET": "c.yaml", "RUNNER_TEMP": str(tmp_path), "GITHUB_STEP_SUMMARY": str(summary)}
    assert steps.run_check("coverage", env, WORKSPACE, runner) == 0
    assert capsys.readouterr().out == "Result: complete\n"
    assert summary.read_text() == "Result: complete\n"


def test_cli_path_points_at_the_runner():
    assert steps.CLI == ROOT / "cmd" / "contract-tests" / "cli.py"
    assert steps.CLI.is_file()


# summarize

def openapi_report(status, mode="report-only", **extra):
    report = {"status": status, "mode": mode, "contract_id": "svc-v1", "baselines": [], "errors": []}
    report.update(extra)
    return report


def test_breaking_openapi_report_in_report_mode_is_a_warning_with_findings():
    finding = {"operation": "GET", "path": "/api/v1/items", "text": "removed a|b"}
    report = openapi_report("breaking", baselines=[
        {"sha": SHA, "source": "default", "status": "compared", "compatible": False, "findings": [finding]},
    ])
    lines, commands = steps.summarize("openapi", report)
    assert lines[0] == "## OpenAPI compatibility: svc-v1"
    assert f"| `{SHA}` | default | no | 1 |" in lines
    assert "- `GET /api/v1/items` — removed a\\|b" in lines
    assert commands == ["::warning::svc-v1: breaking (report-only); 1 breaking findings. "
                        "Download the contract-report artifact for details."]


def test_breaking_report_in_enforce_mode_is_an_error():
    report = openapi_report("breaking", mode="enforce", baselines=[{"findings": [{"text": "x"}]}])
    assert steps.summarize("openapi", report)[1][0].startswith("::error::svc-v1: breaking (enforce)")


def test_new_openapi_contract_is_explained():
    report = openapi_report("new", baselines=[{"sha": SHA, "status": "new"}])
    lines, commands = steps.summarize("openapi", report)
    assert f"| `{SHA}` | default | new (not in baseline) | 0 |" in lines
    assert any("does not exist at any baseline yet" in line for line in lines)
    assert commands == ["::notice::svc-v1: new (report-only); 0 findings."]


def test_error_report_annotation_escapes_newlines():
    report = openapi_report("error", errors=["oasdiff failed:\nbad input", "second"])
    assert steps.summarize("openapi", report)[1] == [
        "::error::svc-v1: error (report-only); oasdiff failed:%0Abad input; second",
    ]


def test_crd_summary_uses_the_glob_as_label():
    report = {"status": "compatible", "mode": "report-only", "crd_glob": "config/crd/*.yaml",
              "baselines": [{"findings": []}]}
    lines, commands = steps.summarize("crd", report)
    assert lines[0] == "## CRD compatibility: config/crd/*.yaml"
    assert not any(line.startswith("|") for line in lines)
    assert commands == ["::notice::CRD compatibility: compatible (report-only); 0 findings."]


def test_summarize_report_writes_markdown_to_the_summary_and_commands_to_stdout(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(openapi_report("compatible")))
    summary = tmp_path / "summary.md"
    assert steps.summarize_report("openapi", {"GITHUB_STEP_SUMMARY": str(summary)}, report_path) == 0
    assert summary.read_text().startswith("## OpenAPI compatibility: svc-v1\n")
    assert capsys.readouterr().out == "::notice::svc-v1: compatible (report-only); 0 findings.\n"


def test_missing_report_fails_the_summary_step(tmp_path, capsys):
    assert steps.summarize_report("crd", {}, tmp_path / "report.json") == 1
    assert capsys.readouterr().out == "::error::CRD compatibility check did not produce report.json\n"


# annotate-coverage

def test_coverage_gaps_are_warnings_in_report_mode_and_errors_in_enforce_mode():
    report = {"problems": ["a.yaml is uncovered"], "errors": []}
    assert steps.coverage_annotations(report, "report") == [
        "::warning title=API contract coverage gap::a.yaml is uncovered",
    ]
    assert steps.coverage_annotations(report, "enforce")[0].startswith("::error title=API contract coverage gap::")


def test_coverage_errors_and_missing_report_are_errors():
    assert steps.coverage_annotations({"problems": [], "errors": ["100% broken"]}, "report") == [
        "::error title=API contract coverage error::100%25 broken",
    ]
    assert steps.coverage_annotations(None, "report") == [
        "::error title=API contract coverage::The coverage check did not produce a report",
    ]


def test_annotate_coverage_never_fails_the_step(tmp_path, capsys):
    assert steps.annotate_coverage({"RUNNER_TEMP": str(tmp_path), "MODE": "enforce"}) == 0
    assert "did not produce a report" in capsys.readouterr().out


# run/prepare manifest: building cli.py arguments from workflow inputs

def test_manifest_args_default_to_the_standard_manifest_set():
    env = {"MODE": "report", "BASELINE_REFS": f"{SHA} {OTHER}"}
    assert steps.check_args("manifest", env, WORKSPACE) == [
        "manifest-check", "--repo", "/work/provider", "--manifest-set", ".rhoai/manifests.yaml",
        "--baseline-ref", SHA, "--baseline-ref", OTHER,
        "--output-dir", "/work/provider/.contract-report",
    ]


def test_manifest_args_pass_explicit_inputs_and_enforce():
    env = {"MODE": "enforce", "MANIFEST_SET": "configs/manifests.yaml", "SCENARIO_ID": "helm-prod",
           "BASELINE_REFS": SHA, "TOOL_CACHE_DIR": "/runner/tmp/manifest-tools"}
    assert steps.check_args("manifest", env, WORKSPACE) == [
        "manifest-check", "--repo", "/work/provider", "--manifest-set", "configs/manifests.yaml",
        "--scenario-id", "helm-prod", "--baseline-ref", SHA,
        "--output-dir", "/work/provider/.contract-report",
        "--tool-cache-dir", "/runner/tmp/manifest-tools", "--enforce",
    ]


def test_manifest_raw_scenarios_omit_the_tool_cache():
    env = {"MODE": "report", "BASELINE_REFS": SHA}
    assert "--tool-cache-dir" not in steps.check_args("manifest", env, WORKSPACE)


def test_manifest_requires_at_least_one_baseline():
    with pytest.raises(steps.InputError, match="baseline-refs is required"):
        steps.check_args("manifest", {"MODE": "report", "BASELINE_REFS": " "}, WORKSPACE)


@pytest.mark.parametrize("manifest_set", ["/etc/manifests.yaml", "../outside.yaml", "configs/../../outside.yaml"])
def test_manifest_set_must_be_repository_relative(manifest_set):
    env = {"MODE": "report", "BASELINE_REFS": SHA, "MANIFEST_SET": manifest_set}
    with pytest.raises(steps.InputError, match="manifest-set must be a repository-relative path"):
        steps.check_args("manifest", env, WORKSPACE)


def test_manifest_scenario_id_must_name_one_scenario():
    env = {"MODE": "report", "BASELINE_REFS": SHA, "SCENARIO_ID": "one two"}
    with pytest.raises(steps.InputError, match="scenario-id must name exactly one scenario"):
        steps.check_args("manifest", env, WORKSPACE)


@pytest.mark.parametrize("cache", [
    "/work/provider", "/work/provider/cache", "/work/provider/sub/cache", "cache", "./cache", "./",
])
def test_manifest_tool_cache_inside_the_checkout_is_rejected(cache):
    env = {"MODE": "report", "BASELINE_REFS": SHA, "TOOL_CACHE_DIR": cache}
    with pytest.raises(steps.InputError, match="outside the provider checkout"):
        steps.check_args("manifest", env, WORKSPACE)


def test_manifest_tool_cache_outside_the_checkout_is_kept():
    env = {"MODE": "report", "BASELINE_REFS": SHA, "TOOL_CACHE_DIR": "/runner/tmp/manifest-tools"}
    assert steps.check_args("manifest", env, WORKSPACE)[
        steps.check_args("manifest", env, WORKSPACE).index("--tool-cache-dir") + 1
    ] == "/runner/tmp/manifest-tools"


def test_run_manifest_reports_invalid_input_as_an_error_without_running(capsys):
    def runner(*args, **kwargs):
        raise AssertionError("the checker must not run")

    env = {"MODE": "report", "BASELINE_REFS": SHA, "TOOL_CACHE_DIR": "/work/provider/cache"}
    assert steps.run_check("manifest", env, WORKSPACE, runner) == 2
    assert capsys.readouterr().out.startswith("::error::tool cache must live outside the provider checkout")


def test_run_manifest_passes_the_checker_exit_code_through():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1)

    env = {"MODE": "enforce", "BASELINE_REFS": SHA}
    assert steps.run_check("manifest", env, WORKSPACE, runner) == 1
    assert calls[0][1] == str(steps.CLI)
    assert calls[0][2] == "manifest-check"
    assert calls[0][-1] == "--enforce"


# prepare manifest

def test_manifest_prepare_args():
    env = {"MANIFEST_SET": "configs/manifests.yaml", "TOOL_CACHE_DIR": "/runner/tmp/tools"}
    assert steps.prepare_args("manifest", env, WORKSPACE) == [
        "manifest-prepare", "--repo", "/work/provider", "--manifest-set", "configs/manifests.yaml",
        "--tool-cache-dir", "/runner/tmp/tools",
    ]


def test_manifest_prepare_defaults_and_scenario_selection():
    env = {"SCENARIO_ID": "helm-prod", "TOOL_CACHE_DIR": "/runner/tmp/tools"}
    args = steps.prepare_args("manifest", env, WORKSPACE)
    assert args[args.index("--manifest-set") + 1] == ".rhoai/manifests.yaml"
    assert args[args.index("--scenario-id") + 1] == "helm-prod"


def test_manifest_prepare_requires_a_cache():
    with pytest.raises(steps.InputError, match="tool-cache-dir is required"):
        steps.prepare_args("manifest", {}, WORKSPACE)


def test_manifest_prepare_rejects_a_cache_inside_the_checkout():
    env = {"TOOL_CACHE_DIR": "/work/provider/cache"}
    with pytest.raises(steps.InputError, match="outside the provider checkout"):
        steps.prepare_args("manifest", env, WORKSPACE)


def test_run_prepare_reports_invalid_input_as_an_error_without_running(capsys):
    def runner(*args, **kwargs):
        raise AssertionError("the checker must not run")

    assert steps.run_prepare("manifest", {}, WORKSPACE, runner) == 2
    assert capsys.readouterr().out.startswith("::error::tool-cache-dir is required")


def test_run_prepare_passes_the_checker_exit_code_through():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    env = {"TOOL_CACHE_DIR": "/runner/tmp/tools"}
    assert steps.run_prepare("manifest", env, WORKSPACE, runner) == 0
    assert calls[0][1] == str(steps.CLI)
    assert calls[0][2] == "manifest-prepare"
    assert "--baseline-ref" not in calls[0]


# summarize manifest

def manifest_report(status="compatible", mode="report-only", **extra):
    report = {
        "status": status, "mode": mode, "manifest_set": ".rhoai/manifests.yaml",
        "policy_version": "2026-11-06", "candidate": {"head": SHA, "scenarios": {}},
        "candidate_findings": [], "baselines": [], "errors": [],
    }
    report.update(extra)
    return report


def compared_baseline(ref=SHA, **extra):
    baseline = {"ref": ref, "sha": ref, "status": "compared", "compatible": True,
                "scenarios": {}, "findings": [], "associated_candidate_findings": [], "errors": []}
    baseline.update(extra)
    return baseline


def test_manifest_summary_mixed_baselines_label_null_compatibility_truthfully():
    unresolved = "c" * 40
    blocked = "d" * 40
    report = manifest_report(status="error", baselines=[
        compared_baseline(compatible=False),
        {"ref": OTHER, "sha": OTHER, "status": "new", "compatible": None, "scenarios": {},
         "findings": [], "associated_candidate_findings": [], "errors": []},
        {"ref": unresolved, "sha": None, "status": "error", "compatible": None, "scenarios": {},
         "findings": [], "associated_candidate_findings": [],
         "errors": ["Cannot resolve baseline ref " + unresolved]},
        {"ref": blocked, "sha": None, "status": "not-run", "compatible": None, "scenarios": {
            "app": {"status": "not-run", "reason": "blocked: candidate scenario did not render",
                    "object_count": None, "errors": []}},
         "findings": [], "associated_candidate_findings": [], "errors": []},
    ], errors=["scenario 'app': no files match source pattern(s) 'manifests/absent.yaml'"])
    lines, commands = steps.summarize("manifest", report)
    assert lines[0] == "## Manifest compatibility: .rhoai/manifests.yaml"
    assert f"| `{SHA}` | `{SHA}` | compared | no | 0 | 0 |" in lines
    assert f"| `{OTHER}` | `{OTHER}` | new | untested (new) | 0 | 0 |" in lines
    assert f"| `{unresolved}` | `unresolved` | error | incomplete (error) | 0 | 0 |" in lines
    assert f"| `{blocked}` | `unresolved` | not-run | incomplete (not run) | 0 | 0 |" in lines
    # Never a false pass: null compatibility is never rendered as yes or no.
    assert not any(cell.endswith("| yes |") for cell in lines if cell.startswith("| `"))
    # Blocked scenarios keep their reason visible.
    assert "blocked: candidate scenario did not render" in " ".join(lines)
    assert commands == [
        f"::error::Manifest compatibility: .rhoai/manifests.yaml: error (report-only); "
        f"scenario 'app': no files match source pattern(s) 'manifests/absent.yaml'; "
        f"Cannot resolve baseline ref {unresolved}",
    ]


def test_manifest_summary_counts_candidate_findings_once_and_shows_associations():
    association = {"ref": SHA, "sha": SHA, "edge_id": "f" * 64,
                   "path": "/spec/template/spec/containers/0/env/0/valueFrom/configMapKeyRef",
                   "related_path": "/data/alpha"}
    finding = {
        "id": "required-reference-lost", "severity": "error", "scenario": "app",
        "path": "/spec/template/spec/containers/0/env/1/valueFrom/configMapKeyRef",
        "text": "Deployment web (default) requires ConfigMap shared (key 'alpha')",
        "resource": {"group": "apps", "kind": "Deployment", "namespace": "default", "name": "web"},
        "related_resource": {"group": "", "kind": "ConfigMap", "namespace": "default", "name": "shared"},
        "classification": "reference", "evidence": "graph", "edge_id": "e" * 64,
        "baseline_associations": [association],
    }
    report = manifest_report(status="breaking", mode="enforce", candidate_findings=[finding],
                             baselines=[compared_baseline(
                                 compatible=False,
                                 associated_candidate_findings=[
                                     {"scenario": "app", "id": "required-reference-lost", "edge_id": "e" * 64}],
                             )])
    lines, commands = steps.summarize("manifest", report)
    # Counted once globally: the finding line appears exactly once.
    finding_lines = [line for line in lines if "`required-reference-lost`" in line]
    assert len(finding_lines) == 1
    # The association is separate and keeps the original baseline pointer.
    assert (f"  - baseline `{SHA}` at "
            f"`/spec/template/spec/containers/0/env/0/valueFrom/configMapKeyRef`") in lines
    # The affected completed baseline shows the link and stays incompatible.
    assert f"| `{SHA}` | `{SHA}` | compared | no | 0 | 1 |" in lines
    assert "- **Candidate validation findings:** 1" in lines
    assert commands[0].startswith(
        "::error::Manifest compatibility: .rhoai/manifests.yaml: breaking (enforce); "
        "1 breaking findings, 0 warnings.")


def test_manifest_summary_shows_warning_only_and_coverage_findings():
    removal = {"id": "resource-removed", "severity": "warn", "classification": "removal",
               "scenario": "app", "path": "", "text": "ConfigMap shared removed from the render",
               "resource": {"group": "", "kind": "ConfigMap", "namespace": "default", "name": "shared"}}
    partial = {"id": "rule-coverage-partial", "severity": "warn", "classification": "coverage",
               "scenario": "app", "path": "", "text": "scenario targets unaudited Kubernetes 1.34 fields",
               "resource": {"group": "", "kind": "", "namespace": "default", "name": "app"}}
    risk = {"id": "conditional-update-risk", "severity": "warn", "classification": "risk",
            "scenario": "app", "path": "/spec", "text": "live eligibility unknown",
            "resource": {"group": "batch", "kind": "Job", "namespace": "default", "name": "migrate"}}
    report = manifest_report(baselines=[compared_baseline(findings=[removal, partial, risk])])
    lines, commands = steps.summarize("manifest", report)
    assert "- **Warnings:** 3" in lines
    assert "### Coverage limitations" in lines
    assert "`rule-coverage-partial`" in " ".join(lines)
    assert "`conditional-update-risk`" in " ".join(lines)
    assert "### Warnings" in lines
    assert "`resource-removed`" in " ".join(lines)
    # Warning-only findings never dominate the result or the command level.
    assert report["status"] == "compatible"
    assert commands == ["::notice::Manifest compatibility: .rhoai/manifests.yaml: compatible "
                        "(report-only); 0 candidate findings, 3 baseline findings, 3 warnings."]


def test_manifest_summary_shows_suppressed_findings_and_their_reasons():
    waived = {"id": "storageclass-provisioner-immutable", "severity": "error", "classification": "immutable",
              "scenario": "app", "path": "/provisioner", "text": "provisioner changed",
              "resource": {"group": "storage.k8s.io", "kind": "StorageClass", "namespace": "", "name": "fast"},
              "suppressed": True, "suppressed_reason": "coordinated migration"}
    report = manifest_report(baselines=[compared_baseline(findings=[waived])])
    lines, commands = steps.summarize("manifest", report)
    assert "### Suppressed findings (waived exceptions)" in lines
    assert "`storageclass-provisioner-immutable` at `/provisioner`" in " ".join(lines)
    assert "waived: coordinated migration" in " ".join(lines)
    assert "(severity stays error)" in " ".join(lines)
    assert "- **Baseline comparison findings:** 0 active, 1 suppressed" in lines
    assert commands[0].startswith("::notice::Manifest compatibility: .rhoai/manifests.yaml: compatible")


def test_manifest_summary_shows_candidate_scenario_states_and_errors():
    report = manifest_report(status="error", candidate={"head": SHA, "scenarios": {
        "app": {"status": "error", "object_count": None, "errors": [
            "scenario 'app': no files match source pattern(s) 'manifests/absent.yaml'"]},
        "raw": {"status": "ready", "object_count": 3, "errors": []},
    }}, errors=["scenario 'app': no files match source pattern(s) 'manifests/absent.yaml'"])
    lines, commands = steps.summarize("manifest", report)
    assert "| `app` | error | unknown | 1 |" in lines
    assert "| `raw` | ready | 3 | 0 |" in lines
    assert "### Errors" in lines
    assert "- scenario 'app': no files match source pattern(s) 'manifests/absent.yaml'" in lines
    assert commands[0].startswith("::error::Manifest compatibility: .rhoai/manifests.yaml: error")


def test_manifest_summary_escapes_untrusted_text():
    hostile = "line one\nline two | table | injection %0A ::error:: fake"
    finding = {"id": "resource-removed", "severity": "warn", "classification": "removal",
               "scenario": "app|id", "path": "/data", "text": hostile,
               "resource": {"group": "", "kind": "ConfigMap", "namespace": "default", "name": "shared"}}
    report = manifest_report(status="error", baselines=[compared_baseline(findings=[finding])],
                             errors=[hostile])
    lines, commands = steps.summarize("manifest", report)
    joined = "\n".join(lines)
    # Markdown cells escape pipes and collapse newlines.
    assert "line one line two \\| table \\| injection %0A ::error:: fake" in joined
    assert "\nline two" not in joined
    # Workflow commands escape the dangerous characters.
    assert "line one%0Aline two" in commands[0]
    assert "%0A ::error:: fake" not in commands[0]


def test_summarize_manifest_report_writes_markdown_and_commands(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(manifest_report()))
    summary = tmp_path / "summary.md"
    assert steps.summarize_report("manifest", {"GITHUB_STEP_SUMMARY": str(summary)}, report_path) == 0
    assert summary.read_text().startswith("## Manifest compatibility: .rhoai/manifests.yaml\n")
    assert capsys.readouterr().out == "::notice::Manifest compatibility: .rhoai/manifests.yaml: " \
                                       "compatible (report-only); 0 candidate findings, 0 baseline findings, 0 warnings.\n"


def test_missing_manifest_report_fails_the_summary_step(tmp_path, capsys):
    assert steps.summarize_report("manifest", {}, tmp_path / "report.json") == 1
    assert capsys.readouterr().out == "::error::Manifest compatibility check did not produce report.json\n"


def test_malformed_report_fails_the_summary_step(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    report_path.write_text("{not json", encoding="utf-8")
    assert steps.summarize_report("manifest", {}, report_path) == 1
    assert capsys.readouterr().out.startswith("::error::Manifest compatibility check produced an unreadable report.json")


def test_malformed_report_fails_for_existing_checks_too(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    report_path.write_text("not json at all", encoding="utf-8")
    assert steps.summarize_report("crd", {}, report_path) == 1
    assert capsys.readouterr().out.startswith("::error::CRD compatibility check produced an unreadable report.json")
