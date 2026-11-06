"""Real-renderer integration tests for the manifest compatibility checker.

Everything in this module (selected with ``-m manifest_renderers``) invokes
the actual pinned go-run tools — ``helm.sh/helm/v4/cmd/helm@v4.3.1`` and
``sigs.k8s.io/kustomize/kustomize/v5@v5.8.3`` — exactly as production does:
offline, through a prepared tool cache, with no installed binaries and no
mocked subprocesses. The group requires:

* Go >= 1.27 on PATH (the pinned Kustomize module requires it), and
* ``MANIFEST_RENDERERS_CACHE`` pointing at a cache prepared by
  ``cli.py manifest-prepare --repo . --manifest-set selftest/manifests.yaml
  --tool-cache-dir <dir>`` (outside any repository checkout).

A missing or unprepared cache fails the tests loudly instead of skipping
them: a silent CI skip is exactly what this group exists to prevent.

The fixtures under ``selftest/manifests/`` are copied verbatim into temporary
provider repositories, so the tests exercise the same inputs the reusable
workflow self-test (``.github/workflows/self-test.yml``) renders in CI.
"""

import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[3]
CLI = ROOT / "cmd" / "contract-tests" / "cli.py"
FIXTURES = ROOT / "selftest" / "manifests"
DESCRIPTOR = ROOT / "selftest" / "manifests.yaml"

spec = importlib.util.spec_from_file_location(
    "manifest_compat_renderers", ROOT / "modules" / "manifest-compat" / "renderers.py"
)
assert spec is not None and spec.loader is not None
renderers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderers)

pytestmark = pytest.mark.manifest_renderers

ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
TIMEOUT = 600
GO_VERSION = re.compile(r"go version go(\d+)\.(\d+)\.")


# ---------------------------------------------------------------------------
# Session requirements: a real Go toolchain and a prepared renderer cache
# ---------------------------------------------------------------------------

def _local_go_version() -> str:
    try:
        result = subprocess.run(["go", "version"], capture_output=True, text=True,
                                timeout=60, env=ENV)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout if result.returncode == 0 else ""


@pytest.fixture(scope="session")
def go_toolchain() -> str:
    """The local Go version, proven new enough for both pinned modules."""
    version_text = _local_go_version()
    match = GO_VERSION.search(version_text)
    if match is None:
        pytest.fail(
            "go must be on PATH for the manifest_renderers group: the pinned "
            "helm and kustomize modules are invoked with `go run`; install "
            "Go 1.27 or newer (no installed renderer binaries are used)"
        )
    major, minor = int(match.group(1)), int(match.group(2))
    if (major, minor) < (1, 27):
        pytest.fail(
            f"local go {major}.{minor} is too old for the manifest_renderers "
            "group: the pinned Kustomize module requires Go >= 1.27"
        )
    return f"{major}.{minor}"


@pytest.fixture(scope="session")
def tool_cache(go_toolchain: str) -> Path:
    """The prepared renderer cache named by MANIFEST_RENDERERS_CACHE."""
    raw = os.environ.get("MANIFEST_RENDERERS_CACHE", "")
    if not raw:
        pytest.fail(
            "MANIFEST_RENDERERS_CACHE is not set; prepare a renderer tool cache "
            "outside any repository checkout with\n"
            f"  {sys.executable} {CLI} manifest-prepare --repo {ROOT} "
            "--manifest-set selftest/manifests.yaml --tool-cache-dir <dir>\n"
            "and point MANIFEST_RENDERERS_CACHE at it"
        )
    cache = Path(raw)
    if not cache.is_dir():
        pytest.fail(f"MANIFEST_RENDERERS_CACHE {raw!r} is not a directory")
    for renderer in ("helm", "kustomize"):
        try:
            renderers._verify_prepared_cache(cache, renderer)
        except Exception as error:  # noqa: BLE001 - turned into a loud failure
            pytest.fail(f"renderer cache at {raw!r} is unusable: {error}")
    return cache


# ---------------------------------------------------------------------------
# Temporary provider repositories, seeded from the self-test fixtures
# ---------------------------------------------------------------------------

class ProviderRepo:
    """A temporary provider repository with an isolated Git environment."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q", "-b", "main", ".")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "test")

    def git(self, *args: str) -> str:
        result = subprocess.run(["git", *args], cwd=self.root, env=ENV,
                                capture_output=True, text=True, check=True)
        return result.stdout.strip()

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def edit(self, relative: str, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        assert old in text, f"{old!r} not found in {relative}"
        path.write_text(text.replace(old, new), encoding="utf-8")

    def copy_fixtures(self, *subtrees: str) -> None:
        """Copy selftest/manifests/<subtree> into the repository verbatim."""
        for subtree in subtrees:
            source = FIXTURES / subtree
            assert source.is_dir(), f"missing fixture subtree {source}"
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    relative = path.relative_to(ROOT).as_posix()
                    self.write(relative, path.read_text(encoding="utf-8"))

    def move_tree(self, source_rel: str, target_rel: str) -> None:
        source = self.root / source_rel
        target = self.root / target_rel
        assert source.is_dir(), f"missing directory {source_rel}"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(target))

    def load_descriptor(self) -> dict[str, Any]:
        return yaml.safe_load(DESCRIPTOR.read_text(encoding="utf-8"))

    def scenarios(self, *scenario_ids: str) -> list[dict[str, Any]]:
        document = self.load_descriptor()
        selected = [scenario for scenario in document["spec"]["scenarios"]
                    if scenario["id"] in scenario_ids]
        assert len(selected) == len(scenario_ids), "unknown scenario id requested"
        return copy.deepcopy(selected)

    def descriptor(self, scenarios: list[dict[str, Any]] | None = None,
                   name: str = "selftest") -> None:
        document = self.load_descriptor()
        document["metadata"]["name"] = name
        if scenarios is not None:
            document["spec"]["scenarios"] = scenarios
        self.write(".rhoai/manifests.yaml", yaml.safe_dump(document, sort_keys=False))

    def commit(self, message: str = "commit") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def check(self, baselines: list[str], output: Path, *, enforce: bool = False,
              scenario_id: str | None = None, cache: Path | None = None,
              manifest_set: str = ".rhoai/manifests.yaml",
              env: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        argv = [sys.executable, str(CLI), "manifest-check",
                "--repo", str(self.root), "--manifest-set", manifest_set]
        for baseline in baselines:
            argv += ["--baseline-ref", baseline]
        if scenario_id is not None:
            argv += ["--scenario-id", scenario_id]
        argv += ["--output-dir", str(output)]
        if cache is not None:
            argv += ["--tool-cache-dir", str(cache)]
        if enforce:
            argv.append("--enforce")
        result = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT,
                                env=env or ENV)
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        return result, report


@pytest.fixture
def repo(tmp_path: Path) -> ProviderRepo:
    return ProviderRepo(tmp_path / "repo")


@pytest.fixture
def outputs(tmp_path: Path) -> Path:
    # The CLI requires a fresh output directory per run; each test uses this
    # path (or a sibling) at most once.
    return tmp_path / "reports"


def raw_scenario(scenario_id: str, sources: list[str],
                 version: str = "1.37.2", **extra: Any) -> dict[str, Any]:
    scenario: dict[str, Any] = {
        "id": scenario_id,
        "renderer": "raw",
        "namespace": "default",
        "kubernetesVersion": version,
        "sources": sources,
    }
    scenario.update(extra)
    return scenario


def scenario_baseline_findings(report: dict[str, Any], scenario_id: str,
                               index: int = 0) -> list[dict[str, Any]]:
    return [finding for finding in report["baselines"][index]["findings"]
            if finding.get("scenario") == scenario_id]


def candidate_findings_for(report: dict[str, Any], scenario_id: str) -> list[dict[str, Any]]:
    return [finding for finding in report.get("candidate_findings", [])
            if finding.get("scenario") == scenario_id]


def joined_errors(report: dict[str, Any]) -> str:
    parts = list(report.get("errors", []))
    for baseline in report.get("baselines", []):
        parts.extend(baseline.get("errors", []))
        for entry in (baseline.get("scenarios") or {}).values():
            parts.extend(entry.get("errors") or [])
    for entry in (report.get("candidate") or {}).get("scenarios", {}).values():
        parts.extend(entry.get("errors") or [])
    return "\n".join(str(part) for part in parts)


PVC = """apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: {size}
"""

JOB_SCHEDULING = """apiVersion: batch/v1
kind: Job
metadata:
  name: migrate
  namespace: default
spec:
  scheduling:
    parallelism: {parallelism}
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: example.com/migrate:1.0
"""


# ---------------------------------------------------------------------------
# Preparation and offline rendering
# ---------------------------------------------------------------------------

class TestPreparationAndOfflineRendering:
    def test_prepare_and_render_need_only_the_cache(
        self, tool_cache: Path, tmp_path: Path
    ) -> None:
        """manifest-prepare succeeds with the proxy pointed at the cache itself.

        With GOPROXY as a file:// URL rooted at the prepared cache's download
        directory, no network request is possible, so a successful prepare
        proves the cache holds everything the pinned go-run commands need —
        the same cache every offline render in this module reuses.
        """
        proxy = (tool_cache / "gomodcache" / "cache" / "download").as_uri()
        argv = [sys.executable, str(CLI), "manifest-prepare",
                "--repo", str(ROOT), "--manifest-set", "selftest/manifests.yaml",
                "--tool-cache-dir", str(tool_cache)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT,
                                 cwd=tmp_path, env={**ENV, "GOPROXY": proxy})
        assert result.returncode == 0, result.stderr
        provenance = json.loads(result.stdout)
        assert provenance["needed"] == ["helm", "kustomize"]
        assert provenance["provider_content_rendered"] is False
        pins = {tool["renderer"]: tool["pin"] for tool in provenance["tools"]}
        assert pins == {"helm": renderers.HELM_PIN, "kustomize": renderers.KUSTOMIZE_PIN}
        assert (tool_cache / "prepared.json").is_file()

    def test_unprepared_cache_fails_actionably(
        self, repo: ProviderRepo, outputs: Path, tool_cache: Path, tmp_path: Path
    ) -> None:
        """An empty cache must fail closed with instructions, never silently."""
        repo.copy_fixtures("kustomize")
        repo.descriptor(repo.scenarios("kustomize-app"))
        base = repo.commit("baseline")
        empty = tmp_path / "empty-cache"
        empty.mkdir()
        result, report = repo.check([base], outputs, cache=empty)
        assert result.returncode == 2
        assert report["status"] == "error"
        errors = joined_errors(report)
        assert "does not contain kustomize" in errors
        assert "manifest-prepare" in errors
        # The session cache itself still works for the same inputs, proving the
        # empty cache — not the fixtures — caused the failure.
        ok_result, ok_report = repo.check([base], outputs.parent / "ok", cache=tool_cache)
        assert ok_result.returncode == 0
        assert ok_report["status"] == "compatible"


# ---------------------------------------------------------------------------
# Real rendering: compatible changes, breaks, and conditional warnings
# ---------------------------------------------------------------------------

class TestRealRendererComparisons:
    def test_compatible_rollout_across_all_renderers(
        self, repo: ProviderRepo, outputs: Path, tool_cache: Path
    ) -> None:
        repo.copy_fixtures("raw", "helm", "kustomize")
        repo.descriptor()
        base = repo.commit("baseline")
        repo.edit("selftest/manifests/raw/deployment.yaml",
                  "image: example.com/web:1.0", "image: example.com/web:1.1")
        repo.edit("selftest/manifests/helm/values-selftest.yaml",
                  'tag: "1.1"', 'tag: "1.2"')
        repo.edit("selftest/manifests/kustomize/base/deployment.yaml",
                  "image: example.com/web:1.0", "image: example.com/web:1.1")
        repo.commit("rollout")

        result, report = repo.check([base], outputs, cache=tool_cache, enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"
        assert report["errors"] == []

        candidate_scenarios = report["candidate"]["scenarios"]
        assert {scenario_id: entry["status"]
                for scenario_id, entry in candidate_scenarios.items()} == {
            "raw-app": "ready", "helm-app": "ready", "kustomize-app": "ready",
        }
        assert {scenario_id: entry["object_count"]
                for scenario_id, entry in candidate_scenarios.items()} == {
            "raw-app": 3, "helm-app": 4, "kustomize-app": 3,
        }
        baseline = report["baselines"][0]
        assert baseline["status"] == "compared"
        assert baseline["compatible"] is True
        assert baseline["findings"] == []
        assert {scenario_id: entry["status"]
                for scenario_id, entry in baseline["scenarios"].items()} == {
            "raw-app": "compared", "helm-app": "compared", "kustomize-app": "compared",
        }

    def test_immutable_selector_change_enforces(
        self, repo: ProviderRepo, outputs: Path
    ) -> None:
        repo.copy_fixtures("raw")
        repo.descriptor(repo.scenarios("raw-app"))
        base = repo.commit("baseline")
        # Selector and template labels move together, so the Deployment stays
        # internally consistent while its (immutable) selector changes and the
        # Service selector stops matching the template.
        repo.edit("selftest/manifests/raw/deployment.yaml", "app: web", "app: web2")
        repo.commit("selector change")

        enforced, enforce_report = repo.check([base], outputs, enforce=True)
        assert enforced.returncode == 1
        assert enforce_report["status"] == "breaking"
        findings = enforce_report["baselines"][0]["findings"]
        by_id = {finding["id"]: finding for finding in findings}
        assert by_id["deployment-selector-immutable"]["severity"] == "error"
        assert by_id["selector-target-lost"]["severity"] == "error"
        assert by_id["selector-target-lost"]["resource"]["name"] == "web"

        # Report mode surfaces the same findings without failing the run.
        reported, report_only = repo.check([base], outputs.parent / "report")
        assert reported.returncode == 0
        assert report_only["status"] == "breaking"
        assert {finding["id"] for finding in report_only["baselines"][0]["findings"]} == \
            {finding["id"] for finding in findings}

    def test_template_label_loss_is_a_candidate_validation_break(
        self, repo: ProviderRepo, outputs: Path
    ) -> None:
        repo.copy_fixtures("raw")
        repo.descriptor(repo.scenarios("raw-app"))
        base = repo.commit("baseline")
        repo.edit("selftest/manifests/raw/deployment.yaml",
                  "    metadata:\n      labels:\n        app: web\n",
                  "    metadata:\n      labels: {}\n")
        repo.commit("label loss")

        result, report = repo.check([base], outputs, enforce=True)
        assert result.returncode == 1
        assert report["status"] == "breaking"
        # The mismatch exists in the candidate alone: it is validated on the
        # candidate and breaks every baseline, enforce or not.
        candidates = candidate_findings_for(report, "raw-app")
        assert [finding["id"] for finding in candidates] == ["selector-template-mismatch"]
        assert candidates[0]["severity"] == "error"
        baseline = report["baselines"][0]
        assert baseline["compatible"] is False
        assert any(finding["id"] == "selector-target-lost"
                   for finding in baseline["findings"])

    def test_storage_decrease_is_a_conditional_warning(
        self, repo: ProviderRepo, outputs: Path
    ) -> None:
        scenario = raw_scenario("storage", ["manifests/storage/*.yaml"])
        repo.descriptor([scenario])
        repo.write("manifests/storage/pvc.yaml", PVC.format(size="10Gi"))
        base = repo.commit("baseline")
        repo.write("manifests/storage/pvc.yaml", PVC.format(size="5Gi"))
        repo.commit("shrink")

        # Warnings alone stay compatible, even in enforce mode.
        result, report = repo.check([base], outputs, enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"
        findings = report["baselines"][0]["findings"]
        assert [finding["id"] for finding in findings] == ["pvc-storage-resize-risk"]
        assert findings[0]["severity"] == "warn"
        assert "decreased" in findings[0]["text"]

    def test_job_scheduling_change_is_a_conditional_warning(
        self, repo: ProviderRepo, outputs: Path
    ) -> None:
        scenario = raw_scenario("jobs", ["manifests/jobs/*.yaml"])
        repo.descriptor([scenario])
        repo.write("manifests/jobs/migrate.yaml", JOB_SCHEDULING.format(parallelism="1"))
        base = repo.commit("baseline")
        repo.write("manifests/jobs/migrate.yaml", JOB_SCHEDULING.format(parallelism="2"))
        repo.commit("reschedule")

        result, report = repo.check([base], outputs, enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"
        findings = report["baselines"][0]["findings"]
        assert [finding["id"] for finding in findings] == ["job-scheduling-update"]
        assert findings[0]["severity"] == "warn"
        assert findings[0]["resource"]["name"] == "migrate"

    def test_generated_configmap_rotation_keeps_references(
        self, repo: ProviderRepo, outputs: Path, tool_cache: Path
    ) -> None:
        repo.copy_fixtures("kustomize")
        repo.descriptor(repo.scenarios("kustomize-app"))
        base = repo.commit("baseline")
        repo.edit("selftest/manifests/kustomize/base/kustomization.yaml",
                  "alpha=one", "alpha=two")
        repo.commit("rotate generated config")

        result, report = repo.check([base], outputs, cache=tool_cache, enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"
        findings = report["baselines"][0]["findings"]
        # The old hash-suffixed object disappears (ordinary removal warning) and
        # nothing else fires: kustomize rewrote the Deployment reference to the
        # new generated name, so no reference was lost.
        assert [finding["id"] for finding in findings] == ["resource-removed"]
        assert findings[0]["severity"] == "warn"
        assert findings[0]["resource"]["kind"] == "ConfigMap"
        assert report["candidate_findings"] == []

    def test_moved_kustomize_path_compares_via_baseline_inputs(
        self, repo: ProviderRepo, outputs: Path, tool_cache: Path
    ) -> None:
        repo.copy_fixtures("kustomize")
        repo.descriptor(repo.scenarios("kustomize-app"))
        base = repo.commit("baseline")
        repo.move_tree("selftest/manifests/kustomize", "config/kustomize")
        scenarios = repo.scenarios("kustomize-app")
        scenarios[0]["path"] = "config/kustomize/overlay"
        scenarios[0]["baselineCases"].append({
            "ref": base, "state": "existing",
            "inputs": {"path": "selftest/manifests/kustomize/overlay"},
        })
        repo.descriptor(scenarios)
        repo.commit("move kustomization")

        result, report = repo.check([base], outputs, cache=tool_cache, enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"
        baseline = report["baselines"][0]
        assert baseline["status"] == "compared"
        assert baseline["compatible"] is True
        assert baseline["findings"] == []
        assert baseline["scenarios"]["kustomize-app"]["object_count"] == 3

    def test_zero_object_candidate_warns_unprotected_and_enforces_protected(
        self, repo: ProviderRepo, outputs: Path, tool_cache: Path
    ) -> None:
        repo.copy_fixtures("kustomize")
        repo.descriptor(repo.scenarios("kustomize-app"))
        base = repo.commit("baseline")
        repo.write("selftest/manifests/kustomize/overlay/kustomization.yaml",
                   "resources: []\nnamespace: selftest\n")
        repo.commit("empty render")

        # A successful zero-object render is a valid candidate: every baseline
        # object was removed, which is a warning for unprotected resources.
        result, report = repo.check([base], outputs, cache=tool_cache, enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"
        assert report["candidate"]["scenarios"]["kustomize-app"]["object_count"] == 0
        removals = report["baselines"][0]["findings"]
        assert {finding["id"] for finding in removals} == {"resource-removed"}
        assert all(finding["severity"] == "warn" for finding in removals)
        assert len(removals) == 3

        # Protecting one of the removed objects turns its removal into an error.
        scenarios = repo.scenarios("kustomize-app")
        scenarios[0]["protectedResources"] = [{
            "group": "apps", "kind": "Deployment",
            "namespace": "selftest", "name": "web",
        }]
        repo.descriptor(scenarios)
        protected, protected_report = repo.check(
            [base], outputs.parent / "protected", cache=tool_cache, enforce=True)
        assert protected.returncode == 1
        assert protected_report["status"] == "breaking"
        findings = protected_report["baselines"][0]["findings"]
        by_id = {finding["id"]: finding for finding in findings}
        assert by_id["protected-resource-removed"]["severity"] == "error"
        assert by_id["protected-resource-removed"]["resource"]["kind"] == "Deployment"

    def test_equivalent_change_across_renderers_yields_equivalent_findings(
        self, repo: ProviderRepo, outputs: Path, tool_cache: Path
    ) -> None:
        """The same object break maps to the same rules under every renderer.

        Each renderer emits its objects in a different order from a different
        input shape; the rule inventory must depend on the rendered objects,
        not on the source. The raw scenario also lists its sources in reverse
        order to prove source ordering is irrelevant.
        """
        repo.copy_fixtures("raw", "helm", "kustomize")
        scenarios = repo.scenarios("raw-app", "helm-app", "kustomize-app")
        scenarios[0]["sources"] = [
            "selftest/manifests/raw/service.yaml",
            "selftest/manifests/raw/configmap.yaml",
            "selftest/manifests/raw/deployment.yaml",
        ]
        repo.descriptor(scenarios)
        base = repo.commit("baseline")
        # Orphan the pod-template label in every renderer: the Deployment keeps
        # its own selector, so its template stops matching both its selector
        # and the Service selector — a break expressed identically everywhere.
        repo.edit("selftest/manifests/raw/deployment.yaml",
                  "    metadata:\n      labels:\n        app: web\n",
                  "    metadata:\n      labels:\n        app: orphaned\n")
        repo.edit("selftest/manifests/helm/app/templates/deployment.yaml",
                  "    metadata:\n      labels:\n        app: {{ .Release.Name }}\n",
                  "    metadata:\n      labels:\n        app: orphaned\n")
        repo.edit("selftest/manifests/kustomize/base/deployment.yaml",
                  "    metadata:\n      labels:\n        app: web\n",
                  "    metadata:\n      labels:\n        app: orphaned\n")
        repo.commit("orphan template label")

        result, report = repo.check([base], outputs, cache=tool_cache, enforce=True)
        assert result.returncode == 1
        assert report["status"] == "breaking"
        baseline = report["baselines"][0]
        assert baseline["status"] == "compared"
        per_scenario: dict[str, set[tuple[str, str]]] = {}
        for scenario_id in ("raw-app", "helm-app", "kustomize-app"):
            findings = scenario_baseline_findings(report, scenario_id)
            assert findings, f"no findings for {scenario_id}"
            per_scenario[scenario_id] = {(finding["id"], finding["severity"])
                                         for finding in findings}
            candidate = candidate_findings_for(report, scenario_id)
            assert [finding["id"] for finding in candidate] == ["selector-template-mismatch"]
            assert candidate[0]["severity"] == "error"
        assert per_scenario["raw-app"] == per_scenario["helm-app"] == per_scenario["kustomize-app"]
        assert ("selector-target-lost", "error") in per_scenario["raw-app"]

    def test_report_is_byte_deterministic(
        self, repo: ProviderRepo, outputs: Path, tool_cache: Path
    ) -> None:
        repo.copy_fixtures("raw", "helm", "kustomize")
        repo.descriptor()
        base = repo.commit("baseline")
        repo.edit("selftest/manifests/helm/values-selftest.yaml",
                  'tag: "1.1"', 'tag: "1.2"')
        repo.commit("rollout")

        first, _ = repo.check([base], outputs / "one", cache=tool_cache)
        second, _ = repo.check([base], outputs / "two", cache=tool_cache)
        assert first.returncode == 0 and second.returncode == 0
        assert (outputs / "one" / "report.json").read_bytes() == \
            (outputs / "two" / "report.json").read_bytes()


# ---------------------------------------------------------------------------
# Explicit-new bootstrap declarations (PR base and previous-push events)
# ---------------------------------------------------------------------------

class TestBootstrapDeclarations:
    def test_declared_absent_baseline_is_explicitly_new(
        self, repo: ProviderRepo, outputs: Path
    ) -> None:
        """The fixture-introduction event: PR base lacks the sources."""
        pre = repo.commit("history before the fixtures")
        repo.copy_fixtures("raw")
        scenarios = repo.scenarios("raw-app")
        scenarios[0]["baselineCases"].append({
            "ref": pre, "state": "new",
            "reason": "verified absence: the fixtures were introduced later",
        })
        repo.descriptor(scenarios)
        repo.commit("introduce fixtures")

        result, report = repo.check([pre], outputs, enforce=True)
        assert result.returncode == 0
        assert report["status"] == "new"
        baseline = report["baselines"][0]
        assert baseline["status"] == "new"
        assert baseline["compatible"] is None
        entry = baseline["scenarios"]["raw-app"]
        assert entry["status"] == "new"
        assert "verified absence" in entry["reason"]
        assert baseline["findings"] == []
        # The shipped descriptor's real historical declarations (fab2dfff and
        # 8eb2880) were never requested: unused provenance, not an error.
        assert report["errors"] == []
        assert "stale" not in joined_errors(report)

    def test_absent_baseline_without_declaration_fails_actionably(
        self, repo: ProviderRepo, outputs: Path
    ) -> None:
        pre = repo.commit("history before the fixtures")
        repo.copy_fixtures("raw")
        repo.descriptor(repo.scenarios("raw-app"))
        repo.commit("introduce fixtures")

        result, report = repo.check([pre], outputs)
        assert result.returncode == 2
        assert report["status"] == "error"
        errors = joined_errors(report)
        assert "inputs are absent at baseline" in errors
        assert "declare an explicit new baselineCase" in errors

    def test_changed_event_ref_without_declaration_fails(
        self, repo: ProviderRepo, outputs: Path
    ) -> None:
        """A different previous-push ref is not covered by another declaration."""
        repo.commit("first push before the fixtures")
        second = repo.commit("second push, still no fixtures")
        repo.copy_fixtures("raw")
        repo.descriptor(repo.scenarios("raw-app"))
        repo.commit("introduce fixtures")

        result, report = repo.check([second], outputs)
        assert result.returncode == 2
        assert report["status"] == "error"
        assert "declare an explicit new baselineCase" in joined_errors(report)

    def test_false_new_declaration_for_present_inputs_fails(
        self, repo: ProviderRepo, outputs: Path
    ) -> None:
        pre = repo.commit("history before the fixtures")
        repo.copy_fixtures("raw")
        repo.descriptor(repo.scenarios("raw-app"))
        introduction = repo.commit("introduce fixtures")
        repo.edit("selftest/manifests/raw/deployment.yaml",
                  "image: example.com/web:1.0", "image: example.com/web:1.1")
        scenarios = repo.scenarios("raw-app")
        scenarios[0]["baselineCases"].append({
            "ref": introduction, "state": "new",
            "reason": "falsely claims the inputs are absent",
        })
        repo.descriptor(scenarios)
        repo.commit("rollout with a false declaration")

        result, report = repo.check([introduction], outputs)
        assert result.returncode == 2
        assert report["status"] == "error"
        errors = joined_errors(report)
        assert "declares scenario 'raw-app' new but its inputs are present" in errors
        assert "must be compared, not declared new" in errors

    def test_partially_missing_inputs_cannot_be_declared_new(
        self, repo: ProviderRepo, outputs: Path, tool_cache: Path
    ) -> None:
        """A baseline with the chart but not the selected values file."""
        repo.copy_fixtures("helm/app")  # chart only: the selected values file is absent
        pre = repo.commit("chart without the values file")
        repo.copy_fixtures("helm")  # candidate has the complete source set
        scenarios = repo.scenarios("helm-app")
        scenarios[0]["baselineCases"].append({
            "ref": pre, "state": "new",
            "reason": "falsely claims a fully absent source set",
        })
        repo.descriptor(scenarios)
        repo.commit("complete the source set")

        result, report = repo.check([pre], outputs, cache=tool_cache)
        assert result.returncode == 2
        assert report["status"] == "error"
        errors = joined_errors(report)
        assert "some inputs are present" in errors
        assert "cannot be declared new" in errors

    def test_later_baselines_with_fixtures_compare_normally(
        self, repo: ProviderRepo, outputs: Path, tool_cache: Path
    ) -> None:
        """After introduction, event baselines contain the fixtures.

        The declaration for the pre-fixture ref stays behind as harmless
        unused provenance while the requested baseline compares for real.
        """
        pre = repo.commit("history before the fixtures")
        repo.copy_fixtures("raw", "kustomize")
        scenarios = repo.scenarios("raw-app", "kustomize-app")
        for scenario in scenarios:
            scenario["baselineCases"].append({
                "ref": pre, "state": "new",
                "reason": "verified absence: the fixtures were introduced later",
            })
        repo.descriptor(scenarios)
        repo.commit("introduce fixtures")
        repo.edit("selftest/manifests/kustomize/base/deployment.yaml",
                  "image: example.com/web:1.0", "image: example.com/web:1.1")
        later = repo.commit("rollout")

        result, report = repo.check([later], outputs, cache=tool_cache, enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"
        baseline = report["baselines"][0]
        assert baseline["status"] == "compared"
        assert baseline["compatible"] is True
        assert baseline["findings"] == []
        assert report["errors"] == []
        assert "stale" not in joined_errors(report)
