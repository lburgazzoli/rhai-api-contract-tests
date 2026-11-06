"""Regression tests for the manifest compatibility checker and its CLI wiring.

Runs the real CLI as a subprocess against temporary Git repositories, so the
full prepare/check flows (config validation, snapshots, rendering, comparison,
exceptions, correlation, report publication, cleanup) are exercised exactly as
providers invoke them. Raw scenarios keep every test offline: no Go toolchain,
tool cache, network, or cluster is required.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "modules" / "manifest-compat" / "checker.py"
CLI = ROOT / "cmd" / "contract-tests" / "cli.py"
POLICY = ROOT / "modules" / "manifest-compat" / "policy.json"

spec = importlib.util.spec_from_file_location("manifest_compat_checker", MODULE)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

CATALOGUE = json.loads(POLICY.read_text(encoding="utf-8"))

ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}


STORAGE_CLASS = """apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast
provisioner: example.com/fast
"""

STORAGE_CLASS_CHANGED = STORAGE_CLASS.replace("example.com/fast", "example.com/slow")

CONFIGMAP = """apiVersion: v1
kind: ConfigMap
metadata:
  name: shared
  namespace: default
data:
  alpha: one
  beta: two
"""

CONFIGMAP_KEY_DROPPED = """apiVersion: v1
kind: ConfigMap
metadata:
  name: shared
  namespace: default
data:
  beta: two
"""

CONFIGMAP_ADDED = """apiVersion: v1
kind: ConfigMap
metadata:
  name: added
  namespace: default
data:
  key: value
"""

DEPLOYMENT_WITH_ENV = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: example.com/app:1
          env:
            - name: ONE
              valueFrom:
                configMapKeyRef:
                  name: shared
                  key: alpha
            - name: TWO
              valueFrom:
                configMapKeyRef:
                  name: shared
                  key: beta
"""

SECRET = """apiVersion: v1
kind: Secret
metadata:
  name: creds
  namespace: default
type: Opaque
stringData:
  password: manifest-check-secret-marker
"""

KUSTOMIZE_TOOLS = {"helmVersion": "4.3.1", "kustomizeVersion": "5.8.3"}

RENDERED_OBJECT = """apiVersion: v1
kind: ConfigMap
metadata:
  name: shared
data:
  alpha: one
"""


def fake_renderer_run(real_run: Any, render_output: bytes) -> Any:
    """Subprocess double for in-process kustomize checks: no Go, no network.

    Git commands pass through to the real runner, ``go version`` reports a
    compatible toolchain, and every ``go run`` render returns the fixed
    ``render_output`` (identical on both determinism passes).
    """
    def fake(argv: Any, *, cwd: Any = None, env: Any = None, timeout: float,
             stdout_limit: int, stderr_limit: int = 8192
             ) -> subprocess.CompletedProcess[bytes]:
        command = [str(argument) for argument in argv]
        if command[0] == "git":
            return real_run(command, cwd=cwd, env=env, timeout=timeout,
                            stdout_limit=stdout_limit, stderr_limit=stderr_limit)
        if command[:2] == ["go", "version"]:
            return subprocess.CompletedProcess(
                command, 0, b"go version go1.27.0 linux/amd64", b"")
        if command[1] == "run":
            return subprocess.CompletedProcess(command, 0, render_output, b"")
        raise AssertionError(f"unexpected command {command}")
    return fake


def deployment(name: str, label: str) -> str:
    return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: default
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: {label}
    spec:
      containers:
        - name: app
          image: example.com/app:1
"""


SERVICE = """apiVersion: v1
kind: Service
metadata:
  name: svc
  namespace: default
spec:
  selector:
    app: web
  ports:
    - port: 80
"""


class Repo:
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

    def descriptor(self, scenarios: list[dict[str, Any]], name: str = "set",
                   tools: dict[str, str] | None = None) -> None:
        spec: dict[str, Any] = {"scenarios": scenarios}
        if tools is not None:
            spec["tools"] = tools
        document = {
            "apiVersion": "contracts.rhoai.io/v1alpha1",
            "kind": "ManifestSet",
            "metadata": {"name": name},
            "spec": spec,
        }
        self.write(".rhoai/manifests.yaml", yaml.safe_dump(document, sort_keys=False))

    def raw_scenario(self, scenario_id: str = "app", sources: list[str] | None = None,
                     **extra: Any) -> dict[str, Any]:
        scenario: dict[str, Any] = {
            "id": scenario_id,
            "renderer": "raw",
            "namespace": "default",
            "kubernetesVersion": "1.37.2",
            "sources": sources or ["manifests/*.yaml"],
        }
        scenario.update(extra)
        return scenario

    def kustomize_scenario(self, scenario_id: str = "app",
                           path: str = "manifests/overlays/prod", **extra: Any) -> dict[str, Any]:
        scenario: dict[str, Any] = {
            "id": scenario_id,
            "renderer": "kustomize",
            "namespace": "default",
            "kubernetesVersion": "1.37.2",
            "path": path,
        }
        scenario.update(extra)
        return scenario

    def commit(self, message: str = "commit") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def check(self, baselines: list[str], output: Path, *, enforce: bool = False,
              scenario_id: str | None = None,
              manifest_set: str = ".rhoai/manifests.yaml") -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        argv = [sys.executable, str(CLI), "manifest-check",
                "--repo", str(self.root), "--manifest-set", manifest_set]
        for baseline in baselines:
            argv += ["--baseline-ref", baseline]
        if scenario_id is not None:
            argv += ["--scenario-id", scenario_id]
        argv += ["--output-dir", str(output)]
        if enforce:
            argv.append("--enforce")
        result = subprocess.run(argv, capture_output=True, text=True, timeout=120, env=ENV)
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        return result, report


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path / "repo")


@pytest.fixture
def outputs(tmp_path: Path) -> Path:
    path = tmp_path / "reports"
    path.mkdir()
    return path


def finding_ids(report: dict[str, Any], index: int = 0) -> list[str]:
    return [finding["id"] for finding in report["baselines"][index]["findings"]]


def finding_for(report: dict[str, Any], rule_id: str, index: int = 0) -> dict[str, Any]:
    matches = [f for f in report["baselines"][index]["findings"] if f["id"] == rule_id]
    assert matches, f"no {rule_id} finding in baseline findings"
    return matches[0]


# ---------------------------------------------------------------------------
# Handler and ID coverage
# ---------------------------------------------------------------------------

class TestHandlerCoverage:
    def test_shipped_catalogue_and_modules_agree(self) -> None:
        assert runner.verify_handler_coverage(CATALOGUE, runner._modules()) == []

    def test_active_rule_for_unhandled_kind_is_detected(self) -> None:
        catalogue = copy.deepcopy(CATALOGUE)
        catalogue["rules"].append({
            "id": "bogus-kind-rule", "status": "active", "group": "",
            "kind": "Bogus", "classification": "immutable",
        })
        problems = runner.verify_handler_coverage(catalogue, runner._modules())
        assert any("bogus-kind-rule" in problem and "no handler module" in problem
                   for problem in problems)

    def test_kindless_rule_without_owner_is_detected(self) -> None:
        catalogue = copy.deepcopy(CATALOGUE)
        catalogue["rules"].append({
            "id": "orphan-graph-rule", "status": "active", "group": "",
            "kind": "", "classification": "selector",
        })
        problems = runner.verify_handler_coverage(catalogue, runner._modules())
        assert any("orphan-graph-rule" in problem and "no owning module" in problem
                   for problem in problems)

    def test_checker_and_cross_cutting_rule_ids_are_exempt(self) -> None:
        catalogue = copy.deepcopy(CATALOGUE)
        catalogue["rules"].append({
            "id": "stale-exception", "status": "active", "group": "",
            "kind": "Bogus", "classification": "coverage",
        })
        catalogue["rules"].append({
            "id": "conditional-update-risk", "status": "active", "group": "",
            "kind": "", "classification": "risk",
        })
        assert runner.verify_handler_coverage(catalogue, runner._modules()) == []

    def test_graph_rule_with_kind_list_is_not_misattributed(self) -> None:
        # selector-target-lost lists Service/PDB/NetworkPolicy kinds; Service
        # also has a storage-service field handler. The graph ownership must
        # win without reporting a conflict.
        catalogue = copy.deepcopy(CATALOGUE)
        for rule in catalogue["rules"]:
            if rule["id"] == "selector-target-lost":
                rule["status"] = "active"
        assert runner.verify_handler_coverage(catalogue, runner._modules()) == []

    def test_unregistered_emitted_rule_id_fails_closed(self) -> None:
        class Stub:
            @staticmethod
            def compare(baseline: dict[str, Any], candidate: dict[str, Any],
                        scenario: dict[str, Any], catalogue: dict[str, Any]) -> list[dict[str, Any]]:
                return [{
                    "id": "not-a-registered-rule", "path": "/spec", "text": "x",
                    "severity": "error", "scenario": "s", "resource": {},
                    "classification": "immutable", "evidence": "api-rule",
                }]

        class Silent:
            @staticmethod
            def compare(baseline: dict[str, Any], candidate: dict[str, Any],
                        scenario: dict[str, Any], catalogue: dict[str, Any]) -> list[dict[str, Any]]:
                return []

        modules: dict[str, Any] = {
            "workloads": Stub(), "resources": Silent(),
            "storage_service": Silent(), "relationships": Silent(),
        }
        with pytest.raises(runner.CheckError, match="unregistered rule id"):
            runner._compare_scenario({}, {}, {"id": "s"}, CATALOGUE, modules)


# ---------------------------------------------------------------------------
# Compatible, breaking, and warning-only runs
# ---------------------------------------------------------------------------

class TestCheckStatusMatrix:
    def test_compatible_run(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 0, result.stderr
        assert report["status"] == "compatible"
        assert report["mode"] == "enforce"
        assert report["baselines"][0]["status"] == "compared"
        assert report["baselines"][0]["compatible"] is True
        assert report["baselines"][0]["findings"] == []
        assert report["candidate_findings"] == []

    def test_breaking_change_report_only_exits_zero(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/sc.yaml", STORAGE_CLASS_CHANGED)
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 0
        assert report["status"] == "breaking"
        finding = finding_for(report, "storageclass-provisioner-immutable")
        assert finding["path"] == "/provisioner"
        assert finding["severity"] == "error"
        assert finding["evidence"] == "api-rule"
        assert finding["classification"] == "immutable"
        assert finding["resource"] == {
            "group": "storage.k8s.io", "kind": "StorageClass",
            "namespace": "", "name": "fast",
        }
        assert finding["baseline_ref"] == baseline
        assert finding["baseline_sha"] == baseline

    def test_breaking_change_enforce_exits_one(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/sc.yaml", STORAGE_CLASS_CHANGED)
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 1
        assert report["status"] == "breaking"
        assert report["baselines"][0]["compatible"] is False

    def test_warning_only_never_breaks(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/cm.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/cm.yaml", "# removed\n")
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"
        finding = finding_for(report, "resource-removed")
        assert finding["severity"] == "warn"
        assert finding["resource"]["kind"] == "ConfigMap"
        assert finding["resource"]["name"] == "shared"

    def test_dirty_candidate_compares_working_tree(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/sc.yaml", STORAGE_CLASS_CHANGED)  # uncommitted
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 1
        assert finding_ids(report) == ["storageclass-provisioner-immutable"]


# ---------------------------------------------------------------------------
# Baseline selection and provenance
# ---------------------------------------------------------------------------

class TestBaselines:
    def test_multiple_baselines_all_compatible(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        first = repo.commit("first")
        second = repo.commit("second")
        result, report = repo.check([first, second], outputs / "r1", enforce=True)
        assert result.returncode == 0
        assert [b["status"] for b in report["baselines"]] == ["compared", "compared"]
        assert [b["compatible"] for b in report["baselines"]] == [True, True]
        assert [b["sha"] for b in report["baselines"]] == [first, second]

    def test_mixed_baselines_breaking_dominates(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        first = repo.commit("original")
        repo.write("manifests/sc.yaml", STORAGE_CLASS_CHANGED)
        second = repo.commit("changed")
        result, report = repo.check([first, second], outputs / "r1", enforce=True)
        assert result.returncode == 1
        assert report["status"] == "breaking"
        assert report["baselines"][0]["compatible"] is False
        assert report["baselines"][1]["compatible"] is True
        assert finding_ids(report, 0) == ["storageclass-provisioner-immutable"]
        assert finding_ids(report, 1) == []

    def test_unresolvable_sha_fails_closed_with_null_provenance(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        missing = "0" * 40
        result, report = repo.check([baseline, missing], outputs / "r1", enforce=True)
        assert result.returncode == 2
        assert report["status"] == "error"
        assert report["baselines"][0]["status"] == "compared"
        assert report["baselines"][0]["compatible"] is True
        assert report["baselines"][1]["status"] == "error"
        assert report["baselines"][1]["sha"] is None
        assert report["baselines"][1]["compatible"] is None
        assert any("Cannot resolve baseline ref" in error for error in report["errors"])

    def test_mutable_ref_rejected_by_configuration(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        repo.commit()
        result, report = repo.check(["main"], outputs / "r1")
        assert result.returncode == 2
        assert report["status"] == "error"
        assert report["baselines"][0]["status"] == "not-run"
        assert report["baselines"][0]["sha"] is None

    def test_existing_output_directory_is_never_overwritten(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        output = outputs / "r1"
        output.mkdir()
        (output / "sentinel").write_text("keep", encoding="utf-8")
        argv = [sys.executable, str(CLI), "manifest-check",
                "--repo", str(repo.root), "--manifest-set", ".rhoai/manifests.yaml",
                "--baseline-ref", baseline, "--output-dir", str(output)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=120, env=ENV)
        assert result.returncode == 2
        assert "Cannot create new output directory" in result.stderr
        assert (output / "sentinel").read_text(encoding="utf-8") == "keep"
        assert not (output / "report.json").exists()

    def test_missing_descriptor_fails(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.commit()
        result, report = repo.check(["0" * 40], outputs / "r1", manifest_set=".rhoai/absent.yaml")
        assert result.returncode == 2
        assert report["status"] == "error"
        assert report["candidate"] is None

    def test_unknown_scenario_id_fails(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario("known")])
        baseline = repo.commit()
        result, report = repo.check([baseline], outputs / "r1", scenario_id="unknown")
        assert result.returncode == 2
        assert "Unknown scenario id" in result.stderr

    def test_single_scenario_selection(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.write("manifests/cm.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario("storage", ["manifests/sc.yaml"]),
                         repo.raw_scenario("config", ["manifests/cm.yaml"])])
        baseline = repo.commit()
        repo.write("manifests/sc.yaml", STORAGE_CLASS_CHANGED)
        result, report = repo.check([baseline], outputs / "r1", scenario_id="storage")
        assert result.returncode == 0
        assert set(report["candidate"]["scenarios"]) == {"storage"}
        assert finding_ids(report) == ["storageclass-provisioner-immutable"]

    def test_report_provenance_fields(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario("prov")])
        baseline = repo.commit()
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 0
        assert report["policy_version"] == CATALOGUE["policy_version"]
        assert report["manifest_set"] == ".rhoai/manifests.yaml"
        candidate = report["candidate"]
        assert candidate["head"] == repo.git("rev-parse", "HEAD")
        descriptor_bytes = (repo.root / ".rhoai/manifests.yaml").read_bytes()
        assert candidate["config_sha256"] == hashlib.sha256(descriptor_bytes).hexdigest()
        entry = candidate["scenarios"]["prov"]
        assert entry["status"] == "ready"
        assert entry["object_count"] == 1
        assert len(entry["render_digest"]) == 64
        assert entry["coverage"]["object_count"] == 1
        inventory = entry["inventory"]
        assert [item["file"] for item in inventory] == ["manifests/sc.yaml"]
        assert all(len(item["sha256"]) == 64 for item in inventory)
        baseline_entry = report["baselines"][0]["scenarios"]["prov"]
        assert baseline_entry["status"] == "compared"
        assert baseline_entry["object_count"] == 1
        assert [item["file"] for item in baseline_entry["inventory"]] == ["manifests/sc.yaml"]
        assert report["baselines"][0]["sha"] == baseline


# ---------------------------------------------------------------------------
# New declarations and historical emptiness
# ---------------------------------------------------------------------------

class TestNewDeclarations:
    def test_absent_baseline_inputs_without_declaration_fail(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/old.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario(sources=["manifests/added.yaml"])])
        baseline = repo.commit()
        repo.write("manifests/added.yaml", CONFIGMAP)
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 2
        entry = report["baselines"][0]["scenarios"]["app"]
        assert entry["status"] == "error"
        assert "declare an explicit new baselineCase" in entry["errors"][0]
        assert report["baselines"][0]["status"] == "error"

    def test_declared_new_scenario_reports_new(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/old.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario(
            sources=["manifests/added.yaml"],
            baselineCases=[{"ref": "PENDING", "state": "new",
                            "reason": "feature introduced in this change"}],
        )])
        baseline = repo.commit()
        # Point the case at the real baseline SHA.
        descriptor_text = (repo.root / ".rhoai/manifests.yaml").read_text(encoding="utf-8")
        repo.write(".rhoai/manifests.yaml", descriptor_text.replace("PENDING", baseline))
        repo.write("manifests/added.yaml", CONFIGMAP_ADDED)
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 0
        entry = report["baselines"][0]["scenarios"]["app"]
        assert entry["status"] == "new"
        assert entry["reason"] == "feature introduced in this change"
        assert report["baselines"][0]["status"] == "new"
        assert report["baselines"][0]["compatible"] is None
        assert report["status"] == "new"
        # Candidate validation still ran for the new objects.
        assert report["candidate"]["scenarios"]["app"]["status"] == "ready"

    def test_false_new_declaration_fails(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/old.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario(
            sources=["manifests/old.yaml"],
            baselineCases=[{"ref": "PENDING", "state": "new", "reason": "wrong"}],
        )])
        baseline = repo.commit()
        descriptor_text = (repo.root / ".rhoai/manifests.yaml").read_text(encoding="utf-8")
        repo.write(".rhoai/manifests.yaml", descriptor_text.replace("PENDING", baseline))
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 2
        entry = report["baselines"][0]["scenarios"]["app"]
        assert entry["status"] == "error"
        assert "must be compared, not declared new" in entry["errors"][0]

    def test_partially_present_declared_new_fails(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/old.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario(
            sources=["manifests/old.yaml", "manifests/added.yaml"],
            baselineCases=[{"ref": "PENDING", "state": "new", "reason": "wrong"}],
        )])
        baseline = repo.commit()
        descriptor_text = (repo.root / ".rhoai/manifests.yaml").read_text(encoding="utf-8")
        repo.write(".rhoai/manifests.yaml", descriptor_text.replace("PENDING", baseline))
        repo.write("manifests/added.yaml", CONFIGMAP_ADDED)
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 2
        entry = report["baselines"][0]["scenarios"]["app"]
        assert entry["status"] == "error"
        assert "partially missing source set" in entry["errors"][0]

    def test_partially_present_kustomize_declared_new_fails(
            self, repo: Repo, outputs: Path, tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch) -> None:
        # Same fail-closed rule for kustomize: a kustomization that exists at
        # the baseline but references a file that does not is a broken
        # (partially present) input set, never an absent one, so an explicit
        # new declaration must be refused. Kustomize scenarios normally need
        # Go and a prepared cache; the faked renderer subprocess keeps this
        # offline while exercising the real checker dispatch.
        repo.write("manifests/overlays/prod/kustomization.yaml", "resources:\n  - added.yaml\n")
        repo.descriptor(
            [repo.kustomize_scenario(
                baselineCases=[{"ref": "PENDING", "state": "new", "reason": "declared absent"}],
            )],
            tools=KUSTOMIZE_TOOLS,
        )
        baseline = repo.commit()
        descriptor_text = (repo.root / ".rhoai/manifests.yaml").read_text(encoding="utf-8")
        repo.write(".rhoai/manifests.yaml", descriptor_text.replace("PENDING", baseline))
        # Candidate: the referenced file now exists, so the candidate renders.
        repo.write("manifests/overlays/prod/added.yaml", CONFIGMAP)

        modules = runner._modules()
        renderers_module = modules["renderers"]
        real_run = renderers_module._run
        monkeypatch.setattr(
            renderers_module, "_run", fake_renderer_run(real_run, RENDERED_OBJECT.encode()))
        cache = tmp_path / "cache"
        tool = renderers_module.PREPARED_TOOLS["kustomize"]
        module_dir = cache / "gomodcache" / f"{tool['module']}@v{tool['version']}"
        module_dir.mkdir(parents=True)
        (module_dir / "go.mod").write_text("module pin\n")

        output = outputs / "r1"
        args = argparse.Namespace(
            repo=repo.root, manifest_set=Path(".rhoai/manifests.yaml"),
            baseline_ref=[baseline], output_dir=output, enforce=False,
            tool_cache_dir=cache, scenario_id=None,
        )
        code = runner.run_check(args)
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        assert code == 2
        assert report["candidate"]["scenarios"]["app"]["status"] == "ready"
        entry = report["baselines"][0]["scenarios"]["app"]
        assert entry["status"] == "error"
        assert "does not exist in the snapshot" in entry["errors"][0]
        assert report["baselines"][0]["status"] == "error"
        assert report["status"] == "error"

    def test_historical_zero_object_render_fails(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/cm.yaml", "# nothing here\n")
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/cm.yaml", CONFIGMAP)
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 2
        entry = report["baselines"][0]["scenarios"]["app"]
        assert entry["status"] == "error"
        assert "cannot be empty" in entry["errors"][0]


# ---------------------------------------------------------------------------
# Candidate states
# ---------------------------------------------------------------------------

class TestCandidateStates:
    def test_missing_candidate_source_fails(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/cm.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario(sources=["manifests/absent.yaml"])])
        baseline = repo.commit()
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 2
        assert report["status"] == "error"
        entry = report["candidate"]["scenarios"]["app"]
        assert entry["status"] == "error"
        assert "no files match source pattern" in entry["errors"][0]
        # The baseline was requested and stays present, blocked from running.
        assert report["baselines"][0]["status"] == "not-run"
        blocked = report["baselines"][0]["scenarios"]["app"]
        assert blocked["status"] == "not-run"
        assert blocked["reason"] == "blocked: candidate scenario did not render"

    def test_zero_object_candidate_unprotected_removal_is_warning_only(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/cm.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/cm.yaml", "# everything removed\n")
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 0
        assert report["candidate"]["scenarios"]["app"]["object_count"] == 0
        assert report["candidate"]["scenarios"]["app"]["status"] == "ready"
        assert report["baselines"][0]["scenarios"]["app"]["status"] == "compared"
        assert finding_ids(report) == ["resource-removed"]
        assert report["status"] == "compatible"

    def test_zero_object_candidate_protected_removal_breaks(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/cm.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario(protectedResources=[{
            "group": "", "kind": "ConfigMap", "namespace": "default", "name": "shared",
        }])])
        baseline = repo.commit()
        repo.write("manifests/cm.yaml", "# everything removed\n")
        enforce_result, enforce_report = repo.check([baseline], outputs / "enforce", enforce=True)
        report_result, report_only = repo.check([baseline], outputs / "report")
        assert enforce_result.returncode == 1
        assert report_result.returncode == 0
        finding = finding_for(enforce_report, "protected-resource-removed")
        assert finding["severity"] == "error"
        assert finding["resource"]["name"] == "shared"
        assert enforce_report["status"] == "breaking"
        assert enforce_report["baselines"][0]["compatible"] is False
        # Never silently new: the scenario really was compared.
        assert enforce_report["baselines"][0]["scenarios"]["app"]["status"] == "compared"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TestExceptions:
    def breaking_repo(self, repo: Repo) -> str:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/sc.yaml", STORAGE_CLASS_CHANGED)
        return baseline

    def test_exact_waiver_suppresses_without_deleting_evidence(
            self, repo: Repo, outputs: Path) -> None:
        baseline = self.breaking_repo(repo)
        repo.descriptor([repo.raw_scenario(exceptions=[{
            "ruleId": "storageclass-provisioner-immutable",
            "resource": {"group": "storage.k8s.io", "kind": "StorageClass",
                         "namespace": "", "name": "fast"},
            "path": "/provisioner",
            "baselineRef": baseline,
            "reason": "coordinated migration",
        }])])
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"
        finding = finding_for(report, "storageclass-provisioner-immutable")
        assert finding["suppressed"] is True
        assert finding["suppressed_reason"] == "coordinated migration"
        assert finding["severity"] == "error"  # evidence keeps its severity
        assert report["baselines"][0]["compatible"] is True

    def test_empty_pointer_exception_waives_protected_removal(
            self, repo: Repo, outputs: Path) -> None:
        # protected-resource-removed emits the empty JSON pointer (the whole
        # document); an exception with path "" must be able to waive it.
        repo.write("manifests/cm.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario(
            protectedResources=[{
                "group": "", "kind": "ConfigMap", "namespace": "default", "name": "shared",
            }],
            exceptions=[{
                "ruleId": "protected-resource-removed",
                "resource": {"group": "", "kind": "ConfigMap",
                             "namespace": "default", "name": "shared"},
                "path": "",
                "baselineRef": "PENDING",
                "reason": "deliberate decommission",
            }],
        )])
        baseline = repo.commit()
        descriptor_text = (repo.root / ".rhoai/manifests.yaml").read_text(encoding="utf-8")
        repo.write(".rhoai/manifests.yaml", descriptor_text.replace("PENDING", baseline))
        repo.write("manifests/cm.yaml", "# everything removed\n")
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"
        finding = finding_for(report, "protected-resource-removed")
        assert finding["suppressed"] is True
        assert finding["suppressed_reason"] == "deliberate decommission"
        assert finding["severity"] == "error"
        assert report["baselines"][0]["compatible"] is True

    def test_exception_for_other_path_does_not_waive(
            self, repo: Repo, outputs: Path) -> None:
        baseline = self.breaking_repo(repo)
        repo.descriptor([repo.raw_scenario(exceptions=[{
            "ruleId": "storageclass-provisioner-immutable",
            "resource": {"group": "storage.k8s.io", "kind": "StorageClass",
                         "namespace": "", "name": "fast"},
            "path": "/reclaimPolicy",
            "baselineRef": baseline,
            "reason": "targets nothing",
        }])])
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 1
        finding = finding_for(report, "storageclass-provisioner-immutable")
        assert not finding.get("suppressed")
        stale = finding_for(report, "stale-exception")
        assert stale["severity"] == "warn"

    def test_stale_exception_warns_while_underlying_change_stays_active(
            self, repo: Repo, outputs: Path) -> None:
        baseline = self.breaking_repo(repo)
        repo.descriptor([repo.raw_scenario(exceptions=[{
            "ruleId": "storageclass-reclaim-policy-immutable",
            "resource": {"group": "storage.k8s.io", "kind": "StorageClass",
                         "namespace": "", "name": "fast"},
            "path": "/reclaimPolicy",
            "baselineRef": baseline,
            "reason": "describes an older change",
        }])])
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 1
        assert set(finding_ids(report)) == {
            "storageclass-provisioner-immutable", "stale-exception"}
        stale = finding_for(report, "stale-exception")
        assert stale["severity"] == "warn"
        assert stale["resource"] == {
            "group": "storage.k8s.io", "kind": "StorageClass",
            "namespace": "", "name": "fast",
        }

    def test_unrequested_baseline_exception_is_unused_provenance(
            self, repo: Repo, outputs: Path) -> None:
        baseline = self.breaking_repo(repo)
        other = "1" * 40
        repo.descriptor([repo.raw_scenario(exceptions=[{
            "ruleId": "storageclass-reclaim-policy-immutable",
            "resource": {"group": "storage.k8s.io", "kind": "StorageClass",
                         "namespace": "", "name": "fast"},
            "path": "/reclaimPolicy",
            "baselineRef": other,
            "reason": "for a different baseline",
        }])])
        result, report = repo.check([baseline], outputs / "r1")
        assert "stale-exception" not in finding_ids(report)

    def test_non_waivable_rule_rejected_at_configuration(
            self, repo: Repo, outputs: Path) -> None:
        baseline = self.breaking_repo(repo)
        repo.descriptor([repo.raw_scenario(exceptions=[{
            "ruleId": "resource-removed",
            "resource": {"group": "", "kind": "ConfigMap",
                         "namespace": "default", "name": "shared"},
            "path": "/data",
            "baselineRef": baseline,
            "reason": "not allowed",
        }])])
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 2
        assert "never waiver-eligible" in result.stderr

    def test_one_of_two_relational_losses_waived(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/web1.yaml", deployment("web1", "web"))
        repo.write("manifests/web2.yaml", deployment("web2", "web"))
        repo.write("manifests/svc.yaml", SERVICE)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/web1.yaml", deployment("web1", "broken"))
        repo.write("manifests/web2.yaml", deployment("web2", "broken"))
        first_result, first_report = repo.check([baseline], outputs / "r1", enforce=True)
        assert first_result.returncode == 1
        losses = [f for f in first_report["baselines"][0]["findings"]
                  if f["id"] == "selector-target-lost"]
        assert len(losses) == 2
        assert {f["related_resource"]["name"] for f in losses} == {"web1", "web2"}
        waived = next(f for f in losses if f["related_resource"]["name"] == "web1")
        repo.descriptor([repo.raw_scenario(exceptions=[{
            "ruleId": "selector-target-lost",
            "resource": {"group": "", "kind": "Service",
                         "namespace": "default", "name": "svc"},
            "path": "/spec/selector",
            "baselineRef": baseline,
            "relatedResource": {"group": "apps", "kind": "Deployment",
                                "namespace": "default", "name": "web1"},
            "edgeId": waived["edge_id"],
            "reason": "intentional deselection",
        }])])
        result, report = repo.check([baseline], outputs / "r2", enforce=True)
        assert result.returncode == 1  # web2 loss remains active
        losses = [f for f in report["baselines"][0]["findings"]
                  if f["id"] == "selector-target-lost"]
        assert len(losses) == 2
        active = [f for f in losses if not f.get("suppressed")]
        suppressed = [f for f in losses if f.get("suppressed")]
        assert len(active) == 1 and len(suppressed) == 1
        assert active[0]["related_resource"]["name"] == "web2"
        assert suppressed[0]["related_resource"]["name"] == "web1"
        assert suppressed[0]["severity"] == "error"
        assert "stale-exception" not in finding_ids(report)


# ---------------------------------------------------------------------------
# Candidate-edge correlation
# ---------------------------------------------------------------------------

class TestCandidateEdgeCorrelation:
    def correlation_repo(self, repo: Repo, *, reorder: bool = False) -> str:
        repo.write("manifests/cm.yaml", CONFIGMAP)
        repo.write("manifests/dep.yaml", DEPLOYMENT_WITH_ENV)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/cm.yaml", CONFIGMAP_KEY_DROPPED)
        if reorder:
            # Reorder the candidate env list: ONE moves from index 0 to 1.
            one = """            - name: ONE
              valueFrom:
                configMapKeyRef:
                  name: shared
                  key: alpha
"""
            two = """            - name: TWO
              valueFrom:
                configMapKeyRef:
                  name: shared
                  key: beta
"""
            repo.write("manifests/dep.yaml",
                       DEPLOYMENT_WITH_ENV.replace(one + two, two + one))
        return baseline

    def env_candidate_findings(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        return [f for f in report["candidate_findings"] if "env" in f["path"]]

    def test_comparison_duplicate_absorbed_into_candidate_finding(
            self, repo: Repo, outputs: Path) -> None:
        baseline = self.correlation_repo(repo)
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 1
        findings = self.env_candidate_findings(report)
        assert len(findings) == 1
        finding = findings[0]
        assert finding["id"] == "required-reference-lost"
        assert finding["severity"] == "error"
        assert finding["path"] == "/spec/template/spec/containers/0/env/0/valueFrom/configMapKeyRef"
        assert finding["resource"]["name"] == "web"
        assert finding["related_resource"]["name"] == "shared"
        associations = finding["baseline_associations"]
        assert len(associations) == 1
        assert associations[0]["ref"] == baseline
        assert associations[0]["sha"] == baseline
        assert associations[0]["path"] == finding["path"]
        assert associations[0]["related_path"] == "/data/alpha"
        # The comparison duplicate is gone from the baseline findings...
        assert report["baselines"][0]["findings"] == []
        # ...but the baseline records the link and stays incompatible.
        links = report["baselines"][0]["associated_candidate_findings"]
        assert links == [{"scenario": "app", "id": "required-reference-lost",
                          "edge_id": finding["edge_id"]}]
        assert report["baselines"][0]["compatible"] is False
        assert report["baselines"][0]["scenarios"]["app"]["status"] == "compared"

    def test_reordered_env_list_keeps_association(
            self, repo: Repo, outputs: Path) -> None:
        baseline = self.correlation_repo(repo, reorder=True)
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 1
        findings = self.env_candidate_findings(report)
        assert len(findings) == 1
        finding = findings[0]
        # The candidate slot moved to index 1, but the association still
        # points at the original baseline slot at index 0.
        assert finding["path"] == "/spec/template/spec/containers/0/env/1/valueFrom/configMapKeyRef"
        assert finding["baseline_associations"][0]["path"] == \
            "/spec/template/spec/containers/0/env/0/valueFrom/configMapKeyRef"
        assert report["baselines"][0]["findings"] == []
        assert report["baselines"][0]["compatible"] is False

    def test_two_slots_sharing_target_stay_distinct(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/cm.yaml", CONFIGMAP)
        both = DEPLOYMENT_WITH_ENV.replace(
            """            - name: ONE
              valueFrom:
                configMapKeyRef:
                  name: shared
                  key: alpha
""", """            - name: ONE
              valueFrom:
                configMapKeyRef:
                  name: shared
                  key: alpha
            - name: ONE_BIS
              valueFrom:
                configMapKeyRef:
                  name: shared
                  key: alpha
""")
        repo.write("manifests/dep.yaml", both)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/cm.yaml", CONFIGMAP_KEY_DROPPED)
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 1
        findings = self.env_candidate_findings(report)
        assert len(findings) == 2
        assert len({f["edge_id"] for f in findings}) == 2
        for finding in findings:
            assert len(finding["baseline_associations"]) == 1
        # Distinct baseline pointers prove the two slots were not merged.
        assoc_paths = {f["baseline_associations"][0]["path"] for f in findings}
        assert len(assoc_paths) == 2
        assert report["baselines"][0]["findings"] == []
        assert len(report["baselines"][0]["associated_candidate_findings"]) == 2

    def test_multiple_baselines_accumulate_associations(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/cm.yaml", CONFIGMAP)
        repo.write("manifests/dep.yaml", DEPLOYMENT_WITH_ENV)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit("original")
        repo.write("manifests/note.txt", "unrelated change\n")
        second = repo.commit("unrelated")
        repo.write("manifests/cm.yaml", CONFIGMAP_KEY_DROPPED)
        result, report = repo.check([baseline, second], outputs / "r1", enforce=True)
        assert result.returncode == 1
        findings = self.env_candidate_findings(report)
        assert len(findings) == 1
        associations = findings[0]["baseline_associations"]
        assert [a["ref"] for a in associations] == [baseline, second]
        for index, base in enumerate((baseline, second)):
            links = report["baselines"][index]["associated_candidate_findings"]
            assert len(links) == 1
            assert links[0]["edge_id"] == findings[0]["edge_id"]
            assert report["baselines"][index]["compatible"] is False

    def test_waiving_an_absorbed_candidate_finding_fails(
            self, repo: Repo, outputs: Path) -> None:
        baseline = self.correlation_repo(repo)
        first_result, first_report = repo.check([baseline], outputs / "r1", enforce=True)
        assert first_result.returncode == 1
        finding = self.env_candidate_findings(first_report)[0]
        association = finding["baseline_associations"][0]
        repo.descriptor([repo.raw_scenario(exceptions=[{
            "ruleId": "required-reference-lost",
            "resource": finding["resource"],
            "path": association["path"],
            "baselineRef": baseline,
            "relatedResource": finding["related_resource"],
            "edgeId": association["edge_id"],
            "reason": "attempt to waive candidate validation",
        }])])
        result, report = repo.check([baseline], outputs / "r2")
        assert result.returncode == 2
        assert report["status"] == "error"
        assert any("cannot be waived" in error for error in report["errors"])


# ---------------------------------------------------------------------------
# Patch extrapolation
# ---------------------------------------------------------------------------

class TestPatchExtrapolation:
    def test_other_patch_of_audited_minor_warns(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario(kubernetesVersion="1.37.1")])
        baseline = repo.commit()
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 0  # a warning never breaks enforcement
        findings = report["candidate_findings"]
        assert [f["id"] for f in findings] == ["patch-coverage-extrapolated"]
        finding = findings[0]
        assert finding["severity"] == "warn"
        assert finding["classification"] == "coverage"
        assert "1.37.1" in finding["text"]
        assert "1.37.2" in finding["text"]

    def test_audited_patch_does_not_warn(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario(kubernetesVersion="1.37.2")])
        baseline = repo.commit()
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 0
        assert report["candidate_findings"] == []


# ---------------------------------------------------------------------------
# Report safety, determinism, and cleanup
# ---------------------------------------------------------------------------

class TestReportSafety:
    def test_scenario_inventory_normalizes_dotted_paths(self) -> None:
        # Rendering normalizes "./" prefixes and trailing slashes (mirroring
        # renderers._validate_repo_relative); inventories must select with
        # the same form or a successfully rendered scenario would report no
        # inputs.
        records = [
            {"file": "manifests/overlays/prod/kustomization.yaml", "sha256": "a"},
            {"file": "manifests/cm.yaml", "sha256": "b"},
            {"file": "other/file.yaml", "sha256": "c"},
        ]
        kustomize = {"renderer": "kustomize", "path": "./manifests/overlays/prod/"}
        assert [e["file"] for e in runner._scenario_inventory(records, kustomize)] == [
            "manifests/overlays/prod/kustomization.yaml"]
        raw = {"renderer": "raw", "sources": ["./manifests/*.yaml"]}
        assert [e["file"] for e in runner._scenario_inventory(records, raw)] == [
            "manifests/cm.yaml", "manifests/overlays/prod/kustomization.yaml"]

    def test_dotted_raw_sources_render_with_full_inventory(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/cm.yaml", CONFIGMAP)
        repo.descriptor([repo.raw_scenario(sources=["./manifests/*.yaml"])])
        baseline = repo.commit()
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 0
        assert report["status"] == "compatible"
        entry = report["baselines"][0]["scenarios"]["app"]
        assert entry["status"] == "compared"
        assert [item["file"] for item in entry["inventory"]] == ["manifests/cm.yaml"]

    def test_secret_values_never_leak_into_report(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/secret.yaml", SECRET)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        result, report = repo.check([baseline], outputs / "r1")
        assert result.returncode == 0
        text = (outputs / "r1" / "report.json").read_text(encoding="utf-8")
        assert "manifest-check-secret-marker" not in text
        # The secret object is counted, not reproduced.
        assert report["candidate"]["scenarios"]["app"]["object_count"] == 1

    def test_reports_are_deterministic(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/web1.yaml", deployment("web1", "web"))
        repo.write("manifests/web2.yaml", deployment("web2", "web"))
        repo.write("manifests/svc.yaml", SERVICE)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        repo.write("manifests/web1.yaml", deployment("web1", "broken"))
        repo.write("manifests/web2.yaml", deployment("web2", "broken"))
        repo.check([baseline], outputs / "first")
        repo.check([baseline], outputs / "second")
        first = (outputs / "first" / "report.json").read_bytes()
        second = (outputs / "second" / "report.json").read_bytes()
        assert first == second
        report = json.loads(first)
        paths = [(f["id"], f["resource"]["name"], f["path"])
                 for f in report["baselines"][0]["findings"]]
        assert paths == sorted(paths, key=str)

    def test_temporary_work_directories_are_cleaned(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        before = set(Path(tempfile.gettempdir()).glob("manifest-check-*"))
        result, _ = repo.check([baseline], outputs / "r1")
        assert result.returncode == 0
        after = set(Path(tempfile.gettempdir()).glob("manifest-check-*"))
        assert after == before


# ---------------------------------------------------------------------------
# manifest-prepare
# ---------------------------------------------------------------------------

class TestPrepareCommand:
    def prepare(self, repo: Repo, output: Path | None = None,
                manifest_set: str = ".rhoai/manifests.yaml",
                scenario_id: str | None = None) -> subprocess.CompletedProcess[str]:
        cache = output or (repo.root.parent / "cache")
        argv = [sys.executable, str(CLI), "manifest-prepare",
                "--repo", str(repo.root), "--manifest-set", manifest_set,
                "--tool-cache-dir", str(cache)]
        if scenario_id is not None:
            argv += ["--scenario-id", scenario_id]
        return subprocess.run(argv, capture_output=True, text=True, timeout=120, env=ENV)

    def test_raw_only_prepare_needs_no_go_or_cache(
            self, repo: Repo, tmp_path: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        repo.commit()
        result = self.prepare(repo, tmp_path / "cache")
        assert result.returncode == 0, result.stderr
        provenance = json.loads(result.stdout)
        assert provenance["needed"] == []
        assert provenance["tools"] == []
        assert provenance["provider_content_rendered"] is False

    def test_prepare_missing_descriptor_fails(self, repo: Repo, tmp_path: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.commit()
        result = self.prepare(repo, tmp_path / "cache", manifest_set=".rhoai/absent.yaml")
        assert result.returncode == 2
        assert "not found in repository" in result.stderr

    def test_prepare_unknown_scenario_fails(self, repo: Repo, tmp_path: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario("known")])
        repo.commit()
        result = self.prepare(repo, tmp_path / "cache", scenario_id="unknown")
        assert result.returncode == 2
        assert "Unknown scenario id" in result.stderr

    def test_raw_check_never_requires_a_cache(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        result, report = repo.check([baseline], outputs / "r1", enforce=True)
        assert result.returncode == 0
        assert report["status"] == "compatible"


# ---------------------------------------------------------------------------
# Tool-cache placement
# ---------------------------------------------------------------------------

class TestCacheLocation:
    """A cache inside the checkout would be snapshotted as repository content."""

    def prepare_into(self, repo: Repo, cache: Path) -> subprocess.CompletedProcess[str]:
        argv = [sys.executable, str(CLI), "manifest-prepare",
                "--repo", str(repo.root), "--manifest-set", ".rhoai/manifests.yaml",
                "--tool-cache-dir", str(cache)]
        return subprocess.run(argv, capture_output=True, text=True, timeout=120, env=ENV)

    def check_into(self, repo: Repo, baseline: str, output: Path,
                   cache: Path) -> subprocess.CompletedProcess[str]:
        argv = [sys.executable, str(CLI), "manifest-check",
                "--repo", str(repo.root), "--manifest-set", ".rhoai/manifests.yaml",
                "--baseline-ref", baseline, "--output-dir", str(output),
                "--tool-cache-dir", str(cache)]
        return subprocess.run(argv, capture_output=True, text=True, timeout=120, env=ENV)

    def test_prepare_rejects_cache_inside_checkout(self, repo: Repo) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        repo.commit()
        result = self.prepare_into(repo, repo.root / "tool-cache")
        assert result.returncode == 2
        assert "resolves inside the repository" in result.stderr
        assert not (repo.root / "tool-cache").exists()

    def test_check_rejects_cache_inside_checkout(
            self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        result = self.check_into(repo, baseline, outputs / "r1", repo.root / "tool-cache")
        assert result.returncode == 2
        assert "resolves inside the repository" in result.stderr
        # The failure still publishes an error report, never a silent pass.
        report = json.loads((outputs / "r1" / "report.json").read_text(encoding="utf-8"))
        assert report["status"] == "error"

    def test_check_rejects_symlinked_cache_pointing_into_checkout(
            self, repo: Repo, outputs: Path, tmp_path: Path) -> None:
        # A path outside the checkout that is a symlink into it must not
        # bypass the containment check.
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        baseline = repo.commit()
        (repo.root / "tool-cache").mkdir()
        os.symlink(repo.root / "tool-cache", tmp_path / "outside-cache")
        result = self.check_into(repo, baseline, outputs / "r1", tmp_path / "outside-cache")
        assert result.returncode == 2
        assert "resolves inside the repository" in result.stderr


# ---------------------------------------------------------------------------
# Existing CLI behavior stays unchanged
# ---------------------------------------------------------------------------

class TestExistingCLI:
    @pytest.mark.parametrize("command", [
        "check", "crd-check", "coverage", "discover",
        "manifest-prepare", "manifest-check",
    ])
    def test_subcommand_help_still_works(self, command: str) -> None:
        result = subprocess.run([sys.executable, str(CLI), command, "--help"],
                                capture_output=True, text=True, timeout=60, env=ENV)
        assert result.returncode == 0
        assert "usage:" in result.stdout

    def test_unknown_command_still_fails(self) -> None:
        result = subprocess.run([sys.executable, str(CLI), "not-a-command"],
                                capture_output=True, text=True, timeout=60, env=ENV)
        assert result.returncode == 2

    def test_manifest_check_requires_baseline(self, repo: Repo, outputs: Path) -> None:
        repo.write("manifests/sc.yaml", STORAGE_CLASS)
        repo.descriptor([repo.raw_scenario()])
        repo.commit()
        result = subprocess.run(
            [sys.executable, str(CLI), "manifest-check",
             "--repo", str(repo.root), "--manifest-set", ".rhoai/manifests.yaml",
             "--output-dir", str(outputs / "r1")],
            capture_output=True, text=True, timeout=60, env=ENV)
        assert result.returncode == 2
        assert "--baseline-ref" in result.stderr
