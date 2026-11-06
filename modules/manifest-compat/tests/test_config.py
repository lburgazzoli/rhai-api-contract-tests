"""Regression tests for ManifestSet descriptor loading and validation.

Two corpora, kept separate by contract:

- The static corpus must classify identically under the actual Draft 2020-12
  schema (schemas/manifest-set.schema.json, via the pinned test-only
  jsonschema) and the runtime structural validation in config.py.
- The contextual corpus exercises checks that need the repository, the
  requested baselines, or the policy catalogue: unique/unknown scenario ids,
  Kubernetes version support, tool pins, kindScopes conflicts, exception
  policy validity, and filesystem containment/existence.
"""

import copy
import importlib.util
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = ROOT / "schemas" / "manifest-set.schema.json"
MODULE_PATH = ROOT / "modules" / "manifest-compat" / "config.py"
POLICY_PATH = ROOT / "modules" / "manifest-compat" / "policy.json"

spec = importlib.util.spec_from_file_location("manifest_config_test", MODULE_PATH)
assert spec is not None and spec.loader is not None
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)

import jsonschema  # type: ignore[import-untyped]  # noqa: E402  (pinned test-only dependency, no bundled py.typed)

SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
CATALOGUE = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

SHA40 = "a" * 40
SHA64 = "b" * 64
EDGE_ID = "c" * 64


def raw_document() -> dict[str, Any]:
    return {
        "apiVersion": "contracts.rhoai.io/v1alpha1",
        "kind": "ManifestSet",
        "metadata": {"name": "provider"},
        "spec": {
            "scenarios": [
                {
                    "id": "raw-main",
                    "renderer": "raw",
                    "namespace": "rhoai",
                    "kubernetesVersion": "1.36.6",
                    "sources": ["manifests/*.yaml"],
                }
            ]
        },
    }


def helm_document() -> dict[str, Any]:
    return {
        "apiVersion": "contracts.rhoai.io/v1alpha1",
        "kind": "ManifestSet",
        "metadata": {"name": "provider"},
        "spec": {
            "tools": {"helmVersion": "4.3.1", "kustomizeVersion": "5.8.3"},
            "scenarios": [
                {
                    "id": "helm-main",
                    "renderer": "helm",
                    "namespace": "rhoai",
                    "kubernetesVersion": "1.37.2",
                    "path": "charts/demo",
                    "releaseName": "demo",
                    "valuesFiles": ["charts/demo/values.yaml"],
                    "setValues": {"image.tag": "latest"},
                    "releaseMode": "install",
                    "apiVersions": ["v1", "apps/v1"],
                    "baselineCases": [
                        {
                            "ref": SHA40,
                            "state": "existing",
                            "inputs": {"path": "charts/legacy", "valuesFiles": ["charts/legacy/values.yaml"]},
                        }
                    ],
                }
            ],
        },
    }


def kustomize_document() -> dict[str, Any]:
    return {
        "apiVersion": "contracts.rhoai.io/v1alpha1",
        "kind": "ManifestSet",
        "metadata": {"name": "provider"},
        "spec": {
            "scenarios": [
                {
                    "id": "kustomize-main",
                    "renderer": "kustomize",
                    "namespace": "rhoai",
                    "kubernetesVersion": "1.35.10",
                    "path": "overlays/prod",
                    "baselineCases": [{"ref": SHA40, "state": "new", "reason": "overlay introduced in this PR"}],
                }
            ]
        },
    }


def full_optional_document() -> dict[str, Any]:
    document = raw_document()
    scenario = document["spec"]["scenarios"][0]
    scenario["apiVersions"] = ["v1"]
    scenario["kindScopes"] = [{"group": "demo.example.com", "kind": "Widget", "scope": "Namespaced"}]
    scenario["protectedLabels"] = [
        {"location": "/metadata/labels", "keys": ["app.kubernetes.io/name"]},
        {"location": "/spec/template/metadata/labels", "keys": ["app.kubernetes.io/name", "team"]},
    ]
    scenario["protectedResources"] = [
        {"group": "", "kind": "ConfigMap", "namespace": "rhoai", "name": "dashboard-config"},
        {"group": "demo.example.com", "kind": "Widget", "namespace": "", "name": "cluster-widget"},
    ]
    scenario["exceptions"] = [
        {
            "ruleId": "deployment-selector-immutable",
            "resource": {"group": "apps", "kind": "Deployment", "namespace": "rhoai", "name": "api"},
            "path": "/spec/selector",
            "baselineRef": SHA40,
            "reason": "intentional selector migration tracked in RHOAIENG-1",
        },
        {
            "ruleId": "selector-target-lost",
            "resource": {"group": "", "kind": "Service", "namespace": "rhoai", "name": "api"},
            "path": "/spec/selector",
            "baselineRef": SHA40,
            "reason": "intentional re-targeting tracked in RHOAIENG-2",
            "relatedResource": {"group": "apps", "kind": "Deployment", "namespace": "rhoai", "name": "api"},
            "edgeId": EDGE_ID,
        },
    ]
    scenario["baselineCases"] = [
        {"ref": SHA64, "state": "new", "reason": "scenario introduced after this baseline"},
    ]
    return document


VALID_CORPUS: list[tuple[str, dict[str, Any]]] = [
    ("minimal raw", raw_document()),
    ("raw with all optional fields", full_optional_document()),
    ("helm full", helm_document()),
    ("kustomize with new baseline case", kustomize_document()),
    ("raw and helm scenarios", {
        "apiVersion": "contracts.rhoai.io/v1alpha1",
        "kind": "ManifestSet",
        "metadata": {"name": "provider"},
        "spec": {
            "tools": {"helmVersion": "4.3.1", "kustomizeVersion": "5.8.3"},
            "scenarios": [
                raw_document()["spec"]["scenarios"][0],
                helm_document()["spec"]["scenarios"][0],
            ],
        },
    }),
    ("kustomize existing inputs path override", {
        "apiVersion": "contracts.rhoai.io/v1alpha1",
        "kind": "ManifestSet",
        "metadata": {"name": "provider"},
        "spec": {"scenarios": [{
            "id": "k", "renderer": "kustomize", "namespace": "rhoai",
            "kubernetesVersion": "1.36.6", "path": "overlays/prod",
            "baselineCases": [
                {"ref": SHA40, "state": "existing", "inputs": {"path": "overlays/legacy"}},
            ],
        }]},
    }),
    ("raw existing inputs sources override", {
        "apiVersion": "contracts.rhoai.io/v1alpha1",
        "kind": "ManifestSet",
        "metadata": {"name": "provider"},
        "spec": {"scenarios": [{
            "id": "r", "renderer": "raw", "namespace": "rhoai",
            "kubernetesVersion": "1.36.6", "sources": ["manifests/*.yaml"],
            "baselineCases": [
                {"ref": SHA40, "state": "existing", "inputs": {"sources": ["legacy/*.yaml"]}},
            ],
        }]},
    }),
]


def _mutated(base: dict[str, Any], mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    document = copy.deepcopy(base)
    mutate(document)
    return document


INVALID_CORPUS: list[tuple[str, dict[str, Any]]] = [
    ("unknown root property", _mutated(raw_document(), lambda d: d.update({"extra": 1}))),
    ("wrong apiVersion", _mutated(raw_document(), lambda d: d.update({"apiVersion": "v2"}))),
    ("wrong kind", _mutated(raw_document(), lambda d: d.update({"kind": "ContractSet"}))),
    ("metadata unknown property", _mutated(raw_document(), lambda d: d["metadata"].update({"labels": {}}))),
    ("metadata empty name", _mutated(raw_document(), lambda d: d["metadata"].update({"name": ""}))),
    ("spec missing scenarios", _mutated(raw_document(), lambda d: d["spec"].pop("scenarios"))),
    ("spec empty scenarios", _mutated(raw_document(), lambda d: d["spec"].update({"scenarios": []}))),
    ("spec unknown property", _mutated(raw_document(), lambda d: d["spec"].update({"baseline": {}}))),
    ("tools unknown property", _mutated(raw_document(), lambda d: d["spec"].update(
        {"tools": {"helmVersion": "4.3.1", "kustomizeVersion": "5.8.3", "extra": 1}}))),
    ("tools wrong helm pin", _mutated(raw_document(), lambda d: d["spec"].update(
        {"tools": {"helmVersion": "4.2.0", "kustomizeVersion": "5.8.3"}}))),
    ("tools missing kustomize pin", _mutated(raw_document(), lambda d: d["spec"].update(
        {"tools": {"helmVersion": "4.3.1"}}))),
    ("scenario unknown property", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update({"chart": "x"}))),
    ("scenario missing id", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].pop("id"))),
    ("scenario missing renderer", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].pop("renderer"))),
    ("scenario unknown renderer", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update({"renderer": "cue"}))),
    ("scenario invalid namespace", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update({"namespace": "My Namespace"}))),
    ("scenario two-part version", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update({"kubernetesVersion": "1.36"}))),
    ("scenario v-prefixed version", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update({"kubernetesVersion": "v1.36.6"}))),
    ("scenario non-object", _mutated(raw_document(), lambda d: d["spec"].update({"scenarios": ["raw-main"]}))),
    ("raw without sources", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].pop("sources"))),
    ("raw with empty sources", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update({"sources": []}))),
    ("raw declares path", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update({"path": "charts/x"}))),
    ("raw declares releaseMode", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update({"releaseMode": "install"}))),
    ("helm without path", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0].pop("path"))),
    ("helm without releaseName", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0].pop("releaseName"))),
    ("helm declares sources", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0].update({"sources": ["m/*.yaml"]}))),
    ("helm invalid releaseMode", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0].update({"releaseMode": "rollback"}))),
    ("helm setValues non-string value", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0].update({"setValues": {"replicas": 3}}))),
    ("helm valuesFiles non-string item", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0].update({"valuesFiles": [1]}))),
    ("kustomize declares sources", _mutated(kustomize_document(), lambda d: d["spec"]["scenarios"][0].update({"sources": ["m/*.yaml"]}))),
    ("kustomize declares setValues", _mutated(kustomize_document(), lambda d: d["spec"]["scenarios"][0].update({"setValues": {"a": "b"}}))),
    ("apiVersions non-list", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update({"apiVersions": "v1"}))),
    ("apiVersions empty string item", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update({"apiVersions": [""]}))),
    ("baselineCase mutable ref", _mutated(kustomize_document(), lambda d: d["spec"]["scenarios"][0]["baselineCases"][0].update({"ref": "main"}))),
    ("baselineCase unknown state", _mutated(kustomize_document(), lambda d: d["spec"]["scenarios"][0]["baselineCases"][0].update({"state": "absent"}))),
    ("baselineCase new without reason", _mutated(kustomize_document(), lambda d: d["spec"]["scenarios"][0]["baselineCases"][0].pop("reason"))),
    ("baselineCase new with inputs", _mutated(kustomize_document(), lambda d: d["spec"]["scenarios"][0]["baselineCases"][0].update({"inputs": {"path": "x"}}))),
    ("baselineCase existing without inputs", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0]["baselineCases"][0].pop("inputs"))),
    ("baselineCase existing with reason", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0]["baselineCases"][0].update({"reason": "x"}))),
    ("baselineCase empty inputs", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0]["baselineCases"][0].update({"inputs": {}}))),
    ("baselineCase inputs unknown key", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0]["baselineCases"][0]["inputs"].update({"releaseName": "x"}))),
    ("raw baselineCase overrides path", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update(
        {"baselineCases": [{"ref": SHA40, "state": "existing", "inputs": {"path": "old"}}]}))),
    ("raw baselineCase overrides valuesFiles", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update(
        {"baselineCases": [{"ref": SHA40, "state": "existing", "inputs": {"valuesFiles": ["old.yaml"]}}]}))),
    ("helm baselineCase overrides sources", _mutated(helm_document(), lambda d: d["spec"]["scenarios"][0]["baselineCases"][0]["inputs"].update({"sources": ["old/*.yaml"]}))),
    ("kustomize baselineCase overrides valuesFiles", _mutated(kustomize_document(), lambda d: d["spec"]["scenarios"][0].update(
        {"baselineCases": [{"ref": SHA40, "state": "existing", "inputs": {"valuesFiles": ["old.yaml"]}}]}))),
    ("kindScope bad scope", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update(
        {"kindScopes": [{"group": "demo.example.com", "kind": "Widget", "scope": "Global"}]}))),
    ("kindScope missing kind", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update(
        {"kindScopes": [{"group": "demo.example.com", "scope": "Namespaced"}]}))),
    ("protectedLabels empty keys", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update(
        {"protectedLabels": [{"location": "/metadata/labels", "keys": []}]}))),
    ("protectedLabels invalid pointer", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update(
        {"protectedLabels": [{"location": "metadata labels", "keys": ["a"]}]}))),
    ("protectedLabels pointer bad escape", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update(
        {"protectedLabels": [{"location": "/metadata/labels~x", "keys": ["a"]}]}))),
    ("protectedResource missing name", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update(
        {"protectedResources": [{"group": "", "kind": "ConfigMap", "namespace": "rhoai"}]}))),
    ("protectedResource unknown property", _mutated(raw_document(), lambda d: d["spec"]["scenarios"][0].update(
        {"protectedResources": [{"group": "", "kind": "ConfigMap", "namespace": "rhoai", "name": "c", "extra": 1}]}))),
    ("exception missing reason", _mutated(full_optional_document(), lambda d: d["spec"]["scenarios"][0]["exceptions"][0].pop("reason"))),
    ("exception unknown property", _mutated(full_optional_document(), lambda d: d["spec"]["scenarios"][0]["exceptions"][0].update({"expires": "2027-01-01"}))),
    ("exception invalid path pointer", _mutated(full_optional_document(), lambda d: d["spec"]["scenarios"][0]["exceptions"][0].update({"path": "spec selector"}))),
    ("exception mutable baselineRef", _mutated(full_optional_document(), lambda d: d["spec"]["scenarios"][0]["exceptions"][0].update({"baselineRef": "HEAD"}))),
    ("exception bad edgeId", _mutated(full_optional_document(), lambda d: d["spec"]["scenarios"][0]["exceptions"][1].update({"edgeId": "not-a-hash"}))),
    ("exception empty ruleId", _mutated(full_optional_document(), lambda d: d["spec"]["scenarios"][0]["exceptions"][0].update({"ruleId": ""}))),
]


class TestSchemaAndRuntimeAgree:
    def test_schema_is_valid_draft_2020_12(self) -> None:
        jsonschema.Draft202012Validator.check_schema(SCHEMA)

    @pytest.mark.parametrize("label,document", VALID_CORPUS, ids=[label for label, _ in VALID_CORPUS])
    def test_valid_documents_accepted_by_both(self, label: str, document: dict[str, Any]) -> None:
        jsonschema.Draft202012Validator(SCHEMA).validate(document)
        assert config.validate_structure(document) == document

    @pytest.mark.parametrize("label,document", INVALID_CORPUS, ids=[label for label, _ in INVALID_CORPUS])
    def test_invalid_documents_rejected_by_both(self, label: str, document: dict[str, Any]) -> None:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(SCHEMA).validate(document)
        with pytest.raises(config.ConfigError):
            config.validate_structure(document)

    def test_validate_structure_does_not_mutate(self) -> None:
        document = full_optional_document()
        snapshot = copy.deepcopy(document)
        config.validate_structure(document)
        assert document == snapshot


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / "app.yaml").write_text("kind: ConfigMap\n", encoding="utf-8")
    (tmp_path / "charts" / "demo").mkdir(parents=True)
    (tmp_path / "charts" / "demo" / "Chart.yaml").write_text("apiVersion: v2\n", encoding="utf-8")
    (tmp_path / "charts" / "demo" / "values.yaml").write_text("a: b\n", encoding="utf-8")
    (tmp_path / "charts" / "legacy").mkdir(parents=True)
    (tmp_path / "charts" / "legacy" / "Chart.yaml").write_text("apiVersion: v2\n", encoding="utf-8")
    (tmp_path / "charts" / "legacy" / "values.yaml").write_text("a: b\n", encoding="utf-8")
    (tmp_path / "overlays" / "prod").mkdir(parents=True)
    (tmp_path / "overlays" / "prod" / "kustomization.yaml").write_text("resources: []\n", encoding="utf-8")
    return tmp_path


def write_descriptor(repo: Path, document: dict[str, Any]) -> Path:
    path = repo / ".rhoai" / "manifests.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


class TestLoadConfig:
    def test_loads_all_scenarios(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["scenarios"].append(helm_document()["spec"]["scenarios"][0])
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        assert loaded["manifest_set"] == path.as_posix()
        assert loaded["tools"] == {}
        assert [scenario["id"] for scenario in loaded["scenarios"]] == ["raw-main", "helm-main"]

    def test_selects_one_scenario(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["tools"] = {"helmVersion": "4.3.1", "kustomizeVersion": "5.8.3"}
        document["spec"]["scenarios"].append(helm_document()["spec"]["scenarios"][0])
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path, scenario_id="helm-main")
        assert [scenario["id"] for scenario in loaded["scenarios"]] == ["helm-main"]
        assert loaded["tools"] == {"helmVersion": "4.3.1", "kustomizeVersion": "5.8.3"}

    def test_unknown_scenario_id_is_rejected(self, repo: Path) -> None:
        path = write_descriptor(repo, raw_document())
        with pytest.raises(config.ConfigError, match="Unknown scenario id 'nope'"):
            config.load_config(repo, path, scenario_id="nope")

    def test_duplicate_scenario_ids_are_rejected(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["scenarios"].append(raw_document()["spec"]["scenarios"][0])
        path = write_descriptor(repo, document)
        with pytest.raises(config.ConfigError, match="Duplicate scenario ids: raw-main"):
            config.load_config(repo, path)

    def test_missing_descriptor_is_rejected(self, repo: Path) -> None:
        with pytest.raises(config.ConfigError, match="not found"):
            config.load_config(repo, Path(".rhoai/manifests.yaml"))

    def test_malformed_descriptor_is_rejected(self, repo: Path) -> None:
        path = repo / ".rhoai" / "manifests.yaml"
        path.parent.mkdir(parents=True)
        path.write_text("apiVersion: [unclosed", encoding="utf-8")
        with pytest.raises(config.ConfigError, match="Cannot parse"):
            config.load_config(repo, Path(".rhoai/manifests.yaml"))

    def test_duplicate_descriptor_keys_are_rejected(self, repo: Path) -> None:
        path = repo / ".rhoai" / "manifests.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(
            "apiVersion: contracts.rhoai.io/v1alpha1\nkind: ManifestSet\n"
            "apiVersion: contracts.rhoai.io/v1alpha1\n",
            encoding="utf-8",
        )
        with pytest.raises(config.ConfigError, match="Cannot parse"):
            config.load_config(repo, Path(".rhoai/manifests.yaml"))

    def test_descriptor_outside_repository_is_rejected(self, repo: Path) -> None:
        outside = repo.parent / "outside.yaml"
        outside.write_text(yaml.safe_dump(raw_document()), encoding="utf-8")
        with pytest.raises(config.ConfigError, match="outside the repository"):
            config.load_config(repo, outside)


class TestValidateContext:
    def check(self, repo: Path, document: dict[str, Any], baseline_refs: list[str] | None = None) -> None:
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        config.validate_context(loaded, repo, baseline_refs or [SHA40], CATALOGUE)

    def test_valid_raw_context_passes(self, repo: Path) -> None:
        self.check(repo, raw_document())

    def test_unsupported_minor_is_rejected(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["scenarios"][0]["kubernetesVersion"] = "1.34.2"
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="outside the audited minors"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_non_audited_patch_of_supported_minor_passes(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["scenarios"][0]["kubernetesVersion"] = "1.35.4"
        self.check(repo, document)

    def test_mutable_requested_ref_is_rejected(self, repo: Path) -> None:
        path = write_descriptor(repo, raw_document())
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="full 40- or 64-character"):
            config.validate_context(loaded, repo, ["main"], CATALOGUE)

    def test_helm_scenario_requires_helm_pin(self, repo: Path) -> None:
        document = helm_document()
        document["spec"].pop("tools")
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="helmVersion must be pinned"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_raw_only_descriptor_needs_no_tools(self, repo: Path) -> None:
        self.check(repo, raw_document())

    def test_kustomize_scenario_requires_kustomize_pin(self, repo: Path) -> None:
        document = kustomize_document()
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="kustomizeVersion must be pinned"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_kustomize_with_pins_passes(self, repo: Path) -> None:
        document = kustomize_document()
        document["spec"]["tools"] = {"helmVersion": "4.3.1", "kustomizeVersion": "5.8.3"}
        self.check(repo, document)

    def test_kindscope_conflict_is_rejected(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["scenarios"][0]["kindScopes"] = [
            {"group": "demo.example.com", "kind": "Widget", "scope": "Namespaced"},
            {"group": "demo.example.com", "kind": "Widget", "scope": "Cluster"},
        ]
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="conflicting kindScopes"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_kindscope_for_builtin_kind_is_rejected(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["scenarios"][0]["kindScopes"] = [
            {"group": "apps", "kind": "Deployment", "scope": "Cluster"},
        ]
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="duplicates the built-in scope table"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_identical_duplicate_kindscopes_pass(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["scenarios"][0]["kindScopes"] = [
            {"group": "demo.example.com", "kind": "Widget", "scope": "Namespaced"},
            {"group": "demo.example.com", "kind": "Widget", "scope": "Namespaced"},
        ]
        self.check(repo, document)

    def test_exception_for_unknown_rule_is_rejected(self, repo: Path) -> None:
        document = full_optional_document()
        document["spec"]["scenarios"][0]["exceptions"][0]["ruleId"] = "not-a-rule"
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="unknown rule id 'not-a-rule'"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_exception_for_never_waivable_rule_is_rejected(self, repo: Path) -> None:
        document = full_optional_document()
        document["spec"]["scenarios"][0]["exceptions"][0]["ruleId"] = "label-removed"
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="never waiver-eligible"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_relational_exception_requires_edge_fields(self, repo: Path) -> None:
        document = full_optional_document()
        exception = document["spec"]["scenarios"][0]["exceptions"][1]
        exception.pop("relatedResource")
        exception.pop("edgeId")
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="requires relatedResource and edgeId"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_nonrelational_exception_rejects_edge_fields(self, repo: Path) -> None:
        document = full_optional_document()
        exception = document["spec"]["scenarios"][0]["exceptions"][0]
        exception["relatedResource"] = {"group": "", "kind": "Pod", "namespace": "rhoai", "name": "p"}
        exception["edgeId"] = EDGE_ID
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="must not declare"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_valid_exceptions_pass(self, repo: Path) -> None:
        self.check(repo, full_optional_document())

    def test_helm_chart_path_must_exist(self, repo: Path) -> None:
        document = helm_document()
        document["spec"]["scenarios"][0]["path"] = "charts/absent"
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="does not exist"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_helm_values_file_must_exist(self, repo: Path) -> None:
        document = helm_document()
        document["spec"]["scenarios"][0]["valuesFiles"] = ["charts/demo/absent.yaml"]
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="does not exist"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_kustomize_path_must_exist(self, repo: Path) -> None:
        document = kustomize_document()
        document["spec"]["tools"] = {"helmVersion": "4.3.1", "kustomizeVersion": "5.8.3"}
        document["spec"]["scenarios"][0]["path"] = "overlays/absent"
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="does not exist"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_absolute_chart_path_is_rejected(self, repo: Path) -> None:
        document = helm_document()
        document["spec"]["scenarios"][0]["path"] = "/etc"
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="repo-relative"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_traversing_chart_path_is_rejected(self, repo: Path) -> None:
        document = helm_document()
        document["spec"]["scenarios"][0]["path"] = "../outside"
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="repo-relative"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_traversing_raw_glob_is_rejected(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["scenarios"][0]["sources"] = ["../secrets/*.yaml"]
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="repo-relative"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_absolute_raw_glob_is_rejected(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["scenarios"][0]["sources"] = ["/etc/*.yaml"]
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="repo-relative"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_unmatched_raw_glob_is_allowed_at_config_time(self, repo: Path) -> None:
        document = raw_document()
        document["spec"]["scenarios"][0]["sources"] = ["absent/*.yaml"]
        self.check(repo, document)

    def test_baseline_case_inputs_traversal_is_rejected(self, repo: Path) -> None:
        document = helm_document()
        document["spec"]["scenarios"][0]["baselineCases"][0]["inputs"]["path"] = "../outside"
        path = write_descriptor(repo, document)
        loaded = config.load_config(repo, path)
        with pytest.raises(config.ConfigError, match="repo-relative"):
            config.validate_context(loaded, repo, [SHA40], CATALOGUE)

    def test_baseline_case_for_unrequested_ref_is_retained(self, repo: Path) -> None:
        document = full_optional_document()
        scenario = document["spec"]["scenarios"][0]
        scenario["baselineCases"].append(
            {"ref": "d" * 40, "state": "existing", "inputs": {"sources": ["legacy/*.yaml"]}}
        )
        self.check(repo, document)
