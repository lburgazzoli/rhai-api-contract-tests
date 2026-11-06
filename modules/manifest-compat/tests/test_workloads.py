"""Regression tests for the workload immutable-update policy module.

Covers the standing Workloads matrix: apps/v1 selector immutability, the
StatefulSet allowlist/immutable split across audited minors,
ControllerRevision data freezing, Job fixed fields, selector and
completions rules with source-verified defaulting, suspended-Job template
exceptions, direct-Pod normal-update restrictions (including the
tolerationSeconds edit across all three audited minors), CronJob
non-freezing, default-equivalence uncertainty, subresource boundaries,
catalogue registration of every emitted ID, and input purity.
"""

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "modules" / "manifest-compat" / "policies_workloads.py"
NORMALIZER_PATH = ROOT / "modules" / "manifest-compat" / "normalizer.py"
POLICY_PATH = ROOT / "modules" / "manifest-compat" / "policy.json"

spec = importlib.util.spec_from_file_location("manifest_workloads_test", MODULE_PATH)
assert spec is not None and spec.loader is not None
policies = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policies)

normalizer_spec = importlib.util.spec_from_file_location("manifest_normalizer_workloads_test", NORMALIZER_PATH)
assert normalizer_spec is not None and normalizer_spec.loader is not None
normalizer = importlib.util.module_from_spec(normalizer_spec)
normalizer_spec.loader.exec_module(normalizer)

CATALOGUE: dict[str, Any] = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
RULES: dict[str, dict[str, Any]] = {rule["id"]: rule for rule in CATALOGUE["rules"]}

AUDITED_VERSIONS = {"1.35": "1.35.10", "1.36": "1.36.6", "1.37": "1.37.2"}


def scenario_for(version: str = "1.36.6") -> dict[str, Any]:
    return {
        "id": "workload-scenario",
        "renderer": "raw",
        "namespace": "rhoai",
        "kubernetesVersion": version,
        "sources": ["rendered.yaml"],
    }


SCENARIO = scenario_for()


def run(
    baseline_documents: list[dict[str, Any]],
    candidate_documents: list[dict[str, Any]],
    scenario: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    scenario = scenario if scenario is not None else SCENARIO
    baseline = normalizer.normalize(
        yaml.safe_dump_all(baseline_documents, sort_keys=False).encode("utf-8"),
        "baseline.yaml",
        scenario,
    )
    candidate = normalizer.normalize(
        yaml.safe_dump_all(candidate_documents, sort_keys=False).encode("utf-8"),
        "candidate.yaml",
        scenario,
    )
    return policies.compare(baseline, candidate, scenario, CATALOGUE)


def deployment(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web"},
        "spec": {
            "replicas": 3,
            "selector": {"matchLabels": {"app": "web"}},
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {"containers": [{"name": "app", "image": "app:1"}]},
            },
        },
    }
    for key, value in overrides.items():
        if key == "selector":
            document["spec"]["selector"] = value
        elif key == "image":
            document["spec"]["template"]["spec"]["containers"][0]["image"] = value
        elif key == "replicas":
            document["spec"]["replicas"] = value
        elif key == "name":
            document["metadata"]["name"] = value
        elif key == "template_labels":
            document["spec"]["template"]["metadata"]["labels"] = value
        else:
            document[key] = value
    return document


def daemonset(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {"name": "agent"},
        "spec": {
            "selector": {"matchLabels": {"app": "agent"}},
            "template": {
                "metadata": {"labels": {"app": "agent"}},
                "spec": {"containers": [{"name": "agent", "image": "agent:1"}]},
            },
        },
    }
    for key, value in overrides.items():
        if key == "selector":
            document["spec"]["selector"] = value
        elif key == "image":
            document["spec"]["template"]["spec"]["containers"][0]["image"] = value
        else:
            document[key] = value
    return document


def replicaset(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {"name": "web-pod"},
        "spec": {
            "replicas": 2,
            "selector": {"matchLabels": {"app": "web"}},
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {"containers": [{"name": "app", "image": "app:1"}]},
            },
        },
    }
    for key, value in overrides.items():
        if key == "selector":
            document["spec"]["selector"] = value
        else:
            document[key] = value
    return document


def statefulset(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {"name": "db"},
        "spec": {
            "serviceName": "db",
            "replicas": 2,
            "selector": {"matchLabels": {"app": "db"}},
            "template": {
                "metadata": {"labels": {"app": "db"}},
                "spec": {"containers": [{"name": "db", "image": "pg:15"}]},
            },
            "volumeClaimTemplates": [
                {
                    "metadata": {"name": "data"},
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": "1Gi"}},
                    },
                }
            ],
        },
    }
    for key, value in overrides.items():
        if key in (
            "serviceName", "selector", "replicas", "template",
            "volumeClaimTemplates", "podManagementPolicy", "updateStrategy",
            "revisionHistoryLimit", "persistentVolumeClaimRetentionPolicy",
            "minReadySeconds", "ordinals",
        ):
            if value is None:
                document["spec"].pop(key, None)
            else:
                document["spec"][key] = value
        else:
            document[key] = value
    return document


def controllerrevision(data: dict[str, Any], revision: int = 1) -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "ControllerRevision",
        "metadata": {"name": "db-abc123"},
        "revision": revision,
        "data": data,
    }


def job(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": "ingest"},
        "spec": {
            "template": {
                "metadata": {},
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [{"name": "worker", "image": "worker:1"}],
                },
            },
        },
    }
    for key, value in overrides.items():
        if value is None:
            document["spec"].pop(key, None)
        else:
            document["spec"][key] = value
    return document


def cronjob(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": "nightly"},
        "spec": {
            "schedule": "0 0 * * *",
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "restartPolicy": "Never",
                            "containers": [{"name": "runner", "image": "runner:1"}],
                        },
                    },
                },
            },
        },
    }
    for key, value in overrides.items():
        if key == "image":
            document["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["image"] = value
        elif key == "schedule":
            document["spec"]["schedule"] = value
        else:
            document[key] = value
    return document


def pod(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "standalone"},
        "spec": {"containers": [{"name": "app", "image": "app:1"}]},
    }
    for key, value in overrides.items():
        if key == "image":
            document["spec"]["containers"][0]["image"] = value
        elif key == "containers":
            document["spec"]["containers"] = value
        elif value is None:
            document["spec"].pop(key, None)
        else:
            document["spec"][key] = value
    return document


def noexecute_toleration(seconds: int = 300) -> dict[str, Any]:
    return {
        "key": "node.kubernetes.io/not-ready",
        "operator": "Exists",
        "effect": "NoExecute",
        "tolerationSeconds": seconds,
    }


def assert_registered(finding: dict[str, Any]) -> None:
    """Every emitted finding must match its registered catalogue rule."""
    rule = RULES[finding["id"]]
    assert finding["severity"] == rule["severity"]
    assert finding["evidence"] == rule["evidence"]
    assert finding["classification"] == rule["classification"]
    assert finding["scenario"] == "workload-scenario"
    assert isinstance(finding["text"], str) and finding["text"]


def only(finding_list: list[dict[str, Any]]) -> dict[str, Any]:
    assert len(finding_list) == 1, finding_list
    finding = finding_list[0]
    assert_registered(finding)
    return finding


class TestDeploymentSelectors:
    def test_selector_value_change_is_an_error(self) -> None:
        findings = run(
            [deployment()],
            [deployment(selector={"matchLabels": {"app": "web-2"}})],
        )
        finding = only(findings)
        assert finding["id"] == "deployment-selector-immutable"
        assert finding["path"] == "/spec/selector"
        assert finding["resource"] == {
            "group": "apps", "kind": "Deployment", "namespace": "rhoai", "name": "web",
        }

    @pytest.mark.parametrize("version", AUDITED_VERSIONS.values())
    def test_selector_immutable_across_audited_versions(self, version: str) -> None:
        findings = run(
            [deployment()],
            [deployment(selector={"matchLabels": {"app": "other"}})],
            scenario_for(version),
        )
        assert [f["id"] for f in findings] == ["deployment-selector-immutable"]

    def test_match_expression_order_matters(self) -> None:
        selector = {
            "matchLabels": {"app": "web"},
            "matchExpressions": [
                {"key": "tier", "operator": "In", "values": ["a", "b"]},
            ],
        }
        reordered = {
            "matchLabels": {"app": "web"},
            "matchExpressions": [
                {"key": "tier", "operator": "In", "values": ["b", "a"]},
            ],
        }
        findings = run([deployment(selector=selector)], [deployment(selector=reordered)])
        assert [f["id"] for f in findings] == ["deployment-selector-immutable"]

    def test_rolling_updates_are_compatible(self) -> None:
        candidate = deployment(
            image="app:2",
            replicas=5,
            template_labels={"app": "web", "tier": "backend"},
        )
        candidate["spec"]["template"]["metadata"]["annotations"] = {"rev": "2"}
        candidate["spec"]["template"]["spec"]["containers"][0]["command"] = ["sleep"]
        findings = run([deployment()], [candidate])
        assert findings == []

    def test_removed_object_is_not_compared(self) -> None:
        findings = run([deployment(), deployment(name="extra")], [deployment()])
        assert findings == []

    def test_added_object_is_not_compared(self) -> None:
        findings = run([deployment()], [deployment(), deployment(name="extra")])
        assert findings == []


class TestDaemonSetReplicaSet:
    def test_daemonset_selector_immutable(self) -> None:
        findings = run(
            [daemonset()],
            [daemonset(selector={"matchLabels": {"app": "other"}})],
        )
        finding = only(findings)
        assert finding["id"] == "daemonset-selector-immutable"
        assert finding["path"] == "/spec/selector"

    def test_daemonset_template_rolls_freely(self) -> None:
        findings = run([daemonset()], [daemonset(image="agent:2")])
        assert findings == []

    def test_replicaset_selector_immutable(self) -> None:
        findings = run(
            [replicaset()],
            [replicaset(selector={"matchLabels": {"app": "other"}})],
        )
        finding = only(findings)
        assert finding["id"] == "replicaset-selector-immutable"
        assert finding["path"] == "/spec/selector"

    def test_replicaset_scaling_and_images_compatible(self) -> None:
        candidate = replicaset()
        candidate["spec"]["replicas"] = 6
        candidate["spec"]["template"]["spec"]["containers"][0]["image"] = "app:2"
        assert run([replicaset()], [candidate]) == []


class TestStatefulSet:
    @pytest.mark.parametrize("version", AUDITED_VERSIONS.values())
    def test_selector_immutable_in_every_audited_minor(self, version: str) -> None:
        findings = run(
            [statefulset()],
            [statefulset(selector={"matchLabels": {"app": "other"}})],
            scenario_for(version),
        )
        assert [f["id"] for f in findings] == ["statefulset-selector-immutable"]
        assert findings[0]["path"] == "/spec/selector"

    def test_service_name_immutable(self) -> None:
        findings = run([statefulset()], [statefulset(serviceName="db-legacy")])
        finding = only(findings)
        assert finding["id"] == "statefulset-service-name-immutable"
        assert finding["path"] == "/spec/serviceName"

    def test_pod_management_policy_immutable(self) -> None:
        findings = run(
            [statefulset()],
            [statefulset(podManagementPolicy="Parallel")],
        )
        finding = only(findings)
        assert finding["id"] == "statefulset-pod-management-policy-immutable"
        assert finding["path"] == "/spec/podManagementPolicy"

    def test_pod_management_policy_default_equivalent(self) -> None:
        assert run([statefulset()], [statefulset(podManagementPolicy="OrderedReady")]) == []

    def test_volume_claim_templates_change_is_an_error(self) -> None:
        candidate = statefulset(
            volumeClaimTemplates=[
                {
                    "metadata": {"name": "data"},
                    "spec": {
                        "accessModes": ["ReadWriteMany"],
                        "resources": {"requests": {"storage": "1Gi"}},
                    },
                }
            ]
        )
        findings = run([statefulset()], [candidate])
        finding = only(findings)
        assert finding["id"] == "statefulset-volume-claim-templates-immutable"
        assert finding["path"] == "/spec/volumeClaimTemplates"

    def test_volume_claim_template_storage_growth_is_conditional(self) -> None:
        candidate = statefulset(
            volumeClaimTemplates=[
                {
                    "metadata": {"name": "data"},
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": "2Gi"}},
                    },
                }
            ]
        )
        findings = run([statefulset()], [candidate])
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"
        assert finding["severity"] == "warn"
        assert finding["evidence"] == "unverified"
        assert finding["path"] == "/spec/volumeClaimTemplates"

    def test_volume_claim_template_storage_decrease_is_an_error(self) -> None:
        candidate = statefulset(
            volumeClaimTemplates=[
                {
                    "metadata": {"name": "data"},
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": "512Mi"}},
                    },
                }
            ]
        )
        findings = run([statefulset()], [candidate])
        assert [f["id"] for f in findings] == ["statefulset-volume-claim-templates-immutable"]

    def test_volume_claim_template_defaulted_volume_mode_equivalent(self) -> None:
        candidate = statefulset(
            volumeClaimTemplates=[
                {
                    "metadata": {"name": "data"},
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "volumeMode": "Filesystem",
                        "resources": {"requests": {"storage": "1Gi"}},
                    },
                }
            ]
        )
        assert run([statefulset()], [candidate]) == []

    def test_mutable_allowlist_fields_roll_freely(self) -> None:
        candidate = statefulset(
            replicas=4,
            updateStrategy={"type": "OnDelete"},
            revisionHistoryLimit=5,
            minReadySeconds=10,
            ordinals={"start": 1},
            persistentVolumeClaimRetentionPolicy={
                "whenDeleted": "Retain", "whenScaled": "Delete",
            },
        )
        candidate["spec"]["template"]["spec"]["containers"][0]["image"] = "pg:16"
        candidate["spec"]["template"]["metadata"]["labels"] = {"app": "db", "v": "2"}
        assert run([statefulset()], [candidate]) == []

    @pytest.mark.parametrize("version,expected", [
        ("1.35.10", "statefulset-spec-field-forbidden"),
        ("1.36.6", "statefulset-spec-field-forbidden"),
        ("1.37.2", "rule-coverage-partial"),
    ])
    def test_unknown_spec_field_follows_the_audited_minor(self, version: str, expected: str) -> None:
        candidate = statefulset()
        candidate["spec"]["someNewField"] = True
        findings = run([statefulset()], [candidate], scenario_for(version))
        finding = only(findings)
        assert finding["id"] == expected
        assert finding["path"] == "/spec/someNewField"


class TestControllerRevision:
    def test_data_is_immutable(self) -> None:
        findings = run(
            [controllerrevision({"spec": {"a": 1}})],
            [controllerrevision({"spec": {"a": 2}})],
        )
        finding = only(findings)
        assert finding["id"] == "controllerrevision-data-immutable"
        assert finding["path"] == "/data"
        assert finding["resource"]["kind"] == "ControllerRevision"

    def test_revision_is_mutable(self) -> None:
        assert run(
            [controllerrevision({"spec": {"a": 1}}, revision=1)],
            [controllerrevision({"spec": {"a": 1}}, revision=7)],
        ) == []


class TestJobFixedFields:
    def test_explicit_selector_change_is_an_error(self) -> None:
        selector = {"matchLabels": {"batch.kubernetes.io/job-name": "ingest"}}
        findings = run(
            [job(selector=selector)],
            [job(selector={"matchLabels": {"other": "value"}})],
        )
        finding = only(findings)
        assert finding["id"] == "job-selector-immutable"
        assert finding["path"] == "/spec/selector"

    def test_one_sided_selector_from_baseline_is_conditional(self) -> None:
        selector = {"matchLabels": {"batch.kubernetes.io/job-name": "ingest"}}
        findings = run([job(selector=selector)], [job(selector=None)])
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"
        assert finding["severity"] == "warn"
        assert finding["path"] == "/spec/selector"

    def test_one_sided_selector_from_candidate_is_conditional(self) -> None:
        selector = {"matchLabels": {"batch.kubernetes.io/job-name": "ingest"}}
        findings = run([job(selector=None)], [job(selector=selector)])
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"

    def test_both_sides_generated_selector_absence_is_compatible(self) -> None:
        assert run([job(selector=None)], [job(selector=None)]) == []

    def test_completion_mode_change_is_an_error(self) -> None:
        findings = run([job(completionMode="NonIndexed")], [job(completionMode="Indexed")])
        finding = only(findings)
        assert finding["id"] == "job-completion-mode-immutable"
        assert finding["path"] == "/spec/completionMode"

    def test_completion_mode_default_equivalent(self) -> None:
        assert run([job(completionMode=None)], [job(completionMode="NonIndexed")]) == []

    def test_pod_failure_policy_immutable(self) -> None:
        policy = {"rules": [{"action": "FailJob", "onExitCodes": {"operator": "In", "values": [42]}}]}
        findings = run([job(podFailurePolicy=None)], [job(podFailurePolicy=policy)])
        finding = only(findings)
        assert finding["id"] == "job-pod-failure-policy-immutable"
        assert finding["path"] == "/spec/podFailurePolicy"

    def test_backoff_limit_per_index_immutable(self) -> None:
        findings = run([job(backoffLimitPerIndex=3)], [job(backoffLimitPerIndex=4)])
        finding = only(findings)
        assert finding["id"] == "job-backoff-limit-per-index-immutable"
        assert finding["path"] == "/spec/backoffLimitPerIndex"

    def test_managed_by_immutable(self) -> None:
        findings = run([job(managedBy=None)], [job(managedBy="example.com/operator")])
        finding = only(findings)
        assert finding["id"] == "job-managed-by-immutable"
        assert finding["path"] == "/spec/managedBy"

    def test_success_policy_immutable(self) -> None:
        policy = {"successes": 5}
        findings = run([job(successPolicy=None)], [job(successPolicy=policy)])
        finding = only(findings)
        assert finding["id"] == "job-success-policy-immutable"
        assert finding["path"] == "/spec/successPolicy"


class TestJobCompletions:
    def test_non_indexed_completions_are_immutable(self) -> None:
        findings = run(
            [job(completions=5, parallelism=2)],
            [job(completions=3, parallelism=2)],
        )
        finding = only(findings)
        assert finding["id"] == "job-completions-rule"
        assert finding["path"] == "/spec/completions"

    def test_non_indexed_completions_removal_is_an_error(self) -> None:
        findings = run(
            [job(completions=5, parallelism=2)],
            [job(completions=None, parallelism=2)],
        )
        finding = only(findings)
        assert finding["id"] == "job-completions-rule"

    def test_both_omitted_defaults_make_explicit_ones_compatible(self) -> None:
        assert run(
            [job(completions=None, parallelism=None)],
            [job(completions=1, parallelism=1)],
        ) == []

    def test_defaulted_completions_change_is_still_an_error(self) -> None:
        findings = run(
            [job(completions=None, parallelism=None)],
            [job(completions=2, parallelism=1)],
        )
        finding = only(findings)
        assert finding["id"] == "job-completions-rule"

    def test_parallelism_only_default_equivalence(self) -> None:
        assert run(
            [job(completions=5, parallelism=None)],
            [job(completions=5, parallelism=1)],
        ) == []

    def test_indexed_valid_resize_is_compatible(self) -> None:
        assert run(
            [job(completionMode="Indexed", completions=3, parallelism=3)],
            [job(completionMode="Indexed", completions=5, parallelism=5)],
        ) == []

    def test_indexed_resize_without_matching_parallelism_is_an_error(self) -> None:
        findings = run(
            [job(completionMode="Indexed", completions=3, parallelism=3)],
            [job(completionMode="Indexed", completions=5, parallelism=3)],
        )
        finding = only(findings)
        assert finding["id"] == "job-completions-rule"
        assert finding["path"] == "/spec/completions"

    def test_indexed_completions_removal_is_an_error(self) -> None:
        findings = run(
            [job(completionMode="Indexed", completions=3, parallelism=3)],
            [job(completionMode="Indexed", completions=None, parallelism=3)],
        )
        finding = only(findings)
        assert finding["id"] == "job-completions-rule"


class TestJobTemplate:
    def test_image_change_is_a_definite_error(self) -> None:
        candidate = job()
        candidate["spec"]["template"]["spec"]["containers"][0]["image"] = "worker:2"
        findings = run([job()], [candidate])
        finding = only(findings)
        assert finding["id"] == "job-template-immutable"
        assert finding["path"] == "/spec/template"
        assert finding["severity"] == "error"
        assert finding["evidence"] == "api-rule"

    def test_command_change_is_a_definite_error(self) -> None:
        candidate = job()
        candidate["spec"]["template"]["spec"]["containers"][0]["command"] = ["worker"]
        findings = run([job()], [candidate])
        finding = only(findings)
        assert finding["id"] == "job-template-immutable"

    def test_suspended_job_image_change_is_still_an_error(self) -> None:
        candidate = job(suspend=True)
        candidate["spec"]["template"]["spec"]["containers"][0]["image"] = "worker:2"
        findings = run([job(suspend=True)], [candidate])
        finding = only(findings)
        assert finding["id"] == "job-template-immutable"

    def test_non_suspended_scheduling_change_is_an_error(self) -> None:
        candidate = job()
        candidate["spec"]["template"]["spec"]["nodeSelector"] = {"disk": "ssd"}
        findings = run([job()], [candidate])
        finding = only(findings)
        assert finding["id"] == "job-template-immutable"

    def test_suspended_job_scheduling_change_warns(self) -> None:
        candidate = job(suspend=True)
        candidate["spec"]["template"]["spec"]["nodeSelector"] = {"disk": "ssd"}
        findings = run([job(suspend=True)], [candidate])
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"
        assert finding["severity"] == "warn"
        assert finding["evidence"] == "unverified"
        assert finding["path"] == "/spec/template"

    def test_suspended_job_tolerations_labels_and_gates_warn(self) -> None:
        candidate = job(suspend=True)
        candidate["spec"]["template"]["spec"]["tolerations"] = [noexecute_toleration()]
        candidate["spec"]["template"]["spec"]["schedulingGates"] = [{"name": "example.com/wait"}]
        candidate["spec"]["template"]["metadata"]["labels"] = {"extra": "label"}
        candidate["spec"]["template"]["metadata"]["annotations"] = {"note": "x"}
        findings = run([job(suspend=True)], [candidate])
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"

    def test_suspended_job_container_resources_warn(self) -> None:
        candidate = job(suspend=True)
        candidate["spec"]["template"]["spec"]["containers"][0]["resources"] = {
            "requests": {"cpu": "200m"}
        }
        findings = run([job(suspend=True)], [candidate])
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"

    def test_suspended_job_env_change_is_an_error(self) -> None:
        candidate = job(suspend=True)
        candidate["spec"]["template"]["spec"]["containers"][0]["env"] = [
            {"name": "MODE", "value": "fast"}
        ]
        findings = run([job(suspend=True)], [candidate])
        finding = only(findings)
        assert finding["id"] == "job-template-immutable"

    def test_suspended_job_node_affinity_change_warns(self) -> None:
        candidate = job(suspend=True)
        candidate["spec"]["template"]["spec"]["affinity"] = {
            "nodeAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": [
                        {"matchExpressions": [{"key": "k", "operator": "Exists"}]}
                    ]
                }
            }
        }
        findings = run([job(suspend=True)], [candidate])
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"

    def test_suspended_job_pod_affinity_change_is_an_error(self) -> None:
        affinity: dict[str, Any] = {
            "nodeAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": [{"matchExpressions": []}]
                }
            }
        }
        candidate = job(suspend=True)
        candidate["spec"]["template"]["spec"]["affinity"] = {
            **copy.deepcopy(affinity),
            "podAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": []},
        }
        baseline = job(suspend=True)
        baseline["spec"]["template"]["spec"]["affinity"] = affinity
        findings = run([baseline], [candidate])
        finding = only(findings)
        assert finding["id"] == "job-template-immutable"

    def test_template_default_equivalence_warns_instead_of_erroring(self) -> None:
        candidate = job()
        candidate["spec"]["template"]["spec"]["terminationGracePeriodSeconds"] = 30
        findings = run([job()], [candidate])
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"
        assert finding["severity"] == "warn"

    def test_suspend_flag_itself_is_mutable(self) -> None:
        assert run([job(suspend=None)], [job(suspend=True)]) == []


class TestJobSchedulingInventory:
    def test_scheduling_change_warns_as_partial_coverage_on_137(self) -> None:
        scheduling: dict[str, Any] = {"schedulingPolicy": {"basic": {}}}
        findings = run(
            [job(scheduling=scheduling)],
            [job(scheduling={"schedulingPolicy": {"gang": {"minCount": 2}}})],
            scenario_for("1.37.2"),
        )
        finding = only(findings)
        assert finding["id"] == "job-scheduling-update"
        assert finding["severity"] == "warn"
        assert finding["evidence"] == "unverified"
        assert finding["classification"] == "risk"
        assert finding["path"] == "/spec/scheduling"

    def test_scheduling_is_not_evaluated_on_136(self) -> None:
        scheduling: dict[str, Any] = {"schedulingPolicy": {"basic": {}}}
        assert run(
            [job(scheduling=scheduling)],
            [job(scheduling={"schedulingPolicy": {"gang": {"minCount": 2}}})],
            scenario_for("1.36.6"),
        ) == []


class TestCronJob:
    def test_job_template_and_schedule_changes_are_compatible(self) -> None:
        assert run([cronjob()], [cronjob(image="runner:2", schedule="30 0 * * *")]) == []

    def test_job_template_container_changes_are_not_frozen(self) -> None:
        candidate = cronjob()
        candidate["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0][
            "command"
        ] = ["runner", "--fast"]
        candidate["spec"]["jobTemplate"]["spec"]["template"]["spec"]["nodeSelector"] = {
            "disk": "ssd"
        }
        assert run([cronjob()], [candidate]) == []


class TestDirectPod:
    @pytest.mark.parametrize("version", AUDITED_VERSIONS.values())
    def test_image_change_is_compatible_everywhere(self, version: str) -> None:
        assert run([pod()], [pod(image="app:2")], scenario_for(version)) == []

    def test_init_container_image_change_is_compatible(self) -> None:
        baseline = pod()
        baseline["spec"]["initContainers"] = [{"name": "setup", "image": "setup:1"}]
        candidate = pod()
        candidate["spec"]["initContainers"] = [{"name": "setup", "image": "setup:2"}]
        assert run([baseline], [candidate]) == []

    def test_active_deadline_set_is_compatible(self) -> None:
        assert run([pod(activeDeadlineSeconds=None)], [pod(activeDeadlineSeconds=100)]) == []

    def test_active_deadline_decrease_is_compatible(self) -> None:
        assert run([pod(activeDeadlineSeconds=100)], [pod(activeDeadlineSeconds=50)]) == []

    def test_active_deadline_increase_is_an_error(self) -> None:
        findings = run([pod(activeDeadlineSeconds=50)], [pod(activeDeadlineSeconds=100)])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/activeDeadlineSeconds"
        assert finding["severity"] == "error"

    def test_active_deadline_removal_is_an_error(self) -> None:
        findings = run([pod(activeDeadlineSeconds=100)], [pod(activeDeadlineSeconds=None)])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/activeDeadlineSeconds"

    @pytest.mark.parametrize("version", AUDITED_VERSIONS.values())
    def test_noexecute_toleration_seconds_edit_across_audited_versions(self, version: str) -> None:
        baseline = pod(tolerations=[noexecute_toleration(300)])
        candidate = pod(tolerations=[noexecute_toleration(600)])
        assert run([baseline], [candidate], scenario_for(version)) == []

    def test_added_toleration_is_compatible(self) -> None:
        baseline = pod(tolerations=[noexecute_toleration(300)])
        candidate = pod(
            tolerations=[noexecute_toleration(300), noexecute_toleration(0) | {"key": "other"}]
        )
        assert run([baseline], [candidate]) == []

    def test_toleration_removal_is_rejected(self) -> None:
        findings = run([pod(tolerations=[noexecute_toleration()])], [pod(tolerations=None)])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/tolerations/0"

    def test_toleration_effect_mutation_without_preservation_is_rejected(self) -> None:
        mutated = noexecute_toleration() | {"effect": "NoSchedule"}
        findings = run([pod(tolerations=[noexecute_toleration()])], [pod(tolerations=[mutated])])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/tolerations/0"

    def test_toleration_key_mutation_is_rejected(self) -> None:
        mutated = noexecute_toleration() | {"key": "node.kubernetes.io/unreachable"}
        findings = run([pod(tolerations=[noexecute_toleration()])], [pod(tolerations=[mutated])])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"

    def test_toleration_value_mutation_is_rejected(self) -> None:
        baseline_toleration = {"key": "zone", "operator": "Equal", "value": "a", "effect": "NoSchedule"}
        mutated = baseline_toleration | {"value": "b"}
        findings = run(
            [pod(tolerations=[baseline_toleration])], [pod(tolerations=[mutated])]
        )
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"

    def test_toleration_operator_mutation_is_rejected(self) -> None:
        baseline_toleration = {"key": "zone", "operator": "Equal", "value": "a", "effect": "NoSchedule"}
        mutated = baseline_toleration | {"operator": "Exists", "value": None}
        findings = run(
            [pod(tolerations=[baseline_toleration])], [pod(tolerations=[mutated])]
        )
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"

    def test_scheduling_gate_removal_is_compatible(self) -> None:
        baseline = pod(schedulingGates=[{"name": "example.com/wait"}])
        assert run([baseline], [pod(schedulingGates=None)]) == []

    def test_scheduling_gate_addition_is_an_error(self) -> None:
        findings = run([pod(schedulingGates=None)], [pod(schedulingGates=[{"name": "g"}])])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/schedulingGates"

    def test_gated_pod_node_selector_addition_is_compatible(self) -> None:
        baseline = pod(schedulingGates=[{"name": "example.com/wait"}], nodeSelector={"disk": "ssd"})
        candidate = pod(
            schedulingGates=[{"name": "example.com/wait"}],
            nodeSelector={"disk": "ssd", "zone": "a"},
        )
        assert run([baseline], [candidate]) == []

    def test_gated_pod_node_selector_mutation_is_an_error(self) -> None:
        baseline = pod(schedulingGates=[{"name": "example.com/wait"}], nodeSelector={"disk": "ssd"})
        candidate = pod(schedulingGates=[{"name": "example.com/wait"}], nodeSelector={"disk": "hdd"})
        findings = run([baseline], [candidate])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/nodeSelector"

    def test_ungated_pod_node_selector_change_is_an_error(self) -> None:
        findings = run([pod(nodeSelector={"disk": "ssd"})], [pod(nodeSelector={"disk": "hdd"})])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/nodeSelector"

    def test_gated_pod_node_affinity_initialization_is_compatible(self) -> None:
        baseline = pod(schedulingGates=[{"name": "example.com/wait"}])
        candidate = pod(schedulingGates=[{"name": "example.com/wait"}])
        candidate["spec"]["affinity"] = {
            "nodeAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": [
                        {"matchExpressions": [{"key": "k", "operator": "Exists"}]}
                    ]
                }
            }
        }
        assert run([baseline], [candidate]) == []

    def test_gated_pod_node_affinity_term_addition_is_an_error(self) -> None:
        affinity = {
            "nodeAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": [
                        {"matchExpressions": [{"key": "k", "operator": "Exists"}]}
                    ]
                }
            }
        }
        candidate_affinity = copy.deepcopy(affinity)
        candidate_affinity["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][
            "nodeSelectorTerms"
        ].append({"matchExpressions": [{"key": "j", "operator": "Exists"}]})
        baseline = pod(schedulingGates=[{"name": "example.com/wait"}])
        baseline["spec"]["affinity"] = affinity
        candidate = pod(schedulingGates=[{"name": "example.com/wait"}])
        candidate["spec"]["affinity"] = candidate_affinity
        findings = run([baseline], [candidate])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/affinity/nodeAffinity"

    def test_gated_pod_node_affinity_requirement_addition_is_compatible(self) -> None:
        affinity = {
            "nodeAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": [
                        {"matchExpressions": [{"key": "k", "operator": "Exists"}]}
                    ]
                }
            }
        }
        candidate_affinity = copy.deepcopy(affinity)
        candidate_affinity["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][
            "nodeSelectorTerms"
        ][0]["matchExpressions"].append({"key": "j", "operator": "Exists"})
        baseline = pod(schedulingGates=[{"name": "example.com/wait"}])
        baseline["spec"]["affinity"] = affinity
        candidate = pod(schedulingGates=[{"name": "example.com/wait"}])
        candidate["spec"]["affinity"] = candidate_affinity
        assert run([baseline], [candidate]) == []

    def test_termination_grace_period_repair_is_compatible(self) -> None:
        assert run(
            [pod(terminationGracePeriodSeconds=-5)],
            [pod(terminationGracePeriodSeconds=1)],
        ) == []

    def test_termination_grace_period_change_is_an_error(self) -> None:
        findings = run(
            [pod(terminationGracePeriodSeconds=30)],
            [pod(terminationGracePeriodSeconds=60)],
        )
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/terminationGracePeriodSeconds"

    def test_default_equivalent_termination_grace_period_warns(self) -> None:
        findings = run(
            [pod(terminationGracePeriodSeconds=None)],
            [pod(terminationGracePeriodSeconds=30)],
        )
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"
        assert finding["severity"] == "warn"
        assert finding["evidence"] == "unverified"

    def test_default_equivalent_restart_policy_warns(self) -> None:
        findings = run([pod(restartPolicy=None)], [pod(restartPolicy="Always")])
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"

    def test_default_equivalent_requests_from_limits_warns(self) -> None:
        baseline = pod()
        baseline["spec"]["containers"][0]["resources"] = {"limits": {"cpu": "1"}}
        candidate = pod()
        candidate["spec"]["containers"][0]["resources"] = {
            "limits": {"cpu": "1"}, "requests": {"cpu": "1"},
        }
        findings = run([baseline], [candidate])
        finding = only(findings)
        assert finding["id"] == "conditional-update-risk"

    def test_container_resources_change_documents_the_resize_boundary(self) -> None:
        baseline = pod()
        baseline["spec"]["containers"][0]["resources"] = {"requests": {"cpu": "100m"}}
        candidate = pod()
        candidate["spec"]["containers"][0]["resources"] = {"requests": {"cpu": "200m"}}
        findings = run([baseline], [candidate])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/containers/0/resources"
        assert "pods/resize" in finding["text"]

    def test_ephemeral_containers_change_documents_the_subresource_boundary(self) -> None:
        candidate = pod()
        candidate["spec"]["ephemeralContainers"] = [
            {"name": "debug", "image": "debug:1"}
        ]
        findings = run([pod()], [candidate])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/ephemeralContainers"
        assert "ephemeralcontainers" in finding["text"]

    def test_container_command_change_is_an_error(self) -> None:
        candidate = pod()
        candidate["spec"]["containers"][0]["command"] = ["app"]
        findings = run([pod()], [candidate])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/containers/0/command"

    def test_container_addition_is_an_error(self) -> None:
        candidate = pod(
            containers=[{"name": "app", "image": "app:1"}, {"name": "side", "image": "s:1"}]
        )
        findings = run([pod()], [candidate])
        finding = only(findings)
        assert finding["id"] == "pod-update-restricted"
        assert finding["path"] == "/spec/containers"

    def test_workload_templates_are_not_treated_as_stored_pods(self) -> None:
        candidate = daemonset()
        candidate["spec"]["template"]["spec"]["tolerations"] = [
            noexecute_toleration() | {"effect": "NoSchedule"}
        ]
        candidate["spec"]["template"]["spec"]["nodeSelector"] = {"disk": "ssd"}
        assert run([daemonset()], [candidate]) == []

    def test_unknown_minor_returns_no_findings(self) -> None:
        findings = run([pod()], [pod(image="app:2")], scenario_for("1.34.1"))
        assert findings == []


class TestApiVersionCoverage:
    def test_beta_api_version_gets_partial_coverage_instead_of_stable_rules(self) -> None:
        beta_baseline = deployment(selector={"matchLabels": {"app": "web"}})
        beta_baseline["apiVersion"] = "apps/v1beta2"
        beta_candidate = deployment(selector={"matchLabels": {"app": "other"}})
        beta_candidate["apiVersion"] = "apps/v1beta2"
        findings = run([beta_baseline], [beta_candidate])
        finding = only(findings)
        assert finding["id"] == "rule-coverage-partial"
        assert finding["severity"] == "warn"
        assert finding["classification"] == "coverage"


class TestPurityAndRegistration:
    def _normalized_pair(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        baseline_documents = [
            deployment(),
            statefulset(),
            job(suspend=True),
            pod(tolerations=[noexecute_toleration(300)]),
            controllerrevision({"spec": {"a": 1}}),
        ]
        candidate_documents = [
            deployment(selector={"matchLabels": {"app": "other"}}),
            statefulset(serviceName="other"),
            job(suspend=True),
            pod(tolerations=[noexecute_toleration(300)]),
            controllerrevision({"spec": {"a": 2}}),
        ]
        baseline = normalizer.normalize(
            yaml.safe_dump_all(baseline_documents, sort_keys=False).encode("utf-8"),
            "baseline.yaml",
            SCENARIO,
        )
        candidate = normalizer.normalize(
            yaml.safe_dump_all(candidate_documents, sort_keys=False).encode("utf-8"),
            "candidate.yaml",
            SCENARIO,
        )
        return baseline, candidate, copy.deepcopy(SCENARIO)

    def test_compare_does_not_mutate_its_inputs(self) -> None:
        baseline, candidate, scenario = self._normalized_pair()
        baseline_before = copy.deepcopy(baseline)
        candidate_before = copy.deepcopy(candidate)
        scenario_before = copy.deepcopy(scenario)
        catalogue_before = copy.deepcopy(CATALOGUE)
        findings = policies.compare(baseline, candidate, scenario, CATALOGUE)
        assert findings, "the fixture must produce findings for the purity check"
        assert baseline == baseline_before
        assert candidate == candidate_before
        assert scenario == scenario_before
        assert CATALOGUE == catalogue_before

    def test_every_emitted_id_is_registered_with_matching_metadata(self) -> None:
        baseline, candidate, scenario = self._normalized_pair()
        findings = policies.compare(baseline, candidate, scenario, CATALOGUE)
        assert findings
        for finding in findings:
            assert_registered(finding)
            assert finding["scenario"] == "workload-scenario"
            assert set(finding) == {
                "id", "path", "text", "severity", "scenario",
                "resource", "classification", "evidence",
            }

    def test_findings_are_deterministic_and_sorted(self) -> None:
        baseline, candidate, scenario = self._normalized_pair()
        first = policies.compare(baseline, candidate, scenario, CATALOGUE)
        second = policies.compare(baseline, candidate, scenario, CATALOGUE)
        assert first == second
        keys = [
            (
                f["resource"]["kind"], f["resource"]["name"], f["id"], f["path"],
            )
            for f in first
        ]
        assert keys == sorted(keys)

    def test_workload_rules_never_leak_raw_values(self) -> None:
        baseline, candidate, scenario = self._normalized_pair()
        findings = policies.compare(baseline, candidate, scenario, CATALOGUE)
        markers = ("app:1", "worker:1", "pg:15", "300", "db-abc123")
        for finding in findings:
            for marker in markers:
                assert marker not in finding["text"], (finding["id"], marker)
