"""Regression tests for manifest selector and reference relationship checks.

Covers the graph matrix from the standing testing rules: label-selector
operator semantics with missing-key behavior, API-specific nil/empty
selector meanings for Service/PDB/NetworkPolicy, namespace isolation, the
required-reference transition and optionality table, slot matching by name
under list reordering, deterministic edge IDs with candidate correlation
keys, protected label/resource contracts, label and removal drift, Service
named targetPort reliance, and partial-coverage reporting for unsupported
selector surfaces. The mirrored finding metadata is asserted against the
policy.json catalogue so the two can never drift apart.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "modules" / "manifest-compat" / "relationships.py"
POLICY_PATH = ROOT / "modules" / "manifest-compat" / "policy.json"

spec = importlib.util.spec_from_file_location("manifest_relationships_test", MODULE_PATH)
assert spec is not None and spec.loader is not None
relationships = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relationships)

CATALOGUE = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

SCENARIO: dict[str, Any] = {"id": "rel-scenario"}
NS = "ns"
Key = tuple[str, str, str, str]

_UNSET: Any = object()


# ---------------------------------------------------------------------------
# Object-map helpers
# ---------------------------------------------------------------------------


def key_of(document: dict[str, Any]) -> Key:
    api_version = document["apiVersion"]
    group = api_version.split("/")[0] if "/" in api_version else ""
    metadata = document.get("metadata", {})
    return (group, document["kind"], metadata.get("namespace", ""), metadata["name"])


def objects(*documents: dict[str, Any]) -> dict[Key, dict[str, Any]]:
    result: dict[Key, dict[str, Any]] = {}
    for index, document in enumerate(documents, start=1):
        result[key_of(document)] = {
            "document": document,
            "source": "rendered.yaml",
            "document_index": index,
        }
    return result


def compare(baseline_docs: list[dict[str, Any]], candidate_docs: list[dict[str, Any]],
            scenario: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    return relationships.compare(
        objects(*baseline_docs), objects(*candidate_docs),
        SCENARIO if scenario is None else scenario, CATALOGUE,
    )


def validate(candidate_docs: list[dict[str, Any]],
             scenario: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    return relationships.validate_candidate(
        objects(*candidate_docs), SCENARIO if scenario is None else scenario
    )


def findings_for(findings: list[dict[str, Any]], rule_id: str) -> list[dict[str, Any]]:
    return [finding for finding in findings if finding["id"] == rule_id]


def ids_of(findings: list[dict[str, Any]]) -> list[str]:
    return [finding["id"] for finding in findings]


def identity_of(key: Key) -> dict[str, str]:
    group, kind, namespace, name = key
    return {"group": group, "kind": kind, "namespace": namespace, "name": name}


def expected_edge_id(relation: str, consumer: Key, consumer_path: str,
                     target: Key, target_path: str) -> str:
    payload = {
        "relation": relation,
        "consumer": identity_of(consumer),
        "consumer_path": consumer_path,
        "target": identity_of(target),
        "target_path": target_path,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Document builders
# ---------------------------------------------------------------------------


def configmap(name: str, data: dict[str, str] | None = None,
              labels: dict[str, str] | None = None, namespace: str = NS) -> dict[str, Any]:
    metadata: dict[str, Any] = {"name": name, "namespace": namespace}
    if labels is not None:
        metadata["labels"] = labels
    document: dict[str, Any] = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata}
    if data is not None:
        document["data"] = data
    return document


def secret_doc(name: str, data: dict[str, str] | None = None,
               namespace: str = NS) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
    }
    if data is not None:
        document["data"] = data
    return document


def service_account(name: str, namespace: str = NS) -> dict[str, Any]:
    return {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"name": name, "namespace": namespace},
    }


def service(name: str, selector: Any = _UNSET, ports: list[dict[str, Any]] | None = None,
            namespace: str = NS) -> dict[str, Any]:
    spec: dict[str, Any] = {}
    if selector is not _UNSET:
        spec["selector"] = selector
    if ports is not None:
        spec["ports"] = ports
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": namespace}, "spec": spec}


def container(name: str = "main", env: list[dict[str, Any]] | None = None,
              env_from: list[dict[str, Any]] | None = None,
              ports: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"name": name, "image": f"img/{name}"}
    if env is not None:
        result["env"] = env
    if env_from is not None:
        result["envFrom"] = env_from
    if ports is not None:
        result["ports"] = ports
    return result


def workload(kind: str, name: str, *, template_labels: dict[str, str] | None = None,
             selector: Any = _UNSET, containers: list[dict[str, Any]] | None = None,
             init_containers: list[dict[str, Any]] | None = None,
             volumes: list[dict[str, Any]] | None = None, service_account_name: str | None = None,
             metadata_labels: dict[str, str] | None = None,
             namespace: str = NS) -> dict[str, Any]:
    api_version = "batch/v1" if kind in ("Job", "CronJob") else "apps/v1"
    if selector is _UNSET:
        selector = {"matchLabels": dict(template_labels or {})}
    metadata: dict[str, Any] = {"name": name, "namespace": namespace}
    if metadata_labels is not None:
        metadata["labels"] = metadata_labels
    pod_spec: dict[str, Any] = {
        "containers": containers if containers is not None else [container()],
    }
    if init_containers is not None:
        pod_spec["initContainers"] = init_containers
    if volumes is not None:
        pod_spec["volumes"] = volumes
    if service_account_name is not None:
        pod_spec["serviceAccountName"] = service_account_name
    return {
        "apiVersion": api_version, "kind": kind, "metadata": metadata,
        "spec": {
            "selector": selector,
            "template": {
                "metadata": {"labels": dict(template_labels or {})},
                "spec": pod_spec,
            },
        },
    }


def pod(name: str, labels: dict[str, str] | None = None,
        namespace: str = NS) -> dict[str, Any]:
    metadata: dict[str, Any] = {"name": name, "namespace": namespace}
    if labels is not None:
        metadata["labels"] = labels
    return {"apiVersion": "v1", "kind": "Pod", "metadata": metadata,
            "spec": {"containers": [container()]}}


def pdb(name: str, selector: Any = _UNSET, namespace: str = NS) -> dict[str, Any]:
    spec: dict[str, Any] = {}
    if selector is not _UNSET:
        spec["selector"] = selector
    return {"apiVersion": "policy/v1", "kind": "PodDisruptionBudget",
            "metadata": {"name": name, "namespace": namespace}, "spec": spec}


def networkpolicy(name: str, pod_selector: Any = _UNSET,
                  ingress: list[dict[str, Any]] | None = None,
                  egress: list[dict[str, Any]] | None = None,
                  namespace: str = NS) -> dict[str, Any]:
    spec: dict[str, Any] = {}
    if pod_selector is not _UNSET:
        spec["podSelector"] = pod_selector
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": namespace}, "spec": spec}


def role(name: str, namespace: str = NS) -> dict[str, Any]:
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": name, "namespace": namespace}}


def cluster_role(name: str) -> dict[str, Any]:
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": {"name": name}}


def role_binding(name: str, ref_kind: str, ref_name: str,
                 namespace: str = NS) -> dict[str, Any]:
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": name, "namespace": namespace},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                        "kind": ref_kind, "name": ref_name},
            "subjects": []}


def cluster_role_binding(name: str, ref_kind: str, ref_name: str) -> dict[str, Any]:
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": name},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                        "kind": ref_kind, "name": ref_name},
            "subjects": []}


def backend(service_name: str, port_name: str | None = None,
            port_number: int | None = None) -> dict[str, Any]:
    port: dict[str, Any] = {}
    if port_name is not None:
        port["name"] = port_name
    if port_number is not None:
        port["number"] = port_number
    return {"service": {"name": service_name, "port": port}}


def ingress_doc(name: str = "ing", rules: list[dict[str, Any]] | None = None,
                default_backend: dict[str, Any] | None = None,
                namespace: str = NS) -> dict[str, Any]:
    spec: dict[str, Any] = {}
    if default_backend is not None:
        spec["defaultBackend"] = default_backend
    if rules is not None:
        spec["rules"] = rules
    return {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
            "metadata": {"name": name, "namespace": namespace}, "spec": spec}


def env_key_ref(env_name: str, ref_field: str, ref_name: str, key: str,
                optional: bool = False) -> dict[str, Any]:
    ref: dict[str, Any] = {"name": ref_name, "key": key}
    if optional:
        ref["optional"] = True
    return {"name": env_name, "valueFrom": {ref_field: ref}}


def env_configmap_key(env_name: str, cfg_name: str, key: str,
                      optional: bool = False) -> dict[str, Any]:
    return env_key_ref(env_name, "configMapKeyRef", cfg_name, key, optional)


def env_secret_key(env_name: str, secret_name: str, key: str,
                   optional: bool = False) -> dict[str, Any]:
    return env_key_ref(env_name, "secretKeyRef", secret_name, key, optional)


def env_literal(env_name: str, value: str = "literal") -> dict[str, Any]:
    return {"name": env_name, "value": value}


def envfrom(ref_field: str, name: str, optional: bool = False) -> dict[str, Any]:
    ref: dict[str, Any] = {"name": name}
    if optional:
        ref["optional"] = True
    return {ref_field: ref}


def volume_configmap(volume_name: str, cfg_name: str, keys: list[str] | None = None,
                     optional: bool = False) -> dict[str, Any]:
    ref: dict[str, Any] = {"name": cfg_name}
    if keys is not None:
        ref["items"] = [{"key": key} for key in keys]
    if optional:
        ref["optional"] = True
    return {"name": volume_name, "configMap": ref}


def volume_secret(volume_name: str, secret_name: str, keys: list[str] | None = None,
                  optional: bool = False) -> dict[str, Any]:
    ref: dict[str, Any] = {"secretName": secret_name}
    if keys is not None:
        ref["items"] = [{"key": key} for key in keys]
    if optional:
        ref["optional"] = True
    return {"name": volume_name, "secret": ref}


def projected_volume(volume_name: str,
                     sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {"name": volume_name, "projected": {"sources": sources}}


def dep_with_env(env: list[dict[str, Any]], name: str = "web") -> dict[str, Any]:
    return workload("Deployment", name, template_labels={"app": "web"},
                    containers=[container(env=env)])


def dep_exposing(port_name: str, protocol: str | None = None) -> dict[str, Any]:
    port: dict[str, Any] = {"name": port_name, "containerPort": 8080}
    if protocol is not None:
        port["protocol"] = protocol
    return workload("Deployment", "web", template_labels={"app": "web"},
                    containers=[container(ports=[port])])


def svc_target_port(name: str = "svc") -> dict[str, Any]:
    return service(name, selector={"app": "web"},
                   ports=[{"name": "http", "port": 80, "targetPort": "http"}])


DEP_KEY: Key = ("apps", "Deployment", NS, "web")
SVC_KEY: Key = ("", "Service", NS, "svc")
ENV_REF_PATH = "/spec/template/spec/containers/0/env/0/valueFrom/configMapKeyRef"
TEMPLATE_LABELS = "/spec/template/metadata/labels"


# ---------------------------------------------------------------------------
# Finding metadata registry agreement
# ---------------------------------------------------------------------------


class TestRulesRegistryAgreement:
    def test_mirrored_rules_agree_with_policy_catalogue(self) -> None:
        catalogue_by_id = {entry["id"]: entry for entry in CATALOGUE["rules"]}
        expected_ids = {
            "selector-template-mismatch", "selector-target-lost",
            "mutable-selector-changed", "required-reference-lost",
            "external-reference-unverified", "label-removed", "label-value-changed",
            "protected-label-changed", "resource-removed",
            "protected-resource-removed", "rule-coverage-partial",
        }
        assert expected_ids <= set(relationships._RULES)
        assert set(relationships._RULES) <= set(catalogue_by_id)
        for rule_id, metadata in relationships._RULES.items():
            entry = catalogue_by_id[rule_id]
            assert metadata["severity"] == entry["severity"], rule_id
            assert metadata["evidence"] == entry["evidence"], rule_id
            assert metadata["classification"] == entry["classification"], rule_id


# ---------------------------------------------------------------------------
# Label selector semantics
# ---------------------------------------------------------------------------


class TestSelectorForm:
    @pytest.mark.parametrize("expression,labels,expected", [
        ({"key": "env", "operator": "In", "values": ["prod"]}, {"env": "prod"}, True),
        ({"key": "env", "operator": "In", "values": ["prod"]}, {"env": "dev"}, False),
        ({"key": "env", "operator": "In", "values": ["prod"]}, {}, False),
        ({"key": "env", "operator": "NotIn", "values": ["prod"]}, {"env": "dev"}, True),
        ({"key": "env", "operator": "NotIn", "values": ["prod"]}, {"env": "prod"}, False),
        ({"key": "env", "operator": "NotIn", "values": ["prod"]}, {}, True),
        ({"key": "env", "operator": "Exists", "values": []}, {"env": "dev"}, True),
        ({"key": "env", "operator": "Exists", "values": []}, {}, False),
        ({"key": "env", "operator": "DoesNotExist", "values": []}, {}, True),
        ({"key": "env", "operator": "DoesNotExist", "values": []}, {"env": "dev"}, False),
        ({"key": "env", "operator": "Gt", "values": ["1"]}, {"env": "2"}, False),
    ])
    def test_operator_matrix(self, expression: dict[str, Any],
                             labels: dict[str, Any], expected: bool) -> None:
        form = relationships._selector_form({"matchExpressions": [expression]})
        assert form is not None
        assert relationships._form_matches(form, labels) is expected

    def test_match_labels_require_equality(self) -> None:
        form = relationships._selector_form({"matchLabels": {"app": "web"}})
        assert form is not None
        assert relationships._form_matches(form, {"app": "web"})
        assert not relationships._form_matches(form, {"app": "other"})
        assert not relationships._form_matches(form, {})

    def test_plain_map_and_match_labels_canonicalize_identically(self) -> None:
        assert (relationships._selector_form({"app": "web"})
                == relationships._selector_form({"matchLabels": {"app": "web"}}))

    @pytest.mark.parametrize("selector", [None, {}, {"matchLabels": {}},
                                          {"matchExpressions": []}])
    def test_empty_selectors_have_no_form(self, selector: Any) -> None:
        assert relationships._selector_form(selector) is None


# ---------------------------------------------------------------------------
# Selector target graph (compare)
# ---------------------------------------------------------------------------


class TestSelectorTargetGraph:
    def test_value_edit_on_referenced_label_loses_selection(self) -> None:
        baseline_dep = workload("Deployment", "web", template_labels={"app": "web"})
        candidate_dep = workload("Deployment", "web", template_labels={"app": "other"})
        findings = compare(
            [service("svc", selector={"app": "web"}), baseline_dep],
            [service("svc", selector={"app": "web"}), candidate_dep],
        )
        assert ids_of(findings) == ["selector-target-lost"]
        finding = findings[0]
        assert finding["resource"] == identity_of(SVC_KEY)
        assert finding["path"] == "/spec/selector"
        assert finding["severity"] == "error"
        assert finding["evidence"] == "local-graph"
        assert finding["classification"] == "selector"
        assert finding["scenario"] == "rel-scenario"
        assert finding["relation"] == "selects"
        assert finding["related_resource"] == identity_of(DEP_KEY)
        assert finding["related_path"] == TEMPLATE_LABELS
        assert finding["path_origin"] == "baseline"
        assert finding["edge_id"] == expected_edge_id(
            "selects", SVC_KEY, "/spec/selector", DEP_KEY, TEMPLATE_LABELS)
        assert "candidate_edge_id" not in finding
        assert "no longer selects" in finding["text"]
        assert "not a live endpoint" in finding["text"]

    def test_label_removal_loses_selection_and_suppresses_drift(self) -> None:
        baseline_dep = workload("Deployment", "web",
                                template_labels={"app": "web", "tier": "front"})
        candidate_dep = workload("Deployment", "web", template_labels={"tier": "front"})
        findings = compare(
            [service("svc", selector={"app": "web"}), baseline_dep],
            [service("svc", selector={"app": "web"}), candidate_dep],
        )
        assert ids_of(findings) == ["selector-target-lost"]
        assert "no longer declares" not in findings[0]["text"]

    def test_label_addition_breaking_does_not_exist_expression(self) -> None:
        selector = {"matchExpressions": [
            {"key": "env", "operator": "DoesNotExist"}]}
        baseline_dep = workload("Deployment", "web", template_labels={"app": "web"})
        candidate_dep = workload("Deployment", "web",
                                 template_labels={"app": "web", "env": "prod"})
        findings = compare(
            [pdb("budget", selector=selector), baseline_dep],
            [pdb("budget", selector=selector), candidate_dep],
        )
        assert ids_of(findings) == ["selector-target-lost"]

    def test_not_in_value_edit_loses_selection(self) -> None:
        selector = {"matchExpressions": [
            {"key": "env", "operator": "NotIn", "values": ["prod"]}]}
        baseline_dep = workload("Deployment", "web",
                                template_labels={"app": "web", "env": "dev"})
        candidate_dep = workload("Deployment", "web",
                                 template_labels={"app": "web", "env": "prod"})
        findings = compare(
            [pdb("budget", selector=selector), baseline_dep],
            [pdb("budget", selector=selector), candidate_dep],
        )
        assert ids_of(findings) == ["selector-target-lost"]
        assert findings[0]["related_resource"] == identity_of(DEP_KEY)

    def test_target_disappearance_loses_selection(self) -> None:
        findings = compare(
            [service("svc", selector={"app": "web"}),
             workload("Deployment", "web", template_labels={"app": "web"})],
            [service("svc", selector={"app": "web"})],
        )
        assert ids_of(findings) == ["resource-removed", "selector-target-lost"]
        removed = findings_for(findings, "resource-removed")[0]
        assert removed["resource"] == identity_of(DEP_KEY)
        assert removed["path"] == ""
        assert removed["severity"] == "warn"
        assert removed["evidence"] == "unverified"
        assert "disappeared" in findings_for(findings, "selector-target-lost")[0]["text"]

    def test_namespace_isolation(self) -> None:
        findings = compare(
            [service("svc", selector={"app": "web"}),
             workload("Deployment", "web", template_labels={"app": "web"}),
             pod("other", labels={"app": "web"}, namespace="other-ns")],
            [service("svc", selector={"app": "web"}),
             workload("Deployment", "web", template_labels={"app": "web"}),
             pod("other", labels={"app": "changed"}, namespace="other-ns")],
        )
        assert findings_for(findings, "selector-target-lost") == []
        assert ids_of(findings) == ["label-value-changed"]

    def test_unreferenced_label_change_keeps_selection_and_warns_drift(self) -> None:
        findings = compare(
            [service("svc", selector={"app": "web"}),
             workload("Deployment", "web",
                      template_labels={"app": "web", "tier": "front"})],
            [service("svc", selector={"app": "web"}),
             workload("Deployment", "web",
                      template_labels={"app": "web", "tier": "back"})],
        )
        assert ids_of(findings) == ["label-value-changed"]
        assert findings[0]["path"] == f"{TEMPLATE_LABELS}/tier"

    def test_changed_consumer_selector_warns_without_edge_metadata(self) -> None:
        dep = workload("Deployment", "web", template_labels={"app": "web"})
        findings = compare(
            [service("svc", selector={"app": "web"}), dep],
            [service("svc", selector={"app": "other"}), dep],
        )
        assert ids_of(findings) == ["mutable-selector-changed"]
        finding = findings[0]
        assert finding["severity"] == "warn"
        assert finding["evidence"] == "unverified"
        assert finding["relation"] == "selects"
        assert finding["path"] == "/spec/selector"
        assert "edge_id" not in finding
        assert "related_resource" not in finding
        assert "path_origin" not in finding
        assert "changed its selector" in finding["text"]

    def test_plain_map_empty_to_absent_is_unchanged(self) -> None:
        dep = workload("Deployment", "web", template_labels={"app": "web"})
        findings = compare(
            [service("svc", selector={}), dep],
            [service("svc"), dep],
        )
        assert findings == []

    def test_pdb_nil_to_empty_is_a_selector_change(self) -> None:
        dep = workload("Deployment", "web", template_labels={"app": "web"})
        findings = compare(
            [pdb("budget", selector=None), dep],
            [pdb("budget", selector={}), dep],
        )
        assert ids_of(findings) == ["mutable-selector-changed"]

    def test_pdb_empty_selector_survives_label_change(self) -> None:
        findings = compare(
            [pdb("budget", selector={}),
             workload("Deployment", "web", template_labels={"app": "web"})],
            [pdb("budget", selector={}),
             workload("Deployment", "web", template_labels={"app": "other"})],
        )
        assert ids_of(findings) == ["label-value-changed"]

    def test_pdb_empty_selector_loses_disappeared_target(self) -> None:
        findings = compare(
            [pdb("budget", selector={}),
             workload("Deployment", "web", template_labels={"app": "web"})],
            [pdb("budget", selector={})],
        )
        assert ids_of(findings) == ["resource-removed", "selector-target-lost"]
        assert findings_for(findings, "selector-target-lost")[0][
            "related_resource"] == identity_of(DEP_KEY)

    def test_pdb_nil_selector_selects_nothing(self) -> None:
        findings = compare(
            [pdb("budget", selector=None),
             workload("Deployment", "web", template_labels={"app": "web"})],
            [pdb("budget", selector=None),
             workload("Deployment", "web", template_labels={"app": "other"})],
        )
        assert ids_of(findings) == ["label-value-changed"]

    def test_networkpolicy_empty_pod_selector_survives_label_change(self) -> None:
        findings = compare(
            [networkpolicy("np", pod_selector={}), pod("p", labels={"app": "a"})],
            [networkpolicy("np", pod_selector={}), pod("p", labels={"app": "b"})],
        )
        assert ids_of(findings) == ["label-value-changed"]

    def test_networkpolicy_absent_pod_selector_loses_disappeared_target(self) -> None:
        findings = compare(
            [networkpolicy("np"), pod("p", labels={"app": "a"})],
            [networkpolicy("np")],
        )
        assert ids_of(findings) == ["resource-removed", "selector-target-lost"]

    def test_service_absent_selector_selects_nothing(self) -> None:
        findings = compare(
            [service("svc"), pod("p", labels={"app": "a"})],
            [service("svc"), pod("p", labels={"app": "b"})],
        )
        assert ids_of(findings) == ["label-value-changed"]


# ---------------------------------------------------------------------------
# Selector/template validation (validate_candidate)
# ---------------------------------------------------------------------------


APPS_KINDS = ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"]


class TestSelectorTemplateValidation:
    @pytest.mark.parametrize("kind", APPS_KINDS)
    @pytest.mark.parametrize("selector", [None, {}])
    def test_apps_nil_or_empty_selector_is_invalid(self, kind: str,
                                                   selector: Any) -> None:
        findings = validate([workload(kind, "web", template_labels={"app": "web"},
                                      selector=selector)])
        assert ids_of(findings) == ["selector-template-mismatch"]
        finding = findings[0]
        assert finding["severity"] == "error"
        assert finding["evidence"] == "local-graph"
        assert finding["classification"] == "render-validation"
        assert finding["path"] == "/spec/selector"
        assert "absent or empty" in finding["text"]

    @pytest.mark.parametrize("kind", APPS_KINDS)
    def test_apps_selector_template_mismatch(self, kind: str) -> None:
        findings = validate([workload(kind, "web", template_labels={"app": "other"},
                                      selector={"matchLabels": {"app": "web"}})])
        assert ids_of(findings) == ["selector-template-mismatch"]
        assert "does not match its own pod template labels" in findings[0]["text"]

    @pytest.mark.parametrize("kind", APPS_KINDS)
    def test_apps_selector_template_match_is_valid(self, kind: str) -> None:
        findings = validate([workload(kind, "web", template_labels={"app": "web"})])
        assert findings == []

    def test_match_expressions_selector_template_match_is_valid(self) -> None:
        findings = validate([workload(
            "Deployment", "web",
            template_labels={"app": "web", "tier": "front"},
            selector={"matchExpressions": [
                {"key": "app", "operator": "In", "values": ["web"]}]})])
        assert findings == []

    def test_job_selector_is_never_fabricated(self) -> None:
        findings = validate([workload("Job", "j", template_labels={"app": "j"},
                                      selector=None)])
        assert findings == []

    def test_job_explicit_selector_mismatch(self) -> None:
        findings = validate([workload("Job", "j", template_labels={"app": "j"},
                                      selector={"matchLabels": {"app": "other"}})])
        assert ids_of(findings) == ["selector-template-mismatch"]

    def test_job_explicit_selector_match(self) -> None:
        findings = validate([workload("Job", "j", template_labels={"app": "j"})])
        assert findings == []

    def test_cronjob_is_not_selector_validated(self) -> None:
        cronjob = {
            "apiVersion": "batch/v1", "kind": "CronJob",
            "metadata": {"name": "cj", "namespace": NS},
            "spec": {"schedule": "* * * * *", "jobTemplate": {"spec": {"template": {
                "metadata": {"labels": {"app": "x"}},
                "spec": {"containers": [{"name": "c", "image": "i"}]}}}}},
        }
        assert validate([cronjob]) == []

    def test_finding_carries_candidate_metadata(self) -> None:
        findings = validate([workload("Deployment", "web",
                                      template_labels={"app": "other"},
                                      selector={"matchLabels": {"app": "web"}})])
        finding = findings[0]
        assert finding["relation"] == "selects-template"
        assert finding["related_resource"] == identity_of(DEP_KEY)
        assert finding["related_path"] == TEMPLATE_LABELS
        assert finding["path_origin"] == "candidate"
        assert finding["baseline_associations"] == []
        assert finding["edge_id"] == expected_edge_id(
            "selects-template", DEP_KEY, "/spec/selector", DEP_KEY, TEMPLATE_LABELS)
        assert "cannot be waived" in finding["text"]


# ---------------------------------------------------------------------------
# Reference transition table (compare)
# ---------------------------------------------------------------------------


class TestReferenceTransitions:
    def test_env_reference_replaced_by_literal_ends_reliance(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg", "k")]),
             configmap("cfg", {"k": "v"})],
            [dep_with_env([env_literal("A")]), configmap("cfg", {"k": "v"})],
        )
        assert findings == []

    def test_ended_reliance_still_reports_independent_removal(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg", "k")]),
             configmap("cfg", {"k": "v"})],
            [dep_with_env([env_literal("A")])],
        )
        assert ids_of(findings) == ["resource-removed"]

    def test_env_slot_removal_ends_reliance(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg", "k")]),
             configmap("cfg", {"k": "v"})],
            [dep_with_env([])],
        )
        assert ids_of(findings) == ["resource-removed"]

    def test_envfrom_removal_ends_reliance(self) -> None:
        baseline = workload("Deployment", "web", template_labels={"app": "web"},
                            containers=[container(env_from=[envfrom("configMapRef", "cfg")])])
        candidate = workload("Deployment", "web", template_labels={"app": "web"},
                             containers=[container()])
        findings = compare([baseline, configmap("cfg")], [candidate])
        assert ids_of(findings) == ["resource-removed"]

    def test_volume_removal_ends_reliance(self) -> None:
        baseline = workload("Deployment", "web", template_labels={"app": "web"},
                            volumes=[volume_configmap("v", "cfg", keys=["k"])])
        candidate = workload("Deployment", "web", template_labels={"app": "web"})
        findings = compare([baseline, configmap("cfg", {"k": "v"})], [candidate])
        assert ids_of(findings) == ["resource-removed"]

    def test_reference_kind_switch_with_local_targets_is_compatible(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg", "k")]),
             configmap("cfg", {"k": "v"})],
            [dep_with_env([env_secret_key("A", "sec", "s")]),
             configmap("cfg", {"k": "v"}), secret_doc("sec", {"s": "b"})],
        )
        assert findings == []

    def test_candidate_optionality_suppresses_object_loss(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg", "k")]),
             configmap("cfg", {"k": "v"})],
            [dep_with_env([env_configmap_key("A", "cfg", "k", optional=True)])],
        )
        assert ids_of(findings) == ["resource-removed"]

    def test_optional_to_required_stays_unverified(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg-ext", "k", optional=True)])],
            [dep_with_env([env_configmap_key("A", "cfg-ext", "k")])],
        )
        assert ids_of(findings) == ["external-reference-unverified"]
        finding = findings[0]
        assert finding["severity"] == "warn"
        assert finding["evidence"] == "unverified"
        assert finding["path_origin"] == "baseline"
        assert finding["relation"] == "env-configmap-key"

    def test_required_to_optional_key_loss_is_suppressed(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg", "k")]),
             configmap("cfg", {"k": "v"})],
            [dep_with_env([env_configmap_key("A", "cfg", "k", optional=True)]),
             configmap("cfg", {})],
        )
        assert findings == []

    def test_local_object_loss_errors(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg", "k")]),
             configmap("cfg", {"k": "v"})],
            [dep_with_env([env_configmap_key("A", "cfg", "k")])],
        )
        assert ids_of(findings) == ["required-reference-lost", "resource-removed"]
        finding = findings[0]
        cfg_key: Key = ("", "ConfigMap", NS, "cfg")
        assert finding["resource"] == identity_of(DEP_KEY)
        assert finding["path"] == ENV_REF_PATH
        assert finding["relation"] == "env-configmap-key"
        assert finding["related_resource"] == identity_of(cfg_key)
        assert finding["related_path"] == ""
        assert finding["path_origin"] == "baseline"
        assert finding["edge_id"] == expected_edge_id(
            "env-configmap-key", DEP_KEY, ENV_REF_PATH, cfg_key, "")
        assert "candidate_edge_id" not in finding
        assert finding["severity"] == "error"

    def test_local_key_loss_errors_with_correlation_key(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg", "k")]),
             configmap("cfg", {"k": "v"})],
            [dep_with_env([env_configmap_key("A", "cfg", "k")]), configmap("cfg", {})],
        )
        assert ids_of(findings) == ["required-reference-lost"]
        finding = findings[0]
        cfg_key: Key = ("", "ConfigMap", NS, "cfg")
        assert finding["related_path"] == "/data/k"
        assert finding["edge_id"] == expected_edge_id(
            "env-configmap-key", DEP_KEY, ENV_REF_PATH, cfg_key, "/data/k")
        assert finding["candidate_edge_id"] == finding["edge_id"]
        assert "key 'k'" in finding["text"]

    def test_retarget_to_local_resolving_target_is_compatible(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg-old", "k")]),
             configmap("cfg-old", {"k": "v"})],
            [dep_with_env([env_configmap_key("A", "cfg-new", "k")]),
             configmap("cfg-new", {"k": "v"})],
        )
        assert ids_of(findings) == ["resource-removed"]

    def test_retarget_to_unresolved_target_warns(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg", "k")]),
             configmap("cfg", {"k": "v"})],
            [dep_with_env([env_configmap_key("A", "cfg-gone", "k")]),
             configmap("cfg", {"k": "v"})],
        )
        assert ids_of(findings) == ["external-reference-unverified"]
        assert findings[0]["path_origin"] == "baseline"

    def test_new_required_reference_warns(self) -> None:
        findings = compare(
            [dep_with_env([])],
            [dep_with_env([env_configmap_key("A", "cfg-new", "k")])],
        )
        assert ids_of(findings) == ["external-reference-unverified"]
        finding = findings[0]
        assert finding["path_origin"] == "candidate"
        assert finding["relation"] == "env-configmap-key"

    def test_already_external_reference_still_warns(self) -> None:
        docs = [dep_with_env([env_configmap_key("A", "cfg-ext", "k")])]
        findings = compare(docs, [dep_with_env([env_configmap_key("A", "cfg-ext", "k")])])
        assert ids_of(findings) == ["external-reference-unverified"]
        assert findings[0]["path_origin"] == "baseline"

    def test_baseline_broken_key_is_owned_by_candidate_validation(self) -> None:
        baseline = [dep_with_env([env_configmap_key("A", "cfg", "k")]),
                    configmap("cfg", {})]
        candidate = [dep_with_env([env_configmap_key("A", "cfg", "k")]),
                     configmap("cfg", {})]
        assert compare(baseline, candidate) == []
        findings = validate(candidate)
        assert ids_of(findings) == ["required-reference-lost"]
        finding = findings[0]
        assert finding["path_origin"] == "candidate"
        assert finding["baseline_associations"] == []
        assert finding["related_path"] == "/data/k"

    def test_slot_reordering_keeps_baseline_anchoring(self) -> None:
        baseline = [dep_with_env([
            env_configmap_key("A", "cfg1", "k"),
            env_configmap_key("B", "cfg2", "k"),
        ]), configmap("cfg1", {"k": "v"}), configmap("cfg2", {"k": "v"})]
        candidate = [dep_with_env([
            env_configmap_key("B", "cfg2", "k"),
            env_configmap_key("A", "cfg1", "k"),
        ])]
        findings = compare(baseline, candidate)
        assert ids_of(findings) == ["required-reference-lost", "required-reference-lost",
                                    "resource-removed", "resource-removed"]
        first, second = findings[0], findings[1]
        assert first["path"] == ENV_REF_PATH
        assert second["path"] == ENV_REF_PATH.replace("env/0", "env/1")
        cfg1: Key = ("", "ConfigMap", NS, "cfg1")
        cfg2: Key = ("", "ConfigMap", NS, "cfg2")
        assert first["related_resource"] == identity_of(cfg1)
        assert second["related_resource"] == identity_of(cfg2)
        assert first["edge_id"] != second["edge_id"]
        assert first["edge_id"] == expected_edge_id(
            "env-configmap-key", DEP_KEY, ENV_REF_PATH, cfg1, "")
        assert second["edge_id"] == expected_edge_id(
            "env-configmap-key", DEP_KEY,
            ENV_REF_PATH.replace("env/0", "env/1"), cfg2, "")
        assert "candidate_edge_id" not in first
        assert "candidate_edge_id" not in second

    def test_two_losses_to_different_targets_have_distinct_edges(self) -> None:
        baseline = [dep_with_env([
            env_configmap_key("A", "cfg1", "k"),
            env_configmap_key("B", "cfg2", "k"),
        ]), configmap("cfg1", {"k": "v"}), configmap("cfg2", {"k": "v"})]
        candidate = [dep_with_env([
            env_configmap_key("A", "cfg1", "k"),
            env_configmap_key("B", "cfg2", "k"),
        ])]
        findings = compare(baseline, candidate)
        assert ids_of(findings) == ["required-reference-lost", "required-reference-lost",
                                    "resource-removed", "resource-removed"]
        first, second = findings[0], findings[1]
        cfg1: Key = ("", "ConfigMap", NS, "cfg1")
        cfg2: Key = ("", "ConfigMap", NS, "cfg2")
        assert first["related_resource"] == identity_of(cfg1)
        assert second["related_resource"] == identity_of(cfg2)
        assert first["edge_id"] != second["edge_id"]

    def test_two_env_slots_sharing_target_and_key_stay_distinct(self) -> None:
        baseline = [dep_with_env([
            env_configmap_key("A", "cfg", "k"),
            env_configmap_key("B", "cfg", "k"),
        ]), configmap("cfg", {"k": "v"})]
        candidate = [dep_with_env([
            env_configmap_key("A", "cfg", "k"),
            env_configmap_key("B", "cfg", "k"),
        ]), configmap("cfg", {})]
        findings = compare(baseline, candidate)
        assert ids_of(findings) == ["required-reference-lost", "required-reference-lost"]
        first, second = findings
        assert first["path"] == ENV_REF_PATH
        assert second["path"] == ENV_REF_PATH.replace("env/0", "env/1")
        assert first["edge_id"] != second["edge_id"]
        assert first["candidate_edge_id"] != second["candidate_edge_id"]
        validation = validate(candidate)
        assert ids_of(validation) == ["required-reference-lost", "required-reference-lost"]
        assert {f["edge_id"] for f in validation} == {
            first["candidate_edge_id"], second["candidate_edge_id"]}

    def test_candidate_edge_id_matches_validation_after_reordering(self) -> None:
        baseline = [dep_with_env([
            env_configmap_key("A", "cfg", "k"),
            env_literal("X"),
        ]), configmap("cfg", {"k": "v"})]
        candidate = [dep_with_env([
            env_literal("X"),
            env_configmap_key("A", "cfg", "k"),
        ]), configmap("cfg", {})]
        findings = compare(baseline, candidate)
        assert ids_of(findings) == ["required-reference-lost"]
        finding = findings[0]
        assert finding["path"] == ENV_REF_PATH
        candidate_path = ENV_REF_PATH.replace("env/0", "env/1")
        assert finding["candidate_edge_id"] != finding["edge_id"]
        assert finding["candidate_edge_id"] == expected_edge_id(
            "env-configmap-key", DEP_KEY, candidate_path,
            ("", "ConfigMap", NS, "cfg"), "/data/k")
        validation = validate(candidate)
        assert ids_of(validation) == ["required-reference-lost"]
        assert validation[0]["edge_id"] == finding["candidate_edge_id"]
        assert validation[0]["path"] == candidate_path


# ---------------------------------------------------------------------------
# Reference kinds
# ---------------------------------------------------------------------------


class TestReferenceKinds:
    def test_service_account_reference_loss(self) -> None:
        baseline = [workload("Deployment", "web", template_labels={"app": "web"},
                             service_account_name="sa"), service_account("sa")]
        candidate = [workload("Deployment", "web", template_labels={"app": "web"},
                              service_account_name="sa")]
        findings = compare(baseline, candidate)
        assert ids_of(findings) == ["required-reference-lost", "resource-removed"]
        finding = findings[0]
        sa_key: Key = ("", "ServiceAccount", NS, "sa")
        assert finding["relation"] == "service-account"
        assert finding["path"] == "/spec/template/spec/serviceAccountName"
        assert finding["related_resource"] == identity_of(sa_key)

    def test_rolebinding_role_loss(self) -> None:
        baseline = [role_binding("rb", "Role", "r1"), role("r1")]
        findings = compare(baseline, [role_binding("rb", "Role", "r1")])
        assert ids_of(findings) == ["required-reference-lost", "resource-removed"]
        finding = findings[0]
        assert finding["relation"] == "role-ref"
        assert finding["path"] == "/roleRef"
        assert finding["related_resource"] == identity_of(
            ("rbac.authorization.k8s.io", "Role", NS, "r1"))

    def test_clusterrolebinding_clusterrole_loss(self) -> None:
        baseline = [cluster_role_binding("crb", "ClusterRole", "cr"), cluster_role("cr")]
        findings = compare(baseline, [cluster_role_binding("crb", "ClusterRole", "cr")])
        assert ids_of(findings) == ["required-reference-lost", "resource-removed"]
        assert findings[0]["relation"] == "role-ref"
        assert findings[0]["related_resource"] == identity_of(
            ("rbac.authorization.k8s.io", "ClusterRole", "", "cr"))

    def test_rolebinding_retarget_to_local_role_is_compatible(self) -> None:
        findings = compare(
            [role_binding("rb", "Role", "r1"), role("r1")],
            [role_binding("rb", "Role", "r2"), role("r1"), role("r2")],
        )
        assert findings == []

    def test_rolebinding_retarget_to_unresolved_warns(self) -> None:
        findings = compare(
            [role_binding("rb", "Role", "r1"), role("r1")],
            [role_binding("rb", "Role", "r9"), role("r1")],
        )
        assert ids_of(findings) == ["external-reference-unverified"]
        assert findings[0]["relation"] == "role-ref"

    def test_ingress_backend_service_loss(self) -> None:
        ingress = ingress_doc(
            default_backend=backend("svc"),
            rules=[{"host": "a.example", "http": {"paths": [
                {"path": "/", "pathType": "Prefix",
                 "backend": backend("svc", port_name="web")}]}}],
        )
        svc = service("svc", ports=[{"name": "web", "port": 80, "targetPort": 8080}])
        findings = compare([ingress, svc], [ingress])
        assert ids_of(findings) == [
            "required-reference-lost", "required-reference-lost", "resource-removed"]
        first, second, _ = findings
        assert first["path"] == "/spec/defaultBackend"
        assert second["path"] == "/spec/rules/0/http/paths/0/backend"
        assert first["relation"] == "ingress-backend-service"
        assert first["edge_id"] != second["edge_id"]

    def test_ingress_backend_without_port_resolves_when_service_present(self) -> None:
        ingress = ingress_doc(rules=[{"host": "a.example", "http": {"paths": [
            {"path": "/", "pathType": "Prefix", "backend": backend("svc")}]}}])
        svc = service("svc", ports=[{"name": "web", "port": 80, "targetPort": 8080}])
        assert compare([ingress, svc], [ingress, svc]) == []
        assert validate([ingress, svc]) == []

    def test_ingress_backend_port_loss(self) -> None:
        ingress = ingress_doc(rules=[{"host": "a.example", "http": {"paths": [
            {"path": "/", "pathType": "Prefix",
             "backend": backend("svc", port_name="web")}]}}])
        findings = compare(
            [ingress, service("svc", ports=[{"name": "web", "port": 80,
                                             "targetPort": 8080}])],
            [ingress, service("svc", ports=[{"name": "api", "port": 80,
                                             "targetPort": 8080}])],
        )
        assert ids_of(findings) == ["required-reference-lost"]
        finding = findings[0]
        assert finding["related_path"] == "/spec/ports"
        assert "candidate_edge_id" in finding
        assert "requested service port" in finding["text"]

    def test_volume_configmap_key_loss(self) -> None:
        baseline = [workload("Deployment", "web", template_labels={"app": "web"},
                             volumes=[volume_configmap("v", "cfg", keys=["k"])]),
                    configmap("cfg", {"k": "v"})]
        candidate = [workload("Deployment", "web", template_labels={"app": "web"},
                              volumes=[volume_configmap("v", "cfg", keys=["k"])]),
                     configmap("cfg", {})]
        findings = compare(baseline, candidate)
        assert ids_of(findings) == ["required-reference-lost"]
        finding = findings[0]
        assert finding["relation"] == "volume-configmap"
        assert finding["path"] == "/spec/template/spec/volumes/0/configMap"
        assert finding["related_path"] == "/data/k"

    def test_projected_sources_key_loss(self) -> None:
        volume = projected_volume("p", [
            {"configMap": {"name": "cfg", "items": [{"key": "k"}]}},
            {"secret": {"name": "sec", "items": [{"key": "s"}]}},
        ])
        baseline = [workload("Deployment", "web", template_labels={"app": "web"},
                             volumes=[volume]),
                    configmap("cfg", {"k": "v"}), secret_doc("sec", {"s": "b"})]
        candidate = [workload("Deployment", "web", template_labels={"app": "web"},
                              volumes=[volume]),
                     configmap("cfg", {}), secret_doc("sec", {})]
        findings = compare(baseline, candidate)
        assert ids_of(findings) == ["required-reference-lost", "required-reference-lost"]
        first, second = findings
        assert first["relation"] == "projected-configmap"
        assert first["path"] == "/spec/template/spec/volumes/0/projected/sources/0/configMap"
        assert second["relation"] == "projected-secret"
        assert second["path"] == "/spec/template/spec/volumes/0/projected/sources/1/secret"

    def test_envfrom_configmap_loss(self) -> None:
        baseline = [workload("Deployment", "web", template_labels={"app": "web"},
                             containers=[container(env_from=[envfrom("configMapRef", "cfg")])]),
                    configmap("cfg")]
        candidate = [workload("Deployment", "web", template_labels={"app": "web"},
                              containers=[container(env_from=[envfrom("configMapRef", "cfg")])])]
        findings = compare(baseline, candidate)
        assert ids_of(findings) == ["required-reference-lost", "resource-removed"]
        assert findings[0]["relation"] == "envfrom-configmap"
        assert findings[0]["path"] == "/spec/template/spec/containers/0/envFrom/0/configMapRef"

    def test_envfrom_secret_optional_never_finds(self) -> None:
        docs = [workload("Deployment", "web", template_labels={"app": "web"},
                         containers=[container(env_from=[envfrom("secretRef", "sec",
                                                                 optional=True)])])]
        assert compare(docs, docs) == []
        assert validate(docs) == []

    def test_generated_config_rotation_with_updated_references(self) -> None:
        baseline = [dep_with_env([env_configmap_key("A", "app-5d4b8", "k")]),
                    configmap("app-5d4b8", {"k": "v"})]
        candidate = [dep_with_env([env_configmap_key("A", "app-9f2c1", "k")]),
                     configmap("app-9f2c1", {"k": "v"})]
        findings = compare(baseline, candidate)
        assert ids_of(findings) == ["resource-removed"]
        assert findings[0]["resource"] == identity_of(("", "ConfigMap", NS, "app-5d4b8"))
        assert validate(candidate) == []

    def test_init_container_env_reference_loss(self) -> None:
        baseline = [workload("Deployment", "web", template_labels={"app": "web"},
                             init_containers=[container(name="init",
                                                        env=[env_configmap_key("A", "cfg", "k")])]),
                    configmap("cfg", {"k": "v"})]
        candidate = [workload("Deployment", "web", template_labels={"app": "web"},
                             init_containers=[container(name="init",
                                                        env=[env_configmap_key("A", "cfg", "k")])]),
                     configmap("cfg", {})]
        findings = compare(baseline, candidate)
        assert ids_of(findings) == ["required-reference-lost"]
        assert findings[0]["path"] == (
            "/spec/template/spec/initContainers/0/env/0/valueFrom/configMapKeyRef")


# ---------------------------------------------------------------------------
# Service named targetPort
# ---------------------------------------------------------------------------


class TestServiceTargetPort:
    def test_named_target_port_exposure_loss(self) -> None:
        findings = compare(
            [svc_target_port(), dep_exposing("http")],
            [svc_target_port(), dep_exposing("https")],
        )
        assert ids_of(findings) == ["required-reference-lost"]
        finding = findings[0]
        assert finding["relation"] == "service-target-port"
        assert finding["resource"] == identity_of(SVC_KEY)
        assert finding["path"] == "/spec/ports/0/targetPort"
        assert finding["related_resource"] == identity_of(DEP_KEY)
        assert finding["related_path"] == "/spec/template/spec/containers"
        assert finding["path_origin"] == "baseline"
        assert "candidate_edge_id" in finding
        assert "named targetPort" in finding["text"]

    def test_protocol_mismatch_is_a_loss(self) -> None:
        findings = compare(
            [svc_target_port(), dep_exposing("http")],
            [svc_target_port(), dep_exposing("http", protocol="UDP")],
        )
        assert ids_of(findings) == ["required-reference-lost"]
        assert findings[0]["relation"] == "service-target-port"

    def test_target_port_becomes_numeric_ends_reliance(self) -> None:
        numeric = service("svc", selector={"app": "web"},
                          ports=[{"name": "http", "port": 80, "targetPort": 8080}])
        findings = compare(
            [svc_target_port(), dep_exposing("http")],
            [numeric, dep_exposing("https")],
        )
        assert findings == []

    def test_service_port_rename_ends_reliance(self) -> None:
        renamed = service("svc", selector={"app": "web"},
                          ports=[{"name": "web", "port": 80, "targetPort": "http"}])
        findings = compare(
            [svc_target_port(), dep_exposing("http")],
            [renamed, dep_exposing("https")],
        )
        assert findings == []

    def test_provider_deselection_is_reported_only_by_selector_graph(self) -> None:
        findings = compare(
            [svc_target_port(), dep_exposing("http")],
            [svc_target_port(), workload("Deployment", "web",
                                         template_labels={"app": "other"},
                                         containers=[container(ports=[
                                             {"name": "http", "containerPort": 8080}])])],
        )
        assert ids_of(findings) == ["selector-target-lost"]

    def test_validation_reports_missing_named_port(self) -> None:
        findings = validate([svc_target_port(), dep_exposing("grpc")])
        assert ids_of(findings) == ["required-reference-lost"]
        finding = findings[0]
        assert finding["relation"] == "service-target-port"
        assert finding["related_resource"] == identity_of(DEP_KEY)
        assert finding["path_origin"] == "candidate"
        assert finding["baseline_associations"] == []
        assert finding["path"] == "/spec/ports/0/targetPort"

    def test_validation_anchors_on_first_sorted_selected_target(self) -> None:
        findings = validate([
            svc_target_port(),
            workload("Deployment", "b", template_labels={"app": "web"},
                     containers=[container(name="b", ports=[
                         {"name": "grpc", "containerPort": 9090}])]),
            workload("Deployment", "a", template_labels={"app": "web"},
                     containers=[container(name="a", ports=[
                         {"name": "grpc", "containerPort": 9090}])]),
        ])
        assert ids_of(findings) == ["required-reference-lost"]
        assert findings[0]["related_resource"] == identity_of(
            ("apps", "Deployment", NS, "a"))

    def test_validation_without_selector_or_targets_is_silent(self) -> None:
        assert validate([service("svc"), pod("p", labels={"app": "other"})]) == []
        assert validate([svc_target_port(), pod("p", labels={"app": "other"})]) == []


# ---------------------------------------------------------------------------
# Protected contracts and label drift
# ---------------------------------------------------------------------------


class TestProtectedContractsAndDrift:
    def scenario_with_labels(self, location: str, keys: list[str]) -> dict[str, Any]:
        return {"id": "rel-scenario",
                "protectedLabels": [{"location": location, "keys": keys}]}

    def test_protected_label_value_change(self) -> None:
        scenario = self.scenario_with_labels("/metadata/labels", ["team"])
        findings = compare(
            [configmap("cm", {"k": "v"}, labels={"team": "red", "env": "x"})],
            [configmap("cm", {"k": "v"}, labels={"team": "blue", "env": "x"})],
            scenario,
        )
        assert ids_of(findings) == ["protected-label-changed"]
        finding = findings[0]
        assert finding["severity"] == "error"
        assert finding["evidence"] == "declared-contract"
        assert finding["classification"] == "contract"
        assert finding["path"] == "/metadata/labels/team"
        assert "protected" in finding["text"]

    def test_protected_label_removal(self) -> None:
        scenario = self.scenario_with_labels("/metadata/labels", ["team"])
        findings = compare(
            [configmap("cm", labels={"team": "red", "env": "x"})],
            [configmap("cm", labels={"env": "x"})],
            scenario,
        )
        assert ids_of(findings) == ["protected-label-changed"]

    def test_protected_label_without_baseline_pair_is_ignored(self) -> None:
        scenario = self.scenario_with_labels("/metadata/labels", ["team"])
        findings = compare(
            [configmap("cm", labels={"env": "x"})],
            [configmap("cm", labels={"env": "x", "team": "new"})],
            scenario,
        )
        assert findings == []

    def test_protected_template_label(self) -> None:
        scenario = self.scenario_with_labels(TEMPLATE_LABELS, ["app"])
        findings = compare(
            [workload("Deployment", "web", template_labels={"app": "web"})],
            [workload("Deployment", "web", template_labels={"app": "other"})],
            scenario,
        )
        assert ids_of(findings) == ["protected-label-changed"]
        assert findings[0]["path"] == f"{TEMPLATE_LABELS}/app"

    def test_protected_resource_removal(self) -> None:
        scenario = {"id": "rel-scenario", "protectedResources": [
            {"group": "", "kind": "ConfigMap", "namespace": NS, "name": "keep"}]}
        findings = compare(
            [configmap("keep"), configmap("drop")],
            [configmap("keep")],
            scenario,
        )
        assert ids_of(findings) == ["resource-removed"]
        assert findings[0]["resource"] == identity_of(("", "ConfigMap", NS, "drop"))
        findings = compare(
            [configmap("keep"), configmap("drop")],
            [],
            scenario,
        )
        assert ids_of(findings) == ["protected-resource-removed", "resource-removed"]
        first, second = findings
        assert first["resource"] == identity_of(("", "ConfigMap", NS, "keep"))
        assert first["severity"] == "error"
        assert second["resource"] == identity_of(("", "ConfigMap", NS, "drop"))
        assert second["severity"] == "warn"

    def test_unprotected_removal_warns(self) -> None:
        findings = compare([configmap("drop")], [])
        assert ids_of(findings) == ["resource-removed"]
        finding = findings[0]
        assert finding["severity"] == "warn"
        assert finding["path"] == ""
        assert "absent from the candidate render" in finding["text"]

    def test_label_drift_removed_and_changed(self) -> None:
        findings = compare(
            [configmap("cm", labels={"a": "1", "b": "2"})],
            [configmap("cm", labels={"a": "2", "c": "3"})],
        )
        assert ids_of(findings) == ["label-removed", "label-value-changed"]
        first, second = findings
        assert first["path"] == "/metadata/labels/b"
        assert second["path"] == "/metadata/labels/a"
        for finding in (first, second):
            assert finding["severity"] == "warn"
            assert finding["evidence"] == "unverified"

    def test_template_label_drift(self) -> None:
        findings = compare(
            [workload("Deployment", "web",
                      template_labels={"app": "web", "tier": "front"})],
            [workload("Deployment", "web",
                      template_labels={"app": "web", "tier": "back"})],
        )
        assert ids_of(findings) == ["label-value-changed"]
        assert findings[0]["path"] == f"{TEMPLATE_LABELS}/tier"

    def test_label_addition_never_warns(self) -> None:
        findings = compare(
            [configmap("cm", labels={"a": "1"})],
            [configmap("cm", labels={"a": "1", "new": "n"})],
        )
        assert findings == []

    def test_metadata_and_template_locations_both_checked(self) -> None:
        findings = compare(
            [workload("Deployment", "web", template_labels={"app": "web"},
                      metadata_labels={"team": "a"})],
            [workload("Deployment", "web", template_labels={"app": "web"},
                      metadata_labels={"team": "b"})],
        )
        assert ids_of(findings) == ["label-value-changed"]
        assert findings[0]["path"] == "/metadata/labels/team"


# ---------------------------------------------------------------------------
# Unsupported graph scope (validate_candidate)
# ---------------------------------------------------------------------------


class TestGraphScopeCoverage:
    def test_networkpolicy_peer_selectors_warn(self) -> None:
        np = networkpolicy(
            "np",
            ingress=[{"from": [{"podSelector": {"matchLabels": {"app": "x"}}}]}],
            egress=[{"to": [{"namespaceSelector": {}}]}],
        )
        findings = validate([np])
        assert ids_of(findings) == ["rule-coverage-partial", "rule-coverage-partial"]
        first, second = findings
        assert first["path"] == "/spec/egress"
        assert second["path"] == "/spec/ingress"
        for finding in (first, second):
            assert finding["severity"] == "warn"
            assert finding["evidence"] == "unverified"
            assert finding["classification"] == "coverage"
            assert "does not evaluate" in finding["text"]

    def test_networkpolicy_ipblock_peers_do_not_warn(self) -> None:
        np = networkpolicy("np", ingress=[{"from": [
            {"ipBlock": {"cidr": "10.0.0.0/8"}}]}])
        assert validate([np]) == []

    def test_affinity_and_topology_spread_warnings(self) -> None:
        dep = workload("Deployment", "web", template_labels={"app": "web"},
                       containers=[container(ports=None)])
        dep["spec"]["template"]["spec"]["affinity"] = {
            "podAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [
                {"topologyKey": "kubernetes.io/hostname",
                 "labelSelector": {"matchLabels": {"app": "x"}}}]}}
        dep["spec"]["template"]["spec"]["topologySpreadConstraints"] = [
            {"topologyKey": "kubernetes.io/zone",
             "labelSelector": {"matchLabels": {"app": "x"}},
             "whenUnsatisfiable": "DoNotSchedule"}]
        findings = validate([dep])
        assert ids_of(findings) == ["rule-coverage-partial", "rule-coverage-partial"]
        first, second = findings
        assert first["path"] == "/spec/template/spec/affinity"
        assert second["path"] == "/spec/template/spec/topologySpreadConstraints"

    def test_plain_objects_have_no_coverage_warnings(self) -> None:
        assert validate([workload("Deployment", "web",
                                  template_labels={"app": "web"})]) == []
        assert validate([networkpolicy("np", pod_selector={})]) == []


# ---------------------------------------------------------------------------
# Purity and interface
# ---------------------------------------------------------------------------


class TestPurityAndInterface:
    def test_compare_and_validate_preserve_inputs(self) -> None:
        baseline = objects(
            dep_with_env([env_configmap_key("A", "cfg", "k")]),
            configmap("cfg", {"k": "v"}),
        )
        candidate = objects(
            dep_with_env([env_configmap_key("A", "cfg", "k")]),
            configmap("cfg", {}),
        )
        baseline_copy = copy.deepcopy(baseline)
        candidate_copy = copy.deepcopy(candidate)
        relationships.compare(baseline, candidate, SCENARIO, CATALOGUE)
        relationships.validate_candidate(candidate, SCENARIO)
        assert baseline == baseline_copy
        assert candidate == candidate_copy

    def test_compare_accepts_full_normalize_result(self) -> None:
        baseline_docs = [dep_with_env([env_configmap_key("A", "cfg", "k")]),
                         configmap("cfg", {"k": "v"})]
        candidate_docs = [dep_with_env([env_configmap_key("A", "cfg", "k")]),
                          configmap("cfg", {})]
        full = {"objects": objects(*baseline_docs),
                "coverage": {"object_count": len(baseline_docs)}}
        findings_full = relationships.compare(
            full, objects(*candidate_docs), SCENARIO, CATALOGUE)
        assert findings_full == compare(baseline_docs, candidate_docs)

    def test_compare_is_deterministic(self) -> None:
        baseline = [service("svc", selector={"app": "web"}),
                    workload("Deployment", "web", template_labels={"app": "web"})]
        candidate = [service("svc", selector={"app": "web"})]
        assert compare(baseline, candidate) == compare(baseline, candidate)

    def test_finding_shape(self) -> None:
        findings = compare(
            [dep_with_env([env_configmap_key("A", "cfg", "k")]), configmap("cfg")],
            [dep_with_env([env_configmap_key("A", "cfg", "k")])],
        )
        assert findings
        for finding in findings:
            for key in ("id", "path", "text", "severity", "scenario", "resource",
                        "classification", "evidence"):
                assert key in finding
            assert finding["scenario"] == "rel-scenario"
            assert isinstance(finding["text"], str) and finding["text"]
