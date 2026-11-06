"""Regression tests for the configuration/other-built-ins immutable policies.

Covers the "Other built-ins" matrix of the audited catalogue: for every rule a
positive breaking fixture, a compatible counterexample, the default-equivalent
case where the catalogue records defaults, target-version coverage, and the
conditional CSINode allocatable warning. Fixtures go through the real
normalizer so defaults and Secret byte canonicalization behave exactly as in
production, and every test asserts exact rule ID, pointer, resource identity,
severity, and evidence rather than only finding counts.
"""

import base64
import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
MODULES = ROOT / "modules" / "manifest-compat"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


normalizer = _load("manifest_normalizer_for_resources_tests", MODULES / "normalizer.py")
policies = _load("manifest_policies_resources_tests", MODULES / "policies_resources.py")
CATALOGUE: dict[str, Any] = json.loads((MODULES / "policy.json").read_text(encoding="utf-8"))

SECRET_MARKER = "super-secret-marker-value"

DEFAULT_SCENARIO: dict[str, Any] = {
    "id": "resources-test",
    "renderer": "raw",
    "namespace": "rhoai",
    "kubernetesVersion": "1.36.6",
    "sources": ["rendered.yaml"],
}


def render(documents: list[dict[str, Any]]) -> bytes:
    return yaml.safe_dump_all(documents, sort_keys=False).encode("utf-8")


def run_compare(baseline_docs: list[dict[str, Any]], candidate_docs: list[dict[str, Any]],
                scenario: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    scenario = dict(DEFAULT_SCENARIO if scenario is None else scenario)
    baseline = normalizer.normalize(render(baseline_docs), "baseline.yaml", scenario)
    candidate = normalizer.normalize(render(candidate_docs), "candidate.yaml", scenario)
    return policies.compare(baseline, candidate, scenario, CATALOGUE)


def doc(api_version: str, kind: str, name: str, **extra: Any) -> dict[str, Any]:
    return {"apiVersion": api_version, "kind": kind, "metadata": {"name": name}, **extra}


def configmap(name: str = "cfg", **extra: Any) -> dict[str, Any]:
    return doc("v1", "ConfigMap", name, **extra)


def secret(name: str = "sec", **extra: Any) -> dict[str, Any]:
    return doc("v1", "Secret", name, **extra)


def only(findings: list[dict[str, Any]]) -> dict[str, Any]:
    assert len(findings) == 1, f"expected exactly one finding, got {findings}"
    return findings[0]


def ids(findings: list[dict[str, Any]]) -> list[str]:
    return [finding["id"] for finding in findings]


def assert_resource(finding: dict[str, Any], kind: str, name: str,
                    namespace: str = "rhoai", group: str = "") -> None:
    assert finding["resource"] == {
        "group": group, "kind": kind, "namespace": namespace, "name": name,
    }
    assert finding["scenario"] == "resources-test"


class TestConfigMap:
    def test_immutable_data_change_errors(self) -> None:
        findings = run_compare(
            [configmap(immutable=True, data={"a": "alpha-value", "b": "beta-value"})],
            [configmap(immutable=True, data={"a": "alpha-value", "b": "gamma-value"})],
        )
        finding = only(findings)
        assert finding["id"] == "configmap-immutable-data"
        assert finding["path"] == "/data/b"
        assert finding["severity"] == "error"
        assert finding["classification"] == "immutable"
        assert finding["evidence"] == "api-rule"
        assert_resource(finding, "ConfigMap", "cfg")
        assert "beta-value" not in json.dumps(findings)
        assert "gamma-value" not in json.dumps(findings)

    def test_immutable_key_removed_and_added_error(self) -> None:
        findings = run_compare(
            [configmap(immutable=True, data={"a": "one"})],
            [configmap(immutable=True, data={"b": "one"})],
        )
        assert ids(findings) == ["configmap-immutable-data", "configmap-immutable-data"]
        assert {finding["path"] for finding in findings} == {"/data/a", "/data/b"}

    def test_immutable_flag_unset_errors(self) -> None:
        findings = run_compare(
            [configmap(immutable=True, data={"a": "one"})],
            [configmap(data={"a": "one"})],
        )
        finding = only(findings)
        assert finding["id"] == "configmap-immutable-data"
        assert finding["path"] == "/immutable"

    def test_first_setting_immutable_with_data_change_is_compatible(self) -> None:
        findings = run_compare(
            [configmap(data={"a": "one"})],
            [configmap(immutable=True, data={"a": "two"})],
        )
        assert findings == []

    def test_binary_data_change_errors(self) -> None:
        findings = run_compare(
            [configmap(immutable=True, binaryData={"blob": base64.b64encode(b"x").decode()})],
            [configmap(immutable=True, binaryData={"blob": base64.b64encode(b"y").decode()})],
        )
        finding = only(findings)
        assert finding["id"] == "configmap-immutable-data"
        assert finding["path"] == "/binaryData/blob"

    def test_absent_versus_empty_mapping_is_a_change(self) -> None:
        # ValidateConfigMapUpdate compares maps with reflect.DeepEqual, where
        # an absent data mapping and an empty one differ.
        findings = run_compare(
            [configmap(immutable=True, data={})],
            [configmap(immutable=True)],
        )
        finding = only(findings)
        assert finding["id"] == "configmap-immutable-data"
        assert finding["path"] == "/data"

    def test_metadata_change_is_not_a_data_change(self) -> None:
        findings = run_compare(
            [configmap(immutable=True, data={"a": "one"}, metadata={"name": "cfg", "labels": {"x": "1"}})],
            [configmap(immutable=True, data={"a": "one"}, metadata={"name": "cfg", "labels": {"x": "2"}})],
        )
        assert findings == []

    def test_data_key_order_is_irrelevant(self) -> None:
        findings = run_compare(
            [configmap(immutable=True, data={"a": "one", "b": "two"})],
            [configmap(immutable=True, data={"b": "two", "a": "one"})],
        )
        assert findings == []


class TestSecret:
    def test_immutable_data_change_errors_without_content(self) -> None:
        findings = run_compare(
            [secret(immutable=True, data={"k": base64.b64encode(SECRET_MARKER.encode()).decode()})],
            [secret(immutable=True, data={"k": base64.b64encode(b"other").decode()})],
        )
        finding = only(findings)
        assert finding["id"] == "secret-immutable-data"
        assert finding["path"] == "/data/k"
        assert_resource(finding, "Secret", "sec")
        assert SECRET_MARKER not in json.dumps(findings)
        assert base64.b64encode(SECRET_MARKER.encode()).decode() not in json.dumps(findings)

    def test_immutable_flag_unset_errors(self) -> None:
        findings = run_compare(
            [secret(immutable=True, data={"k": base64.b64encode(b"x").decode()})],
            [secret(data={"k": base64.b64encode(b"x").decode()})],
        )
        finding = only(findings)
        assert finding["id"] == "secret-immutable-data"
        assert finding["path"] == "/immutable"

    def test_stringdata_base64_equivalence_is_compatible(self) -> None:
        encoded = base64.b64encode(b"same-bytes").decode()
        findings = run_compare(
            [secret(immutable=True, data={"k": encoded})],
            [secret(immutable=True, stringData={"k": "same-bytes"})],
        )
        assert findings == []

    def test_first_setting_immutable_with_data_change_is_compatible(self) -> None:
        findings = run_compare(
            [secret(data={"k": base64.b64encode(b"x").decode()})],
            [secret(immutable=True, data={"k": base64.b64encode(b"y").decode()})],
        )
        assert findings == []

    def test_type_change_errors_independently_of_the_flag(self) -> None:
        findings = run_compare(
            [secret(type="Opaque", data={"k": base64.b64encode(b"x").decode()})],
            [secret(type="kubernetes.io/tls", data={"k": base64.b64encode(b"x").decode()})],
        )
        finding = only(findings)
        assert finding["id"] == "secret-type-immutable"
        assert finding["path"] == "/type"
        assert_resource(finding, "Secret", "sec")

    def test_type_default_equivalence_is_compatible(self) -> None:
        findings = run_compare(
            [secret(data={"k": base64.b64encode(b"x").decode()})],
            [secret(type="Opaque", data={"k": base64.b64encode(b"x").decode()})],
        )
        assert findings == []

    def test_ungated_data_change_is_compatible(self) -> None:
        findings = run_compare(
            [secret(data={"k": base64.b64encode(b"x").decode()})],
            [secret(data={"k": base64.b64encode(b"y").decode()})],
        )
        assert findings == []


class TestBindings:
    def test_rolebinding_roleref_change_errors(self) -> None:
        findings = run_compare(
            [doc("rbac.authorization.k8s.io/v1", "RoleBinding", "rb",
                 roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "old"},
                 subjects=[{"kind": "User", "name": "alice", "apiGroup": "rbac.authorization.k8s.io"}])],
            [doc("rbac.authorization.k8s.io/v1", "RoleBinding", "rb",
                 roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "new"},
                 subjects=[{"kind": "User", "name": "alice", "apiGroup": "rbac.authorization.k8s.io"}])],
        )
        finding = only(findings)
        assert finding["id"] == "rolebinding-roleref-immutable"
        assert finding["path"] == "/roleRef"
        assert_resource(finding, "RoleBinding", "rb", group="rbac.authorization.k8s.io")

    def test_rolebinding_subjects_are_mutable(self) -> None:
        findings = run_compare(
            [doc("rbac.authorization.k8s.io/v1", "RoleBinding", "rb",
                 roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "r"},
                 subjects=[{"kind": "User", "name": "alice", "apiGroup": "rbac.authorization.k8s.io"}])],
            [doc("rbac.authorization.k8s.io/v1", "RoleBinding", "rb",
                 roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "r"},
                 subjects=[{"kind": "User", "name": "bob", "apiGroup": "rbac.authorization.k8s.io"}])],
        )
        assert findings == []

    def test_clusterrolebinding_roleref_change_errors(self) -> None:
        findings = run_compare(
            [doc("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "crb",
                 roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "old"},
                 subjects=[])],
            [doc("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "crb",
                 roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "new"},
                 subjects=[])],
        )
        finding = only(findings)
        assert finding["id"] == "clusterrolebinding-roleref-immutable"
        assert finding["path"] == "/roleRef"
        assert_resource(finding, "ClusterRoleBinding", "crb", namespace="", group="rbac.authorization.k8s.io")

    def test_clusterrolebinding_subjects_are_mutable(self) -> None:
        findings = run_compare(
            [doc("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "crb",
                 roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "r"},
                 subjects=[])],
            [doc("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "crb",
                 roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "r"},
                 subjects=[{"kind": "ServiceAccount", "name": "sa", "namespace": "rhoai"}])],
        )
        assert findings == []


class TestStorageClass:
    BASE = {"provisioner": "ebs.csi.aws.com", "parameters": {"type": "gp3"},
            "reclaimPolicy": "Delete", "volumeBindingMode": "Immediate"}

    def sc(self, **overrides: Any) -> dict[str, Any]:
        merged = dict(self.BASE)
        merged.update(overrides)
        return doc("storage.k8s.io/v1", "StorageClass", "fast", **merged)

    def test_provisioner_change_errors(self) -> None:
        finding = only(run_compare([self.sc()], [self.sc(provisioner="other.csi.k8s.io")]))
        assert finding["id"] == "storageclass-provisioner-immutable"
        assert finding["path"] == "/provisioner"
        assert_resource(finding, "StorageClass", "fast", namespace="", group="storage.k8s.io")

    def test_parameters_change_errors(self) -> None:
        finding = only(run_compare([self.sc()], [self.sc(parameters={"type": "io2"})]))
        assert finding["id"] == "storageclass-parameters-immutable"
        assert finding["path"] == "/parameters"

    def test_reclaim_policy_default_equivalence_is_compatible(self) -> None:
        assert run_compare([self.sc()], [self.sc(reclaimPolicy=None)]) == []

    def test_reclaim_policy_change_errors(self) -> None:
        finding = only(run_compare([self.sc()], [self.sc(reclaimPolicy="Retain")]))
        assert finding["id"] == "storageclass-reclaim-policy-immutable"
        assert finding["path"] == "/reclaimPolicy"

    def test_volume_binding_mode_default_equivalence_is_compatible(self) -> None:
        assert run_compare([self.sc()], [self.sc(volumeBindingMode=None)]) == []

    def test_volume_binding_mode_change_errors(self) -> None:
        finding = only(run_compare([self.sc()], [self.sc(volumeBindingMode="WaitForFirstConsumer")]))
        assert finding["id"] == "storageclass-volume-binding-mode-immutable"
        assert finding["path"] == "/volumeBindingMode"

    def test_other_storage_settings_are_mutable(self) -> None:
        assert run_compare(
            [self.sc()],
            [self.sc(mountOptions=["ext4"], allowVolumeExpansion=True)],
        ) == []


class TestCSIDriver:
    def csi(self, **spec: Any) -> dict[str, Any]:
        return doc("storage.k8s.io/v1", "CSIDriver", "csi", spec=spec)

    def test_attach_required_default_equivalence_is_compatible(self) -> None:
        assert run_compare([self.csi()], [self.csi(attachRequired=True)]) == []

    def test_attach_required_change_errors(self) -> None:
        finding = only(run_compare([self.csi(attachRequired=True)], [self.csi(attachRequired=False)]))
        assert finding["id"] == "csidriver-attach-required-immutable"
        assert finding["path"] == "/spec/attachRequired"
        assert_resource(finding, "CSIDriver", "csi", namespace="", group="storage.k8s.io")

    def test_volume_lifecycle_modes_default_equivalence_is_compatible(self) -> None:
        assert run_compare(
            [self.csi()], [self.csi(volumeLifecycleModes=["Persistent"])]
        ) == []

    def test_volume_lifecycle_modes_empty_list_defaults_like_omitted(self) -> None:
        # SetDefaults_CSIDriver applies the default for len(modes)==0, so an
        # explicitly empty list equals the defaulted ["Persistent"].
        assert run_compare(
            [self.csi(volumeLifecycleModes=[])], [self.csi(volumeLifecycleModes=["Persistent"])]
        ) == []

    def test_volume_lifecycle_modes_change_errors(self) -> None:
        finding = only(run_compare(
            [self.csi(volumeLifecycleModes=["Persistent"])],
            [self.csi(volumeLifecycleModes=["Ephemeral"])],
        ))
        assert finding["id"] == "csidriver-volume-lifecycle-modes-immutable"
        assert finding["path"] == "/spec/volumeLifecycleModes"

    def test_pod_info_on_mount_is_mutable(self) -> None:
        assert run_compare(
            [self.csi(podInfoOnMount=False)], [self.csi(podInfoOnMount=True)]
        ) == []


class TestVolumeAttributesClass:
    def vac(self, **extra: Any) -> dict[str, Any]:
        base: dict[str, Any] = {"driverName": "csi.example.com", "parameters": {"a": "1"}}
        base.update(extra)
        return doc("storage.k8s.io/v1", "VolumeAttributesClass", "vac", **base)

    def test_driver_name_change_errors(self) -> None:
        finding = only(run_compare(
            [self.vac()], [self.vac(driverName="other.example.com")]
        ))
        assert finding["id"] == "volumeattributesclass-driver-name-immutable"
        assert finding["path"] == "/driverName"
        assert_resource(finding, "VolumeAttributesClass", "vac", namespace="", group="storage.k8s.io")

    def test_parameters_change_errors(self) -> None:
        finding = only(run_compare([self.vac()], [self.vac(parameters={"a": "2"})]))
        assert finding["id"] == "volumeattributesclass-parameters-immutable"
        assert finding["path"] == "/parameters"

    def test_beta_api_version_is_visible_not_compared(self) -> None:
        finding = only(run_compare(
            [doc("storage.k8s.io/v1beta1", "VolumeAttributesClass", "vac",
                 driverName="csi.example.com", parameters={"a": "1"})],
            [doc("storage.k8s.io/v1beta1", "VolumeAttributesClass", "vac",
                 driverName="changed.example.com", parameters={"a": "2"})],
        ))
        assert finding["id"] == "rule-coverage-partial"
        assert finding["severity"] == "warn"
        assert finding["classification"] == "coverage"
        assert finding["evidence"] == "unverified"
        assert "v1beta1" in finding["text"]


class TestVolumeAttachment:
    def test_spec_change_errors(self) -> None:
        finding = only(run_compare(
            [doc("storage.k8s.io/v1", "VolumeAttachment", "va",
                 spec={"attacher": "csi.example.com", "nodeName": "node-a", "source": {"persistentVolumeName": "pv"}})],
            [doc("storage.k8s.io/v1", "VolumeAttachment", "va",
                 spec={"attacher": "csi.example.com", "nodeName": "node-b", "source": {"persistentVolumeName": "pv"}})],
        ))
        assert finding["id"] == "volumeattachment-spec-immutable"
        assert finding["path"] == "/spec"
        assert_resource(finding, "VolumeAttachment", "va", namespace="", group="storage.k8s.io")

    def test_metadata_change_is_compatible(self) -> None:
        assert run_compare(
            [doc("storage.k8s.io/v1", "VolumeAttachment", "va",
                 spec={"attacher": "c", "nodeName": "n", "source": {}},
                 metadata={"name": "va", "labels": {"a": "1"}})],
            [doc("storage.k8s.io/v1", "VolumeAttachment", "va",
                 spec={"attacher": "c", "nodeName": "n", "source": {}},
                 metadata={"name": "va", "labels": {"a": "2"}})],
        ) == []


class TestCSIStorageCapacity:
    def csc(self, **extra: Any) -> dict[str, Any]:
        base = {"nodeTopology": {"matchLabels": {"topology": "zone-a"}},
                "storageClassName": "fast", "capacity": "100Gi"}
        base.update(extra)
        return doc("storage.k8s.io/v1", "CSIStorageCapacity", "cap", **base)

    def test_node_topology_change_errors(self) -> None:
        finding = only(run_compare(
            [self.csc()],
            [self.csc(nodeTopology={"matchLabels": {"topology": "zone-b"}})],
        ))
        assert finding["id"] == "csistoragecapacity-node-topology-immutable"
        assert finding["path"] == "/nodeTopology"
        assert_resource(finding, "CSIStorageCapacity", "cap", group="storage.k8s.io")

    def test_storage_class_name_change_errors(self) -> None:
        finding = only(run_compare([self.csc()], [self.csc(storageClassName="slow")]))
        assert finding["id"] == "csistoragecapacity-storage-class-name-immutable"
        assert finding["path"] == "/storageClassName"

    def test_capacity_is_not_frozen(self) -> None:
        assert run_compare([self.csc()], [self.csc(capacity="200Gi")]) == []


class TestCSINode:
    def csinode(self, drivers: list[dict[str, Any]]) -> dict[str, Any]:
        return doc("storage.k8s.io/v1", "CSINode", "node", spec={"drivers": drivers})

    def test_matched_entry_change_errors(self) -> None:
        finding = only(run_compare(
            [self.csinode([{"name": "csi.example.com", "nodeID": "node-1",
                            "allocatable": {"count": 4}}])],
            [self.csinode([{"name": "csi.example.com", "nodeID": "node-2",
                            "allocatable": {"count": 4}}])],
        ))
        assert finding["id"] == "csinode-driver-entries-immutable"
        assert finding["path"] == "/spec/drivers"
        assert finding["severity"] == "error"
        assert_resource(finding, "CSINode", "node", namespace="", group="storage.k8s.io")

    def test_matched_entry_allocatable_only_change_warns(self) -> None:
        finding = only(run_compare(
            [self.csinode([{"name": "csi.example.com", "nodeID": "node-1",
                            "allocatable": {"count": 4}}])],
            [self.csinode([{"name": "csi.example.com", "nodeID": "node-1",
                            "allocatable": {"count": 8}}])],
        ))
        assert finding["id"] == "conditional-update-risk"
        assert finding["severity"] == "warn"
        assert finding["classification"] == "risk"
        assert finding["evidence"] == "unverified"
        assert "MutableCSINodeAllocatableCount" in finding["text"]

    def test_entry_add_is_not_forbidden(self) -> None:
        assert run_compare(
            [self.csinode([{"name": "a.csi.example.com", "nodeID": "n"}])],
            [self.csinode([
                {"name": "a.csi.example.com", "nodeID": "n"},
                {"name": "b.csi.example.com", "nodeID": "n"},
            ])],
        ) == []

    def test_entry_removal_is_not_forbidden(self) -> None:
        assert run_compare(
            [self.csinode([
                {"name": "a.csi.example.com", "nodeID": "n"},
                {"name": "b.csi.example.com", "nodeID": "n"},
            ])],
            [self.csinode([{"name": "a.csi.example.com", "nodeID": "n"}])],
        ) == []


class TestRuntimeClass:
    def test_handler_change_errors(self) -> None:
        finding = only(run_compare(
            [doc("node.k8s.io/v1", "RuntimeClass", "rc", handler="runc",
                 overhead={"podFixed": {"cpu": "100m"}})],
            [doc("node.k8s.io/v1", "RuntimeClass", "rc", handler="kata",
                 overhead={"podFixed": {"cpu": "100m"}})],
        ))
        assert finding["id"] == "runtimeclass-handler-immutable"
        assert finding["path"] == "/handler"
        assert_resource(finding, "RuntimeClass", "rc", namespace="", group="node.k8s.io")

    def test_overhead_is_mutable(self) -> None:
        assert run_compare(
            [doc("node.k8s.io/v1", "RuntimeClass", "rc", handler="runc",
                 overhead={"podFixed": {"cpu": "100m"}})],
            [doc("node.k8s.io/v1", "RuntimeClass", "rc", handler="runc",
                 overhead={"podFixed": {"cpu": "250m"}})],
        ) == []


class TestPriorityClass:
    def pc(self, **extra: Any) -> dict[str, Any]:
        base = {"value": 1000, "preemptionPolicy": "PreemptLowerPriority",
                "description": "high", "globalDefault": False}
        base.update(extra)
        return doc("scheduling.k8s.io/v1", "PriorityClass", "high", **base)

    def test_value_change_errors(self) -> None:
        finding = only(run_compare([self.pc()], [self.pc(value=2000)]))
        assert finding["id"] == "priorityclass-value-immutable"
        assert finding["path"] == "/value"
        assert_resource(finding, "PriorityClass", "high", namespace="", group="scheduling.k8s.io")

    def test_preemption_policy_default_equivalence_is_compatible(self) -> None:
        assert run_compare([self.pc()], [self.pc(preemptionPolicy=None)]) == []

    def test_preemption_policy_change_errors(self) -> None:
        finding = only(run_compare([self.pc()], [self.pc(preemptionPolicy="Never")]))
        assert finding["id"] == "priorityclass-preemption-policy-immutable"
        assert finding["path"] == "/preemptionPolicy"

    def test_description_and_global_default_are_mutable(self) -> None:
        assert run_compare(
            [self.pc()], [self.pc(description="other", globalDefault=True)]
        ) == []


class TestIngressClass:
    def test_controller_change_errors(self) -> None:
        finding = only(run_compare(
            [doc("networking.k8s.io/v1", "IngressClass", "ic",
                 spec={"controller": "example.com/ingress-controller"})],
            [doc("networking.k8s.io/v1", "IngressClass", "ic",
                 spec={"controller": "other.com/ingress-controller"})],
        ))
        assert finding["id"] == "ingressclass-controller-immutable"
        assert finding["path"] == "/spec/controller"
        assert_resource(finding, "IngressClass", "ic", namespace="", group="networking.k8s.io")

    def test_parameters_are_mutable(self) -> None:
        assert run_compare(
            [doc("networking.k8s.io/v1", "IngressClass", "ic",
                 spec={"controller": "c", "parameters": {"apiGroup": "g", "kind": "K", "name": "n"}})],
            [doc("networking.k8s.io/v1", "IngressClass", "ic",
                 spec={"controller": "c", "parameters": {"apiGroup": "g", "kind": "K", "name": "m"}})],
        ) == []


class TestEndpointSlice:
    def test_address_type_change_errors(self) -> None:
        finding = only(run_compare(
            [doc("discovery.k8s.io/v1", "EndpointSlice", "eps", addressType="IPv4", endpoints=[])],
            [doc("discovery.k8s.io/v1", "EndpointSlice", "eps", addressType="IPv6", endpoints=[])],
        ))
        assert finding["id"] == "endpointslice-address-type-immutable"
        assert finding["path"] == "/addressType"
        assert_resource(finding, "EndpointSlice", "eps", group="discovery.k8s.io")

    def test_endpoint_and_port_edits_are_not_immutable(self) -> None:
        assert run_compare(
            [doc("discovery.k8s.io/v1", "EndpointSlice", "eps", addressType="IPv4",
                 endpoints=[{"addresses": ["10.0.0.1"]}], ports=[{"port": 80, "name": "http"}])],
            [doc("discovery.k8s.io/v1", "EndpointSlice", "eps", addressType="IPv4",
                 endpoints=[{"addresses": ["10.0.0.2"]}], ports=[{"port": 81, "name": "http"}])],
        ) == []


class TestResourceQuota:
    def rq(self, scopes: list[str], hard: dict[str, str] | None = None) -> dict[str, Any]:
        return doc("v1", "ResourceQuota", "quota",
                   spec={"scopes": scopes, "hard": hard or {"cpu": "4"}})

    def test_scope_reordering_is_compatible(self) -> None:
        assert run_compare(
            [self.rq(["PriorityClass", "Terminating"])],
            [self.rq(["Terminating", "PriorityClass"])],
        ) == []

    def test_scope_change_errors(self) -> None:
        finding = only(run_compare(
            [self.rq(["Terminating"])], [self.rq(["NotTerminating"])]
        ))
        assert finding["id"] == "resourcequota-scopes-immutable"
        assert finding["path"] == "/spec/scopes"
        assert_resource(finding, "ResourceQuota", "quota")

    def test_scope_removal_errors(self) -> None:
        finding = only(run_compare([self.rq(["Terminating"])], [self.rq([])]))
        assert finding["id"] == "resourcequota-scopes-immutable"

    def test_resource_limits_are_not_frozen(self) -> None:
        assert run_compare(
            [self.rq(["Terminating"], {"cpu": "4"})],
            [self.rq(["Terminating"], {"cpu": "8", "memory": "16Gi"})],
        ) == []


class TestDynamicResourceAllocation:
    def test_resource_claim_spec_change_errors(self) -> None:
        finding = only(run_compare(
            [doc("resource.k8s.io/v1", "ResourceClaim", "claim",
                 spec={"resourceClassName": "nvidia.example.com"})],
            [doc("resource.k8s.io/v1", "ResourceClaim", "claim",
                 spec={"resourceClassName": "amd.example.com"})],
        ))
        assert finding["id"] == "resourceclaim-spec-immutable"
        assert finding["path"] == "/spec"
        assert_resource(finding, "ResourceClaim", "claim", group="resource.k8s.io")

    def test_resource_claim_template_spec_change_errors(self) -> None:
        finding = only(run_compare(
            [doc("resource.k8s.io/v1", "ResourceClaimTemplate", "tmpl",
                 spec={"spec": {"resourceClassName": "nvidia.example.com"}})],
            [doc("resource.k8s.io/v1", "ResourceClaimTemplate", "tmpl",
                 spec={"spec": {"resourceClassName": "amd.example.com"}})],
        ))
        assert finding["id"] == "resourceclaimtemplate-spec-immutable"
        assert finding["path"] == "/spec"
        assert_resource(finding, "ResourceClaimTemplate", "tmpl", group="resource.k8s.io")

    def test_resource_slice_immutable_fields_error(self) -> None:
        findings = run_compare(
            [doc("resource.k8s.io/v1", "ResourceSlice", "slice",
                 spec={"driver": "d.example.com", "pool": {"name": "p", "generation": 1},
                       "nodeName": "node-a", "resourceName": "r"})],
            [doc("resource.k8s.io/v1", "ResourceSlice", "slice",
                 spec={"driver": "e.example.com", "pool": {"name": "q", "generation": 1},
                       "nodeName": "node-b", "resourceName": "r"})],
        )
        assert ids(findings) == [
            "resourceslice-driver-immutable",
            "resourceslice-node-name-immutable",
            "resourceslice-pool-name-immutable",
        ]
        assert {finding["path"] for finding in findings} == {
            "/spec/driver", "/spec/pool/name", "/spec/nodeName",
        }
        for finding in findings:
            assert_resource(finding, "ResourceSlice", "slice", namespace="", group="resource.k8s.io")

    def test_resource_slice_other_fields_are_not_frozen(self) -> None:
        assert run_compare(
            [doc("resource.k8s.io/v1", "ResourceSlice", "slice",
                 spec={"driver": "d", "pool": {"name": "p", "generation": 1},
                       "nodeName": "n", "resourceName": "old"})],
            [doc("resource.k8s.io/v1", "ResourceSlice", "slice",
                 spec={"driver": "d", "pool": {"name": "p", "generation": 2, "resourceSliceCount": 3},
                       "nodeName": "n", "resourceName": "new"})],
        ) == []

    def test_beta2_api_is_visible_not_compared(self) -> None:
        finding = only(run_compare(
            [doc("resource.k8s.io/v1beta2", "ResourceClaim", "claim",
                 spec={"resourceClassName": "a"})],
            [doc("resource.k8s.io/v1beta2", "ResourceClaim", "claim",
                 spec={"resourceClassName": "b"})],
        ))
        assert finding["id"] == "rule-coverage-partial"
        assert "v1beta2" in finding["text"]


class TestCertificateSigningRequest:
    def csr(self, **spec: Any) -> dict[str, Any]:
        base = {
            "request": "BASE64REQUEST",
            "signerName": "example.com/signer",
            "usages": ["digital signature"],
            "username": "alice",
            "uid": "1111",
            "groups": ["devs"],
            "extra": {"auth": ["token"]},
        }
        base.update(spec)
        return doc("certificates.k8s.io/v1", "CertificateSigningRequest", "csr", spec=base)

    def test_authored_spec_change_is_an_ignored_update(self) -> None:
        finding = only(run_compare(
            [self.csr()],
            [self.csr(request="OTHERBASE64REQUEST", signerName="other.com/signer")],
        ))
        assert finding["id"] == "csr-spec-ignored-update"
        assert finding["path"] == "/spec"
        assert finding["severity"] == "error"
        assert_resource(finding, "CertificateSigningRequest", "csr", namespace="", group="certificates.k8s.io")
        assert "ignored" in finding["text"]
        assert "ineffective" in finding["text"]
        assert "restores the previous spec" in finding["text"]

    def test_api_populated_caller_identity_fields_are_ignored(self) -> None:
        assert run_compare(
            [self.csr()],
            [self.csr(username="bob", uid="2222", groups=["admins"], extra={"auth": ["other"]})],
        ) == []

    def test_unchanged_spec_produces_no_finding(self) -> None:
        assert run_compare([self.csr()], [self.csr()]) == []


class TestStable137OnlyRules:
    """Certificate and migration rows that only exist in the audited 1.37 source."""

    def test_clustertrustbundle_signer_name_change_errors_at_137(self) -> None:
        scenario = {**DEFAULT_SCENARIO, "kubernetesVersion": "1.37.2"}
        finding = only(run_compare(
            [doc("certificates.k8s.io/v1", "ClusterTrustBundle", "ctb",
                 spec={"signerName": "a.example.com", "trustBundle": "DATA"})],
            [doc("certificates.k8s.io/v1", "ClusterTrustBundle", "ctb",
                 spec={"signerName": "b.example.com", "trustBundle": "DATA"})],
            scenario=scenario,
        ))
        assert finding["id"] == "clustertrustbundle-signer-name-immutable"
        assert finding["path"] == "/spec/signerName"
        assert_resource(finding, "ClusterTrustBundle", "ctb", namespace="", group="certificates.k8s.io")

    def test_clustertrustbundle_stable_api_at_136_is_visible_not_compared(self) -> None:
        finding = only(run_compare(
            [doc("certificates.k8s.io/v1", "ClusterTrustBundle", "ctb",
                 spec={"signerName": "a.example.com"})],
            [doc("certificates.k8s.io/v1", "ClusterTrustBundle", "ctb",
                 spec={"signerName": "b.example.com"})],
        ))
        assert finding["id"] == "rule-coverage-partial"
        assert "1.37" in finding["text"]
        assert "1.36.6" in finding["text"]

    def test_clustertrustbundle_beta_form_at_136_is_visible_not_compared(self) -> None:
        finding = only(run_compare(
            [doc("certificates.k8s.io/v1beta1", "ClusterTrustBundle", "ctb",
                 spec={"signerName": "a.example.com"})],
            [doc("certificates.k8s.io/v1beta1", "ClusterTrustBundle", "ctb",
                 spec={"signerName": "b.example.com"})],
        ))
        assert finding["id"] == "rule-coverage-partial"
        assert "v1beta1" in finding["text"]

    def test_podcertificaterequest_spec_change_errors_at_137(self) -> None:
        scenario = {**DEFAULT_SCENARIO, "kubernetesVersion": "1.37.2"}
        finding = only(run_compare(
            [doc("certificates.k8s.io/v1", "PodCertificateRequest", "pcr",
                 spec={"signerName": "a.example.com"})],
            [doc("certificates.k8s.io/v1", "PodCertificateRequest", "pcr",
                 spec={"signerName": "b.example.com"})],
            scenario=scenario,
        ))
        assert finding["id"] == "podcertificaterequest-spec-immutable"
        assert finding["path"] == "/spec"
        assert_resource(finding, "PodCertificateRequest", "pcr", group="certificates.k8s.io")

    def test_storageversionmigration_spec_change_errors_at_137(self) -> None:
        scenario = {**DEFAULT_SCENARIO, "kubernetesVersion": "1.37.2"}
        finding = only(run_compare(
            [doc("storagemigration.k8s.io/v1", "StorageVersionMigration", "svm",
                 spec={"resource": {"group": "apps", "version": "v1", "kind": "Deployment"}})],
            [doc("storagemigration.k8s.io/v1", "StorageVersionMigration", "svm",
                 spec={"resource": {"group": "batch", "version": "v1", "kind": "Job"}})],
            scenario=scenario,
        ))
        assert finding["id"] == "storageversionmigration-spec-immutable"
        assert finding["path"] == "/spec"
        assert_resource(finding, "StorageVersionMigration", "svm", namespace="", group="storagemigration.k8s.io")

    def test_storageversionmigration_beta_form_at_136_is_visible_not_compared(self) -> None:
        finding = only(run_compare(
            [doc("storagemigration.k8s.io/v1beta1", "StorageVersionMigration", "svm",
                 spec={"resource": {"group": "apps", "version": "v1", "kind": "Deployment"}})],
            [doc("storagemigration.k8s.io/v1beta1", "StorageVersionMigration", "svm",
                 spec={"resource": {"group": "batch", "version": "v1", "kind": "Job"}})],
        ))
        assert finding["id"] == "rule-coverage-partial"
        assert "v1beta1" in finding["text"]


class TestApiVersionCoverage:
    def test_unknown_api_version_is_visible_not_compared(self) -> None:
        finding = only(run_compare(
            [configmap(data={"a": "1"})],
            [doc("v2", "ConfigMap", "cfg", data={"a": "2"})],
        ))
        assert finding["id"] == "rule-coverage-partial"
        assert finding["path"] == "/apiVersion"
        assert "v2" in finding["text"]

    @pytest.mark.parametrize("version", ["1.35.10", "1.36.6", "1.37.2"])
    def test_configmap_rule_active_across_audited_minors(self, version: str) -> None:
        scenario = {**DEFAULT_SCENARIO, "kubernetesVersion": version}
        finding = only(run_compare(
            [configmap(immutable=True, data={"a": "one"})],
            [configmap(immutable=True, data={"a": "two"})],
            scenario=scenario,
        ))
        assert finding["id"] == "configmap-immutable-data"

    def test_unaudited_minor_degrades_to_visible_coverage(self) -> None:
        scenario = {**DEFAULT_SCENARIO, "kubernetesVersion": "1.34.9"}
        finding = only(run_compare(
            [configmap(immutable=True, data={"a": "one"})],
            [configmap(immutable=True, data={"a": "two"})],
            scenario=scenario,
        ))
        assert finding["id"] == "rule-coverage-partial"

    def test_candidate_api_version_drives_rule_selection(self) -> None:
        # Baseline on the beta API, candidate migrated to the stable API: the
        # update is served through the candidate's stable API, so the audited
        # stable rules apply rather than a coverage gap.
        finding = only(run_compare(
            [doc("storage.k8s.io/v1beta1", "VolumeAttributesClass", "vac",
                 driverName="csi.example.com", parameters={"a": "1"})],
            [doc("storage.k8s.io/v1", "VolumeAttributesClass", "vac",
                 driverName="other.example.com", parameters={"a": "1"})],
        ))
        assert finding["id"] == "volumeattributesclass-driver-name-immutable"
        assert finding["path"] == "/driverName"


class TestPurityAndContract:
    def test_inputs_are_not_mutated(self) -> None:
        scenario = {**DEFAULT_SCENARIO, "kubernetesVersion": "1.37.2"}
        baseline_docs = [
            configmap(immutable=True, data={"a": "one"}),
            secret(immutable=True, data={"k": base64.b64encode(b"x").decode()}),
            doc("storage.k8s.io/v1", "CSIDriver", "csi", spec={"attachRequired": True}),
            doc("storage.k8s.io/v1", "CSINode", "node", spec={"drivers": [
                {"name": "csi.example.com", "nodeID": "n", "allocatable": {"count": 4}}]}),
        ]
        candidate_docs = [
            configmap(immutable=True, data={"a": "two"}),
            secret(immutable=True, data={"k": base64.b64encode(b"y").decode()}),
            doc("storage.k8s.io/v1", "CSIDriver", "csi", spec={"attachRequired": False}),
            doc("storage.k8s.io/v1", "CSINode", "node", spec={"drivers": [
                {"name": "csi.example.com", "nodeID": "n", "allocatable": {"count": 8}}]}),
        ]
        baseline = normalizer.normalize(render(baseline_docs), "baseline.yaml", scenario)
        candidate = normalizer.normalize(render(candidate_docs), "candidate.yaml", scenario)
        baseline_copy = copy.deepcopy(baseline)
        candidate_copy = copy.deepcopy(candidate)
        scenario_copy = copy.deepcopy(scenario)
        catalogue_copy = copy.deepcopy(CATALOGUE)
        policies.compare(baseline, candidate, scenario, CATALOGUE)
        assert baseline == baseline_copy
        assert candidate == candidate_copy
        assert scenario == scenario_copy
        assert CATALOGUE == catalogue_copy

    def test_bare_object_maps_are_accepted(self) -> None:
        scenario = dict(DEFAULT_SCENARIO)
        baseline = normalizer.normalize(
            render([configmap(immutable=True, data={"a": "one"})]), "baseline.yaml", scenario
        )
        candidate = normalizer.normalize(
            render([configmap(immutable=True, data={"a": "two"})]), "candidate.yaml", scenario
        )
        findings = policies.compare(
            baseline["objects"], candidate["objects"], scenario, CATALOGUE
        )
        assert ids(findings) == ["configmap-immutable-data"]

    def test_finding_shape_matches_the_registry(self) -> None:
        findings = run_compare(
            [configmap(immutable=True, data={"a": "one"})],
            [configmap(immutable=True, data={"a": "two"})],
        )
        registry = {rule["id"]: rule for rule in CATALOGUE["rules"]}
        for finding in findings:
            assert set(finding) == {
                "id", "path", "text", "severity", "scenario",
                "resource", "classification", "evidence",
            }
            rule = registry[finding["id"]]
            assert finding["severity"] == rule["severity"]
            assert finding["classification"] == rule["classification"]
            assert finding["evidence"] == rule["evidence"]
            assert finding["text"].strip()

    def test_only_common_objects_are_compared(self) -> None:
        # A baseline-only object is the removal policy's concern; a
        # candidate-only object has no update to compare.
        assert run_compare(
            [configmap(name="kept", data={"a": "1"}), configmap(name="gone", data={"a": "1"})],
            [configmap(name="kept", data={"a": "1"}), configmap(name="added", data={"a": "1"})],
        ) == []

    def test_scenario_without_kubernetes_version_is_a_contract_error(self) -> None:
        scenario = dict(DEFAULT_SCENARIO)
        scenario.pop("kubernetesVersion")
        baseline = normalizer.normalize(
            render([configmap()]), "baseline.yaml", DEFAULT_SCENARIO
        )
        with pytest.raises(ValueError, match="kubernetesVersion"):
            policies.compare(baseline, baseline, scenario, CATALOGUE)
