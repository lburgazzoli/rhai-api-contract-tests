"""Regression tests for the storage and Service update-transition policies.

Covers every catalogue rule in the storage/networking transition family with a
positive breaking fixture, a compatible counterexample, an
explicit/default-equivalent case where applicable, and target-version
coverage across the three audited minors. Conditional rules exercise both the
provable branch and the unresolved-live-state warning, and every warning
asserts that the text names what cannot be known offline.
"""

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "modules" / "manifest-compat" / "policies_storage_service.py"
NORMALIZER_PATH = ROOT / "modules" / "manifest-compat" / "normalizer.py"
POLICY_PATH = ROOT / "modules" / "manifest-compat" / "policy.json"

_module_spec = importlib.util.spec_from_file_location(
    "manifest_policies_storage_service_test", MODULE_PATH
)
assert _module_spec is not None and _module_spec.loader is not None
policies = importlib.util.module_from_spec(_module_spec)
_module_spec.loader.exec_module(policies)

_normalizer_spec = importlib.util.spec_from_file_location(
    "manifest_normalizer_storage_service_test", NORMALIZER_PATH
)
assert _normalizer_spec is not None and _normalizer_spec.loader is not None
normalizer = importlib.util.module_from_spec(_normalizer_spec)
_normalizer_spec.loader.exec_module(normalizer)

CATALOGUE: dict[str, Any] = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
RULES: dict[str, dict[str, Any]] = {rule["id"]: rule for rule in CATALOGUE["rules"]}

AUDITED_VERSIONS = ["1.35.10", "1.36.6", "1.37.2"]

SCENARIO: dict[str, Any] = {
    "id": "storage-service-test",
    "renderer": "raw",
    "namespace": "rhoai",
    "kubernetesVersion": "1.36.6",
    "sources": ["rendered.yaml"],
}


def normalized(yaml_text: str, scenario: dict[str, Any] | None = None) -> dict[str, Any]:
    return normalizer.normalize(
        yaml_text.encode("utf-8"),
        "rendered.yaml",
        scenario if scenario is not None else SCENARIO,
    )


def run_compare(
    baseline_yaml: str, candidate_yaml: str, scenario: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    scenario = scenario if scenario is not None else SCENARIO
    return policies.compare(
        normalized(baseline_yaml, scenario),
        normalized(candidate_yaml, scenario),
        scenario,
        CATALOGUE,
    )


def ids(findings: list[dict[str, Any]]) -> list[str]:
    return [finding["id"] for finding in findings]


def one(
    findings: list[dict[str, Any]],
    rule_id: str,
    path: str | None = None,
    resource: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Assert exactly one finding for the rule/path and check catalogue consistency."""
    matches = [
        finding
        for finding in findings
        if finding["id"] == rule_id and (path is None or finding["path"] == path)
    ]
    assert matches, (
        f"expected one {rule_id} finding at {path or '<any>'}; "
        f"got {[(f['id'], f['path']) for f in findings]}"
    )
    assert len(matches) == 1, f"expected exactly one {rule_id} at {path or '<any>'}"
    finding = matches[0]
    rule = RULES[rule_id]
    assert finding["severity"] == rule["severity"]
    assert finding["classification"] == rule["classification"]
    assert finding["evidence"] == rule["evidence"]
    assert finding["scenario"] == SCENARIO["id"]
    assert set(finding) == {
        "id", "path", "text", "severity", "scenario",
        "resource", "classification", "evidence",
    }
    if resource is not None:
        assert finding["resource"] == resource
    return finding


PV_RESOURCE = {"group": "", "kind": "PersistentVolume", "namespace": "", "name": "data-pv"}
PVC_RESOURCE = {"group": "", "kind": "PersistentVolumeClaim", "namespace": "rhoai", "name": "data-pvc"}
SERVICE_RESOURCE = {"group": "", "kind": "Service", "namespace": "rhoai", "name": "api"}

PV_BASELINE = """
apiVersion: v1
kind: PersistentVolume
metadata:
  name: data-pv
spec:
  capacity:
    storage: 10Gi
  volumeMode: Filesystem
  persistentVolumeReclaimPolicy: Retain
  storageClassName: slow
  hostPath:
    path: /data
"""

PV_CSI_BASELINE = """
apiVersion: v1
kind: PersistentVolume
metadata:
  name: data-pv
spec:
  capacity:
    storage: 10Gi
  csi:
    driver: ebs.csi.aws.com
    volumeHandle: vol-0123456789
    fsType: ext4
"""

PVC_BASELINE = """
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data-pvc
spec:
  accessModes:
  - ReadWriteOnce
  volumeMode: Filesystem
  resources:
    requests:
      storage: 5Gi
  storageClassName: slow
"""

SERVICE_BASELINE = """
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: ClusterIP
  clusterIPs:
  - 10.96.0.10
  ipFamilies:
  - IPv4
  selector:
    app: api
  ports:
  - name: http
    port: 80
    targetPort: 8080
"""

SERVICE_DUAL_BASELINE = """
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: ClusterIP
  clusterIPs:
  - 10.96.0.10
  - fd00::10
  ipFamilies:
  - IPv4
  - IPv6
  selector:
    app: api
  ports:
  - name: http
    port: 80
    targetPort: 8080
"""

SERVICE_LOAD_BALANCER_BASELINE = """
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: LoadBalancer
  loadBalancerClass: example.com/internal
  externalTrafficPolicy: Local
  healthCheckNodePort: 30123
  selector:
    app: api
  ports:
  - name: https
    port: 443
    targetPort: 8443
"""


class TestPersistentVolume:
    def test_volume_source_change_is_caught(self) -> None:
        candidate = PV_BASELINE.replace(
            "  hostPath:\n    path: /data", "  nfs:\n    server: nfs.example.com\n    path: /exports"
        )
        finding = one(
            run_compare(PV_BASELINE, candidate),
            "pv-volume-source-immutable",
            "/spec/persistentVolumeSource",
            PV_RESOURCE,
        )
        assert finding["severity"] == "error"
        assert "hostPath" in finding["text"]
        assert "controllerExpandSecretRef" in finding["text"]

    def test_volume_source_unchanged_is_compatible(self) -> None:
        candidate = PV_BASELINE.replace("    path: /data", "    path: /data2")
        finding = one(
            run_compare(PV_BASELINE, candidate),
            "pv-volume-source-immutable",
            "/spec/persistentVolumeSource",
        )
        assert "hostPath" in finding["text"]

    def test_reclaim_policy_capacity_and_claim_ref_are_mutable(self) -> None:
        candidate = PV_BASELINE.replace(
            "  persistentVolumeReclaimPolicy: Retain", "  persistentVolumeReclaimPolicy: Delete"
        ).replace("    storage: 10Gi", "    storage: 20Gi") + """  claimRef:
    kind: PersistentVolumeClaim
    namespace: rhoai
    name: data-pvc
"""
        assert run_compare(PV_BASELINE, candidate.rstrip() + "\n") == []

    def test_csi_controller_expand_secret_one_time_initialization(self) -> None:
        candidate = PV_CSI_BASELINE + """    controllerExpandSecretRef:
      name: expand-secret
      namespace: rhoai
"""
        assert run_compare(PV_CSI_BASELINE, candidate) == []

    def test_csi_controller_expand_secret_change_after_set_is_caught(self) -> None:
        baseline = PV_CSI_BASELINE + """    controllerExpandSecretRef:
      name: expand-secret
      namespace: rhoai
"""
        candidate = PV_CSI_BASELINE + """    controllerExpandSecretRef:
      name: other-secret
      namespace: rhoai
"""
        one(
            run_compare(baseline, candidate),
            "pv-volume-source-immutable",
            "/spec/persistentVolumeSource",
        )

    def test_csi_controller_expand_secret_removal_is_caught(self) -> None:
        baseline = PV_CSI_BASELINE + """    controllerExpandSecretRef:
      name: expand-secret
      namespace: rhoai
"""
        one(
            run_compare(baseline, PV_CSI_BASELINE),
            "pv-volume-source-immutable",
            "/spec/persistentVolumeSource",
        )

    def test_volume_mode_change_is_caught(self) -> None:
        candidate = PV_BASELINE.replace("  volumeMode: Filesystem", "  volumeMode: Block")
        one(run_compare(PV_BASELINE, candidate), "pv-volume-mode-immutable", "/spec/volumeMode")

    def test_volume_mode_default_equivalence(self) -> None:
        baseline = PV_BASELINE.replace("  volumeMode: Filesystem\n", "")
        assert run_compare(baseline, PV_BASELINE) == []

    def test_node_affinity_first_initialization_is_permitted(self) -> None:
        candidate = PV_BASELINE + """  nodeAffinity:
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/os
          operator: In
          values:
          - linux
"""
        assert run_compare(PV_BASELINE, candidate.rstrip() + "\n") == []

    def test_node_affinity_edit_when_already_set_warns(self) -> None:
        baseline = PV_BASELINE + """  nodeAffinity:
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/os
          operator: In
          values:
          - linux
"""
        candidate = PV_BASELINE + """  nodeAffinity:
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/os
          operator: In
          values:
          - windows
"""
        finding = one(
            run_compare(baseline.rstrip() + "\n", candidate.rstrip() + "\n"),
            "pv-node-affinity-risk",
            "/spec/nodeAffinity",
        )
        assert finding["severity"] == "warn"
        assert finding["evidence"] == "unverified"
        assert "MutablePVNodeAffinity" in finding["text"]
        assert "cannot" in finding["text"]

    def test_volume_attributes_class_name_change_warns(self) -> None:
        candidate = PV_BASELINE.replace(
            "  storageClassName: slow", "  storageClassName: slow\n  volumeAttributesClassName: silver"
        )
        finding = one(
            run_compare(PV_BASELINE, candidate),
            "pv-volume-attributes-class-name-risk",
            "/spec/volumeAttributesClassName",
        )
        assert finding["severity"] == "warn"
        assert "VolumeAttributesClass feature gate" in finding["text"]


class TestPersistentVolumeClaim:
    def test_access_modes_change_is_caught(self) -> None:
        candidate = PVC_BASELINE.replace("- ReadWriteOnce", "- ReadWriteMany")
        one(run_compare(PVC_BASELINE, candidate), "pvc-access-modes-immutable", "/spec/accessModes")

    def test_selector_added_is_caught(self) -> None:
        candidate = PVC_BASELINE.replace(
            "  storageClassName: slow",
            "  selector:\n    matchLabels:\n      tier: gold\n  storageClassName: slow",
        )
        one(run_compare(PVC_BASELINE, candidate), "pvc-selector-immutable", "/spec/selector")

    def test_data_source_change_is_caught(self) -> None:
        baseline = PVC_BASELINE.replace(
            "  storageClassName: slow",
            "  storageClassName: slow\n  dataSource:\n    kind: PersistentVolumeClaim\n    name: snap",
        )
        candidate = PVC_BASELINE.replace(
            "  storageClassName: slow",
            "  storageClassName: slow\n  dataSource:\n    kind: VolumeSnapshot\n    name: snap",
        )
        one(run_compare(baseline, candidate), "pvc-data-source-immutable", "/spec/dataSource")

    def test_data_source_ref_change_is_caught(self) -> None:
        baseline = PVC_BASELINE.replace(
            "  storageClassName: slow",
            "  storageClassName: slow\n  dataSourceRef:\n    kind: PersistentVolumeClaim\n    name: snap",
        )
        candidate = PVC_BASELINE.replace(
            "  storageClassName: slow",
            "  storageClassName: slow\n  dataSourceRef:\n    kind: PersistentVolumeClaim\n    name: other",
        )
        one(run_compare(baseline, candidate), "pvc-data-source-ref-immutable", "/spec/dataSourceRef")

    def test_volume_mode_change_is_caught(self) -> None:
        candidate = PVC_BASELINE.replace("  volumeMode: Filesystem", "  volumeMode: Block")
        one(run_compare(PVC_BASELINE, candidate), "pvc-volume-mode-immutable", "/spec/volumeMode")

    def test_volume_mode_default_equivalence(self) -> None:
        baseline = PVC_BASELINE.replace("  volumeMode: Filesystem\n", "")
        assert run_compare(baseline, PVC_BASELINE) == []

    def test_volume_name_one_time_initialization(self) -> None:
        candidate = PVC_BASELINE + "  volumeName: data-pv\n"
        assert run_compare(PVC_BASELINE, candidate) == []

    def test_volume_name_change_after_set_is_caught(self) -> None:
        baseline = PVC_BASELINE + "  volumeName: data-pv\n"
        candidate = PVC_BASELINE + "  volumeName: other-pv\n"
        one(run_compare(baseline, candidate), "pvc-volume-name-immutable", "/spec/volumeName")

    def test_volume_name_clearing_is_caught(self) -> None:
        baseline = PVC_BASELINE + "  volumeName: data-pv\n"
        one(run_compare(baseline, PVC_BASELINE), "pvc-volume-name-immutable", "/spec/volumeName")

    def test_storage_class_name_plain_change_is_caught(self) -> None:
        candidate = PVC_BASELINE.replace("  storageClassName: slow", "  storageClassName: fast")
        finding = one(
            run_compare(PVC_BASELINE, candidate),
            "pvc-storage-class-name-immutable",
            "/spec/storageClassName",
        )
        assert "migration" in finding["text"]

    def test_storage_class_beta_annotation_to_equal_field_migration(self) -> None:
        baseline = PVC_BASELINE.replace(
            "  storageClassName: slow",
            "",
        ).replace(
            "metadata:\n  name: data-pvc",
            "metadata:\n  name: data-pvc\n  annotations:\n"
            "    volume.beta.kubernetes.io/storage-class: slow",
        )
        candidate = PVC_BASELINE  # field set to the annotation value, annotation dropped
        assert run_compare(baseline, candidate) == []

    def test_storage_class_nil_to_set_migration(self) -> None:
        baseline = PVC_BASELINE.replace("  storageClassName: slow\n", "")
        candidate = PVC_BASELINE.replace("  storageClassName: slow", "  storageClassName: fast")
        assert run_compare(baseline, candidate) == []

    def test_storage_class_migration_to_different_value_is_caught_twice(self) -> None:
        baseline = PVC_BASELINE.replace(
            "  storageClassName: slow",
            "",
        ).replace(
            "metadata:\n  name: data-pvc",
            "metadata:\n  name: data-pvc\n  annotations:\n"
            "    volume.beta.kubernetes.io/storage-class: slow",
        )
        candidate = PVC_BASELINE.replace("  storageClassName: slow", "  storageClassName: fast")
        findings = run_compare(baseline, candidate)
        one(findings, "pvc-storage-class-name-immutable",
            "/metadata/annotations/volume.beta.kubernetes.io~1storage-class")
        one(findings, "pvc-storage-class-name-immutable", "/spec/storageClassName")

    def test_storage_class_conflicting_annotation_blocks_nil_migration(self) -> None:
        baseline = PVC_BASELINE.replace(
            "  storageClassName: slow",
            "",
        ).replace(
            "metadata:\n  name: data-pvc",
            "metadata:\n  name: data-pvc\n  annotations:\n"
            "    volume.beta.kubernetes.io/storage-class: slow",
        )
        # Candidate keeps the annotation and sets a conflicting field value:
        # neither the annotation migration nor the nil migration applies.
        candidate = PVC_BASELINE.replace(
            "metadata:\n  name: data-pvc",
            "metadata:\n  name: data-pvc\n  annotations:\n"
            "    volume.beta.kubernetes.io/storage-class: slow",
        ).replace("  storageClassName: slow", "  storageClassName: fast")
        findings = run_compare(baseline, candidate)
        one(findings, "pvc-storage-class-name-immutable", "/spec/storageClassName")

    def test_storage_class_annotation_change_in_place_is_caught(self) -> None:
        baseline = PVC_BASELINE.replace(
            "  storageClassName: slow",
            "",
        ).replace(
            "metadata:\n  name: data-pvc",
            "metadata:\n  name: data-pvc\n  annotations:\n"
            "    volume.beta.kubernetes.io/storage-class: slow",
        )
        candidate = baseline.replace("storage-class: slow", "storage-class: fast")
        one(run_compare(baseline, candidate), "pvc-storage-class-name-immutable",
            "/metadata/annotations/volume.beta.kubernetes.io~1storage-class")

    def test_storage_decrease_warns_naming_missing_evidence(self) -> None:
        candidate = PVC_BASELINE.replace("      storage: 5Gi", "      storage: 3Gi")
        finding = one(
            run_compare(PVC_BASELINE, candidate),
            "pvc-storage-resize-risk",
            "/spec/resources/requests/storage",
        )
        assert finding["severity"] == "warn"
        assert finding["evidence"] == "unverified"
        assert "RecoverVolumeExpansionFailure" in finding["text"]
        assert "status.capacity" in finding["text"]
        assert "3Gi" not in finding["text"]

    def test_storage_increase_warns_without_certifying_expansion(self) -> None:
        candidate = PVC_BASELINE.replace("      storage: 5Gi", "      storage: 8Gi")
        finding = one(
            run_compare(PVC_BASELINE, candidate),
            "pvc-storage-resize-risk",
            "/spec/resources/requests/storage",
        )
        assert finding["severity"] == "warn"
        assert "allowVolumeExpansion" in finding["text"]
        assert "8Gi" not in finding["text"]

    def test_equivalent_quantities_compare_equal(self) -> None:
        candidate = PVC_BASELINE.replace("      storage: 5Gi", "      storage: 5368709120")
        assert run_compare(PVC_BASELINE, candidate) == []

    def test_equivalent_decimal_quantities_compare_equal(self) -> None:
        baseline = PVC_BASELINE.replace("      storage: 5Gi", "      storage: 500m")
        candidate = PVC_BASELINE.replace("      storage: 5Gi", "      storage: 0.5")
        assert run_compare(baseline, candidate) == []

    def test_removed_storage_request_counts_as_decrease(self) -> None:
        candidate = PVC_BASELINE.replace(
            "  resources:\n    requests:\n      storage: 5Gi\n", ""
        )
        one(
            run_compare(PVC_BASELINE, candidate),
            "pvc-storage-resize-risk",
            "/spec/resources/requests/storage",
        )

    def test_volume_attributes_class_name_change_warns(self) -> None:
        candidate = PVC_BASELINE.replace(
            "  storageClassName: slow", "  storageClassName: slow\n  volumeAttributesClassName: silver"
        )
        finding = one(
            run_compare(PVC_BASELINE, candidate),
            "pvc-volume-attributes-class-name-risk",
            "/spec/volumeAttributesClassName",
        )
        assert finding["severity"] == "warn"
        assert "status.currentVolumeAttributesClassName" in finding["text"]
        assert "VolumeAttributesClass" in finding["text"]

    def test_multiple_claims_reported_per_resource(self) -> None:
        baseline = (
            PVC_BASELINE
            + "---\n"
            + PVC_BASELINE.replace("  name: data-pvc", "  name: other-pvc")
        )
        candidate = (
            PVC_BASELINE
            + "---\n"
            + PVC_BASELINE.replace("  name: data-pvc", "  name: other-pvc").replace(
                "- ReadWriteOnce", "- ReadWriteMany"
            )
        )
        findings = run_compare(baseline, candidate)
        finding = one(findings, "pvc-access-modes-immutable")
        assert finding["resource"]["name"] == "other-pvc"


class TestServiceClusterIPs:
    def test_primary_cluster_ip_edit_is_caught(self) -> None:
        candidate = SERVICE_BASELINE.replace("  - 10.96.0.10", "  - 10.96.0.11")
        findings = run_compare(SERVICE_BASELINE, candidate)
        finding = one(findings, "service-cluster-ips-transition", "/spec/clusterIPs/0")
        assert "10.96.0.11" not in json.dumps(findings)

    def test_secondary_address_add_is_compatible(self) -> None:
        candidate = SERVICE_BASELINE.replace(
            "  - 10.96.0.10",
            "  - 10.96.0.10\n  - fd00::10",
        ).replace("  - IPv4", "  - IPv4\n  - IPv6")
        assert run_compare(SERVICE_BASELINE, candidate) == []

    def test_secondary_address_release_with_single_stack_is_compatible(self) -> None:
        candidate = SERVICE_DUAL_BASELINE.replace(
            "  - 10.96.0.10\n  - fd00::10", "  - 10.96.0.10"
        ).replace("  - IPv4\n  - IPv6", "  - IPv4").replace(
            "  type: ClusterIP", "  type: ClusterIP\n  ipFamilyPolicy: SingleStack"
        )
        assert run_compare(SERVICE_DUAL_BASELINE, candidate) == []

    def test_secondary_address_release_without_single_stack_is_caught(self) -> None:
        candidate = SERVICE_DUAL_BASELINE.replace(
            "  - 10.96.0.10\n  - fd00::10", "  - 10.96.0.10"
        ).replace("  - IPv4\n  - IPv6", "  - IPv4")
        findings = run_compare(SERVICE_DUAL_BASELINE, candidate)
        one(findings, "service-cluster-ips-transition", "/spec/ipFamilyPolicy")
        one(findings, "service-ip-families-transition", "/spec/ipFamilyPolicy")

    def test_secondary_address_release_with_primary_change_is_caught(self) -> None:
        candidate = SERVICE_DUAL_BASELINE.replace(
            "  - 10.96.0.10\n  - fd00::10", "  - 10.96.0.99"
        ).replace("  - IPv4\n  - IPv6", "  - IPv6").replace(
            "  type: ClusterIP", "  type: ClusterIP\n  ipFamilyPolicy: SingleStack"
        )
        findings = run_compare(SERVICE_DUAL_BASELINE, candidate)
        one(findings, "service-cluster-ips-transition", "/spec/clusterIPs/0")
        one(findings, "service-ip-families-transition", "/spec/ipFamilies/0")
        # SingleStack is set, so the release-policy findings must not fire.
        assert "/spec/ipFamilyPolicy" not in [f["path"] for f in findings]

    def test_omitted_allocation_is_not_a_removal(self) -> None:
        candidate = SERVICE_BASELINE.replace(
            "  clusterIPs:\n  - 10.96.0.10\n", ""
        ).replace("  ipFamilies:\n  - IPv4\n", "")
        assert run_compare(SERVICE_BASELINE, candidate) == []

    def test_baseline_plural_with_candidate_singular_shorthand_is_skipped(self) -> None:
        candidate = """
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: ClusterIP
  clusterIP: 10.96.0.10
  selector:
    app: api
  ports:
  - name: http
    port: 80
    targetPort: 8080
"""
        assert run_compare(SERVICE_DUAL_BASELINE, candidate) == []

    def test_singular_shorthand_primary_change_is_caught(self) -> None:
        baseline = SERVICE_BASELINE.replace(
            "  clusterIPs:\n  - 10.96.0.10", "  clusterIP: 10.96.0.10"
        )
        candidate = SERVICE_BASELINE.replace(
            "  clusterIPs:\n  - 10.96.0.10", "  clusterIP: 10.96.0.12"
        )
        one(run_compare(baseline, candidate), "service-cluster-ips-transition", "/spec/clusterIPs/0")

    def test_external_name_transitions_are_exempt(self) -> None:
        external_name = """
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: ExternalName
  externalName: backend.example.com
"""
        assert run_compare(SERVICE_BASELINE, external_name) == []
        assert run_compare(external_name, SERVICE_BASELINE) == []

    def test_headless_services_are_exempt(self) -> None:
        baseline = SERVICE_BASELINE.replace("  - 10.96.0.10", "  - None")
        candidate = SERVICE_BASELINE.replace("  - 10.96.0.10", "  - None").replace(
            "  - IPv4", "  - IPv6"
        )
        assert run_compare(baseline, candidate) == []

    def test_headless_to_assigned_address_is_caught(self) -> None:
        baseline = SERVICE_BASELINE.replace("  - 10.96.0.10", "  - None")
        findings = run_compare(baseline, SERVICE_BASELINE)
        one(findings, "service-cluster-ips-transition", "/spec/clusterIPs/0")


class TestServiceIPFamilies:
    def test_primary_family_change_is_caught(self) -> None:
        candidate = SERVICE_BASELINE.replace("  - IPv4", "  - IPv6")
        one(run_compare(SERVICE_BASELINE, candidate), "service-ip-families-transition",
            "/spec/ipFamilies/0")

    def test_family_reorder_is_caught_per_index(self) -> None:
        candidate = SERVICE_DUAL_BASELINE.replace("  - IPv4\n  - IPv6", "  - IPv6\n  - IPv4")
        findings = run_compare(SERVICE_DUAL_BASELINE, candidate)
        one(findings, "service-ip-families-transition", "/spec/ipFamilies/0")
        one(findings, "service-ip-families-transition", "/spec/ipFamilies/1")

    def test_secondary_family_add_is_compatible(self) -> None:
        candidate = SERVICE_BASELINE.replace(
            "  - IPv4", "  - IPv4\n  - IPv6"
        ).replace("  - 10.96.0.10", "  - 10.96.0.10\n  - fd00::10")
        assert run_compare(SERVICE_BASELINE, candidate) == []

    def test_family_release_with_single_stack_is_compatible(self) -> None:
        candidate = SERVICE_DUAL_BASELINE.replace("  - IPv4\n  - IPv6", "  - IPv4").replace(
            "  - 10.96.0.10\n  - fd00::10", "  - 10.96.0.10"
        ).replace("  type: ClusterIP", "  type: ClusterIP\n  ipFamilyPolicy: SingleStack")
        assert run_compare(SERVICE_DUAL_BASELINE, candidate) == []

    def test_headless_state_change_skips_family_check(self) -> None:
        baseline = SERVICE_BASELINE.replace("  - 10.96.0.10", "  - None")
        candidate = SERVICE_BASELINE.replace("  - 10.96.0.10", "  - None").replace(
            "  - IPv4", "  - IPv6"
        )
        assert run_compare(baseline, candidate) == []


class TestServiceConditionalFields:
    def test_load_balancer_class_change_while_both_load_balancer(self) -> None:
        candidate = SERVICE_LOAD_BALANCER_BASELINE.replace(
            "  loadBalancerClass: example.com/internal", "  loadBalancerClass: example.com/other"
        )
        one(run_compare(SERVICE_LOAD_BALANCER_BASELINE, candidate),
            "service-load-balancer-class-immutable", "/spec/loadBalancerClass")

    def test_load_balancer_class_removal_is_caught(self) -> None:
        candidate = SERVICE_LOAD_BALANCER_BASELINE.replace(
            "  loadBalancerClass: example.com/internal\n", ""
        )
        one(run_compare(SERVICE_LOAD_BALANCER_BASELINE, candidate),
            "service-load-balancer-class-immutable", "/spec/loadBalancerClass")

    def test_load_balancer_class_free_after_type_change(self) -> None:
        candidate = SERVICE_LOAD_BALANCER_BASELINE.replace(
            "  type: LoadBalancer", "  type: NodePort"
        ).replace("  loadBalancerClass: example.com/internal\n", "")
        assert run_compare(SERVICE_LOAD_BALANCER_BASELINE, candidate) == []

    def test_health_check_node_port_change_while_local(self) -> None:
        candidate = SERVICE_LOAD_BALANCER_BASELINE.replace(
            "  healthCheckNodePort: 30123", "  healthCheckNodePort: 30124"
        )
        one(run_compare(SERVICE_LOAD_BALANCER_BASELINE, candidate),
            "service-health-check-node-port-immutable", "/spec/healthCheckNodePort")

    def test_health_check_node_port_free_after_traffic_policy_change(self) -> None:
        candidate = SERVICE_LOAD_BALANCER_BASELINE.replace(
            "  externalTrafficPolicy: Local", "  externalTrafficPolicy: Cluster"
        ).replace("  healthCheckNodePort: 30123", "  healthCheckNodePort: 30124")
        assert run_compare(SERVICE_LOAD_BALANCER_BASELINE, candidate) == []

    def test_health_check_node_port_free_after_type_change(self) -> None:
        candidate = SERVICE_LOAD_BALANCER_BASELINE.replace(
            "  type: LoadBalancer", "  type: NodePort"
        )
        assert run_compare(SERVICE_LOAD_BALANCER_BASELINE, candidate) == []

    def test_type_selector_and_node_port_changes_are_not_immutable(self) -> None:
        candidate = SERVICE_BASELINE.replace("  type: ClusterIP", "  type: NodePort").replace(
            "  selector:\n    app: api", "  selector:\n    app: api-v2"
        ).replace("    targetPort: 8080", "    targetPort: 8080\n    nodePort: 30080")
        assert run_compare(SERVICE_BASELINE, candidate) == []


COMPATIBLE_BASELINE = (
    PV_BASELINE
    + "---\n"
    + PVC_BASELINE.replace(
        "  storageClassName: slow",
        "",
    ).replace(
        "metadata:\n  name: data-pvc",
        "metadata:\n  name: data-pvc\n  annotations:\n"
        "    volume.beta.kubernetes.io/storage-class: slow",
    )
    + "---\n"
    + SERVICE_BASELINE
)

COMPATIBLE_CANDIDATE = (
    PV_BASELINE.replace(
        "  persistentVolumeReclaimPolicy: Retain", "  persistentVolumeReclaimPolicy: Delete"
    ).replace("    storage: 10Gi", "    storage: 20Gi")
    + "---\n"
    + PVC_BASELINE.replace(
        "metadata:\n  name: data-pvc",
        "metadata:\n  name: data-pvc\n  annotations:\n"
        "    volume.beta.kubernetes.io/storage-class: slow",
    )
    + "  volumeName: data-pv\n"
    + "---\n"
    + SERVICE_BASELINE.replace(
        "  - 10.96.0.10", "  - 10.96.0.10\n  - fd00::10"
    ).replace("  - IPv4", "  - IPv4\n  - IPv6")
)

BREAKING_CANDIDATE = (
    PV_BASELINE.replace(
        "  hostPath:\n    path: /data", "  nfs:\n    server: nfs.example.com\n    path: /exports"
    )
    + "---\n"
    + PVC_BASELINE.replace("- ReadWriteOnce", "- ReadWriteMany")
    + "---\n"
    + SERVICE_BASELINE.replace("  - 10.96.0.10", "  - 10.96.0.11")
)

BREAKING_BASELINE = (
    PV_BASELINE
    + "---\n"
    + PVC_BASELINE
    + "---\n"
    + SERVICE_BASELINE
)


class TestVersionCoverage:
    @pytest.mark.parametrize("version", AUDITED_VERSIONS)
    def test_counterexamples_compatible_on_every_audited_minor(self, version: str) -> None:
        scenario = dict(SCENARIO, kubernetesVersion=version)
        findings = run_compare(COMPATIBLE_BASELINE, COMPATIBLE_CANDIDATE, scenario)
        assert findings == []

    @pytest.mark.parametrize("version", AUDITED_VERSIONS)
    def test_breaking_fixtures_error_on_every_audited_minor(self, version: str) -> None:
        scenario = dict(SCENARIO, kubernetesVersion=version)
        findings = run_compare(BREAKING_BASELINE, BREAKING_CANDIDATE, scenario)
        assert set(ids(findings)) == {
            "pv-volume-source-immutable",
            "pvc-access-modes-immutable",
            "service-cluster-ips-transition",
        }
        assert all(finding["severity"] == "error" for finding in findings)

    def test_unsupported_minor_suppresses_rules(self) -> None:
        scenario = dict(SCENARIO, kubernetesVersion="1.34.1")
        findings = run_compare(BREAKING_BASELINE, BREAKING_CANDIDATE, scenario)
        assert findings == []


class TestModuleContract:
    def test_compare_does_not_mutate_inputs(self) -> None:
        baseline = normalized(BREAKING_BASELINE)
        candidate = normalized(BREAKING_CANDIDATE)
        baseline_copy = copy.deepcopy(baseline)
        candidate_copy = copy.deepcopy(candidate)
        assert policies.compare(baseline, candidate, SCENARIO, CATALOGUE) != []
        assert baseline == baseline_copy
        assert candidate == candidate_copy

    def test_removed_objects_are_not_this_modules_concern(self) -> None:
        candidate = SERVICE_BASELINE
        findings = run_compare(BREAKING_BASELINE, candidate)
        assert "pv-volume-source-immutable" not in ids(findings)
        assert "pvc-access-modes-immutable" not in ids(findings)

    def test_unhandled_kinds_are_ignored(self) -> None:
        deployment = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
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
      - name: web
        image: nginx:1.27
"""
        changed = deployment.replace("nginx:1.27", "nginx:1.29")
        assert run_compare(deployment, changed) == []

    def test_findings_are_deterministically_sorted(self) -> None:
        first = run_compare(BREAKING_BASELINE, BREAKING_CANDIDATE)
        second = run_compare(BREAKING_BASELINE, BREAKING_CANDIDATE)
        assert first == second
        keys = [(f["id"], f["resource"]["name"], f["path"]) for f in first]
        assert keys == sorted(keys)
