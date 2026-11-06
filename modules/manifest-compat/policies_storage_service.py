"""Storage and Service update-transition compatibility policies.

Implements the storage and networking transition rules registered in
modules/manifest-compat/policy.json for objects present in both the baseline
and candidate normalized maps: PersistentVolume, PersistentVolumeClaim,
Service, IPAddress, and ServiceCIDR. The behavior mirrors the audited
upstream validators (ValidatePersistentVolumeUpdate,
ValidatePersistentVolumeClaimUpdate with the storage-class migration helpers,
ValidateServiceUpdate with validateUpgradeDowngradeClusterIPs,
validateUpgradeDowngradeIPFamilies, validateLoadBalancerClassField and
validateServiceExternalTrafficFieldsUpdate, ValidateIPAddressUpdate, and
ValidateServiceCIDRUpdate) at the three pinned Kubernetes commits.

Three behavior classes are deliberately distinguished:

* Provable violations (error): frozen PV volume-source union and volumeMode,
  PVC accessModes/selector/dataSource/dataSourceRef/volumeMode, explicit
  primary Service addresses and families, conditional loadBalancerClass and
  healthCheckNodePort edits, IPAddress parentRef, and ServiceCIDR changes
  outside the validated single-to-dual-stack append.
* Source-verified transitions (compatible): the one-time PV
  controllerExpandSecretRef and PVC volumeName initializations, the exact PVC
  beta-annotation and nil storage-class migrations, setting PV nodeAffinity
  when it was previously unset, secondary Service address/family add/remove
  transitions, and the ServiceCIDR dual-stack append.
* Undecidable offline (warn): PV volumeAttributesClassName transitions,
  already-set PV nodeAffinity edits, PVC volumeAttributesClassName edits, and
  PVC storage size changes, whose safety depends on feature gates, live
  status, or driver capability that rendered YAML cannot prove. Warnings name
  exactly what cannot be known; they never assert a rejection or a success.

Only finding IDs registered in the policy catalogue are emitted, and
severity, evidence, and classification are always taken from the catalogue
entry. The module is pure: caller dictionaries are never mutated.
"""

from __future__ import annotations

import importlib.util
import sys
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any

# JSON field names of the PersistentVolumeSpec.PersistentVolumeSource union,
# verified against staging/src/k8s.io/api/core/v1/types.go at the three
# audited commits. Note "storageos" is all lowercase upstream.
PV_SOURCE_FIELDS: tuple[str, ...] = (
    "gcePersistentDisk", "awsElasticBlockStore", "hostPath", "glusterfs", "nfs",
    "rbd", "iscsi", "cinder", "cephfs", "fc", "flocker", "flexVolume", "azureFile",
    "vsphereVolume", "quobyte", "azureDisk", "photonPersistentDisk", "portworxVolume",
    "scaleIO", "local", "storageos", "csi",
)

BETA_STORAGE_CLASS_ANNOTATION = "volume.beta.kubernetes.io/storage-class"
BETA_STORAGE_CLASS_POINTER = "/metadata/annotations/volume.beta.kubernetes.io~1storage-class"

SERVICE_EXTERNAL_NAME = "ExternalName"
SERVICE_LOAD_BALANCER = "LoadBalancer"
SERVICE_LOCAL = "Local"
IP_FAMILY_SINGLE_STACK = "SingleStack"
CLUSTER_IP_NONE = "None"

# PersistentVolumeClaimSpec.Resources.Requests["storage"]; upstream reads a
# missing entry as the zero quantity, so omitted requests compare as zero.
_STORAGE_POINTER = "/spec/resources/requests/storage"


class PolicyError(Exception):
    """The policy catalogue does not contain a rule this module must emit."""


def _load_normalizer() -> ModuleType:
    """Load the sibling normalizer for its shared quantity canonicalization."""
    name = "manifest_compat_normalizer"
    module = sys.modules.get(name)
    if module is not None:
        return module
    path = Path(__file__).resolve().parent / "normalizer.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load sibling module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_normalizer: Any = _load_normalizer()


def _spec_of(document: dict[str, Any]) -> dict[str, Any]:
    spec = document.get("spec")
    return spec if isinstance(spec, dict) else {}


def _annotations_of(document: dict[str, Any]) -> dict[str, Any]:
    metadata = document.get("metadata")
    annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
    return annotations if isinstance(annotations, dict) else {}


def _is_empty(value: Any) -> bool:
    """True for the nil/empty forms apiequality.Semantic equates."""
    return value is None or value == {} or value == []


def _semantic_equal(old: Any, new: Any) -> bool:
    """API structural equality: nil equals empty, arrays keep their order."""
    if _is_empty(old) and _is_empty(new):
        return True
    if isinstance(old, dict) and isinstance(new, dict):
        keys = set(old) | set(new)
        return all(_semantic_equal(old.get(key), new.get(key)) for key in keys)
    if isinstance(old, list) and isinstance(new, list):
        return len(old) == len(new) and all(
            _semantic_equal(old_item, new_item) for old_item, new_item in zip(old, new)
        )
    if isinstance(old, (dict, list)) or isinstance(new, (dict, list)):
        return False
    if isinstance(old, bool) or isinstance(new, bool):
        return isinstance(old, bool) and isinstance(new, bool) and old == new
    return old == new


def _string_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _quantity_of(value: Any) -> Fraction | None:
    """Parse a storage request into an exact number, or None if unparseable.

    Values already canonicalized by the normalizer ("N" or "N/D") parse
    directly; raw quantities ("5Gi", "500m", 10737418240) are canonicalized
    through the shared normalizer first so comparisons are numeric.
    """
    if value is None:
        return Fraction(0)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Fraction(value)
    if not isinstance(value, (str, float)):
        return None
    text = str(value)
    try:
        return Fraction(text)
    except (ValueError, ZeroDivisionError):
        pass
    try:
        canonical = _normalizer.canonical_quantity(value, _STORAGE_POINTER)
    except Exception:  # NormalizeError from the sibling module
        return None
    try:
        return Fraction(str(canonical))
    except (ValueError, ZeroDivisionError):
        return None


def _storage_request(spec: dict[str, Any]) -> Fraction | None:
    resources = spec.get("resources")
    if not isinstance(resources, dict):
        return Fraction(0)
    requests = resources.get("requests")
    if not isinstance(requests, dict):
        return Fraction(0)
    return _quantity_of(requests.get("storage"))


class _ObjectContext:
    """Per-object finding emission: catalogue lookup, versions, and identity."""

    def __init__(
        self,
        rules: dict[str, dict[str, Any]],
        minor: str,
        scenario_id: str,
        resource: dict[str, str],
        api_versions: tuple[str, str],
    ) -> None:
        self._rules = rules
        self._minor = minor
        self._scenario_id = scenario_id
        self._resource = resource
        self._api_versions = api_versions

    def finding(self, rule_id: str, path: str, text: str) -> dict[str, Any] | None:
        rule = self._rules.get(rule_id)
        if rule is None:
            raise PolicyError(f"policy catalogue is missing rule {rule_id!r}")
        if self._minor not in (rule.get("versions") or []):
            return None
        declared = rule.get("api_versions") or []
        # Beta/alpha aliases must not silently reuse a stable rule: emit only
        # when both revisions declare one of the rule's audited API versions.
        if declared and not all(version in declared for version in self._api_versions):
            return None
        return {
            "id": rule_id,
            "path": path,
            "text": text,
            "severity": rule["severity"],
            "scenario": self._scenario_id,
            "resource": dict(self._resource),
            "classification": rule["classification"],
            "evidence": rule["evidence"],
        }


def _compare_persistent_volume(
    old_doc: dict[str, Any], new_doc: dict[str, Any], ctx: _ObjectContext
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    old_spec = _spec_of(old_doc)
    new_spec = _spec_of(new_doc)

    old_source = {field: old_spec.get(field) for field in PV_SOURCE_FIELDS}
    new_source = {field: new_spec.get(field) for field in PV_SOURCE_FIELDS}
    compared_source = new_source
    old_csi = old_source["csi"]
    new_csi = new_source["csi"]
    # One-time initialization: spec.csi.controllerExpandSecretRef may go from
    # unset to set; upstream zeroes it in the comparison copy when it does.
    if (
        isinstance(old_csi, dict) and old_csi.get("controllerExpandSecretRef") is None
        and isinstance(new_csi, dict) and new_csi.get("controllerExpandSecretRef") is not None
    ):
        compared_source = dict(new_source)
        compared_source["csi"] = {
            key: value for key, value in new_csi.items() if key != "controllerExpandSecretRef"
        }
    changed = [
        field for field in PV_SOURCE_FIELDS
        if not _semantic_equal(old_source.get(field), compared_source.get(field))
    ]
    if changed:
        finding = ctx.finding(
            "pv-volume-source-immutable",
            "/spec/persistentVolumeSource",
            "PersistentVolume volume source is immutable after creation; changed source "
            f"field(s): {', '.join(changed)}. Only the one-time initialization of "
            "spec.csi.controllerExpandSecretRef from unset is permitted.",
        )
        if finding is not None:
            findings.append(finding)

    old_mode = old_spec.get("volumeMode")
    new_mode = new_spec.get("volumeMode")
    if (old_mode if isinstance(old_mode, str) else "Filesystem") != (
        new_mode if isinstance(new_mode, str) else "Filesystem"
    ):
        finding = ctx.finding(
            "pv-volume-mode-immutable",
            "/spec/volumeMode",
            "PersistentVolume spec.volumeMode is immutable after creation; omitted values "
            "default to Filesystem and compare equal.",
        )
        if finding is not None:
            findings.append(finding)

    old_affinity = old_spec.get("nodeAffinity")
    new_affinity = new_spec.get("nodeAffinity")
    if old_affinity is not None and not _semantic_equal(old_affinity, new_affinity):
        # Upstream validates nodeAffinity only when it was already set and the
        # MutablePVNodeAffinity gate is disabled; the live gate state cannot be
        # known offline, so an already-set edit is a conditional risk.
        finding = ctx.finding(
            "pv-node-affinity-risk",
            "/spec/nodeAffinity",
            "PersistentVolume spec.nodeAffinity change cannot be decided offline: upstream "
            "freezes it only while the MutablePVNodeAffinity feature gate is disabled, and "
            "the live gate state is not provable from rendered YAML. Setting nodeAffinity "
            "when it was previously unset is permitted and is not reported.",
        )
        if finding is not None:
            findings.append(finding)

    if not _semantic_equal(old_spec.get("volumeAttributesClassName"), new_spec.get("volumeAttributesClassName")):
        finding = ctx.finding(
            "pv-volume-attributes-class-name-risk",
            "/spec/volumeAttributesClassName",
            "PersistentVolume spec.volumeAttributesClassName change cannot be decided "
            "offline: it depends on the VolumeAttributesClass feature gate, which is live "
            "cluster state that rendered YAML cannot resolve.",
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _compare_persistent_volume_claim(
    old_doc: dict[str, Any], new_doc: dict[str, Any], ctx: _ObjectContext
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    old_spec = _spec_of(old_doc)
    new_spec = _spec_of(new_doc)

    for rule_id, pointer, field, text in (
        (
            "pvc-access-modes-immutable",
            "/spec/accessModes",
            "accessModes",
            "PersistentVolumeClaim spec.accessModes is immutable after creation.",
        ),
        (
            "pvc-selector-immutable",
            "/spec/selector",
            "selector",
            "PersistentVolumeClaim spec.selector is immutable after creation.",
        ),
        (
            "pvc-data-source-immutable",
            "/spec/dataSource",
            "dataSource",
            "PersistentVolumeClaim spec.dataSource is immutable after creation.",
        ),
        (
            "pvc-data-source-ref-immutable",
            "/spec/dataSourceRef",
            "dataSourceRef",
            "PersistentVolumeClaim spec.dataSourceRef is immutable after creation.",
        ),
    ):
        if not _semantic_equal(old_spec.get(field), new_spec.get(field)):
            finding = ctx.finding(rule_id, pointer, text)
            if finding is not None:
                findings.append(finding)

    old_mode = old_spec.get("volumeMode")
    new_mode = new_spec.get("volumeMode")
    if (old_mode if isinstance(old_mode, str) else "Filesystem") != (
        new_mode if isinstance(new_mode, str) else "Filesystem"
    ):
        finding = ctx.finding(
            "pvc-volume-mode-immutable",
            "/spec/volumeMode",
            "PersistentVolumeClaim spec.volumeMode is immutable after creation; omitted "
            "values default to Filesystem and compare equal.",
        )
        if finding is not None:
            findings.append(finding)

    # volumeName: one-time initialization from unset; frozen afterwards.
    old_volume_name = old_spec.get("volumeName")
    new_volume_name = new_spec.get("volumeName")
    if old_volume_name and new_volume_name != old_volume_name:
        finding = ctx.finding(
            "pvc-volume-name-immutable",
            "/spec/volumeName",
            "PersistentVolumeClaim spec.volumeName may be set exactly once from unset; it "
            "cannot be changed or cleared afterwards.",
        )
        if finding is not None:
            findings.append(finding)

    # storageClassName and its beta annotation: only the two source-verified
    # migrations may change either; everything else is a violation.
    old_annotations = _annotations_of(old_doc)
    new_annotations = _annotations_of(new_doc)
    old_annotation = old_annotations.get(BETA_STORAGE_CLASS_ANNOTATION)
    new_annotation = new_annotations.get(BETA_STORAGE_CLASS_ANNOTATION)
    old_class = old_spec.get("storageClassName")
    new_class = new_spec.get("storageClassName")
    from_annotation = (
        old_annotation is not None
        and old_class is None
        and new_class is not None
        and new_class == old_annotation
        and (new_annotation is None or new_annotation == old_annotation)
    )
    if not from_annotation:
        if old_annotation != new_annotation:
            finding = ctx.finding(
                "pvc-storage-class-name-immutable",
                BETA_STORAGE_CLASS_POINTER,
                "PersistentVolumeClaim annotation volume.beta.kubernetes.io/storage-class "
                "is immutable after creation; it may move to an equal spec.storageClassName "
                "value only through the exact beta-annotation migration.",
            )
            if finding is not None:
                findings.append(finding)
        from_nil = (
            new_class is not None
            and old_class is None
            and (old_annotation is None or old_annotation == new_class)
        )
        if not from_nil and old_class != new_class:
            finding = ctx.finding(
                "pvc-storage-class-name-immutable",
                "/spec/storageClassName",
                "PersistentVolumeClaim spec.storageClassName may change only through the two "
                "source-verified migrations: from the beta annotation to an equal field "
                "value, or from unset to set when no conflicting annotation exists.",
            )
            if finding is not None:
                findings.append(finding)

    # Storage size: numeric comparison; both directions are conditional risks.
    old_size = _storage_request(old_spec)
    new_size = _storage_request(new_spec)
    if old_size is not None and new_size is not None and new_size != old_size:
        if new_size < old_size:
            text = (
                "PersistentVolumeClaim spec.resources.requests.storage decreased; a "
                "decrease is accepted only when the RecoverVolumeExpansionFailure feature "
                "gate is enabled and the new request stays above live status.capacity, "
                "neither of which is provable from rendered YAML."
            )
        else:
            text = (
                "PersistentVolumeClaim spec.resources.requests.storage increased; update "
                "validation does not reject an increase, but whether it provisions depends "
                "on StorageClass allowVolumeExpansion and CSI driver support, which "
                "rendered YAML cannot prove."
            )
        finding = ctx.finding("pvc-storage-resize-risk", _STORAGE_POINTER, text)
        if finding is not None:
            findings.append(finding)

    if not _semantic_equal(
        old_spec.get("volumeAttributesClassName"), new_spec.get("volumeAttributesClassName")
    ):
        finding = ctx.finding(
            "pvc-volume-attributes-class-name-risk",
            "/spec/volumeAttributesClassName",
            "PersistentVolumeClaim spec.volumeAttributesClassName change cannot be decided "
            "offline: bound claims follow live status.currentVolumeAttributesClassName and "
            "the VolumeAttributesClass feature gate, neither of which is provable from "
            "rendered YAML.",
        )
        if finding is not None:
            findings.append(finding)

    return findings


def _cluster_ips(spec: dict[str, Any]) -> tuple[list[Any], bool]:
    """Explicit cluster addresses: the plural list, else the singular shorthand."""
    ips = spec.get("clusterIPs")
    if isinstance(ips, list) and ips:
        return list(ips), True
    singular = spec.get("clusterIP")
    if isinstance(singular, str) and singular:
        return [singular], False
    return [], False


def _is_headless(ips: list[Any]) -> bool:
    return ips == [CLUSTER_IP_NONE]


def _compare_cluster_ips(
    old_ips: list[Any], new_ips: list[Any], new_spec: dict[str, Any], ctx: _ObjectContext
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if len(old_ips) == len(new_ips):
        for index, (old_ip, new_ip) in enumerate(zip(old_ips, new_ips)):
            if old_ip != new_ip:
                finding = ctx.finding(
                    "service-cluster-ips-transition",
                    f"/spec/clusterIPs/{index}",
                    "Service clusterIPs may not change once set; only validated secondary "
                    "address add/remove transitions are permitted.",
                )
                if finding is not None:
                    findings.append(finding)
        return findings
    if len(old_ips) > len(new_ips):
        if new_ips and new_ips[0] != old_ips[0]:
            finding = ctx.finding(
                "service-cluster-ips-transition",
                "/spec/clusterIPs/0",
                "Service primary clusterIP may not change once set, including while "
                "releasing a secondary address.",
            )
            if finding is not None:
                findings.append(finding)
        if len(new_ips) == 1 and new_spec.get("ipFamilyPolicy") != IP_FAMILY_SINGLE_STACK:
            finding = ctx.finding(
                "service-cluster-ips-transition",
                "/spec/ipFamilyPolicy",
                "Releasing a Service secondary clusterIP requires spec.ipFamilyPolicy "
                "SingleStack in the same update.",
            )
            if finding is not None:
                findings.append(finding)
        return findings
    if new_ips[0] != old_ips[0]:
        finding = ctx.finding(
            "service-cluster-ips-transition",
            "/spec/clusterIPs/0",
            "Service primary clusterIP may not change once set, including while adding a "
            "secondary address.",
        )
        if finding is not None:
            findings.append(finding)
    return findings


def _compare_ip_families(
    old_families: list[Any], new_families: list[Any], new_spec: dict[str, Any],
    ctx: _ObjectContext
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if len(old_families) == len(new_families):
        for index, (old_family, new_family) in enumerate(zip(old_families, new_families)):
            if old_family != new_family:
                finding = ctx.finding(
                    "service-ip-families-transition",
                    f"/spec/ipFamilies/{index}",
                    "Service ipFamilies may not change once set; only validated "
                    "secondary-family add/remove transitions are permitted.",
                )
                if finding is not None:
                    findings.append(finding)
        return findings
    if len(old_families) > len(new_families):
        if new_families and new_families[0] != old_families[0]:
            finding = ctx.finding(
                "service-ip-families-transition",
                "/spec/ipFamilies/0",
                "Service primary IP family may not change once set, including while "
                "releasing a secondary family.",
            )
            if finding is not None:
                findings.append(finding)
        if len(new_families) == 1 and new_spec.get("ipFamilyPolicy") != IP_FAMILY_SINGLE_STACK:
            finding = ctx.finding(
                "service-ip-families-transition",
                "/spec/ipFamilyPolicy",
                "Releasing a Service secondary IP family requires spec.ipFamilyPolicy "
                "SingleStack in the same update.",
            )
            if finding is not None:
                findings.append(finding)
        return findings
    if new_families[0] != old_families[0]:
        finding = ctx.finding(
            "service-ip-families-transition",
            "/spec/ipFamilies/0",
            "Service primary IP family may not change once set, including while adding a "
            "secondary family.",
        )
        if finding is not None:
            findings.append(finding)
    return findings


def _needs_health_check(spec: dict[str, Any]) -> bool:
    return spec.get("type") == SERVICE_LOAD_BALANCER and spec.get("externalTrafficPolicy") == SERVICE_LOCAL


def _health_check_node_port(spec: dict[str, Any]) -> int:
    value = spec.get("healthCheckNodePort")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return 0


def _compare_service(
    old_doc: dict[str, Any], new_doc: dict[str, Any], ctx: _ObjectContext
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    old_spec = _spec_of(old_doc)
    new_spec = _spec_of(new_doc)
    old_type = old_spec.get("type") or ""
    new_type = new_spec.get("type") or ""

    if old_type != SERVICE_EXTERNAL_NAME and new_type != SERVICE_EXTERNAL_NAME:
        old_ips, _old_plural = _cluster_ips(old_spec)
        new_ips, new_plural = _cluster_ips(new_spec)
        old_headless = _is_headless(old_ips)
        new_headless = _is_headless(new_ips)
        # Only explicitly declared addresses are compared. A candidate that
        # omits the plural list while the baseline declared several addresses
        # does not prove a release, so the comparison is skipped entirely.
        if old_ips and new_ips and not (len(old_ips) > 1 and not new_plural):
            if not (old_headless and new_headless):
                findings.extend(_compare_cluster_ips(old_ips, new_ips, new_spec, ctx))
        old_families = _string_list(old_spec.get("ipFamilies"))
        new_families = _string_list(new_spec.get("ipFamilies"))
        if (
            old_families and new_families
            and old_headless == new_headless
            and not new_headless
        ):
            findings.extend(_compare_ip_families(old_families, new_families, new_spec, ctx))

    if old_type == SERVICE_LOAD_BALANCER and new_type == SERVICE_LOAD_BALANCER:
        if not _semantic_equal(
            old_spec.get("loadBalancerClass"), new_spec.get("loadBalancerClass")
        ):
            finding = ctx.finding(
                "service-load-balancer-class-immutable",
                "/spec/loadBalancerClass",
                "Service spec.loadBalancerClass may not change while both the baseline and "
                "candidate types are LoadBalancer; the restriction resets when the type "
                "changes away from LoadBalancer.",
            )
            if finding is not None:
                findings.append(finding)

    if _needs_health_check(old_spec) and _needs_health_check(new_spec):
        if _health_check_node_port(old_spec) != _health_check_node_port(new_spec):
            finding = ctx.finding(
                "service-health-check-node-port-immutable",
                "/spec/healthCheckNodePort",
                "Service spec.healthCheckNodePort may not change while both the baseline "
                "and candidate are LoadBalancer services with externalTrafficPolicy Local; "
                "the restriction resets when either condition stops holding.",
            )
            if finding is not None:
                findings.append(finding)

    return findings


def _parent_ref_of(spec: dict[str, Any]) -> dict[str, str] | None:
    """IPAddress spec.parentRef with plain-string zero-value semantics.

    ParentReference fields are plain strings in the upstream struct, so an
    omitted key and an explicit empty string unmarshal identically; compare
    the four source-verified struct fields with that equivalence.
    """
    ref = spec.get("parentRef")
    if not isinstance(ref, dict):
        return None
    return {key: (ref.get(key) or "") for key in ("group", "kind", "name", "namespace")}


def _compare_ip_address(
    old_doc: dict[str, Any], new_doc: dict[str, Any], ctx: _ObjectContext
) -> list[dict[str, Any]]:
    if _parent_ref_of(_spec_of(old_doc)) != _parent_ref_of(_spec_of(new_doc)):
        finding = ctx.finding(
            "ipaddress-parent-ref-immutable",
            "/spec/parentRef",
            "IPAddress spec.parentRef is immutable after creation.",
        )
        return [finding] if finding is not None else []
    return []


def _cidr_family(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if ":" in value:
        return "IPv6"
    if "." in value:
        return "IPv4"
    return None


def _compare_service_cidr(
    old_doc: dict[str, Any], new_doc: dict[str, Any], ctx: _ObjectContext
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    old_cidrs = _string_list(_spec_of(old_doc).get("cidrs"))
    new_cidrs = _string_list(_spec_of(new_doc).get("cidrs"))
    if old_cidrs == new_cidrs:
        return findings
    if len(old_cidrs) == len(new_cidrs):
        for index, (old_cidr, new_cidr) in enumerate(zip(old_cidrs, new_cidrs)):
            if old_cidr != new_cidr:
                finding = ctx.finding(
                    "servicecidr-cidrs-transition",
                    f"/spec/cidrs/{index}",
                    "ServiceCIDR spec.cidrs entries may not change value; the only "
                    "permitted transition appends one CIDR to convert single-stack to "
                    "dual-stack.",
                )
                if finding is not None:
                    findings.append(finding)
        return findings
    if len(old_cidrs) == 1 and len(new_cidrs) == 2:
        if new_cidrs[0] != old_cidrs[0]:
            finding = ctx.finding(
                "servicecidr-cidrs-transition",
                "/spec/cidrs/0",
                "ServiceCIDR spec.cidrs entries may not change value; the dual-stack append "
                "must keep the existing CIDR unchanged at index 0.",
            )
            if finding is not None:
                findings.append(finding)
        existing_family = _cidr_family(old_cidrs[0])
        appended_family = _cidr_family(new_cidrs[1])
        if existing_family is not None and existing_family == appended_family:
            finding = ctx.finding(
                "servicecidr-cidrs-transition",
                "/spec/cidrs/1",
                "ServiceCIDR dual-stack conversion appends one CIDR of the other IP family; "
                "two CIDRs of the same family are rejected by the validated transition.",
            )
            if finding is not None:
                findings.append(finding)
        return findings
    finding = ctx.finding(
        "servicecidr-cidrs-transition",
        "/spec/cidrs",
        "ServiceCIDR spec.cidrs may not shrink or otherwise restructure; the only permitted "
        "transition appends one CIDR to convert single-stack to dual-stack.",
    )
    if finding is not None:
        findings.append(finding)
    return findings


_HANDLERS = {
    ("", "PersistentVolume"): _compare_persistent_volume,
    ("", "PersistentVolumeClaim"): _compare_persistent_volume_claim,
    ("", "Service"): _compare_service,
    ("networking.k8s.io", "IPAddress"): _compare_ip_address,
    ("networking.k8s.io", "ServiceCIDR"): _compare_service_cidr,
}


def compare(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    scenario: dict[str, Any],
    catalogue: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compare normalized baseline and candidate object maps for this family.

    Applies the catalogue's storage and Service transition rules to every
    object identity present in both maps. Objects only on one side are other
    policies' concern (removal/protection) and are ignored here. The returned
    findings carry the catalogue's severity, evidence, and classification;
    baseline SHA, suppression metadata, and final sorting are added by the
    checker. Inputs are never mutated.
    """
    rules = {rule["id"]: rule for rule in catalogue.get("rules") or []}
    version = str(scenario.get("kubernetesVersion", ""))
    minor = ".".join(version.split(".")[:2])
    scenario_id = scenario.get("id", "<unnamed>")
    baseline_objects = baseline.get("objects") or {}
    candidate_objects = candidate.get("objects") or {}

    findings: list[dict[str, Any]] = []
    for key in sorted(baseline_objects):
        if key not in candidate_objects:
            continue
        group, kind, namespace, name = key
        handler = _HANDLERS.get((group, kind))
        if handler is None:
            continue
        old_doc = baseline_objects[key]["document"]
        new_doc = candidate_objects[key]["document"]
        ctx = _ObjectContext(
            rules=rules,
            minor=minor,
            scenario_id=scenario_id,
            resource={"group": group, "kind": kind, "namespace": namespace, "name": name},
            api_versions=(str(old_doc.get("apiVersion", "")), str(new_doc.get("apiVersion", ""))),
        )
        findings.extend(handler(old_doc, new_doc, ctx))

    findings.sort(
        key=lambda finding: (
            finding["id"],
            finding["resource"]["group"],
            finding["resource"]["kind"],
            finding["resource"]["namespace"],
            finding["resource"]["name"],
            finding["path"],
        )
    )
    return findings
