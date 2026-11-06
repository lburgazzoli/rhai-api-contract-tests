"""Immutable-field comparison policies for configuration and other built-ins.

Implements the "Other built-ins" matrix of the audited field catalogue
(modules/manifest-compat/policy.json): configuration (ConfigMap, Secret,
ResourceQuota), RBAC bindings, storage-class and CSI metadata, node and
scheduling classes, networking classes, endpoint discovery, stable dynamic
resource allocation (DRA) APIs, certificates, and storage-version migration.

The module is pure: it consumes normalized object maps (as produced by
normalizer.normalize), the scenario, and the catalogue, and returns findings.
It never mutates caller data and never touches files or the network.

Semantics follow the audited upstream validators:

- ValidateImmutableField compares with apiequality.Semantic.DeepEqual, where
  slices compare in order but nil equals empty for maps and slices; field
  comparison here mirrors those semantics after applying the defaults recorded
  in the catalogue (list defaults apply to any empty list, matching upstream
  len()==0 defaulting such as CSIDriver volumeLifecycleModes).
- ValidateConfigMapUpdate/ValidateSecretUpdate gate data immutability on the
  *baseline* immutable flag (never the candidate's) and compare data maps with
  reflect.DeepEqual, where an absent mapping and an empty mapping differ.
- ResourceQuota spec.scopes compares as a set (sets.New in the validator);
  resource limits themselves are not frozen.
- ValidateCSINodeUpdate freezes driver entries matched by name, but the
  MutableCSINodeAllocatableCount feature gate excludes allocatable from the
  comparison; gate-dependent allocatable-only changes downgrade to
  conditional-update-risk warnings instead of errors, and entry add/remove is
  not forbidden.
- The CertificateSigningRequest registry strategy restores the previous spec
  (csrStrategy.PrepareForUpdate), so an authored spec change is an ignored,
  ineffective update rather than an API rejection; API-populated caller
  identity fields (username, uid, groups, extra) are excluded.
- Secret contents never appear in findings: effective stringData/base64 bytes
  are compared by the normalizer and only key identities are reported.

API coverage is explicit: a rule applies only when the candidate document's
apiVersion is registered for the kind and the scenario's Kubernetes minor is
covered by the rule. Any other form (beta/alpha APIs, stable APIs outside
their audited minors, unknown versions) produces a rule-coverage-partial
finding instead of a silent comparison or a silent pass; support is never
inferred from an existing internal Go type and beta APIs are never silently
aliased to a stable rule.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

ObjectKey = tuple[str, str, str, str]

# Registry rule IDs; every emitted finding must exist in policy.json.
_RULE_COVERAGE_PARTIAL = "rule-coverage-partial"
_RULE_CONDITIONAL_RISK = "conditional-update-risk"

# CertificateSigningRequest spec fields populated by the API server from the
# requesting user (csrStrategy.PrepareForCreate); never user-authored YAML.
_CSR_CALLER_IDENTITY_FIELDS = ("username", "uid", "groups", "extra")


def _objects_of(side: dict[Any, Any]) -> dict[Any, dict[str, Any]]:
    """Accept either a full normalize() snapshot or a bare object map."""
    objects = side.get("objects") if isinstance(side, dict) else None
    if isinstance(objects, dict):
        return objects
    return side


def _minor_of(scenario: dict[str, Any]) -> str:
    version = scenario.get("kubernetesVersion")
    if not isinstance(version, str) or len(version.split(".")) < 2:
        raise ValueError(
            "scenario is missing a full kubernetesVersion; the policy modules "
            "require a scenario validated by config.validate_context"
        )
    major, minor = version.split(".")[:2]
    if not major.isdigit() or not minor.isdigit():
        raise ValueError(f"scenario kubernetesVersion {version!r} is not a semantic version")
    return f"{major}.{minor}"


def _semantic_equal(baseline: Any, candidate: Any) -> bool:
    """API structural equality (apiequality.Semantic.DeepEqual semantics).

    Slices compare in order; maps compare by key; nil equals the empty value
    for maps and slices, matching DeepEqual's equateNilAndEmpty behavior.
    """
    if isinstance(baseline, dict) and isinstance(candidate, dict):
        if set(baseline) != set(candidate):
            return False
        return all(_semantic_equal(baseline[key], candidate[key]) for key in baseline)
    if isinstance(baseline, list) and isinstance(candidate, list):
        return len(baseline) == len(candidate) and all(
            _semantic_equal(old, new) for old, new in zip(baseline, candidate)
        )
    if baseline is None or candidate is None:
        if baseline is None and candidate is None:
            return True
        other = candidate if baseline is None else baseline
        return isinstance(other, (dict, list)) and len(other) == 0
    return baseline == candidate


def _pointer_token(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _tokens(pointer: str) -> list[str]:
    return pointer.split(".") if pointer else []


def _pointer_of(pointer: str) -> str:
    return "/" + "/".join(_tokens(pointer)) if pointer else ""


def _get(document: dict[str, Any], pointer: str) -> Any:
    value: Any = document
    for token in _tokens(pointer):
        if not isinstance(value, dict):
            return None
        value = value.get(token)
    return value


def _effective(document: dict[str, Any], rule: dict[str, Any], pointer: str) -> Any:
    """Read a field, applying the catalogue-recorded default when omitted.

    The normalizer already applies these unconditional defaults; re-applying
    them keeps the comparison correct on any conforming input and implements
    the rule's registered default handling. List defaults apply to an empty
    list as well, matching upstream len()==0 defaulting.
    """
    value = _get(document, pointer)
    default = (rule.get("defaults") or {}).get(pointer)
    if default is None or value is None:
        return default if value is None else value
    if isinstance(default, list) and isinstance(value, list) and not value:
        return default
    return value


def _resource_of(key: ObjectKey) -> dict[str, str]:
    group, kind, namespace, name = key
    return {"group": group, "kind": kind, "namespace": namespace, "name": name}


def _finding(rule: dict[str, Any], scenario: dict[str, Any], resource: dict[str, str],
             path: str, text: str) -> dict[str, Any]:
    return {
        "id": rule["id"],
        "path": path,
        "text": text,
        "severity": rule["severity"],
        "scenario": scenario.get("id"),
        "resource": dict(resource),
        "classification": rule["classification"],
        "evidence": rule["evidence"],
    }


def _rules_by_id(catalogue: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {rule["id"]: rule for rule in catalogue.get("rules") or []}


def _rule(rules_by_id: dict[str, dict[str, Any]], identifier: str) -> dict[str, Any]:
    rule = rules_by_id.get(identifier)
    if rule is None:
        raise ValueError(f"catalogue is missing registered rule {identifier!r}")
    return rule


def _default_note(rule: dict[str, Any], pointer: str) -> str:
    default = (rule.get("defaults") or {}).get(pointer)
    if default is None:
        return ""
    if isinstance(default, list):
        rendered = "[" + ", ".join(str(item) for item in default) + "]"
    elif isinstance(default, bool):
        rendered = "true" if default else "false"
    else:
        rendered = str(default)
    return f" (omitted values default to {rendered})"


def _field_finding(rule: dict[str, Any], scenario: dict[str, Any], resource: dict[str, str],
                   pointer: str) -> dict[str, Any]:
    text = (
        f"{resource['kind']} field {pointer} is immutable"
        f"{_default_note(rule, pointer)}; the candidate changes it"
    )
    return _finding(rule, scenario, resource, _pointer_of(pointer), text)


def _map_key_diffs(baseline: Any, candidate: Any) -> list[str]:
    baseline_map = baseline if isinstance(baseline, dict) else {}
    candidate_map = candidate if isinstance(candidate, dict) else {}
    return [
        key
        for key in sorted(set(baseline_map) | set(candidate_map))
        if baseline_map.get(key) != candidate_map.get(key)
    ]


Handler = Callable[
    [dict[str, dict[str, Any]], dict[str, Any], dict[str, str], dict[str, Any], dict[str, Any]],
    list[dict[str, Any]],
]
# Handler signature: (rules_by_id, scenario, resource, baseline_doc, candidate_doc).


def _configmap(rules_by_id: dict[str, dict[str, Any]], scenario: dict[str, Any],
               resource: dict[str, str], baseline: dict[str, Any],
               candidate: dict[str, Any]) -> list[dict[str, Any]]:
    rule = _rule(rules_by_id, "configmap-immutable-data")
    findings: list[dict[str, Any]] = []
    if baseline.get("immutable") is not True:
        # Not gated: changing data while first setting immutable is allowed.
        return findings
    if candidate.get("immutable") is not True:
        findings.append(_finding(
            rule, scenario, resource, "/immutable",
            "ConfigMap sets immutable in the baseline; the candidate unsets the flag, "
            "which the API rejects",
        ))
    for field in ("data", "binaryData"):
        old_map, new_map = baseline.get(field), candidate.get(field)
        if old_map == new_map:
            continue
        changed = _map_key_diffs(old_map, new_map)
        if changed:
            for key in changed:
                findings.append(_finding(
                    rule, scenario, resource, f"/{field}/{_pointer_token(key)}",
                    f"ConfigMap {field} key {key!r} changed while the baseline marks "
                    "the object immutable",
                ))
        else:
            # reflect.DeepEqual distinguishes an absent mapping from an empty one.
            findings.append(_finding(
                rule, scenario, resource, f"/{field}",
                f"ConfigMap {field} changed between absent and an empty mapping while "
                "the baseline marks the object immutable",
            ))
    return findings


def _secret(rules_by_id: dict[str, dict[str, Any]], scenario: dict[str, Any],
            resource: dict[str, str], baseline: dict[str, Any],
            candidate: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    data_rule = _rule(rules_by_id, "secret-immutable-data")
    if baseline.get("immutable") is True:
        if candidate.get("immutable") is not True:
            findings.append(_finding(
                data_rule, scenario, resource, "/immutable",
                "Secret sets immutable in the baseline; the candidate unsets the flag, "
                "which the API rejects",
            ))
        old_data, new_data = baseline.get("data"), candidate.get("data")
        if old_data != new_data:
            changed = _map_key_diffs(old_data, new_data)
            for key in changed:
                findings.append(_finding(
                    data_rule, scenario, resource, f"/data/{_pointer_token(key)}",
                    f"Secret data key {key!r} changed while the baseline marks the "
                    "object immutable; effective stringData/base64 bytes are compared "
                    "without exposing content",
                ))
            if not changed:
                findings.append(_finding(
                    data_rule, scenario, resource, "/data",
                    "Secret data changed between absent and an empty mapping while the "
                    "baseline marks the object immutable",
                ))
    # The type is independently immutable, regardless of the immutable flag.
    type_rule = _rule(rules_by_id, "secret-type-immutable")
    if not _semantic_equal(
        _effective(baseline, type_rule, "type"), _effective(candidate, type_rule, "type")
    ):
        findings.append(_finding(
            type_rule, scenario, resource, "/type",
            "Secret type is immutable (omitted values default to Opaque); "
            "the candidate changes it",
        ))
    return findings


def _binding(rule_id: str) -> Handler:
    def handler(rules_by_id: dict[str, dict[str, Any]], scenario: dict[str, Any],
                resource: dict[str, str], baseline: dict[str, Any],
                candidate: dict[str, Any]) -> list[dict[str, Any]]:
        rule = _rule(rules_by_id, rule_id)
        if not _semantic_equal(baseline.get("roleRef"), candidate.get("roleRef")):
            return [_finding(
                rule, scenario, resource, "/roleRef",
                f"{resource['kind']} roleRef is immutable in its entirety; the candidate "
                "changes it (subjects remain mutable and are not checked here)",
            )]
        return []

    return handler


def _fields_handler(field_rules: dict[str, str]) -> Handler:
    """Generic semantic-equal-immutable comparison over named field pointers."""

    def handler(rules_by_id: dict[str, dict[str, Any]], scenario: dict[str, Any],
                resource: dict[str, str], baseline: dict[str, Any],
                candidate: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for pointer, rule_id in field_rules.items():
            rule = _rule(rules_by_id, rule_id)
            if not _semantic_equal(
                _effective(baseline, rule, pointer), _effective(candidate, rule, pointer)
            ):
                findings.append(_field_finding(rule, scenario, resource, pointer))
        return findings

    return handler


def _whole_spec_handler(rule_id: str) -> Handler:
    def handler(rules_by_id: dict[str, dict[str, Any]], scenario: dict[str, Any],
                resource: dict[str, str], baseline: dict[str, Any],
                candidate: dict[str, Any]) -> list[dict[str, Any]]:
        rule = _rule(rules_by_id, rule_id)
        if not _semantic_equal(baseline.get("spec"), candidate.get("spec")):
            return [_finding(
                rule, scenario, resource, "/spec",
                f"{resource['kind']} spec is immutable in its entirety; "
                "the candidate changes it",
            )]
        return []

    return handler


def _resourcequota(rules_by_id: dict[str, dict[str, Any]], scenario: dict[str, Any],
                   resource: dict[str, str], baseline: dict[str, Any],
                   candidate: dict[str, Any]) -> list[dict[str, Any]]:
    rule = _rule(rules_by_id, "resourcequota-scopes-immutable")
    old_scopes = _get(baseline, "spec.scopes")
    new_scopes = _get(candidate, "spec.scopes")
    if isinstance(old_scopes, list) and isinstance(new_scopes, list):
        changed = set(old_scopes) != set(new_scopes)
    else:
        changed = not _semantic_equal(old_scopes, new_scopes)
    if changed:
        return [_finding(
            rule, scenario, resource, "/spec/scopes",
            "ResourceQuota spec.scopes is immutable and compares as a set; the candidate "
            "changes it (resource limits themselves are not frozen by this rule)",
        )]
    return []


def _driver_entries(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    spec = document.get("spec")
    drivers = spec.get("drivers") if isinstance(spec, dict) else None
    entries: dict[str, dict[str, Any]] = {}
    for entry in drivers or []:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            entries.setdefault(entry["name"], entry)
    return entries


def _csinode(rules_by_id: dict[str, dict[str, Any]], scenario: dict[str, Any],
             resource: dict[str, str], baseline: dict[str, Any],
             candidate: dict[str, Any]) -> list[dict[str, Any]]:
    rule = _rule(rules_by_id, "csinode-driver-entries-immutable")
    risk_rule = _rule(rules_by_id, _RULE_CONDITIONAL_RISK)
    old_entries = _driver_entries(baseline)
    new_entries = _driver_entries(candidate)
    findings: list[dict[str, Any]] = []
    for name in sorted(set(old_entries) & set(new_entries)):
        old_entry, new_entry = old_entries[name], new_entries[name]
        if _semantic_equal(old_entry, new_entry):
            continue
        old_rest = {key: value for key, value in old_entry.items() if key != "allocatable"}
        new_rest = {key: value for key, value in new_entry.items() if key != "allocatable"}
        if _semantic_equal(old_rest, new_rest):
            # MutableCSINodeAllocatableCount gate decides; not provable offline.
            findings.append(_finding(
                risk_rule, scenario, resource, "/spec/drivers",
                f"CSINode driver entry {name!r} changes only its allocatable count; "
                "acceptance depends on the MutableCSINodeAllocatableCount feature gate, "
                "which rendered manifests cannot prove, so this is reported as a "
                "conditional risk rather than a violation",
            ))
        else:
            findings.append(_finding(
                rule, scenario, resource, "/spec/drivers",
                f"CSINode driver entry {name!r} is immutable once present; the candidate "
                "changes it (adding or removing entries is not forbidden)",
            ))
    return findings


def _csr(rules_by_id: dict[str, dict[str, Any]], scenario: dict[str, Any],
         resource: dict[str, str], baseline: dict[str, Any],
         candidate: dict[str, Any]) -> list[dict[str, Any]]:
    rule = _rule(rules_by_id, "csr-spec-ignored-update")

    def authored(document: dict[str, Any]) -> Any:
        spec = document.get("spec")
        if not isinstance(spec, dict):
            return spec
        return {key: value for key, value in spec.items() if key not in _CSR_CALLER_IDENTITY_FIELDS}

    if not _semantic_equal(authored(baseline), authored(candidate)):
        return [_finding(
            rule, scenario, resource, "/spec",
            "CertificateSigningRequest spec cannot be updated in place: the registry "
            "update strategy restores the previous spec, so the requested change is "
            "ignored and ineffective rather than rejected by the API server (caller "
            "identity fields populated by the API are excluded from the comparison)",
        )]
    return []


HANDLERS: dict[tuple[str, str], Handler] = {
    ("", "ConfigMap"): _configmap,
    ("", "Secret"): _secret,
    ("", "ResourceQuota"): _resourcequota,
    ("rbac.authorization.k8s.io", "RoleBinding"): _binding("rolebinding-roleref-immutable"),
    ("rbac.authorization.k8s.io", "ClusterRoleBinding"): _binding(
        "clusterrolebinding-roleref-immutable"
    ),
    ("storage.k8s.io", "StorageClass"): _fields_handler({
        "provisioner": "storageclass-provisioner-immutable",
        "parameters": "storageclass-parameters-immutable",
        "reclaimPolicy": "storageclass-reclaim-policy-immutable",
        "volumeBindingMode": "storageclass-volume-binding-mode-immutable",
    }),
    ("storage.k8s.io", "CSIDriver"): _fields_handler({
        "spec.attachRequired": "csidriver-attach-required-immutable",
        "spec.volumeLifecycleModes": "csidriver-volume-lifecycle-modes-immutable",
    }),
    ("storage.k8s.io", "VolumeAttributesClass"): _fields_handler({
        "driverName": "volumeattributesclass-driver-name-immutable",
        "parameters": "volumeattributesclass-parameters-immutable",
    }),
    ("storage.k8s.io", "VolumeAttachment"): _whole_spec_handler("volumeattachment-spec-immutable"),
    ("storage.k8s.io", "CSIStorageCapacity"): _fields_handler({
        "nodeTopology": "csistoragecapacity-node-topology-immutable",
        "storageClassName": "csistoragecapacity-storage-class-name-immutable",
    }),
    ("storage.k8s.io", "CSINode"): _csinode,
    ("node.k8s.io", "RuntimeClass"): _fields_handler({
        "handler": "runtimeclass-handler-immutable",
    }),
    ("scheduling.k8s.io", "PriorityClass"): _fields_handler({
        "value": "priorityclass-value-immutable",
        "preemptionPolicy": "priorityclass-preemption-policy-immutable",
    }),
    ("networking.k8s.io", "IngressClass"): _fields_handler({
        "spec.controller": "ingressclass-controller-immutable",
    }),
    ("discovery.k8s.io", "EndpointSlice"): _fields_handler({
        "addressType": "endpointslice-address-type-immutable",
    }),
    ("resource.k8s.io", "ResourceClaim"): _whole_spec_handler("resourceclaim-spec-immutable"),
    ("resource.k8s.io", "ResourceClaimTemplate"): _whole_spec_handler(
        "resourceclaimtemplate-spec-immutable"
    ),
    ("resource.k8s.io", "ResourceSlice"): _fields_handler({
        "spec.driver": "resourceslice-driver-immutable",
        "spec.pool.name": "resourceslice-pool-name-immutable",
        "spec.nodeName": "resourceslice-node-name-immutable",
    }),
    ("certificates.k8s.io", "CertificateSigningRequest"): _csr,
    ("certificates.k8s.io", "ClusterTrustBundle"): _fields_handler({
        "spec.signerName": "clustertrustbundle-signer-name-immutable",
    }),
    ("certificates.k8s.io", "PodCertificateRequest"): _whole_spec_handler(
        "podcertificaterequest-spec-immutable"
    ),
    ("storagemigration.k8s.io", "StorageVersionMigration"): _whole_spec_handler(
        "storageversionmigration-spec-immutable"
    ),
}


def _coverage_finding(rules_by_id: dict[str, dict[str, Any]], scenario: dict[str, Any],
                      resource: dict[str, str], kind_rules: list[dict[str, Any]],
                      api_version: Any, minor: str) -> dict[str, Any]:
    rule = _rule(rules_by_id, _RULE_COVERAGE_PARTIAL)
    audited_api_versions = sorted({
        version
        for kind_rule in kind_rules
        for version in kind_rule.get("api_versions") or []
    })
    audited_minors = sorted({
        version
        for kind_rule in kind_rules
        for version in kind_rule.get("versions") or []
    })
    target = scenario.get("kubernetesVersion")
    if api_version in audited_api_versions:
        text = (
            f"{resource['kind']} uses API version {api_version!r}, whose audited rules "
            f"cover Kubernetes {', '.join(audited_minors)} only; this scenario targets "
            f"Kubernetes {target} (minor {minor}), so the object was not compared"
        )
    else:
        text = (
            f"{resource['kind']} uses API version {api_version!r}, which has no audited "
            f"stable rule (audited versions: {', '.join(audited_api_versions) or 'none'}); "
            "beta, alpha, and unaudited API forms are inventory only and are never "
            "silently compared or aliased to a stable rule"
        )
    return _finding(rule, scenario, resource, "/apiVersion", text)


def compare(baseline: dict[Any, Any], candidate: dict[Any, Any], scenario: dict[str, Any],
            catalogue: dict[str, Any]) -> list[dict[str, Any]]:
    """Compare normalized baseline and candidate object maps for this family.

    baseline and candidate are either full normalize() snapshots or bare
    object maps keyed by (group, kind, namespace, name). Only objects present
    on both sides are evaluated (removal and addition policies live in other
    modules). Returns findings keyed with id, path, text, severity, scenario,
    resource, classification, and evidence; the caller adds baseline identity,
    suppression metadata, and final ordering. Pure: inputs are never mutated.
    """
    baseline_objects = _objects_of(baseline)
    candidate_objects = _objects_of(candidate)
    minor = _minor_of(scenario)
    rules_by_id = _rules_by_id(catalogue)
    findings: list[dict[str, Any]] = []

    for key in sorted(baseline_objects):
        candidate_entry = candidate_objects.get(key)
        if candidate_entry is None:
            continue
        group, kind = key[0], key[1]
        handler = HANDLERS.get((group, kind))
        if handler is None:
            continue
        baseline_doc = baseline_objects[key].get("document") or {}
        candidate_doc = candidate_entry.get("document") or {}
        kind_rules = [
            rule
            for rule in catalogue.get("rules") or []
            if rule.get("group") == group and rule.get("kind") == kind
        ]
        api_version = candidate_doc.get("apiVersion")
        active = [
            kind_rule
            for kind_rule in kind_rules
            if api_version in (kind_rule.get("api_versions") or [])
            and minor in (kind_rule.get("versions") or [])
        ]
        resource = _resource_of((key[0], key[1], key[2], key[3]))
        if active:
            findings.extend(handler(rules_by_id, scenario, resource, baseline_doc, candidate_doc))
        else:
            findings.append(_coverage_finding(
                rules_by_id, scenario, resource, kind_rules, api_version, minor
            ))

    findings.sort(key=lambda finding: (
        finding["resource"]["group"], finding["resource"]["kind"],
        finding["resource"]["namespace"], finding["resource"]["name"],
        finding["id"], finding["path"],
    ))
    return findings
