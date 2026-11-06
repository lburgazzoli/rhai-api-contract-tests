"""Manifest-level discovery and dependency relationship checks.

Pure ``compare`` and ``validate_candidate`` implementations that catch
legal-but-breaking manifest changes to discovery labels, selector
relationships, required local references, and explicitly protected
resources.

The check proves *declared* selection and reference relationships between
rendered objects of one scenario. It never claims live endpoint
reachability, running Pod counts, traffic behavior, or anything about
objects that are not part of the render: a missing external object alone
is not evidence of a failure.

Selector semantics follow the audited Kubernetes sources for all three
supported minors:

* ``In`` requires the label key to exist with a value in the list;
  ``NotIn`` is satisfied when the key is absent or its value is outside
  the list; ``Exists`` requires the key, ``DoesNotExist`` requires its
  absence (apimachinery ``Requirement.Matches``).
* Service ``spec.selector`` absent or empty selects no pods automatically.
* policy/v1 PodDisruptionBudget ``spec.selector``: a null selector matches
  no pods, an empty (``{}``) selector selects all pods in the namespace
  (documented on ``PodDisruptionBudgetSpec.Selector`` in the audited
  staging API types).
* NetworkPolicy top-level ``spec.podSelector`` empty selects all local
  targets.
* apps/v1 workload selectors are required and must match the pod template
  labels; a Job selector is generated when absent, so only an explicitly
  authored non-empty Job selector is validated (``ValidateDeploymentSpec``
  and ``ValidateJobSpec`` at the audited commits).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

ObjectKey = tuple[str, str, str, str]

SelectorForm = tuple[frozenset[tuple[str, str]], frozenset[tuple[Any, ...]]]

_APPS_WORKLOADS: frozenset[tuple[str, str]] = frozenset({
    ("apps", "Deployment"), ("apps", "DaemonSet"),
    ("apps", "StatefulSet"), ("apps", "ReplicaSet"),
})
_SELECTOR_VALIDATED_KINDS: frozenset[tuple[str, str]] = _APPS_WORKLOADS | {("batch", "Job")}

_TEMPLATE_LABEL_PATHS: dict[tuple[str, str], str] = {
    ("apps", "Deployment"): "/spec/template/metadata/labels",
    ("apps", "DaemonSet"): "/spec/template/metadata/labels",
    ("apps", "StatefulSet"): "/spec/template/metadata/labels",
    ("apps", "ReplicaSet"): "/spec/template/metadata/labels",
    ("batch", "Job"): "/spec/template/metadata/labels",
    ("batch", "CronJob"): "/spec/jobTemplate/spec/template/metadata/labels",
}

_POD_SPEC_PATHS: dict[tuple[str, str], str] = {
    ("", "Pod"): "/spec",
    ("apps", "Deployment"): "/spec/template/spec",
    ("apps", "DaemonSet"): "/spec/template/spec",
    ("apps", "StatefulSet"): "/spec/template/spec",
    ("apps", "ReplicaSet"): "/spec/template/spec",
    ("batch", "Job"): "/spec/template/spec",
    ("batch", "CronJob"): "/spec/jobTemplate/spec/template/spec",
}

_ROLE_BINDING_KINDS: frozenset[tuple[str, str]] = frozenset({
    ("rbac.authorization.k8s.io", "RoleBinding"),
    ("rbac.authorization.k8s.io", "ClusterRoleBinding"),
})

_REFERENCE_CONSUMER_KINDS: frozenset[tuple[str, str]] = (
    frozenset(_POD_SPEC_PATHS) | _ROLE_BINDING_KINDS
    | {("networking.k8s.io", "Ingress")}
)

# Emitted finding metadata, mirroring the registry entries in policy.json.
# test_relationships.py asserts agreement with the catalogue so the two can
# never drift apart.
_RULES: dict[str, dict[str, str]] = {
    "selector-template-mismatch": {
        "severity": "error", "evidence": "local-graph", "classification": "render-validation",
    },
    "selector-target-lost": {
        "severity": "error", "evidence": "local-graph", "classification": "selector",
    },
    "mutable-selector-changed": {
        "severity": "warn", "evidence": "unverified", "classification": "selector",
    },
    "required-reference-lost": {
        "severity": "error", "evidence": "local-graph", "classification": "reference",
    },
    "external-reference-unverified": {
        "severity": "warn", "evidence": "unverified", "classification": "reference",
    },
    "label-removed": {
        "severity": "warn", "evidence": "unverified", "classification": "risk",
    },
    "label-value-changed": {
        "severity": "warn", "evidence": "unverified", "classification": "risk",
    },
    "protected-label-changed": {
        "severity": "error", "evidence": "declared-contract", "classification": "contract",
    },
    "resource-removed": {
        "severity": "warn", "evidence": "unverified", "classification": "removal",
    },
    "protected-resource-removed": {
        "severity": "error", "evidence": "declared-contract", "classification": "contract",
    },
    "rule-coverage-partial": {
        "severity": "warn", "evidence": "unverified", "classification": "coverage",
    },
}


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------


def _objects_of(value: Any) -> dict[ObjectKey, dict[str, Any]]:
    """Accept either a normalized object map or a full normalize() result.

    Object maps are keyed by 4-tuples and never by the string "objects", so
    the unwrap is unambiguous.
    """
    if (
        isinstance(value, dict)
        and isinstance(value.get("objects"), dict)
        and isinstance(value.get("coverage"), dict)
    ):
        return value["objects"]
    return value


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _identity(key: ObjectKey) -> dict[str, str]:
    group, kind, namespace, name = key
    return {"group": group, "kind": kind, "namespace": namespace, "name": name}


def _identity_tuple(identity: dict[str, Any]) -> ObjectKey:
    return (
        identity.get("group", ""), identity.get("kind", ""),
        identity.get("namespace", ""), identity.get("name", ""),
    )


def _escape_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _pointer_get(document: dict[str, Any], pointer: str) -> Any:
    """Resolve an RFC 6901 pointer inside a document; None when absent."""
    if pointer == "":
        return document
    current: Any = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            return None
        current = current[token]
    return current


def _where(key: ObjectKey) -> str:
    group, kind, namespace, name = key
    del group
    scope = f"namespace {namespace!r}" if namespace else "cluster scope"
    return f"{kind} {name!r} in {scope}"


def _edge_id(relation: str, consumer: ObjectKey, consumer_path: str,
             target: ObjectKey, target_path: str) -> str:
    """SHA-256 over identities and pointers only; never field values."""
    payload = {
        "relation": relation,
        "consumer": _identity(consumer),
        "consumer_path": consumer_path,
        "target": _identity(target),
        "target_path": target_path,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _finding(rule_id: str, scenario_id: str, resource: ObjectKey, path: str, text: str, *,
             relation: str | None = None,
             related: ObjectKey | None = None,
             related_path: str | None = None,
             edge_id: str | None = None,
             path_origin: str | None = None,
             candidate_edge_id: str | None = None,
             baseline_associations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    metadata = _RULES[rule_id]
    finding: dict[str, Any] = {
        "id": rule_id,
        "path": path,
        "text": text,
        "severity": metadata["severity"],
        "scenario": scenario_id,
        "resource": _identity(resource),
        "classification": metadata["classification"],
        "evidence": metadata["evidence"],
    }
    if relation is not None:
        finding["relation"] = relation
    if related is not None:
        finding["related_resource"] = _identity(related)
    if related_path is not None:
        finding["related_path"] = related_path
    if edge_id is not None:
        finding["edge_id"] = edge_id
    if path_origin is not None:
        finding["path_origin"] = path_origin
    if candidate_edge_id is not None:
        finding["candidate_edge_id"] = candidate_edge_id
    if baseline_associations is not None:
        finding["baseline_associations"] = baseline_associations
    return finding


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
        resource = _identity_tuple(finding["resource"])
        related = finding.get("related_resource")
        related_key = _identity_tuple(related) if isinstance(related, dict) else ("", "", "", "")
        return (
            finding["id"], resource, finding["path"], related_key,
            finding.get("edge_id") or "", finding.get("candidate_edge_id") or "",
        )

    return sorted(findings, key=sort_key)


def _scenario_id(scenario: Any) -> str:
    if isinstance(scenario, dict) and _nonempty_str(scenario.get("id")):
        return scenario["id"]
    return ""


# ---------------------------------------------------------------------------
# Label selector semantics
# ---------------------------------------------------------------------------


def _selector_form(selector: Any) -> SelectorForm | None:
    """Semantic canonical form of a selector; None when it selects nothing.

    Handles plain ``map[string]string`` selectors (Service) and
    ``matchLabels``/``matchExpressions`` label selectors. Semantically
    equivalent selectors of either shape canonicalize identically, so a
    reworded but equivalent selector between two renders is "unchanged",
    while API-specific nil/empty meaning changes (for example a PDB null
    selector becoming ``{}``) are real changes.
    """
    if not isinstance(selector, dict):
        return None
    if "matchLabels" in selector or "matchExpressions" in selector:
        match_labels = selector.get("matchLabels")
        expressions = selector.get("matchExpressions")
        match_items = frozenset(
            (key, value) for key, value in (match_labels or {}).items()
            if isinstance(key, str) and isinstance(value, str)
        )
        expression_items: set[tuple[Any, ...]] = set()
        for expression in expressions or []:
            if not isinstance(expression, dict) or not _nonempty_str(expression.get("key")):
                continue
            values = expression.get("values") or []
            expression_items.add((
                expression["key"], expression.get("operator"),
                frozenset(value for value in values if isinstance(value, str)),
            ))
        if not match_items and not expression_items:
            return None
        return (match_items, frozenset(expression_items))
    if not selector:
        return None
    return (
        frozenset(
            (key, value) for key, value in selector.items()
            if isinstance(key, str) and isinstance(value, str)
        ),
        frozenset(),
    )


def _form_matches(form: SelectorForm, labels: dict[str, Any]) -> bool:
    """Kubernetes label selector matching with missing-key semantics."""
    match_items, expressions = form
    for key, value in match_items:
        if labels.get(key) != value:
            return False
    for key, operator, values in expressions:
        present = key in labels
        if operator == "In":
            if not present or labels[key] not in values:
                return False
        elif operator == "NotIn":
            # Upstream apimachinery Requirement.Matches: NotIn is satisfied
            # when the key is absent (only a present key whose value is in
            # the list fails the requirement).
            if present and labels[key] in values:
                return False
        elif operator == "Exists":
            if not present:
                return False
        elif operator == "DoesNotExist":
            if present:
                return False
        else:
            return False
    return True


def _referenced_keys(form: SelectorForm) -> set[str]:
    match_items, expressions = form
    return {key for key, _ in match_items} | {key for key, _, _ in expressions}


def _consumer_selection(key: ObjectKey, document: dict[str, Any]) -> tuple[str, SelectorForm | None]:
    """Return (mode, form) with the API-specific empty/nil meaning applied.

    Service: absent/empty selector selects nothing ("none").
    PodDisruptionBudget: nil selects none, empty selects all.
    NetworkPolicy: nil or empty podSelector selects all local targets.
    """
    group, kind = key[0], key[1]
    spec = document.get("spec")
    spec = spec if isinstance(spec, dict) else {}
    if (group, kind) == ("", "Service"):
        form = _selector_form(spec.get("selector"))
        return ("none", None) if form is None else ("match", form)
    if (group, kind) == ("policy", "PodDisruptionBudget"):
        selector = spec.get("selector")
        if selector is None:
            return ("none", None)
        form = _selector_form(selector)
        return ("all", None) if form is None else ("match", form)
    if (group, kind) == ("networking.k8s.io", "NetworkPolicy"):
        form = _selector_form(spec.get("podSelector"))
        return ("all", None) if form is None else ("match", form)
    return ("none", None)


_CONSUMER_SELECTOR_PATHS: dict[tuple[str, str], str] = {
    ("", "Service"): "/spec/selector",
    ("policy", "PodDisruptionBudget"): "/spec/selector",
    ("networking.k8s.io", "NetworkPolicy"): "/spec/podSelector",
}


def _graph_targets(
        objects: dict[ObjectKey, dict[str, Any]]) -> dict[ObjectKey, tuple[dict[str, Any], str]]:
    """Pods and workload pod templates with their label maps and pointers."""
    targets: dict[ObjectKey, tuple[dict[str, Any], str]] = {}
    for key, record in objects.items():
        group, kind = key[0], key[1]
        document = record["document"]
        if (group, kind) == ("", "Pod"):
            metadata = document.get("metadata")
            labels = metadata.get("labels") if isinstance(metadata, dict) else None
            targets[key] = (labels if isinstance(labels, dict) else {}, "/metadata/labels")
        elif (group, kind) in _TEMPLATE_LABEL_PATHS:
            pointer = _TEMPLATE_LABEL_PATHS[(group, kind)]
            labels = _pointer_get(document, pointer)
            targets[key] = (labels if isinstance(labels, dict) else {}, pointer)
    return targets


def _selected_targets(targets: dict[ObjectKey, tuple[dict[str, Any], str]],
                      namespace: str, mode: str,
                      form: SelectorForm | None) -> dict[ObjectKey, tuple[dict[str, Any], str]]:
    """Same-namespace targets selected under the consumer's mode."""
    selected: dict[ObjectKey, tuple[dict[str, Any], str]] = {}
    for key, (labels, pointer) in targets.items():
        if key[2] != namespace:
            continue
        if mode == "all" or (mode == "match" and form is not None and _form_matches(form, labels)):
            selected[key] = (labels, pointer)
    return selected


# ---------------------------------------------------------------------------
# Reference slot extraction
# ---------------------------------------------------------------------------


def _item_keys(ref: dict[str, Any]) -> tuple[str, ...] | None:
    """Requested keys declared through ``items``; None means the whole object."""
    items = ref.get("items")
    if not isinstance(items, list) or not items:
        return None
    keys = [item.get("key") for item in items if isinstance(item, dict)]
    if not keys or not all(_nonempty_str(key) for key in keys):
        return None
    return tuple(str(key) for key in keys)


def _pod_spec_slots(prefix: str, pod_spec: dict[str, Any], namespace: str,
                    slots: list[dict[str, Any]]) -> None:
    for section in ("containers", "initContainers"):
        containers = pod_spec.get(section)
        if not isinstance(containers, list):
            continue
        for index, container in enumerate(containers):
            if not isinstance(container, dict):
                continue
            container_name = container.get("name")
            container_id = (
                container_name if isinstance(container_name, str) and container_name
                else f"#{index}"
            )
            base = f"{prefix}/{section}/{index}"
            _container_env_slots(base, container_id, container, namespace, slots)
    service_account = pod_spec.get("serviceAccountName")
    if _nonempty_str(service_account):
        slots.append({
            "slot": ("serviceAccount",),
            "relation": "service-account",
            "consumer_path": f"{prefix}/serviceAccountName",
            "target": ("", "ServiceAccount", namespace, service_account),
            "optional": False,
            "keys": None,
        })


def _container_env_slots(base: str, container_id: str, container: dict[str, Any],
                         namespace: str, slots: list[dict[str, Any]]) -> None:
    env = container.get("env")
    if isinstance(env, list):
        for env_index, entry in enumerate(env):
            if not isinstance(entry, dict) or not _nonempty_str(entry.get("name")):
                continue
            env_name = entry["name"]
            value_from = entry.get("valueFrom")
            if not isinstance(value_from, dict):
                continue
            ref_base = f"{base}/env/{env_index}/valueFrom"
            config_ref = value_from.get("configMapKeyRef")
            if isinstance(config_ref, dict) and _nonempty_str(config_ref.get("name")):
                _append_key_slot(
                    slots, ("env", container_id, env_name, "configMapKeyRef"),
                    "env-configmap-key", f"{ref_base}/configMapKeyRef",
                    ("", "ConfigMap", namespace, config_ref["name"]),
                    config_ref,
                )
            secret_ref = value_from.get("secretKeyRef")
            if isinstance(secret_ref, dict) and _nonempty_str(secret_ref.get("name")):
                _append_key_slot(
                    slots, ("env", container_id, env_name, "secretKeyRef"),
                    "env-secret-key", f"{ref_base}/secretKeyRef",
                    ("", "Secret", namespace, secret_ref["name"]),
                    secret_ref,
                )

    env_from = container.get("envFrom")
    if isinstance(env_from, list):
        occurrences: dict[str, int] = {}
        for from_index, entry in enumerate(env_from):
            if not isinstance(entry, dict):
                continue
            for ref_field, kind, relation in (
                ("configMapRef", "ConfigMap", "envfrom-configmap"),
                ("secretRef", "Secret", "envfrom-secret"),
            ):
                ref = entry.get(ref_field)
                if not isinstance(ref, dict) or not _nonempty_str(ref.get("name")):
                    continue
                count = occurrences.get(ref_field, 0)
                occurrences[ref_field] = count + 1
                slots.append({
                    "slot": ("envFrom", container_id, ref_field, count),
                    "relation": relation,
                    "consumer_path": f"{base}/envFrom/{from_index}/{ref_field}",
                    "target": ("", kind, namespace, ref["name"]),
                    "optional": bool(ref.get("optional")),
                    "keys": None,
                })


def _append_key_slot(slots: list[dict[str, Any]], slot: tuple[Any, ...], relation: str,
                     consumer_path: str, target: ObjectKey, ref: dict[str, Any]) -> None:
    """Append an env-style key reference; skip refs without a usable key."""
    if not _nonempty_str(ref.get("key")):
        return
    slots.append({
        "slot": slot,
        "relation": relation,
        "consumer_path": consumer_path,
        "target": target,
        "optional": bool(ref.get("optional")),
        "keys": (ref["key"],),
    })


def _volume_slots(prefix: str, pod_spec: dict[str, Any], namespace: str,
                  slots: list[dict[str, Any]]) -> None:
    volumes = pod_spec.get("volumes")
    if not isinstance(volumes, list):
        return
    for volume_index, volume in enumerate(volumes):
        if not isinstance(volume, dict):
            continue
        volume_name = volume.get("name")
        volume_id = volume_name if _nonempty_str(volume_name) else f"#{volume_index}"
        base = f"{prefix}/volumes/{volume_index}"
        config_ref = volume.get("configMap")
        if isinstance(config_ref, dict) and _nonempty_str(config_ref.get("name")):
            slots.append({
                "slot": ("volume", volume_id, "configMap"),
                "relation": "volume-configmap",
                "consumer_path": f"{base}/configMap",
                "target": ("", "ConfigMap", namespace, config_ref["name"]),
                "optional": bool(config_ref.get("optional")),
                "keys": _item_keys(config_ref),
            })
        secret_ref = volume.get("secret")
        if isinstance(secret_ref, dict) and _nonempty_str(secret_ref.get("secretName")):
            slots.append({
                "slot": ("volume", volume_id, "secret"),
                "relation": "volume-secret",
                "consumer_path": f"{base}/secret",
                "target": ("", "Secret", namespace, secret_ref["secretName"]),
                "optional": bool(secret_ref.get("optional")),
                "keys": _item_keys(secret_ref),
            })
        projected = volume.get("projected")
        if not isinstance(projected, dict):
            continue
        sources = projected.get("sources")
        if not isinstance(sources, list):
            continue
        occurrences: dict[str, int] = {}
        for source_index, source in enumerate(sources):
            if not isinstance(source, dict):
                continue
            for ref_field, kind, relation in (
                ("configMap", "ConfigMap", "projected-configmap"),
                ("secret", "Secret", "projected-secret"),
            ):
                ref = source.get(ref_field)
                if not isinstance(ref, dict) or not _nonempty_str(ref.get("name")):
                    continue
                count = occurrences.get(ref_field, 0)
                occurrences[ref_field] = count + 1
                slots.append({
                    "slot": ("projected", volume_id, ref_field, count),
                    "relation": relation,
                    "consumer_path": f"{base}/projected/sources/{source_index}/{ref_field}",
                    "target": ("", kind, namespace, ref["name"]),
                    "optional": bool(ref.get("optional")),
                    "keys": _item_keys(ref),
                })


def _role_binding_slots(document: dict[str, Any], key: ObjectKey,
                        slots: list[dict[str, Any]]) -> None:
    group, kind, namespace, _ = key
    del group
    role_ref = document.get("roleRef")
    if not isinstance(role_ref, dict) or not _nonempty_str(role_ref.get("name")):
        return
    ref_kind = role_ref.get("kind")
    name = role_ref["name"]
    target: ObjectKey | None
    if kind == "RoleBinding":
        if ref_kind == "Role":
            target = ("rbac.authorization.k8s.io", "Role", namespace, name)
        elif ref_kind == "ClusterRole":
            target = ("rbac.authorization.k8s.io", "ClusterRole", "", name)
        else:
            target = None
    elif ref_kind == "ClusterRole":
        target = ("rbac.authorization.k8s.io", "ClusterRole", "", name)
    else:
        target = None
    if target is None:
        return
    slots.append({
        "slot": ("roleRef",),
        "relation": "role-ref",
        "consumer_path": "/roleRef",
        "target": target,
        "optional": False,
        "keys": None,
    })


def _ingress_slots(document: dict[str, Any], namespace: str,
                   slots: list[dict[str, Any]]) -> None:
    spec = document.get("spec")
    if not isinstance(spec, dict):
        return
    default_backend = spec.get("defaultBackend")
    if isinstance(default_backend, dict):
        _append_ingress_slot(
            ("backend", "default"), default_backend, "/spec/defaultBackend", namespace, slots)
    rules = spec.get("rules")
    if not isinstance(rules, list):
        return
    for rule_index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        host = rule.get("host") if isinstance(rule.get("host"), str) else ""
        http = rule.get("http")
        paths = http.get("paths") if isinstance(http, dict) else None
        if not isinstance(paths, list):
            continue
        for path_index, path_entry in enumerate(paths):
            if not isinstance(path_entry, dict):
                continue
            backend = path_entry.get("backend")
            if not isinstance(backend, dict):
                continue
            path_id = path_entry.get("path") if isinstance(path_entry.get("path"), str) else ""
            path_type = path_entry.get("pathType") if isinstance(path_entry.get("pathType"), str) else ""
            slot = ("backend", host, path_id, path_type)
            pointer = f"/spec/rules/{rule_index}/http/paths/{path_index}/backend"
            _append_ingress_slot(slot, backend, pointer, namespace, slots)


def _append_ingress_slot(slot: tuple[Any, ...], backend: dict[str, Any], pointer: str,
                         namespace: str, slots: list[dict[str, Any]]) -> None:
    service = backend.get("service")
    if not isinstance(service, dict) or not _nonempty_str(service.get("name")):
        return
    port = service.get("port")
    port_name = None
    port_number = None
    if isinstance(port, dict):
        if _nonempty_str(port.get("name")):
            port_name = port["name"]
        elif isinstance(port.get("number"), int) and not isinstance(port.get("number"), bool):
            port_number = port["number"]
    slots.append({
        "slot": slot,
        "relation": "ingress-backend-service",
        "consumer_path": pointer,
        "target": ("", "Service", namespace, service["name"]),
        "optional": False,
        "keys": None,
        "port_name": port_name,
        "port_number": port_number,
    })


def _reference_slots(key: ObjectKey, document: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract logical reference slots from one consumer document.

    Slots are matched across revisions by container/env/volume/reference
    names, never by incidental list positions. A slot record carries the
    exact JSON Pointer of the reference inside this revision's document.
    """
    group, kind, namespace, _ = key
    slots: list[dict[str, Any]] = []
    pod_spec_path = _POD_SPEC_PATHS.get((group, kind))
    if pod_spec_path is not None:
        pod_spec = _pointer_get(document, pod_spec_path)
        if isinstance(pod_spec, dict):
            _pod_spec_slots(pod_spec_path, pod_spec, namespace, slots)
            _volume_slots(pod_spec_path, pod_spec, namespace, slots)
    if (group, kind) in _ROLE_BINDING_KINDS:
        _role_binding_slots(document, key, slots)
    if (group, kind) == ("networking.k8s.io", "Ingress"):
        _ingress_slots(document, namespace, slots)
    return slots


def _service_port_slots(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Service ports, keyed by stable slot names (port name or number)."""
    spec = document.get("spec")
    ports = spec.get("ports") if isinstance(spec, dict) else None
    if not isinstance(ports, list):
        return []
    slots: list[dict[str, Any]] = []
    for index, port in enumerate(ports):
        if not isinstance(port, dict):
            continue
        name = port.get("name") if _nonempty_str(port.get("name")) else None
        slot_id = name if name is not None else f"port-{port.get('port')}"
        slots.append({
            "slot": ("targetPort", slot_id),
            "consumer_path": f"/spec/ports/{index}/targetPort",
            "target_port": port.get("targetPort"),
            "protocol": port.get("protocol") if _nonempty_str(port.get("protocol")) else "TCP",
        })
    return slots


def _exposes_port(record: dict[str, Any], kind_pair: tuple[str, str],
                  port_name: str, protocol: str) -> bool:
    """Whether a target's pod spec exposes a named container port."""
    pod_spec_path = _POD_SPEC_PATHS.get(kind_pair)
    if pod_spec_path is None:
        return False
    pod_spec = _pointer_get(record["document"], pod_spec_path)
    if not isinstance(pod_spec, dict):
        return False
    for section in ("containers", "initContainers"):
        containers = pod_spec.get(section)
        if not isinstance(containers, list):
            continue
        for container in containers:
            if not isinstance(container, dict):
                continue
            ports = container.get("ports")
            if not isinstance(ports, list):
                continue
            for port in ports:
                if not isinstance(port, dict) or port.get("name") != port_name:
                    continue
                port_protocol = port.get("protocol") if _nonempty_str(port.get("protocol")) else "TCP"
                if port_protocol == protocol:
                    return True
    return False


def _provider_ports_path(provider: ObjectKey) -> str:
    pod_spec_path = _POD_SPEC_PATHS.get((provider[0], provider[1]), "/spec")
    return f"{pod_spec_path}/containers"


# ---------------------------------------------------------------------------
# Slot resolution
# ---------------------------------------------------------------------------


def _missing_keys(document: dict[str, Any], keys: tuple[str, ...]) -> tuple[str, ...]:
    present: set[str] = set()
    data = document.get("data")
    if isinstance(data, dict):
        present.update(str(key) for key in data)
    binary = document.get("binaryData")
    if isinstance(binary, dict):
        present.update(str(key) for key in binary)
    return tuple(key for key in keys if key not in present)


def _service_port_missing(document: dict[str, Any], slot: dict[str, Any]) -> bool:
    spec = document.get("spec")
    ports = spec.get("ports") if isinstance(spec, dict) else None
    if not isinstance(ports, list):
        return True
    for port in ports:
        if not isinstance(port, dict):
            continue
        if slot.get("port_name") is not None:
            if port.get("name") == slot["port_name"]:
                return False
        elif slot.get("port_number") is not None:
            if port.get("port") == slot["port_number"]:
                return False
    return True


def _slot_status(objects: dict[ObjectKey, dict[str, Any]],
                 slot: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    """Resolution status of a reference slot plus the missing keys/ports.

    Returns ("resolved", ()), ("missing-object", ()), or ("missing-key",
    missing) where missing holds the requested keys (or the port marker
    for port-based references).
    """
    target = slot["target"]
    record = objects.get(target)
    if record is None:
        return ("missing-object", ())
    document = record["document"]
    if slot["relation"] == "ingress-backend-service":
        if slot.get("port_name") is not None or slot.get("port_number") is not None:
            if _service_port_missing(document, slot):
                return ("missing-key", ("port",))
        return ("resolved", ())
    keys = slot["keys"]
    if keys:
        missing = _missing_keys(document, keys)
        if missing:
            return ("missing-key", missing)
    return ("resolved", ())


def _key_target_path(key_name: str) -> str:
    return f"/data/{_escape_token(key_name)}"


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def compare(baseline: dict[str, Any], candidate: dict[str, Any], scenario: dict[str, Any],
            catalogue: dict[str, Any]) -> list[dict[str, Any]]:
    """Compare normalized baseline/candidate object maps of one scenario.

    Emits selector-graph regressions, reference-transition findings, label
    drift, protected-contract violations, and removal-policy findings.
    Pure: neither input map is mutated and no files or network are touched.
    """
    del catalogue  # finding metadata comes from the mirrored _RULES table; kept for interface parity
    baseline_objects = _objects_of(baseline)
    candidate_objects = _objects_of(candidate)
    scenario_id = _scenario_id(scenario)
    findings: list[dict[str, Any]] = []

    _compare_removals(findings, scenario, baseline_objects, candidate_objects)
    responsible = _compare_selector_graph(findings, scenario_id, baseline_objects, candidate_objects)
    _compare_references(findings, scenario_id, baseline_objects, candidate_objects)
    _compare_target_ports(findings, scenario_id, baseline_objects, candidate_objects)
    protected_pairs = _compare_protected_labels(findings, scenario, baseline_objects, candidate_objects)
    _compare_label_drift(findings, scenario_id, baseline_objects, candidate_objects,
                         responsible, protected_pairs)
    return _sort_findings(findings)


def validate_candidate(candidate: dict[str, Any], scenario: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate one candidate object map without any baseline.

    Emits non-waivable render-validation findings: workload
    selector/template self-consistency (for resources new to all baselines
    as much as pre-existing ones) and required references that resolve to a
    declared local object whose requested key or port is missing. Required
    references that cannot be resolved inside the render warn as
    unverified, because absence alone cannot prove cluster absence.
    """
    candidate_objects = _objects_of(candidate)
    scenario_id = _scenario_id(scenario)
    findings: list[dict[str, Any]] = []

    _validate_selector_templates(findings, scenario_id, candidate_objects)
    _validate_references(findings, scenario_id, candidate_objects)
    _validate_target_ports(findings, scenario_id, candidate_objects)
    _validate_graph_scope(findings, scenario_id, candidate_objects)
    return _sort_findings(findings)


# ---------------------------------------------------------------------------
# Removals and protected resources
# ---------------------------------------------------------------------------


def _compare_removals(findings: list[dict[str, Any]], scenario: dict[str, Any],
                      baseline: dict[ObjectKey, dict[str, Any]],
                      candidate: dict[ObjectKey, dict[str, Any]]) -> None:
    scenario_id = _scenario_id(scenario)
    protected: set[ObjectKey] = set()
    for entry in scenario.get("protectedResources") or []:
        if isinstance(entry, dict):
            protected.add(_identity_tuple(entry))
    for key in baseline:
        if key in candidate:
            continue
        if key in protected:
            findings.append(_finding(
                "protected-resource-removed", scenario_id, key, "",
                f"protected {_where(key)} was removed from the candidate render, "
                "violating the declared protected contract",
            ))
        else:
            findings.append(_finding(
                "resource-removed", scenario_id, key, "",
                f"{_where(key)} from the baseline render is absent from the candidate render; "
                "external consumers may still depend on it",
            ))


# ---------------------------------------------------------------------------
# Selector target graph
# ---------------------------------------------------------------------------


def _compare_selector_graph(
        findings: list[dict[str, Any]], scenario_id: str,
        baseline: dict[ObjectKey, dict[str, Any]],
        candidate: dict[ObjectKey, dict[str, Any]]) -> set[tuple[ObjectKey, str, str]]:
    """Emit selector-graph findings; return label keys with stronger evidence.

    The returned set holds (target identity, labels pointer, label key)
    triples whose change already produced a selector-target-lost error, so
    label-drift warnings are not duplicated for them (label drift warns
    only "with no stronger evidence").
    """
    responsible: set[tuple[ObjectKey, str, str]] = set()
    baseline_targets = _graph_targets(baseline)
    candidate_targets = _graph_targets(candidate)
    for key in baseline:
        if key not in candidate or (key[0], key[1]) not in _CONSUMER_SELECTOR_PATHS:
            continue
        group, kind, namespace, _ = key
        selector_path = _CONSUMER_SELECTOR_PATHS[(group, kind)]
        mode_b, form_b = _consumer_selection(key, baseline[key]["document"])
        mode_c, form_c = _consumer_selection(key, candidate[key]["document"])
        if (mode_b, form_b) != (mode_c, form_c):
            findings.append(_finding(
                "mutable-selector-changed", scenario_id, key, selector_path,
                f"{_where(key)} changed its selector at {selector_path}; it now selects a "
                "different set of objects, and consumers outside this render cannot be "
                "certified by the candidate targets alone",
                relation="selects",
            ))
            continue
        if mode_b == "none":
            continue
        selected_b = _selected_targets(baseline_targets, namespace, mode_b, form_b)
        for target_key, (labels_b, target_path) in selected_b.items():
            if target_key not in candidate:
                findings.append(_selector_target_lost(
                    scenario_id, key, selector_path, target_key, target_path,
                    "the target disappeared from the candidate render"))
                continue
            labels_c = candidate_targets.get(target_key, ({}, target_path))[0]
            if mode_b == "all" or (form_b is not None and _form_matches(form_b, labels_c)):
                continue
            findings.append(_selector_target_lost(
                scenario_id, key, selector_path, target_key, target_path,
                "the target template labels changed"))
            if form_b is not None:
                for label_key in _referenced_keys(form_b):
                    if labels_b.get(label_key) != labels_c.get(label_key):
                        responsible.add((target_key, target_path, label_key))
    return responsible


def _selector_target_lost(scenario_id: str, consumer: ObjectKey, selector_path: str,
                          target: ObjectKey, target_path: str, cause: str) -> dict[str, Any]:
    edge = _edge_id("selects", consumer, selector_path, target, target_path)
    return _finding(
        "selector-target-lost", scenario_id, consumer, selector_path,
        f"{_where(consumer)} no longer selects {_where(target)} through its unchanged "
        f"selector because {cause}; this reports the loss of a declared selection "
        "relationship, not a live endpoint or running-Pod state",
        relation="selects", related=target, related_path=target_path,
        edge_id=edge, path_origin="baseline",
    )


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------


def _compare_references(findings: list[dict[str, Any]], scenario_id: str,
                        baseline: dict[ObjectKey, dict[str, Any]],
                        candidate: dict[ObjectKey, dict[str, Any]]) -> None:
    for key in baseline:
        if key not in candidate or (key[0], key[1]) not in _REFERENCE_CONSUMER_KINDS:
            continue
        slots_b = _reference_slots(key, baseline[key]["document"])
        slots_c = _reference_slots(key, candidate[key]["document"])
        by_slot_c: dict[tuple[Any, ...], dict[str, Any]] = {}
        for slot in slots_c:
            by_slot_c.setdefault(slot["slot"], slot)
        slot_keys_b = {slot["slot"] for slot in slots_b}
        for slot_b in slots_b:
            slot_c = by_slot_c.get(slot_b["slot"])
            if slot_c is None:
                continue  # the slot was removed or became non-reference data: ended reliance
            _compare_reference_slot(findings, scenario_id, key, slot_b, slot_c,
                                    baseline, candidate)
        for slot_c in slots_c:
            if slot_c["slot"] in slot_keys_b or slot_c["optional"]:
                continue
            status, _ = _slot_status(candidate, slot_c)
            if status == "missing-object":
                _external_unverified(findings, scenario_id, key, slot_c,
                                     path_origin="candidate")


def _compare_reference_slot(findings: list[dict[str, Any]], scenario_id: str,
                            consumer: ObjectKey, slot_b: dict[str, Any], slot_c: dict[str, Any],
                            baseline: dict[ObjectKey, dict[str, Any]],
                            candidate: dict[ObjectKey, dict[str, Any]]) -> None:
    if slot_c["optional"]:
        return  # candidate optionality governs: no dependency finding for absence
    status_c, missing_c = _slot_status(candidate, slot_c)
    if status_c == "resolved":
        return
    retargeted = slot_c["target"] != slot_b["target"]
    if retargeted:
        if status_c == "missing-object":
            _external_unverified(findings, scenario_id, consumer, slot_b, path_origin="baseline")
        # a retarget onto a local object lacking the requested key is a
        # candidate validation defect, not a comparison regression
        return
    status_b, _ = _slot_status(baseline, slot_b)
    baseline_local = status_b == "resolved"
    if status_c == "missing-object":
        if baseline_local:
            _reference_lost(findings, scenario_id, consumer, slot_b, slot_c,
                            missing=(), candidate_edge=False)
        else:
            _external_unverified(findings, scenario_id, consumer, slot_b, path_origin="baseline")
        return
    # missing-key with the target object still declared locally
    if not baseline_local:
        return  # already broken or external in the baseline; candidate validation owns it
    _reference_lost(findings, scenario_id, consumer, slot_b, slot_c,
                    missing=missing_c, candidate_edge=True)


def _reference_lost(findings: list[dict[str, Any]], scenario_id: str, consumer: ObjectKey,
                    slot_b: dict[str, Any], slot_c: dict[str, Any], *,
                    missing: tuple[str, ...], candidate_edge: bool) -> None:
    relation = slot_b["relation"]
    target = slot_b["target"]
    consumer_path = slot_b["consumer_path"]
    if missing:
        for key_name in missing:
            if key_name == "port":
                target_path = "/spec/ports"
                detail = "its requested service port"
            else:
                target_path = _key_target_path(key_name)
                detail = f"key {key_name!r}"
            finding = _finding(
                "required-reference-lost", scenario_id, consumer, consumer_path,
                f"{_where(consumer)} requires {_where(target)} ({detail}), which resolved "
                "locally in the baseline render but is no longer provided by the candidate "
                "render; this is a declared dependency loss, not a measured live outage",
                relation=relation, related=target, related_path=target_path,
                edge_id=_edge_id(relation, consumer, consumer_path, target, target_path),
                path_origin="baseline",
            )
            if candidate_edge:
                finding["candidate_edge_id"] = _edge_id(
                    relation, consumer, slot_c["consumer_path"], slot_c["target"], target_path)
            findings.append(finding)
    else:
        findings.append(_finding(
            "required-reference-lost", scenario_id, consumer, consumer_path,
            f"{_where(consumer)} requires {_where(target)}, which resolved locally in the "
            "baseline render but was removed from the candidate render; this is a declared "
            "dependency loss, not a measured live outage",
            relation=relation, related=target, related_path="",
            edge_id=_edge_id(relation, consumer, consumer_path, target, ""),
            path_origin="baseline",
        ))


def _external_unverified(findings: list[dict[str, Any]], scenario_id: str,
                         consumer: ObjectKey, slot: dict[str, Any], *,
                         path_origin: str) -> None:
    relation = slot["relation"]
    target = slot["target"]
    consumer_path = slot["consumer_path"]
    findings.append(_finding(
        "external-reference-unverified", scenario_id, consumer, consumer_path,
        f"{_where(consumer)} declares a required reference to {_where(target)} that is not "
        "part of this render; it may be provided by another bundle, so its absence alone is "
        "not proof of breakage",
        relation=relation, related=target, related_path="",
        edge_id=_edge_id(relation, consumer, consumer_path, target, ""),
        path_origin=path_origin,
    ))


# ---------------------------------------------------------------------------
# Service named targetPort graph
# ---------------------------------------------------------------------------


def _target_port_providers(objects: dict[ObjectKey, dict[str, Any]],
                           selected: dict[ObjectKey, tuple[dict[str, Any], str]],
                           port_name: str, protocol: str) -> list[ObjectKey]:
    return [
        key for key in selected
        if _exposes_port(objects[key], (key[0], key[1]), port_name, protocol)
    ]


def _compare_target_ports(findings: list[dict[str, Any]], scenario_id: str,
                          baseline: dict[ObjectKey, dict[str, Any]],
                          candidate: dict[ObjectKey, dict[str, Any]]) -> None:
    baseline_targets = _graph_targets(baseline)
    candidate_targets = _graph_targets(candidate)
    for key in baseline:
        if key not in candidate or (key[0], key[1]) != ("", "Service"):
            continue
        namespace = key[2]
        mode_b, form_b = _consumer_selection(key, baseline[key]["document"])
        mode_c, form_c = _consumer_selection(key, candidate[key]["document"])
        if (mode_b, form_b) != (mode_c, form_c):
            continue  # selector re-targeted; the selector graph already warned
        if mode_b != "match" or form_b is None:
            continue
        selected_b = _selected_targets(baseline_targets, namespace, mode_b, form_b)
        selected_c = _selected_targets(candidate_targets, namespace, mode_c, form_c)
        ports_b = _service_port_slots(baseline[key]["document"])
        ports_c = {slot["slot"]: slot for slot in _service_port_slots(candidate[key]["document"])}
        for slot_b in ports_b:
            port_name = slot_b["target_port"]
            if not isinstance(port_name, str):
                continue  # numeric targetPort: no named-port reliance
            slot_c = ports_c.get(slot_b["slot"])
            if slot_c is None or slot_c["target_port"] != port_name:
                continue  # the named-port request ended or was re-declared
            providers = _target_port_providers(
                baseline, selected_b, port_name, slot_b["protocol"])
            for provider in providers:
                if provider not in candidate or provider not in selected_c:
                    # removal and deselection are reported by the selector graph
                    continue
                if _exposes_port(candidate[provider], (provider[0], provider[1]),
                                 port_name, slot_c["protocol"]):
                    continue
                relation = "service-target-port"
                target_path = _provider_ports_path(provider)
                finding = _finding(
                    "required-reference-lost", scenario_id, key, slot_b["consumer_path"],
                    f"{_where(key)} requires named targetPort {port_name!r} from "
                    f"{_where(provider)}, which the baseline template exposed but the "
                    "candidate template no longer exposes on any selected container; this is "
                    "a declared port loss, not a measured traffic state",
                    relation=relation, related=provider, related_path=target_path,
                    edge_id=_edge_id(relation, key, slot_b["consumer_path"], provider, target_path),
                    path_origin="baseline",
                )
                finding["candidate_edge_id"] = _edge_id(
                    relation, key, slot_c["consumer_path"], provider, target_path)
                findings.append(finding)


# ---------------------------------------------------------------------------
# Protected labels and label drift
# ---------------------------------------------------------------------------


def _protected_label_entries(scenario: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    entries: list[tuple[str, tuple[str, ...]]] = []
    for entry in scenario.get("protectedLabels") or []:
        if not isinstance(entry, dict):
            continue
        location = entry.get("location")
        keys = entry.get("keys")
        if not isinstance(location, str) or not location or not isinstance(keys, list):
            continue
        entries.append((location, tuple(str(key) for key in keys)))
    return entries


def _compare_protected_labels(findings: list[dict[str, Any]], scenario: dict[str, Any],
                              baseline: dict[ObjectKey, dict[str, Any]],
                              candidate: dict[ObjectKey, dict[str, Any]]) -> set[tuple[ObjectKey, str, str]]:
    """Enforce declared protected label contracts on preserved baseline pairs.

    Returns the (identity, location, key) triples that had a baseline pair,
    so generic label drift does not double-report them.
    """
    scenario_id = _scenario_id(scenario)
    protected_pairs: set[tuple[ObjectKey, str, str]] = set()
    entries = _protected_label_entries(scenario)
    if not entries:
        return protected_pairs
    for key in baseline:
        if key not in candidate:
            continue  # removal policy owns removed objects
        baseline_document = baseline[key]["document"]
        candidate_document = candidate[key]["document"]
        for location, keys in entries:
            baseline_labels = _pointer_get(baseline_document, location)
            if not isinstance(baseline_labels, dict):
                continue
            for label_key in keys:
                baseline_value = baseline_labels.get(label_key)
                if not isinstance(baseline_value, str):
                    continue  # no baseline pair to preserve
                protected_pairs.add((key, location, label_key))
                candidate_labels = _pointer_get(candidate_document, location)
                lost = (
                    not isinstance(candidate_labels, dict)
                    or label_key not in candidate_labels
                    or candidate_labels[label_key] != baseline_value
                )
                if lost:
                    findings.append(_finding(
                        "protected-label-changed", scenario_id, key,
                        f"{location}/{_escape_token(label_key)}",
                        f"{_where(key)} removed or changed protected label {label_key!r} at "
                        f"{location}, violating the declared protected contract",
                    ))
    return protected_pairs


def _compare_label_drift(findings: list[dict[str, Any]], scenario_id: str,
                         baseline: dict[ObjectKey, dict[str, Any]],
                         candidate: dict[ObjectKey, dict[str, Any]],
                         responsible: set[tuple[ObjectKey, str, str]],
                         protected_pairs: set[tuple[ObjectKey, str, str]]) -> None:
    """Warn on baseline label removals and value changes with no stronger evidence.

    Label additions never produce a generic finding; they surface only
    through a supported graph or contract regression. Keys already covered
    by a stronger finding (a proven selector loss or a protected-contract
    error) are not re-reported as drift warnings.
    """
    for key in baseline:
        if key not in candidate:
            continue
        group, kind = key[0], key[1]
        baseline_document = baseline[key]["document"]
        candidate_document = candidate[key]["document"]
        label_locations: list[str] = ["/metadata/labels"]
        if (group, kind) in _TEMPLATE_LABEL_PATHS:
            label_locations.append(_TEMPLATE_LABEL_PATHS[(group, kind)])
        for location in label_locations:
            labels_b = _pointer_get(baseline_document, location)
            labels_c = _pointer_get(candidate_document, location)
            if not isinstance(labels_b, dict):
                continue
            labels_c = labels_c if isinstance(labels_c, dict) else {}
            for label_key, baseline_value in labels_b.items():
                if not isinstance(label_key, str) or not isinstance(baseline_value, str):
                    continue
                if (key, location, label_key) in protected_pairs:
                    continue
                if (key, location, label_key) in responsible:
                    continue  # the selector graph proved this exact change
                pointer = f"{location}/{_escape_token(label_key)}"
                if label_key not in labels_c:
                    findings.append(_finding(
                        "label-removed", scenario_id, key, pointer,
                        f"{_where(key)} no longer declares the baseline label {label_key!r} "
                        f"at {location}; external consumers may discover objects by this label",
                    ))
                elif labels_c[label_key] != baseline_value:
                    findings.append(_finding(
                        "label-value-changed", scenario_id, key, pointer,
                        f"{_where(key)} changed the value of baseline label {label_key!r} at "
                        f"{location}; external consumers may match on the baseline value, and "
                        "negative selector expressions are sensitive to value edits",
                    ))


# ---------------------------------------------------------------------------
# Candidate validation
# ---------------------------------------------------------------------------


def _validate_selector_templates(findings: list[dict[str, Any]], scenario_id: str,
                                 candidate: dict[ObjectKey, dict[str, Any]]) -> None:
    for key, record in candidate.items():
        group, kind = key[0], key[1]
        if (group, kind) not in _SELECTOR_VALIDATED_KINDS:
            continue
        document = record["document"]
        spec = document.get("spec")
        selector = spec.get("selector") if isinstance(spec, dict) else None
        form = _selector_form(selector)
        if form is None:
            if (group, kind) == ("batch", "Job"):
                continue  # missing/generated Job selectors are never fabricated
            findings.append(_selector_template_mismatch(
                scenario_id, key,
                "its selector is absent or empty, which the API rejects for this workload"))
            continue
        template_pointer = _TEMPLATE_LABEL_PATHS[(group, kind)]
        labels = _pointer_get(document, template_pointer)
        labels = labels if isinstance(labels, dict) else {}
        if not _form_matches(form, labels):
            findings.append(_selector_template_mismatch(
                scenario_id, key,
                "its selector does not match its own pod template labels"))


def _selector_template_mismatch(scenario_id: str, key: ObjectKey,
                                cause: str) -> dict[str, Any]:
    template_pointer = _TEMPLATE_LABEL_PATHS[(key[0], key[1])]
    return _finding(
        "selector-template-mismatch", scenario_id, key, "/spec/selector",
        f"{_where(key)} is logically invalid: {cause}; the rendered declaration cannot roll "
        "out and this defect cannot be waived as a compatibility exception",
        relation="selects-template", related=key, related_path=template_pointer,
        edge_id=_edge_id("selects-template", key, "/spec/selector", key, template_pointer),
        path_origin="candidate",
        baseline_associations=[],
    )


def _validate_references(findings: list[dict[str, Any]], scenario_id: str,
                         candidate: dict[ObjectKey, dict[str, Any]]) -> None:
    for key, record in candidate.items():
        if (key[0], key[1]) not in _REFERENCE_CONSUMER_KINDS:
            continue
        for slot in _reference_slots(key, record["document"]):
            if slot["optional"]:
                continue
            status, missing = _slot_status(candidate, slot)
            relation = slot["relation"]
            target = slot["target"]
            if status == "missing-object":
                findings.append(_finding(
                    "external-reference-unverified", scenario_id, key, slot["consumer_path"],
                    f"{_where(key)} declares a required reference to {_where(target)} that is "
                    "not part of this render; it may be provided by another bundle, so its "
                    "absence alone is not proof of breakage",
                    relation=relation, related=target, related_path="",
                    edge_id=_edge_id(relation, key, slot["consumer_path"], target, ""),
                    path_origin="candidate", baseline_associations=[],
                ))
            elif status == "missing-key":
                for key_name in missing:
                    if key_name == "port":
                        target_path = "/spec/ports"
                        detail = "its requested service port"
                    else:
                        target_path = _key_target_path(key_name)
                        detail = f"key {key_name!r}"
                    findings.append(_finding(
                        "required-reference-lost", scenario_id, key, slot["consumer_path"],
                        f"{_where(key)} requires {_where(target)} ({detail}); the object is "
                        "declared locally but does not provide the requested key or port; "
                        "this is a declared declaration defect, not a proven live outage",
                        relation=relation, related=target, related_path=target_path,
                        edge_id=_edge_id(
                            relation, key, slot["consumer_path"], target, target_path),
                        path_origin="candidate", baseline_associations=[],
                    ))


def _validate_target_ports(findings: list[dict[str, Any]], scenario_id: str,
                           candidate: dict[ObjectKey, dict[str, Any]]) -> None:
    targets = _graph_targets(candidate)
    for key, record in candidate.items():
        if (key[0], key[1]) != ("", "Service"):
            continue
        mode, form = _consumer_selection(key, record["document"])
        if mode != "match" or form is None:
            continue
        selected = _selected_targets(targets, key[2], mode, form)
        if not selected:
            continue  # nothing selected: no local object to anchor a port claim on
        for slot in _service_port_slots(record["document"]):
            port_name = slot["target_port"]
            if not isinstance(port_name, str):
                continue
            providers = _target_port_providers(
                candidate, selected, port_name, slot["protocol"])
            if providers:
                continue
            provider = sorted(selected)[0]
            relation = "service-target-port"
            target_path = _provider_ports_path(provider)
            findings.append(_finding(
                "required-reference-lost", scenario_id, key, slot["consumer_path"],
                f"{_where(key)} requires named targetPort {port_name!r}, but none of the "
                f"targets selected by its selector, including {_where(provider)}, exposes a "
                "container port with that name and protocol; this is a declared port defect, "
                "not a measured traffic state",
                relation=relation, related=provider, related_path=target_path,
                edge_id=_edge_id(relation, key, slot["consumer_path"], provider, target_path),
                path_origin="candidate", baseline_associations=[],
            ))


def _validate_graph_scope(findings: list[dict[str, Any]], scenario_id: str,
                          candidate: dict[ObjectKey, dict[str, Any]]) -> None:
    """Report selector surfaces this check does not evaluate.

    NetworkPolicy peers, cross-namespace namespaceSelectors, affinity and
    topology selectors, and custom (e.g. ServiceMonitor-style) selectors
    are explicit follow-ons: their scope stays visible as partial coverage
    without any claim about a broken or healthy cluster.
    """

    def peer_selectors_present(rules: Any) -> bool:
        if not isinstance(rules, list):
            return False
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            for direction in ("from", "to"):
                peers = rule.get(direction)
                if not isinstance(peers, list):
                    continue
                for peer in peers:
                    if isinstance(peer, dict) and (
                            "podSelector" in peer or "namespaceSelector" in peer):
                        return True
        return False

    for key, record in candidate.items():
        group, kind = key[0], key[1]
        document = record["document"]
        if (group, kind) == ("networking.k8s.io", "NetworkPolicy"):
            spec = document.get("spec")
            if not isinstance(spec, dict):
                continue
            for direction in ("ingress", "egress"):
                if peer_selectors_present(spec.get(direction)):
                    findings.append(_finding(
                        "rule-coverage-partial", scenario_id, key, f"/spec/{direction}",
                        f"{_where(key)} declares {direction} peer pod/namespace selectors at "
                        f"/spec/{direction} that this check does not evaluate; no claim is "
                        "made about their traffic relationships",
                    ))
            continue
        pod_spec_path = _POD_SPEC_PATHS.get((group, kind))
        if pod_spec_path is None:
            continue
        pod_spec = _pointer_get(document, pod_spec_path)
        if not isinstance(pod_spec, dict):
            continue
        affinity = pod_spec.get("affinity")
        if isinstance(affinity, dict) and (
                "podAffinity" in affinity or "podAntiAffinity" in affinity):
            findings.append(_finding(
                "rule-coverage-partial", scenario_id, key, f"{pod_spec_path}/affinity",
                f"{_where(key)} declares pod affinity/anti-affinity selectors at "
                f"{pod_spec_path}/affinity that this check does not evaluate; no claim is "
                "made about their scheduling relationships",
            ))
        if isinstance(pod_spec.get("topologySpreadConstraints"), list):
            findings.append(_finding(
                "rule-coverage-partial", scenario_id, key,
                f"{pod_spec_path}/topologySpreadConstraints",
                f"{_where(key)} declares topology spread selectors at "
                f"{pod_spec_path}/topologySpreadConstraints that this check does not evaluate; "
                "no claim is made about their scheduling relationships",
            ))
