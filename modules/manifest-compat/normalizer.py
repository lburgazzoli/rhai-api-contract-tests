"""Normalization of rendered Kubernetes manifests into comparable object maps.

Consumes rendered bytes from any renderer (raw YAML, Helm, Kustomize) plus the
scenario configuration, and produces the normalized representation consumed by
the policy modules: an object map keyed by (group, kind, namespace, name),
skip records for Helm hooks and CRDs, and structural coverage metadata.

Only source-verified, unconditional defaults and canonicalizations are applied
here; anything depending on live state, feature gates, or uncertain defaulting
is deliberately left for the policy modules to report as conditional risks.
Documents are compared without their status, server-assigned metadata, and
last-applied annotation. Secret contents are canonicalized in place but never
appear in error messages.
"""

from __future__ import annotations

import base64
import binascii
import importlib.util
import re
import sys
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

_MAX_LIST_DEPTH = 16
_LAST_APPLIED_ANNOTATION = "kubectl.kubernetes.io/last-applied-configuration"
_HELM_HOOK_ANNOTATION = "helm.sh/hook"
_STRIPPED_METADATA = (
    "uid", "resourceVersion", "creationTimestamp", "managedFields",
    "generation", "deletionTimestamp", "deletionGracePeriodSeconds",
)

_QUANTITY_RE = re.compile(r"([+-]?[0-9]*\.?[0-9]+(?:[eE][+-]?[0-9]+)?)([A-Za-z]*)")
_QUANTITY_BINARY: dict[str, int] = {
    "Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3, "Ti": 1024 ** 4, "Pi": 1024 ** 5, "Ei": 1024 ** 6,
}
_QUANTITY_DECIMAL: dict[str, Fraction] = {
    "n": Fraction(1, 10 ** 9), "u": Fraction(1, 10 ** 6), "m": Fraction(1, 10 ** 3), "": Fraction(1),
    "k": Fraction(10 ** 3), "M": Fraction(10 ** 6), "G": Fraction(10 ** 9),
    "T": Fraction(10 ** 12), "P": Fraction(10 ** 15), "E": Fraction(10 ** 18),
}
_SELECTOR_OPERATORS = ("In", "NotIn", "Exists", "DoesNotExist")

ObjectKey = tuple[str, str, str, str]


class NormalizeError(Exception):
    """Rendered content could not be normalized reliably."""


def _load_config_module() -> ModuleType:
    name = "manifest_compat_config"
    module = sys.modules.get(name)
    if module is not None:
        return module
    path = Path(__file__).resolve().parent / "config.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load sibling module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_config: Any = _load_config_module()
BUILTIN_SCOPES: dict[tuple[str, str], str] = _config.BUILTIN_SCOPES
StrictSafeLoader: Any = _config.StrictSafeLoader
DNS_LABEL_PATTERN: re.Pattern[str] = _config.DNS_LABEL_PATTERN


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _flatten_documents(content: bytes, source: str) -> list[dict[str, Any]]:
    """Parse multi-document YAML, expanding kind: List wrappers recursively."""
    try:
        documents = list(yaml.load_all(content, Loader=StrictSafeLoader))
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        line = getattr(mark, "line", None)
        where = f" (line {line + 1})" if isinstance(line, int) else ""
        raise NormalizeError(f"Cannot parse YAML {source}: {type(error).__name__}{where}") from error

    flattened: list[dict[str, Any]] = []

    def walk(document: Any, depth: int) -> None:
        if document is None:
            return
        if not isinstance(document, dict):
            raise NormalizeError(f"{source} contains a non-object YAML document")
        if document.get("kind") == "List":
            if depth >= _MAX_LIST_DEPTH:
                raise NormalizeError(f"{source}: List nesting exceeds {_MAX_LIST_DEPTH} levels")
            items = document.get("items")
            if not isinstance(items, list):
                raise NormalizeError(f"{source}: List document has malformed items")
            for item in items:
                walk(item, depth + 1)
            return
        flattened.append(document)

    for document in documents:
        walk(document, 0)
    return flattened


def _check_scalars(value: Any, where: str) -> None:
    """Reject YAML scalars with no JSON-compatible representation."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise NormalizeError(f"{where}: unsupported non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_scalars(item, f"{where}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _check_scalars(item, f"{where}.{key}")
        return
    raise NormalizeError(f"{where}: unsupported YAML scalar type {type(value).__name__}")


def canonical_quantity(value: Any, where: str) -> str:
    """Parse a Kubernetes quantity into a canonical exact numeric string.

    Binary and decimal SI suffixes and exponents are handled exactly through
    Fraction; "1Gi" and "1073741824" canonicalize identically so later map
    comparisons are numeric, never lexical.
    """
    if isinstance(value, bool):
        raise NormalizeError(f"{where}: quantity must be a number or string, not a boolean")
    if isinstance(value, int):
        number = Fraction(value)
        suffix = ""
    elif isinstance(value, (str, float)):
        match = _QUANTITY_RE.fullmatch(str(value))
        if match is None:
            raise NormalizeError(f"{where}: cannot parse quantity {value!r}")
        try:
            number = Fraction(Decimal(match.group(1)))
        except (InvalidOperation, ValueError) as error:
            raise NormalizeError(f"{where}: cannot parse quantity {value!r}") from error
        suffix = match.group(2)
    else:
        raise NormalizeError(f"{where}: quantity must be a number or string")
    if suffix in _QUANTITY_BINARY:
        total = number * _QUANTITY_BINARY[suffix]
    elif suffix in _QUANTITY_DECIMAL:
        total = number * _QUANTITY_DECIMAL[suffix]
    else:
        raise NormalizeError(f"{where}: unknown quantity suffix {suffix!r}")
    if total.denominator == 1:
        return str(total.numerator)
    return f"{total.numerator}/{total.denominator}"


def _validate_labels(labels: Any, where: str) -> None:
    if not isinstance(labels, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in labels.items()
    ):
        raise NormalizeError(f"{where} must be a mapping of string keys to string values")


def _validate_selector(selector: Any, where: str) -> None:
    if selector is None:
        return
    if not isinstance(selector, dict):
        raise NormalizeError(f"{where} must be a mapping")
    if "matchLabels" in selector or "matchExpressions" in selector:
        if selector.get("matchLabels") is not None:
            _validate_labels(selector["matchLabels"], f"{where}.matchLabels")
        expressions = selector.get("matchExpressions")
        if expressions is not None:
            if not isinstance(expressions, list):
                raise NormalizeError(f"{where}.matchExpressions must be a list")
            for index, expression in enumerate(expressions):
                expression_where = f"{where}.matchExpressions[{index}]"
                if not isinstance(expression, dict):
                    raise NormalizeError(f"{expression_where} must be a mapping")
                if not _nonempty_str(expression.get("key")):
                    raise NormalizeError(f"{expression_where}.key must be a nonempty string")
                operator = expression.get("operator")
                if operator not in _SELECTOR_OPERATORS:
                    raise NormalizeError(
                        f"{expression_where}.operator must be one of {', '.join(_SELECTOR_OPERATORS)}"
                    )
                if operator in ("In", "NotIn"):
                    values = expression.get("values")
                    if not isinstance(values, list) or not all(
                        isinstance(item, str) for item in values
                    ):
                        raise NormalizeError(f"{expression_where}.values must be a list of strings")
    else:
        _validate_labels(selector, where)


def _collect_crd_scopes(documents: list[dict[str, Any]], source: str) -> dict[tuple[str, str], str]:
    scopes: dict[tuple[str, str], str] = {}
    for document in documents:
        if document.get("kind") != "CustomResourceDefinition":
            continue
        spec = document.get("spec") or {}
        names = spec.get("names") or {}
        group, kind, scope = spec.get("group"), names.get("kind"), spec.get("scope")
        if (
            not isinstance(group, str) or not group
            or not isinstance(kind, str) or not kind
            or scope not in ("Namespaced", "Cluster")
        ):
            raise NormalizeError(
                f"{source}: CustomResourceDefinition is missing spec.group, spec.names.kind, "
                "or a valid spec.scope"
            )
        key = (group, kind)
        if key in BUILTIN_SCOPES and BUILTIN_SCOPES[key] != scope:
            raise NormalizeError(
                f"{source}: CustomResourceDefinition for {group}/{kind} declares scope {scope!r} "
                f"but the built-in scope is {BUILTIN_SCOPES[key]!r}"
            )
        previous = scopes.get(key)
        if previous is not None and previous != scope:
            raise NormalizeError(
                f"{source}: conflicting CustomResourceDefinitions declare {group}/{kind} as both "
                f"{previous!r} and {scope!r}"
            )
        scopes[key] = scope
    return scopes


def _merged_scopes(scenario: dict[str, Any], crd_scopes: dict[tuple[str, str], str]) -> dict[tuple[str, str], str]:
    merged = dict(BUILTIN_SCOPES)
    merged.update(crd_scopes)
    scenario_id = scenario.get("id", "<unnamed>")
    for entry in scenario.get("kindScopes") or []:
        key = (entry["group"], entry["kind"])
        previous = merged.get(key)
        if previous is not None and previous != entry["scope"]:
            raise NormalizeError(
                f"scenario {scenario_id!r}: kindScopes declares {key[1]!r} as {entry['scope']!r} "
                f"but another declaration or rendered CRD says {previous!r}"
            )
        merged[key] = entry["scope"]
    return merged


def _identity_of(document: dict[str, Any], source: str, index: int,
                 scenario: dict[str, Any], scopes: dict[tuple[str, str], str]) -> ObjectKey:
    api_version = document.get("apiVersion")
    kind = document.get("kind")
    if not isinstance(api_version, str) or not api_version or not isinstance(kind, str) or not kind:
        raise NormalizeError(f"{source} document {index}: missing apiVersion or kind")
    if api_version.count("/") > 1:
        raise NormalizeError(f"{source} document {index}: invalid apiVersion {api_version!r}")
    group = api_version.split("/", 1)[0] if "/" in api_version else ""
    metadata = document.get("metadata")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise NormalizeError(f"{source} document {index}: metadata must be a mapping")
    name = metadata.get("name")
    if not isinstance(name, str) or not name:
        if isinstance(metadata.get("generateName"), str) and metadata["generateName"]:
            raise NormalizeError(
                f"{source} document {index}: {kind} declares only metadata.generateName; "
                "stable comparison requires metadata.name"
            )
        raise NormalizeError(f"{source} document {index}: {kind} is missing metadata.name")
    explicit_namespace = metadata.get("namespace")
    if explicit_namespace is not None:
        if not isinstance(explicit_namespace, str) or DNS_LABEL_PATTERN.fullmatch(explicit_namespace) is None:
            raise NormalizeError(f"{source} document {index}: invalid metadata.namespace")
    scope = scopes.get((group, kind))
    if scope == "Cluster":
        if explicit_namespace is not None:
            raise NormalizeError(
                f"{source} document {index}: {kind} is cluster-scoped and must not declare metadata.namespace"
            )
        namespace = ""
    elif scope == "Namespaced":
        if explicit_namespace is not None:
            namespace = explicit_namespace
        else:
            scenario_namespace = scenario.get("namespace")
            if not isinstance(scenario_namespace, str) or not scenario_namespace:
                raise NormalizeError(
                    f"{source} document {index}: scenario has no namespace for namespaced kind {kind}"
                )
            namespace = scenario_namespace
    elif explicit_namespace is not None:
        namespace = explicit_namespace
    else:
        raise NormalizeError(
            f"{source} document {index}: cannot determine whether {kind} is namespaced; "
            "declare it in scenario kindScopes or include its CustomResourceDefinition"
        )
    return group, kind, namespace, name


def _identity_dict(identity: ObjectKey) -> dict[str, str]:
    group, kind, namespace, name = identity
    return {"group": group, "kind": kind, "namespace": namespace, "name": name}


def _canonicalize_storage(spec: dict[str, Any], where: str) -> None:
    resources = spec.get("resources")
    if not isinstance(resources, dict):
        return
    requests = resources.get("requests")
    if not isinstance(requests, dict) or requests.get("storage") is None:
        return
    requests["storage"] = canonical_quantity(requests["storage"], f"{where} resources.requests.storage")


def _normalize_secret(document: dict[str, Any], where: str) -> None:
    data = document.get("data") or {}
    string_data = document.get("stringData") or {}
    if not isinstance(data, dict) or not isinstance(string_data, dict):
        raise NormalizeError(f"{where}: Secret data and stringData must be mappings")
    effective: dict[str, bytes] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise NormalizeError(f"{where}: Secret data entries must have string keys and values")
        try:
            effective[key] = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as error:
            raise NormalizeError(f"{where}: Secret data key {key!r} is not valid base64") from error
    for key, value in string_data.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise NormalizeError(f"{where}: Secret stringData entries must have string keys and values")
        effective[key] = value.encode("utf-8")
    document["data"] = {
        key: base64.b64encode(effective[key]).decode("ascii") for key in sorted(effective)
    }
    document.pop("stringData", None)


def _normalize_configmap(document: dict[str, Any], where: str) -> None:
    binary = document.get("binaryData")
    if binary is None:
        return
    if not isinstance(binary, dict):
        raise NormalizeError(f"{where}: ConfigMap binaryData must be a mapping")
    canonical: dict[str, str] = {}
    for key, value in binary.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise NormalizeError(f"{where}: ConfigMap binaryData entries must have string keys and values")
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as error:
            raise NormalizeError(f"{where}: ConfigMap binaryData key {key!r} is not valid base64") from error
        canonical[key] = base64.b64encode(raw).decode("ascii")
    document["binaryData"] = {key: canonical[key] for key in sorted(canonical)}


def _apply_defaults(document: dict[str, Any], group: str, kind: str, where: str) -> None:
    """Apply unconditional, source-verified defaults needed by policy rules.

    Only defaults the API server always applies are set here; conditional
    defaulting (Job completions/parallelism, anything gate- or status-dependent)
    stays with the policy modules so omissions are never fabricated.
    """
    spec = document.get("spec")
    spec = spec if isinstance(spec, dict) else None
    if (group, kind) == ("", "Secret"):
        if not _nonempty_str(document.get("type")):
            document["type"] = "Opaque"
    elif (group, kind) == ("", "PersistentVolumeClaim"):
        if spec is not None and spec.get("volumeMode") is None:
            spec["volumeMode"] = "Filesystem"
        if spec is not None:
            _canonicalize_storage(spec, where)
    elif (group, kind) == ("", "PersistentVolume"):
        if spec is not None and spec.get("volumeMode") is None:
            spec["volumeMode"] = "Filesystem"
    elif (group, kind) == ("storage.k8s.io", "StorageClass"):
        if document.get("reclaimPolicy") is None:
            document["reclaimPolicy"] = "Delete"
        if document.get("volumeBindingMode") is None:
            document["volumeBindingMode"] = "Immediate"
    elif (group, kind) == ("scheduling.k8s.io", "PriorityClass"):
        if document.get("preemptionPolicy") is None:
            document["preemptionPolicy"] = "PreemptLowerPriority"
    elif (group, kind) == ("apps", "StatefulSet"):
        if spec is not None:
            if spec.get("podManagementPolicy") is None:
                spec["podManagementPolicy"] = "OrderedReady"
            templates = spec.get("volumeClaimTemplates")
            if isinstance(templates, list):
                for template in templates:
                    if not isinstance(template, dict):
                        continue
                    template_spec = template.get("spec")
                    if isinstance(template_spec, dict):
                        if template_spec.get("volumeMode") is None:
                            template_spec["volumeMode"] = "Filesystem"
                        _canonicalize_storage(template_spec, where)
    elif (group, kind) == ("batch", "Job"):
        if spec is not None and spec.get("completionMode") is None:
            spec["completionMode"] = "NonIndexed"


def _normalize_document(document: dict[str, Any], identity: ObjectKey, source: str, index: int) -> dict[str, Any]:
    group, kind, namespace, name = identity
    where = f"{source} document {index}: {kind} {name!r}"
    document.pop("status", None)
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        for key in _STRIPPED_METADATA:
            metadata.pop(key, None)
        annotations = metadata.get("annotations")
        if isinstance(annotations, dict):
            annotations.pop(_LAST_APPLIED_ANNOTATION, None)
        if metadata.get("labels") is not None:
            _validate_labels(metadata["labels"], f"{where} metadata.labels")
    spec = document.get("spec")
    if isinstance(spec, dict):
        if spec.get("selector") is not None:
            _validate_selector(spec["selector"], f"{where} spec.selector")
        if spec.get("podSelector") is not None:
            _validate_selector(spec["podSelector"], f"{where} spec.podSelector")
        template = spec.get("template")
        if isinstance(template, dict):
            template_metadata = template.get("metadata")
            if isinstance(template_metadata, dict) and template_metadata.get("labels") is not None:
                _validate_labels(template_metadata["labels"], f"{where} spec.template.metadata.labels")
    _apply_defaults(document, group, kind, where)
    if (group, kind) == ("", "Secret"):
        _normalize_secret(document, where)
    elif (group, kind) == ("", "ConfigMap"):
        _normalize_configmap(document, where)
    elif (group, kind) == ("", "ResourceQuota"):
        if isinstance(spec, dict) and isinstance(spec.get("scopes"), list):
            spec["scopes"] = sorted(spec["scopes"])
    return document


def normalize(content: bytes, source: str, scenario: dict[str, Any]) -> dict[str, Any]:
    """Normalize rendered bytes into {objects, skipped, coverage}.

    Objects are keyed by (group, kind, namespace, name); each value carries the
    normalized document, its source, and its 1-based document index. Helm hook
    and CRD documents are skipped with recorded identities and reasons. The
    scenario mapping is never mutated.
    """
    documents = _flatten_documents(content, source)
    for document in documents:
        _check_scalars(document, source)
    crd_scopes = _collect_crd_scopes(documents, source)
    scopes = _merged_scopes(scenario, crd_scopes)

    objects: dict[ObjectKey, dict[str, Any]] = {}
    skipped: list[dict[str, Any]] = []
    kind_counts: dict[str, int] = {}
    hook_count = 0
    crd_count = 0
    for index, document in enumerate(documents, start=1):
        identity = _identity_of(document, source, index, scenario, scopes)
        kind_counts[f"{identity[0] or 'core'}/{identity[1]}"] = (
            kind_counts.get(f"{identity[0] or 'core'}/{identity[1]}", 0) + 1
        )
        if document.get("kind") == "CustomResourceDefinition":
            crd_count += 1
            skipped.append({
                "identity": _identity_dict(identity), "reason": "crd-delegated",
                "source": source, "document_index": index,
            })
            continue
        metadata = document.get("metadata")
        annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
        if isinstance(annotations, dict) and _HELM_HOOK_ANNOTATION in annotations:
            hook_count += 1
            skipped.append({
                "identity": _identity_dict(identity), "reason": "helm-hook",
                "source": source, "document_index": index,
            })
            continue
        if identity in objects:
            group, kind, namespace, name = identity
            raise NormalizeError(
                f"{source} document {index}: duplicate resource identity {kind} {name!r} "
                f"in namespace {namespace!r} (group {group!r}); rendered scenarios must not "
                "repeat an identity, even identically"
            )
        objects[identity] = {
            "document": _normalize_document(document, identity, source, index),
            "source": source,
            "document_index": index,
        }

    coverage = {
        "object_count": len(objects),
        "kind_counts": dict(sorted(kind_counts.items())),
        "skipped_counts": {"helm-hook": hook_count, "crd-delegated": crd_count},
        "custom_kinds_from_crds": sorted(f"{group}/{kind}" for group, kind in crd_scopes),
    }
    return {"objects": objects, "skipped": skipped, "coverage": coverage}
