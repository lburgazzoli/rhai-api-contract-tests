"""ManifestSet descriptor loading and validation for the manifest check.

Implements the static descriptor contract from schemas/manifest-set.schema.json
in pure runtime code (PyYAML and the standard library only; the pinned
jsonschema package is a test-only dependency used to prove that this module and
the schema agree on a shared corpus). Contextual rules that need the policy
catalogue, the repository, or the requested baselines live in validate_context
and are checked once those inputs are known.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

API_VERSION = "contracts.rhoai.io/v1alpha1"
KIND = "ManifestSet"

SUPPORTED_HELM_VERSION = "4.3.1"
SUPPORTED_KUSTOMIZE_VERSION = "5.8.3"
RENDERERS = ("raw", "helm", "kustomize")
RELEASE_MODES = ("upgrade", "install")
SCOPES = ("Namespaced", "Cluster")

SHA_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
SEMVER_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
DNS_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?")
POINTER_PATTERN = re.compile(r"(?:/(?:[^/~]|~[01])*)*")
EDGE_ID_PATTERN = re.compile(r"[0-9a-f]{64}")

SCENARIO_KEYS = (
    "id", "renderer", "namespace", "kubernetesVersion", "apiVersions",
    "sources", "path", "releaseName", "valuesFiles", "setValues", "releaseMode",
    "baselineCases", "kindScopes", "protectedLabels", "protectedResources", "exceptions",
)
BASELINE_CASE_KEYS = ("ref", "state", "reason", "inputs")
BASELINE_INPUT_KEYS = ("path", "sources", "valuesFiles")
IDENTITY_KEYS = ("group", "kind", "namespace", "name")
EXCEPTION_KEYS = ("ruleId", "resource", "path", "baselineRef", "reason", "relatedResource", "edgeId")

# Built-in resource scopes for the audited API families, keyed by (group, kind).
# Verified against the registry strategies' NamespaceScoped() at the audited
# Kubernetes commits (non-obvious entries: ClusterTrustBundle, StorageVersionMigration,
# IPAddress, ServiceCIDR, and ResourceSlice are cluster-scoped; PodCertificateRequest,
# ResourceClaim, ControllerRevision, CSIStorageCapacity, and EndpointSlice are namespaced).
BUILTIN_SCOPES: dict[tuple[str, str], str] = {
    ("", "ConfigMap"): "Namespaced",
    ("", "Endpoints"): "Namespaced",
    ("", "Event"): "Namespaced",
    ("", "LimitRange"): "Namespaced",
    ("", "Namespace"): "Cluster",
    ("", "Node"): "Cluster",
    ("", "PersistentVolume"): "Cluster",
    ("", "PersistentVolumeClaim"): "Namespaced",
    ("", "Pod"): "Namespaced",
    ("", "ReplicationController"): "Namespaced",
    ("", "ResourceQuota"): "Namespaced",
    ("", "Secret"): "Namespaced",
    ("", "Service"): "Namespaced",
    ("", "ServiceAccount"): "Namespaced",
    ("apiextensions.k8s.io", "CustomResourceDefinition"): "Cluster",
    ("apps", "ControllerRevision"): "Namespaced",
    ("apps", "DaemonSet"): "Namespaced",
    ("apps", "Deployment"): "Namespaced",
    ("apps", "ReplicaSet"): "Namespaced",
    ("apps", "StatefulSet"): "Namespaced",
    ("batch", "CronJob"): "Namespaced",
    ("batch", "Job"): "Namespaced",
    ("certificates.k8s.io", "CertificateSigningRequest"): "Cluster",
    ("certificates.k8s.io", "ClusterTrustBundle"): "Cluster",
    ("certificates.k8s.io", "PodCertificateRequest"): "Namespaced",
    ("discovery.k8s.io", "EndpointSlice"): "Namespaced",
    ("networking.k8s.io", "IPAddress"): "Cluster",
    ("networking.k8s.io", "Ingress"): "Namespaced",
    ("networking.k8s.io", "IngressClass"): "Cluster",
    ("networking.k8s.io", "NetworkPolicy"): "Namespaced",
    ("networking.k8s.io", "ServiceCIDR"): "Cluster",
    ("node.k8s.io", "RuntimeClass"): "Cluster",
    ("policy", "PodDisruptionBudget"): "Namespaced",
    ("rbac.authorization.k8s.io", "ClusterRole"): "Cluster",
    ("rbac.authorization.k8s.io", "ClusterRoleBinding"): "Cluster",
    ("rbac.authorization.k8s.io", "Role"): "Namespaced",
    ("rbac.authorization.k8s.io", "RoleBinding"): "Namespaced",
    ("resource.k8s.io", "ResourceClaim"): "Namespaced",
    ("resource.k8s.io", "ResourceClaimTemplate"): "Namespaced",
    ("resource.k8s.io", "ResourceSlice"): "Cluster",
    ("scheduling.k8s.io", "PriorityClass"): "Cluster",
    ("storage.k8s.io", "CSIDriver"): "Cluster",
    ("storage.k8s.io", "CSIStorageCapacity"): "Namespaced",
    ("storage.k8s.io", "CSINode"): "Cluster",
    ("storage.k8s.io", "StorageClass"): "Cluster",
    ("storage.k8s.io", "VolumeAttachment"): "Cluster",
    ("storage.k8s.io", "VolumeAttributesClass"): "Cluster",
    ("storagemigration.k8s.io", "StorageVersionMigration"): "Cluster",
}


class ConfigError(Exception):
    """The ManifestSet descriptor or its runtime context is invalid."""


class StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate and non-string mapping keys.

    Plain safe_load silently keeps the last duplicate key, which would hide
    descriptor and manifest typos from every later stage.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        seen: set[str] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    None, None, "mapping keys must be strings", key_node.start_mark,
                )
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate mapping key {key!r}", key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _is_str_list(value: Any, *, minimum: int = 0) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= minimum
        and all(isinstance(item, str) and item for item in value)
    )


def _require_mapping(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{what} must be a mapping")
    return value


def _check_keys(mapping: dict[str, Any], allowed: tuple[str, ...] | list[str], what: str) -> None:
    unknown = sorted(str(key) for key in mapping if key not in allowed)
    if unknown:
        raise ConfigError(f"{what} has unknown properties: {', '.join(unknown)}")


def _check_tools(tools: Any) -> None:
    tools = _require_mapping(tools, "spec.tools")
    _check_keys(tools, ["helmVersion", "kustomizeVersion"], "spec.tools")
    if "helmVersion" not in tools or "kustomizeVersion" not in tools:
        raise ConfigError("spec.tools must declare both helmVersion and kustomizeVersion")
    if tools["helmVersion"] != SUPPORTED_HELM_VERSION:
        raise ConfigError(
            f"spec.tools.helmVersion must be {SUPPORTED_HELM_VERSION!r}; "
            f"got {tools['helmVersion']!r}"
        )
    if tools["kustomizeVersion"] != SUPPORTED_KUSTOMIZE_VERSION:
        raise ConfigError(
            f"spec.tools.kustomizeVersion must be {SUPPORTED_KUSTOMIZE_VERSION!r}; "
            f"got {tools['kustomizeVersion']!r}"
        )


def _check_identity(value: Any, what: str) -> None:
    identity = _require_mapping(value, what)
    _check_keys(identity, IDENTITY_KEYS, what)
    if not _nonempty_str(identity.get("kind")):
        raise ConfigError(f"{what}.kind must be a nonempty string")
    if not _nonempty_str(identity.get("name")):
        raise ConfigError(f"{what}.name must be a nonempty string")
    for key in ("group", "namespace"):
        field = identity.get(key)
        if not isinstance(field, str):
            raise ConfigError(f"{what}.{key} must be a string (empty for the core group or cluster scope)")


def _check_pointer(value: Any, what: str) -> None:
    if not _nonempty_str(value) or POINTER_PATTERN.fullmatch(value) is None:
        raise ConfigError(f"{what} must be a valid RFC 6901 JSON Pointer")


def _check_sha(value: Any, what: str) -> None:
    if not isinstance(value, str) or SHA_PATTERN.fullmatch(value) is None:
        raise ConfigError(f"{what} must be a full 40- or 64-character lowercase Git SHA")


def _check_baseline_inputs(inputs: Any, what: str, allowed: tuple[str, ...]) -> None:
    inputs = _require_mapping(inputs, what)
    if not inputs:
        raise ConfigError(f"{what} must declare at least one override")
    _check_keys(inputs, BASELINE_INPUT_KEYS, what)
    if "path" in inputs and not _nonempty_str(inputs["path"]):
        raise ConfigError(f"{what}.path must be a nonempty string")
    if "sources" in inputs and not _is_str_list(inputs["sources"], minimum=1):
        raise ConfigError(f"{what}.sources must be a nonempty list of nonempty strings")
    if "valuesFiles" in inputs and not _is_str_list(inputs["valuesFiles"]):
        raise ConfigError(f"{what}.valuesFiles must be a list of nonempty strings")
    forbidden = sorted(set(inputs) - set(allowed))
    if forbidden:
        raise ConfigError(f"{what} may not override {', '.join(forbidden)} for this renderer")


def _check_baseline_case(case: Any, where: str, renderer: str) -> None:
    case = _require_mapping(case, where)
    _check_keys(case, BASELINE_CASE_KEYS, where)
    _check_sha(case.get("ref"), f"{where}.ref")
    state = case.get("state")
    if state not in ("new", "existing"):
        raise ConfigError(f"{where}.state must be 'new' or 'existing'")
    if state == "new":
        if not _nonempty_str(case.get("reason")):
            raise ConfigError(f"{where} with state 'new' requires a nonempty reason")
        if "inputs" in case:
            raise ConfigError(f"{where} with state 'new' must not declare inputs")
    else:
        if "reason" in case:
            raise ConfigError(f"{where} with state 'existing' must not declare a reason")
        if "inputs" not in case:
            raise ConfigError(f"{where} with state 'existing' requires inputs")
        allowed = {"raw": ("sources",), "helm": ("path", "valuesFiles"), "kustomize": ("path",)}[renderer]
        _check_baseline_inputs(case["inputs"], f"{where}.inputs", allowed)


def _check_scenario(scenario: Any, where: str) -> None:
    scenario = _require_mapping(scenario, where)
    _check_keys(scenario, SCENARIO_KEYS, where)
    if not _nonempty_str(scenario.get("id")):
        raise ConfigError(f"{where}.id must be a nonempty string")
    renderer = scenario.get("renderer")
    if renderer not in RENDERERS:
        raise ConfigError(f"{where}.renderer must be one of {', '.join(RENDERERS)}")
    namespace = scenario.get("namespace")
    if not isinstance(namespace, str) or DNS_LABEL_PATTERN.fullmatch(namespace) is None:
        raise ConfigError(f"{where}.namespace must be a lowercase DNS label")
    version = scenario.get("kubernetesVersion")
    if not isinstance(version, str) or SEMVER_PATTERN.fullmatch(version) is None:
        raise ConfigError(f"{where}.kubernetesVersion must be a full X.Y.Z semantic version")
    api_versions = scenario.get("apiVersions", [])
    if not _is_str_list(api_versions):
        raise ConfigError(f"{where}.apiVersions must be a list of nonempty strings")

    if renderer == "raw":
        if not _is_str_list(scenario.get("sources"), minimum=1):
            raise ConfigError(f"{where} with renderer 'raw' requires a nonempty sources list")
        if "path" in scenario:
            raise ConfigError(f"{where} with renderer 'raw' must not declare path")
    else:
        if "sources" in scenario:
            raise ConfigError(f"{where} with renderer {renderer!r} must not declare sources")
        if not _nonempty_str(scenario.get("path")):
            raise ConfigError(f"{where} with renderer {renderer!r} requires path")
    if renderer == "helm":
        if not _nonempty_str(scenario.get("releaseName")):
            raise ConfigError(f"{where} with renderer 'helm' requires releaseName")
    else:
        for key in ("releaseName", "valuesFiles", "setValues", "releaseMode"):
            if key in scenario:
                raise ConfigError(f"{where} with renderer {renderer!r} must not declare {key}")
    if renderer == "helm":
        if not _is_str_list(scenario.get("valuesFiles", [])):
            raise ConfigError(f"{where}.valuesFiles must be a list of nonempty strings")
        set_values = scenario.get("setValues", {})
        if not isinstance(set_values, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in set_values.items()
        ):
            raise ConfigError(f"{where}.setValues must map string keys to string values")
        if scenario.get("releaseMode", "upgrade") not in RELEASE_MODES:
            raise ConfigError(f"{where}.releaseMode must be one of {', '.join(RELEASE_MODES)}")

    cases = scenario.get("baselineCases", [])
    if not isinstance(cases, list):
        raise ConfigError(f"{where}.baselineCases must be a list")
    for index, case in enumerate(cases):
        _check_baseline_case(case, f"{where}.baselineCases[{index}]", renderer)

    kind_scopes = scenario.get("kindScopes", [])
    if not isinstance(kind_scopes, list):
        raise ConfigError(f"{where}.kindScopes must be a list")
    for index, entry in enumerate(kind_scopes):
        scope_where = f"{where}.kindScopes[{index}]"
        entry = _require_mapping(entry, scope_where)
        _check_keys(entry, ["group", "kind", "scope"], scope_where)
        if not isinstance(entry.get("group"), str):
            raise ConfigError(f"{scope_where}.group must be a string")
        if not _nonempty_str(entry.get("kind")):
            raise ConfigError(f"{scope_where}.kind must be a nonempty string")
        if entry.get("scope") not in SCOPES:
            raise ConfigError(f"{scope_where}.scope must be 'Namespaced' or 'Cluster'")

    protected_labels = scenario.get("protectedLabels", [])
    if not isinstance(protected_labels, list):
        raise ConfigError(f"{where}.protectedLabels must be a list")
    for index, entry in enumerate(protected_labels):
        label_where = f"{where}.protectedLabels[{index}]"
        entry = _require_mapping(entry, label_where)
        _check_keys(entry, ["location", "keys"], label_where)
        _check_pointer(entry.get("location"), f"{label_where}.location")
        if not _is_str_list(entry.get("keys"), minimum=1):
            raise ConfigError(f"{label_where}.keys must be a nonempty list of nonempty strings")

    protected_resources = scenario.get("protectedResources", [])
    if not isinstance(protected_resources, list):
        raise ConfigError(f"{where}.protectedResources must be a list")
    for index, entry in enumerate(protected_resources):
        _check_identity(entry, f"{where}.protectedResources[{index}]")

    exceptions = scenario.get("exceptions", [])
    if not isinstance(exceptions, list):
        raise ConfigError(f"{where}.exceptions must be a list")
    for index, entry in enumerate(exceptions):
        exception_where = f"{where}.exceptions[{index}]"
        entry = _require_mapping(entry, exception_where)
        _check_keys(entry, EXCEPTION_KEYS, exception_where)
        if not _nonempty_str(entry.get("ruleId")):
            raise ConfigError(f"{exception_where}.ruleId must be a nonempty string")
        _check_identity(entry.get("resource"), f"{exception_where}.resource")
        _check_pointer(entry.get("path"), f"{exception_where}.path")
        _check_sha(entry.get("baselineRef"), f"{exception_where}.baselineRef")
        if not _nonempty_str(entry.get("reason")):
            raise ConfigError(f"{exception_where}.reason must be a nonempty string")
        if "relatedResource" in entry:
            _check_identity(entry["relatedResource"], f"{exception_where}.relatedResource")
        if "edgeId" in entry and (
            not isinstance(entry["edgeId"], str) or EDGE_ID_PATTERN.fullmatch(entry["edgeId"]) is None
        ):
            raise ConfigError(f"{exception_where}.edgeId must be a 64-character lowercase hex SHA-256")


def validate_structure(document: Any) -> dict[str, Any]:
    """Validate the static ManifestSet structure and return the document.

    Raises ConfigError on any violation. These checks mirror
    schemas/manifest-set.schema.json exactly; the schema-corpus tests prove the
    two agree. Checks that need repository context (unique scenario selection,
    policy IDs, filesystem containment) live in load_config/validate_context.
    """
    root = _require_mapping(document, "ManifestSet")
    _check_keys(root, ["apiVersion", "kind", "metadata", "spec"], "ManifestSet")
    if root.get("apiVersion") != API_VERSION:
        raise ConfigError(f"apiVersion must be {API_VERSION!r}")
    if root.get("kind") != KIND:
        raise ConfigError(f"kind must be {KIND!r}")
    metadata = _require_mapping(root.get("metadata"), "metadata")
    _check_keys(metadata, ["name"], "metadata")
    if not _nonempty_str(metadata.get("name")):
        raise ConfigError("metadata.name must be a nonempty string")
    spec = _require_mapping(root.get("spec"), "spec")
    _check_keys(spec, ["tools", "scenarios"], "spec")
    if "tools" in spec:
        _check_tools(spec["tools"])
    scenarios = spec.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ConfigError("spec.scenarios must be a nonempty array")
    for index, scenario in enumerate(scenarios):
        _check_scenario(scenario, f"spec.scenarios[{index}]")
    return root


def load_config(repo: Path, descriptor_path: Path, scenario_id: str | None = None) -> dict[str, Any]:
    """Load and validate a ManifestSet, returning the selected run configuration.

    Returns {"manifest_set": <descriptor path as given>, "tools": {...},
    "scenarios": [...]} with either all scenarios or just the selected one.
    Raises ConfigError for unreadable, malformed, or duplicate-id descriptors
    and for an unknown scenario id.
    """
    repo = Path(repo)
    descriptor = Path(descriptor_path)
    path = descriptor if descriptor.is_absolute() else repo / descriptor
    if not path.resolve().is_relative_to(repo.resolve()):
        raise ConfigError(f"ManifestSet descriptor {descriptor} is outside the repository")
    if not path.is_file():
        raise ConfigError(f"ManifestSet descriptor {descriptor} not found in repository")
    try:
        document = yaml.load(path.read_bytes(), Loader=StrictSafeLoader)
    except yaml.YAMLError as error:
        raise ConfigError(f"Cannot parse ManifestSet {descriptor}: {type(error).__name__}") from error
    document = validate_structure(document)

    scenarios = document["spec"]["scenarios"]
    identifiers = [scenario["id"] for scenario in scenarios]
    duplicates = sorted({identifier for identifier in identifiers if identifiers.count(identifier) > 1})
    if duplicates:
        raise ConfigError(f"Duplicate scenario ids: {', '.join(duplicates)}")
    if scenario_id is None:
        selected = list(scenarios)
    else:
        selected = [scenario for scenario in scenarios if scenario["id"] == scenario_id]
        if not selected:
            known = ", ".join(sorted(identifiers))
            raise ConfigError(f"Unknown scenario id {scenario_id!r}; known ids: {known}")
    return {
        "manifest_set": descriptor.as_posix(),
        "tools": dict(document["spec"].get("tools", {})),
        "scenarios": selected,
    }


def _check_contained(repo: Path, value: str, what: str, *, must_exist: bool, directory: bool) -> None:
    candidate = Path(value)
    if candidate.is_absolute() or any(part == ".." for part in candidate.parts):
        raise ConfigError(f"{what} {value!r} must be a repo-relative path without '..' segments")
    target = repo / candidate
    if not target.resolve().is_relative_to(repo.resolve()):
        raise ConfigError(f"{what} {value!r} escapes the repository")
    if must_exist:
        if directory and not target.is_dir():
            raise ConfigError(f"{what} {value!r} does not exist in the repository")
        if not directory and not target.is_file():
            raise ConfigError(f"{what} {value!r} does not exist in the repository")


def _check_scenario_paths(scenario: dict[str, Any], repo: Path, where: str) -> None:
    renderer = scenario["renderer"]
    if renderer == "raw":
        for pattern in scenario["sources"]:
            _check_contained(repo, pattern, f"{where} sources entry", must_exist=False, directory=False)
    elif renderer == "helm":
        _check_contained(repo, scenario["path"], f"{where} chart path", must_exist=True, directory=True)
        for values_file in scenario.get("valuesFiles", []):
            _check_contained(repo, values_file, f"{where} values file", must_exist=True, directory=False)
    else:
        _check_contained(repo, scenario["path"], f"{where} kustomize path", must_exist=True, directory=True)
    for index, case in enumerate(scenario.get("baselineCases", [])):
        inputs = case.get("inputs")
        if not isinstance(inputs, dict):
            continue
        if "path" in inputs:
            _check_contained(repo, inputs["path"], f"{where} baselineCases[{index}] inputs path",
                             must_exist=False, directory=True)
        for key in ("sources", "valuesFiles"):
            for entry in inputs.get(key, []):
                _check_contained(repo, entry, f"{where} baselineCases[{index}] inputs {key} entry",
                                 must_exist=False, directory=False)


def validate_context(config: dict[str, Any], repo: Path, baseline_refs: Sequence[str],
                     catalogue: dict[str, Any]) -> None:
    """Check contextual descriptor rules once the run inputs are known.

    Validates requested baseline ref formats, per-scenario Kubernetes version
    support against the catalogue, tool pin requirements for the selected
    renderers, kindScopes conflicts, exception policy validity against the
    catalogue registry, and filesystem containment/existence of renderer
    inputs. Raises ConfigError on failure; returns None on success.
    """
    repo = Path(repo)
    for ref in baseline_refs:
        _check_sha(ref, "Requested baseline ref")
    supported_minors = set(catalogue["kubernetes"]["supported_minor_versions"])
    rules = {rule["id"]: rule for rule in catalogue["rules"]}
    tools = config.get("tools", {})
    needs_helm = needs_kustomize = False
    for scenario in config["scenarios"]:
        where = f"scenario {scenario['id']!r}"
        version = scenario["kubernetesVersion"]
        minor = ".".join(version.split(".")[:2])
        if minor not in supported_minors:
            raise ConfigError(
                f"{where}: Kubernetes {version} is outside the audited minors "
                f"({', '.join(sorted(supported_minors))})"
            )
        renderer = scenario["renderer"]
        needs_helm = needs_helm or renderer == "helm"
        needs_kustomize = needs_kustomize or renderer == "kustomize"

        declared: dict[tuple[str, str], str] = {}
        for entry in scenario.get("kindScopes", []):
            key = (entry["group"], entry["kind"])
            if key in BUILTIN_SCOPES:
                raise ConfigError(
                    f"{where}: kindScopes entry for {entry['kind']!r} duplicates the built-in scope table; "
                    "remove the declaration"
                )
            previous = declared.get(key)
            if previous is not None and previous != entry["scope"]:
                raise ConfigError(
                    f"{where}: conflicting kindScopes declarations for {key[0] or 'core'}/{key[1]}"
                )
            declared[key] = entry["scope"]

        for index, exception in enumerate(scenario.get("exceptions", [])):
            exception_where = f"{where} exceptions[{index}]"
            rule = rules.get(exception["ruleId"])
            if rule is None:
                raise ConfigError(
                    f"{exception_where}: unknown rule id {exception['ruleId']!r}; "
                    "rule ids come from modules/manifest-compat/policy.json"
                )
            if rule["waiver_eligibility"] != "baseline-comparison-only":
                raise ConfigError(
                    f"{exception_where}: rule {exception['ruleId']!r} is never waiver-eligible"
                )
            if rule["relational"]:
                if "relatedResource" not in exception or "edgeId" not in exception:
                    raise ConfigError(
                        f"{exception_where}: relational rule {exception['ruleId']!r} requires "
                        "relatedResource and edgeId"
                    )
            elif "relatedResource" in exception or "edgeId" in exception:
                raise ConfigError(
                    f"{exception_where}: nonrelational rule {exception['ruleId']!r} must not declare "
                    "relatedResource or edgeId"
                )

        _check_scenario_paths(scenario, repo, where)

    if needs_helm and tools.get("helmVersion") != SUPPORTED_HELM_VERSION:
        raise ConfigError(
            "Selected scenarios render with Helm; spec.tools.helmVersion must be pinned to "
            f"{SUPPORTED_HELM_VERSION!r}"
        )
    if needs_kustomize and tools.get("kustomizeVersion") != SUPPORTED_KUSTOMIZE_VERSION:
        raise ConfigError(
            "Selected scenarios render with Kustomize; spec.tools.kustomizeVersion must be pinned to "
            f"{SUPPORTED_KUSTOMIZE_VERSION!r}"
        )
