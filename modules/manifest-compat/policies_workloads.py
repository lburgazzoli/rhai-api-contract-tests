"""Workload immutable-update rules for rendered Kubernetes manifests.

Implements the standing Workloads matrix of the policy catalogue
(modules/manifest-compat/policy.json) for apps/v1 Deployment, DaemonSet,
ReplicaSet, StatefulSet and ControllerRevision, batch/v1 Job and CronJob,
and direct core/v1 Pod objects. Every emitted finding ID, severity,
evidence, and classification is read from that catalogue, so an emitted
rule is always a registered rule.

Source authority (verified at the audited commits for 1.35/1.36/1.37):

- pkg/apis/apps/validation/validation.go: ValidateDeploymentUpdate,
  ValidateDaemonSetSpecUpdate, ValidateReplicaSetUpdate,
  ValidateStatefulSetUpdate (mutable-field allowlist in 1.35/1.36, the four
  direct immutable-field checks in 1.37), ValidateControllerRevisionUpdate.
- pkg/apis/batch/validation/validation.go: ValidateJobSpecUpdate,
  validateCompletions, validatePodTemplateUpdate,
  validateJobSchedulingUpdate (1.37); pkg/registry/batch/job/strategy.go:
  validationOptionsForJob / shouldAllowMutablePodTemplate.
- pkg/apis/core/validation/validation.go: ValidatePodUpdate,
  ValidateContainerUpdates, validateOnlyAddedTolerations (toleration
  matching ignores tolerationSeconds in all three audited versions),
  validateOnlyDeletedSchedulingGates, validateNodeSelectorMutation,
  validateNodeAffinityMutation; pkg/apis/core/v1/defaults.go:
  SetDefaults_PodSpec / SetDefaults_Pod.

Deliberate boundaries, documented per the standing rules:

- Only same-identity objects are compared; removals are handled elsewhere.
- Suspended-Job scheduling-directive and container-resource template
  changes, one-sided Job selectors, spec.scheduling changes, StatefulSet
  claim-template storage growth, and omission-versus-default differences
  are conditional warnings: their eligibility depends on live status,
  feature gates, or request-path defaulting that rendered YAML cannot
  prove. Absent YAML status is never treated as evidence of a
  never-started Job.
- The modelled pod-spec defaults are the unconditional SetDefaults_PodSpec
  values (dnsPolicy, restartPolicy, schedulerName, securityContext,
  terminationGracePeriodSeconds, serviceAccount aliasing) plus the Pod-only
  SetDefaults_Pod rules (requests defaulted from limits, the
  apiserver-default enableServiceLinks). Container-level defaults such as
  probe thresholds and imagePullPolicy are not modelled; differences there
  are reported as ordinary findings.
- In-place resource resize and ephemeral-container updates are separate
  pod subresources whose validation depends on live pod state; this module
  evaluates only the normal full-object update path, which rejects them.
- CronJob jobTemplate changes affect future Jobs only and are never
  compared under Job-template immutability.
- Empty-list/empty-map versus omission equivalence is only applied where
  the modelled defaults establish it; JSON null is always treated as
  omission, matching Go zero-value decoding.
"""

from __future__ import annotations

import copy
from fractions import Fraction
from typing import Any

EXPECTED_API_VERSIONS: dict[str, str] = {
    "apps": "apps/v1",
    "batch": "batch/v1",
    "": "v1",
}

WORKLOAD_KINDS: frozenset[str] = frozenset({
    "Deployment", "DaemonSet", "ReplicaSet", "StatefulSet", "ControllerRevision",
    "Job", "CronJob", "Pod",
})

SELECTOR_RULE_IDS: dict[tuple[str, str], str] = {
    ("apps", "Deployment"): "deployment-selector-immutable",
    ("apps", "DaemonSet"): "daemonset-selector-immutable",
    ("apps", "ReplicaSet"): "replicaset-selector-immutable",
    ("apps", "StatefulSet"): "statefulset-selector-immutable",
}

# 1.35/1.36 ValidateStatefulSetUpdate clones these fields before the
# Semantic.DeepEqual spec comparison; everything else is frozen.
STATEFULSET_MUTABLE_ALLOWLIST: frozenset[str] = frozenset({
    "replicas", "ordinals", "template", "updateStrategy", "revisionHistoryLimit",
    "persistentVolumeClaimRetentionPolicy", "minReadySeconds",
})

STATEFULSET_IMMUTABLE_RULES: dict[str, str] = {
    "serviceName": "statefulset-service-name-immutable",
    "podManagementPolicy": "statefulset-pod-management-policy-immutable",
    "volumeClaimTemplates": "statefulset-volume-claim-templates-immutable",
}

JOB_FIXED_FIELD_RULES: dict[str, str] = {
    "completionMode": "job-completion-mode-immutable",
    "podFailurePolicy": "job-pod-failure-policy-immutable",
    "backoffLimitPerIndex": "job-backoff-limit-per-index-immutable",
    "managedBy": "job-managed-by-immutable",
    "successPolicy": "job-success-policy-immutable",
}

_PODSPEC_STRING_DEFAULTS: dict[str, str] = {
    "dnsPolicy": "ClusterFirst",
    "restartPolicy": "Always",
    "schedulerName": "default-scheduler",
}
_TERMINATION_GRACE_PERIOD_SECONDS_DEFAULT = 30

_RESIDUAL_POD_TEXT = (
    "Direct Pod spec updates may not change fields other than container images, "
    "activeDeadlineSeconds, tolerations, schedulingGates, and the gated-pod "
    "scheduling directives."
)


# --- generic value helpers -------------------------------------------------


def _strip_nils(value: Any) -> Any:
    """Drop mapping keys whose value is null, matching Go zero-value decode."""
    if isinstance(value, dict):
        return {key: _strip_nils(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_strip_nils(item) for item in value]
    return value


def _structural_equal(left: Any, right: Any) -> bool:
    """API structural equality: maps unordered, arrays ordered, null as zero."""
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, bool) or isinstance(right, bool):
        return left is right if isinstance(left, bool) and isinstance(right, bool) else False
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _structural_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _structural_equal(item, other) for item, other in zip(left, right)
        )
    return left == right


def _changed_keys(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    keys = set(old) | set(new)
    return sorted(key for key in keys if not _structural_equal(old.get(key), new.get(key)))


def _spec_of(document: dict[str, Any]) -> dict[str, Any]:
    spec = document.get("spec")
    return spec if isinstance(spec, dict) else {}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _quantity_value(value: Any) -> Fraction | None:
    """Parse the canonical quantity strings produced by the normalizer."""
    if _is_int(value):
        return Fraction(value)
    if isinstance(value, str):
        try:
            if "/" in value:
                numerator, denominator = value.split("/", 1)
                return Fraction(int(numerator), int(denominator))
            return Fraction(value)
        except (ValueError, ZeroDivisionError):
            return None
    return None


def _copy_field(destination: dict[str, Any], source: dict[str, Any], key: str) -> None:
    """Copy source[key] to destination, removing the key when absent."""
    if key in source:
        destination[key] = copy.deepcopy(source[key])
    else:
        destination.pop(key, None)


def _apply_podspec_defaults(spec: dict[str, Any], pod_object: bool) -> None:
    """Apply source-verified pod-spec defaulting to a private copy.

    Shared defaults come from SetDefaults_PodSpec, which the API server
    applies to every object with a PodSpec, including pod templates. The
    pod_object-only additions come from SetDefaults_Pod. These defaults
    feed the default-equivalence conditional warnings; they never silently
    accept a difference.
    """
    for field, default in _PODSPEC_STRING_DEFAULTS.items():
        if not spec.get(field):
            spec[field] = default
    service_account_name = spec.get("serviceAccountName")
    if not isinstance(service_account_name, str) or not service_account_name:
        service_account = spec.get("serviceAccount")
        service_account_name = service_account if isinstance(service_account, str) else ""
    spec["serviceAccountName"] = service_account_name
    spec["serviceAccount"] = service_account_name
    if spec.get("securityContext") is None:
        spec["securityContext"] = {}
    if spec.get("terminationGracePeriodSeconds") is None:
        spec["terminationGracePeriodSeconds"] = _TERMINATION_GRACE_PERIOD_SECONDS_DEFAULT
    if pod_object:
        for field in ("containers", "initContainers"):
            containers = spec.get(field)
            if not isinstance(containers, list):
                continue
            for container in containers:
                if not isinstance(container, dict):
                    continue
                resources = container.get("resources")
                if not isinstance(resources, dict):
                    continue
                limits = resources.get("limits")
                requests = resources.get("requests")
                if isinstance(limits, dict):
                    if not isinstance(requests, dict):
                        requests = {}
                        resources["requests"] = requests
                    for key, value in limits.items():
                        if key not in requests:
                            requests[key] = copy.deepcopy(value)
        if spec.get("enableServiceLinks") is None:
            spec["enableServiceLinks"] = True


def _munged_affinity(new_affinity: Any, old_affinity: Any) -> Any:
    """Replicate the gated-pod nodeAffinity munging from ValidatePodUpdate.

    Returns the candidate affinity with nodeAffinity replaced by the
    baseline's value, including the nil-collapse cases of the gated-pod
    branch of core ValidatePodUpdate (used for direct Pod updates).
    """
    old_node_affinity = old_affinity.get("nodeAffinity") if isinstance(old_affinity, dict) else None
    if new_affinity is None:
        if old_node_affinity is None:
            return None
        return {"nodeAffinity": copy.deepcopy(old_node_affinity)}
    if (
        old_affinity is None
        and new_affinity.get("podAntiAffinity") is None
        and new_affinity.get("podAffinity") is None
    ):
        return None
    result = copy.deepcopy(new_affinity)
    if old_node_affinity is None:
        result.pop("nodeAffinity", None)
    else:
        result["nodeAffinity"] = copy.deepcopy(old_node_affinity)
    return result


def _job_munged_affinity(old_affinity: Any, new_affinity: Any) -> Any | None:
    """Replicate the old-side affinity munging from batch validatePodTemplateUpdate.

    When AllowMutableSchedulingDirectives is enabled, upstream copies the
    baseline template and adjusts its affinity so nodeAffinity skips the
    immutability check: clearing affinity is allowed when only nodeAffinity
    was set, and setting affinity is allowed for its nodeAffinity alone.
    Inputs are nil-stripped, so a remaining key is a non-nil subfield.
    """
    if new_affinity is None:
        if not isinstance(old_affinity, dict):
            return None
        munged = copy.deepcopy(old_affinity)
        munged.pop("nodeAffinity", None)
        # api.Affinity{} equality: after clearing nodeAffinity the struct is
        # empty only when podAffinity and podAntiAffinity are nil as well.
        return munged if munged else None
    new_node_affinity = (
        new_affinity.get("nodeAffinity") if isinstance(new_affinity, dict) else None
    )
    if not isinstance(old_affinity, dict):
        # template.Spec.Affinity = &api.Affinity{NodeAffinity: new.NodeAffinity}
        if new_node_affinity is None:
            return {}
        return {"nodeAffinity": copy.deepcopy(new_node_affinity)}
    munged = copy.deepcopy(old_affinity)
    if new_node_affinity is None:
        munged.pop("nodeAffinity", None)
    else:
        munged["nodeAffinity"] = copy.deepcopy(new_node_affinity)
    return munged


# --- finding construction --------------------------------------------------


def _minor_of(scenario: dict[str, Any]) -> str | None:
    version = scenario.get("kubernetesVersion")
    if not isinstance(version, str):
        return None
    parts = version.split(".")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    return f"{parts[0]}.{parts[1]}"


def _finding(
    rules: dict[str, dict[str, Any]],
    rule_id: str,
    path: str,
    text: str,
    scenario_id: Any,
    resource: dict[str, str],
    minor: str,
) -> dict[str, Any] | None:
    rule = rules.get(rule_id)
    if rule is None:
        raise LookupError(f"finding ID {rule_id!r} is not registered in the policy catalogue")
    if minor not in rule.get("versions", []):
        return None
    return {
        "id": rule_id,
        "path": path,
        "text": text,
        "severity": rule["severity"],
        "scenario": scenario_id,
        "resource": dict(resource),
        "classification": rule["classification"],
        "evidence": rule["evidence"],
    }


# --- apps/v1 workloads -----------------------------------------------------


def _selector_findings(
    rules: dict[str, dict[str, Any]],
    rule_id: str,
    kind: str,
    old_document: dict[str, Any],
    new_document: dict[str, Any],
    scenario_id: Any,
    resource: dict[str, str],
    minor: str,
) -> list[dict[str, Any]]:
    old_selector = _spec_of(old_document).get("selector")
    new_selector = _spec_of(new_document).get("selector")
    if _structural_equal(_strip_nils(old_selector), _strip_nils(new_selector)):
        return []
    finding = _finding(
        rules, rule_id, "/spec/selector",
        f"apps/v1 {kind} spec.selector is immutable; the candidate changes the selector of an "
        "existing resource. Pod template, image, and replica changes are normal rollout behavior "
        "and are not affected by this rule.",
        scenario_id, resource, minor,
    )
    return [finding] if finding is not None else []


def _volume_claim_templates_growth_only(
    old_templates: Any, new_templates: Any
) -> bool:
    """True when the only change is a strictly larger storage request."""
    if not isinstance(old_templates, list) or not isinstance(new_templates, list):
        return False
    if len(old_templates) != len(new_templates):
        return False
    grew = False
    for old_template, new_template in zip(old_templates, new_templates):
        if not isinstance(old_template, dict) or not isinstance(new_template, dict):
            return False
        old_masked = copy.deepcopy(old_template)
        new_masked = copy.deepcopy(new_template)
        old_storage = _pop_storage_request(old_masked)
        new_storage = _pop_storage_request(new_masked)
        if not _structural_equal(old_masked, new_masked):
            return False
        old_value = _quantity_value(old_storage)
        new_value = _quantity_value(new_storage)
        if old_storage is None and new_storage is None:
            continue
        if old_value is None or new_value is None or new_value < old_value:
            return False
        if new_value > old_value:
            grew = True
    return grew


def _pop_storage_request(template: dict[str, Any]) -> Any:
    spec = template.get("spec")
    if not isinstance(spec, dict):
        return None
    resources = spec.get("resources")
    if not isinstance(resources, dict):
        return None
    requests = resources.get("requests")
    if not isinstance(requests, dict):
        return None
    return requests.pop("storage", None)


def _statefulset_findings(
    rules: dict[str, dict[str, Any]],
    old_document: dict[str, Any],
    new_document: dict[str, Any],
    scenario_id: Any,
    resource: dict[str, str],
    minor: str,
) -> list[dict[str, Any]]:
    old_spec = _strip_nils(copy.deepcopy(_spec_of(old_document)))
    new_spec = _strip_nils(copy.deepcopy(_spec_of(new_document)))
    findings: list[dict[str, Any]] = []
    for field in _changed_keys(old_spec, new_spec):
        if field == "selector":
            finding = _finding(
                rules, SELECTOR_RULE_IDS[("apps", "StatefulSet")], "/spec/selector",
                "apps/v1 StatefulSet spec.selector is immutable; the candidate changes the "
                "selector of an existing StatefulSet.",
                scenario_id, resource, minor,
            )
            if finding is not None:
                findings.append(finding)
        elif field in STATEFULSET_IMMUTABLE_RULES:
            if field == "volumeClaimTemplates" and _volume_claim_templates_growth_only(
                old_spec.get(field), new_spec.get(field)
            ):
                finding = _finding(
                    rules, "conditional-update-risk", "/spec/volumeClaimTemplates",
                    "StatefulSet spec.volumeClaimTemplates storage requests grow. Update "
                    "validation rejects volumeClaimTemplates changes, but whether the growth is "
                    "provisionable for existing claims cannot be decided from rendered YAML, so "
                    "the change is reported as a conditional risk rather than a definite "
                    "rejection.",
                    scenario_id, resource, minor,
                )
                if finding is not None:
                    findings.append(finding)
                continue
            finding = _finding(
                rules, STATEFULSET_IMMUTABLE_RULES[field], f"/spec/{field}",
                f"apps/v1 StatefulSet spec.{field} is immutable"
                + (
                    " after known defaulting (volumeMode defaults to Filesystem)"
                    if field == "volumeClaimTemplates"
                    else " (an omitted value defaults to OrderedReady)"
                    if field == "podManagementPolicy"
                    else ""
                )
                + "; the candidate changes it on an existing StatefulSet.",
                scenario_id, resource, minor,
            )
            if finding is not None:
                findings.append(finding)
        elif field in STATEFULSET_MUTABLE_ALLOWLIST:
            continue
        elif minor in ("1.35", "1.36"):
            finding = _finding(
                rules, "statefulset-spec-field-forbidden", f"/spec/{field}",
                f"Kubernetes {minor} freezes every StatefulSet spec field outside the mutable "
                "allowlist (replicas, ordinals, template, updateStrategy, revisionHistoryLimit, "
                f"persistentVolumeClaimRetentionPolicy, minReadySeconds); the candidate changes "
                f"spec.{field}.",
                scenario_id, resource, minor,
            )
            if finding is not None:
                findings.append(finding)
        else:
            finding = _finding(
                rules, "rule-coverage-partial", f"/spec/{field}",
                f"StatefulSet spec.{field} is outside both the audited mutable allowlist and the "
                "four directly immutable fields; Kubernetes 1.37 does not restrict it, and this "
                "check has no audited rule for it, so the change is reported as partial "
                "coverage.",
                scenario_id, resource, minor,
            )
            if finding is not None:
                findings.append(finding)
    return findings


def _controllerrevision_findings(
    rules: dict[str, dict[str, Any]],
    old_document: dict[str, Any],
    new_document: dict[str, Any],
    scenario_id: Any,
    resource: dict[str, str],
    minor: str,
) -> list[dict[str, Any]]:
    old_data = _strip_nils(old_document.get("data"))
    new_data = _strip_nils(new_document.get("data"))
    if _structural_equal(old_data, new_data):
        return []
    finding = _finding(
        rules, "controllerrevision-data-immutable", "/data",
        "apps/v1 ControllerRevision data is immutable; the candidate changes the stored patch "
        "data. The revision field is mutable and is deliberately not frozen by this rule.",
        scenario_id, resource, minor,
    )
    return [finding] if finding is not None else []


# --- batch/v1 Job ----------------------------------------------------------


def _defaulted_job_counts(spec: dict[str, Any]) -> tuple[Any, Any]:
    """SetDefaults_Job: completions defaults to 1 only when both are omitted;
    parallelism defaults to 1 whenever omitted."""
    completions = spec.get("completions")
    parallelism = spec.get("parallelism")
    if completions is None and parallelism is None:
        return 1, 1
    if parallelism is None:
        parallelism = 1
    return completions, parallelism


def _job_completions_findings(
    rules: dict[str, dict[str, Any]],
    old_spec: dict[str, Any],
    new_spec: dict[str, Any],
    scenario_id: Any,
    resource: dict[str, str],
    minor: str,
) -> list[dict[str, Any]]:
    old_completions, _ = _defaulted_job_counts(old_spec)
    new_completions, new_parallelism = _defaulted_job_counts(new_spec)
    if _structural_equal(old_completions, new_completions):
        return []
    mode = new_spec.get("completionMode")
    mode = mode if isinstance(mode, str) else "NonIndexed"
    text: str
    if mode != "Indexed":
        text = (
            "Non-indexed batch/v1 Job spec.completions are immutable; the candidate changes "
            "the completion count of an existing Job."
        )
    elif new_completions is None:
        text = (
            "Indexed batch/v1 Jobs cannot remove spec.completions; it is required when "
            "completionMode is Indexed."
        )
    elif not _structural_equal(new_completions, new_parallelism):
        text = (
            "Indexed batch/v1 Job spec.completions may change only in tandem with an equal "
            "spec.parallelism value."
        )
    else:
        return []
    finding = _finding(
        rules, "job-completions-rule", "/spec/completions", text,
        scenario_id, resource, minor,
    )
    return [finding] if finding is not None else []


def _munge_suspended_template(
    old_template: dict[str, Any], new_template: dict[str, Any]
) -> dict[str, Any]:
    """Maximal suspended-Job munging of the baseline template copy.

    Applies every exception validatePodTemplateUpdate can grant when the
    eligibility options are maximally enabled: scheduling directives,
    template labels and annotations, and container resources for matching
    container lists.
    """
    munged = copy.deepcopy(old_template)
    old_metadata = munged.get("metadata")
    new_metadata = new_template.get("metadata")
    if isinstance(old_metadata, dict) or isinstance(new_metadata, dict):
        old_metadata = old_metadata if isinstance(old_metadata, dict) else {}
        new_metadata = new_metadata if isinstance(new_metadata, dict) else {}
        for key in ("labels", "annotations"):
            _copy_field(old_metadata, new_metadata, key)
        if old_metadata:
            munged["metadata"] = old_metadata
        else:
            munged.pop("metadata", None)
    old_template_spec = munged.get("spec")
    new_template_spec = new_template.get("spec")
    if isinstance(old_template_spec, dict) and isinstance(new_template_spec, dict):
        for key in ("nodeSelector", "tolerations", "schedulingGates"):
            _copy_field(old_template_spec, new_template_spec, key)
        old_affinity = old_template_spec.get("affinity")
        new_affinity = new_template_spec.get("affinity")
        if old_affinity is not None or new_affinity is not None:
            munged_affinity = _job_munged_affinity(old_affinity, new_affinity)
            if munged_affinity is None:
                old_template_spec.pop("affinity", None)
            else:
                old_template_spec["affinity"] = munged_affinity
        for field in ("containers", "initContainers"):
            old_containers = old_template_spec.get(field)
            new_containers = new_template_spec.get(field)
            if not isinstance(old_containers, list) or not isinstance(new_containers, list):
                continue
            if len(old_containers) != len(new_containers):
                continue
            for index, old_container in enumerate(old_containers):
                new_container = new_containers[index]
                if not isinstance(old_container, dict) or not isinstance(new_container, dict):
                    continue
                if old_container.get("name") != new_container.get("name"):
                    continue
                _copy_field(old_container, new_container, "resources")
    return munged


def _job_template_findings(
    rules: dict[str, dict[str, Any]],
    old_spec: dict[str, Any],
    new_spec: dict[str, Any],
    scenario_id: Any,
    resource: dict[str, str],
    minor: str,
) -> list[dict[str, Any]]:
    old_template = _strip_nils(copy.deepcopy(old_spec.get("template")))
    new_template = _strip_nils(copy.deepcopy(new_spec.get("template")))
    old_template = old_template if isinstance(old_template, dict) else {}
    new_template = new_template if isinstance(new_template, dict) else {}
    for template in (old_template, new_template):
        # ObjectMeta is a value struct upstream: an empty metadata mapping is
        # the zero value, identical to an omitted one.
        metadata = template.get("metadata")
        if isinstance(metadata, dict) and not metadata:
            template.pop("metadata", None)
    if _structural_equal(old_template, new_template):
        return []
    for template in (old_template, new_template):
        spec = template.get("spec")
        if isinstance(spec, dict):
            _apply_podspec_defaults(spec, pod_object=False)
    if _structural_equal(old_template, new_template):
        finding = _finding(
            rules, "conditional-update-risk", "/spec/template",
            "Job spec.template differs only by omission versus known pod-spec defaults; "
            "whether the API server re-applies these defaults on the update path depends on "
            "the request mechanics, so the difference cannot be classified from rendered "
            "YAML.",
            scenario_id, resource, minor,
        )
        return [finding] if finding is not None else []
    suspended = old_spec.get("suspend") is True
    if not suspended:
        finding = _finding(
            rules, "job-template-immutable", "/spec/template",
            "batch/v1 Job spec.template is immutable; the candidate changes template fields "
            "outside every suspended-Job exception (container image, command, or other pod "
            "spec fields).",
            scenario_id, resource, minor,
        )
        return [finding] if finding is not None else []
    munged = _munge_suspended_template(old_template, new_template)
    if _structural_equal(munged, new_template):
        finding = _finding(
            rules, "conditional-update-risk", "/spec/template",
            "Job spec.template changes to scheduling directives, template labels or "
            "annotations, or container resources are permitted only for suspended Jobs that "
            "never started (and, for resources, only with the matching feature gate); live "
            "Job status cannot be established from rendered YAML, so eligibility is "
            "unverified and the change is not treated as a definite rejection.",
            scenario_id, resource, minor,
        )
        return [finding] if finding is not None else []
    finding = _finding(
        rules, "job-template-immutable", "/spec/template",
        "batch/v1 Job spec.template is immutable; the candidate changes template fields that "
        "no suspended-Job exception permits (for example container image or command).",
        scenario_id, resource, minor,
    )
    return [finding] if finding is not None else []


def _job_findings(
    rules: dict[str, dict[str, Any]],
    old_document: dict[str, Any],
    new_document: dict[str, Any],
    scenario_id: Any,
    resource: dict[str, str],
    minor: str,
) -> list[dict[str, Any]]:
    old_spec = _strip_nils(copy.deepcopy(_spec_of(old_document)))
    new_spec = _strip_nils(copy.deepcopy(_spec_of(new_document)))
    findings: list[dict[str, Any]] = []

    completions_findings = _job_completions_findings(
        rules, old_spec, new_spec, scenario_id, resource, minor
    )
    findings.extend(completions_findings)

    old_selector = old_spec.get("selector")
    new_selector = new_spec.get("selector")
    if old_selector is not None and new_selector is not None:
        if not _structural_equal(old_selector, new_selector):
            finding = _finding(
                rules, "job-selector-immutable", "/spec/selector",
                "batch/v1 Job spec.selector is immutable when authored explicitly on both "
                "revisions; the candidate changes the explicit selector of an existing Job.",
                scenario_id, resource, minor,
            )
            if finding is not None:
                findings.append(finding)
    elif (old_selector is None) != (new_selector is None):
        finding = _finding(
            rules, "conditional-update-risk", "/spec/selector",
            "Job spec.selector is present on exactly one revision. The API server generates "
            "selectors on create, so the missing side cannot be fabricated and the difference "
            "cannot be classified from rendered YAML.",
            scenario_id, resource, minor,
        )
        if finding is not None:
            findings.append(finding)

    findings.extend(
        _job_template_findings(rules, old_spec, new_spec, scenario_id, resource, minor)
    )

    for field in sorted(_changed_keys(old_spec, new_spec)):
        rule_id = JOB_FIXED_FIELD_RULES.get(field)
        if rule_id is None:
            continue
        default_note = (
            " (an omitted value defaults to NonIndexed)" if field == "completionMode" else ""
        )
        finding = _finding(
            rules, rule_id, f"/spec/{field}",
            f"batch/v1 Job spec.{field} is immutable{default_note}; the candidate changes it "
            "on an existing Job.",
            scenario_id, resource, minor,
        )
        if finding is not None:
            findings.append(finding)

    if minor == "1.37":
        old_scheduling = old_spec.get("scheduling")
        new_scheduling = new_spec.get("scheduling")
        if not _structural_equal(old_scheduling, new_scheduling):
            finding = _finding(
                rules, "job-scheduling-update", "/spec/scheduling",
                "Job spec.scheduling is new in Kubernetes 1.37 and carries feature-gated "
                "declarative update restrictions (validateJobSchedulingUpdate freezes the "
                "basic/gang policy variant); this check inventories the change as partial "
                "coverage without certifying or rejecting it.",
                scenario_id, resource, minor,
            )
            if finding is not None:
                findings.append(finding)

    return findings


# --- core/v1 direct Pod ----------------------------------------------------


def _toleration_identity(toleration: Any) -> tuple[str, str, str, str]:
    """Identity used by validateOnlyAddedTolerations to match old entries.

    JSON null decodes to the Go zero value, so omitted and empty string are
    the same; tolerationSeconds is deliberately excluded, matching the
    upstream clone-and-compare in all three audited versions.
    """
    if not isinstance(toleration, dict):
        return ("", "", "", "")

    def text(value: Any) -> str:
        return value if isinstance(value, str) else ""

    return (
        text(toleration.get("key")),
        text(toleration.get("operator")),
        text(toleration.get("value")),
        text(toleration.get("effect")),
    )


def _gate_names(gates: Any) -> set[str]:
    if not isinstance(gates, list):
        return set()
    names: set[str] = set()
    for gate in gates:
        if isinstance(gate, dict) and isinstance(gate.get("name"), str):
            names.add(gate["name"])
    return names


def _term_has_only_additions(new_term: Any, old_term: Any) -> bool:
    if not isinstance(new_term, dict) or not isinstance(old_term, dict):
        return False
    old_expressions = old_term.get("matchExpressions") or []
    old_fields = old_term.get("matchFields") or []
    new_expressions = new_term.get("matchExpressions") or []
    new_fields = new_term.get("matchFields") or []
    if not old_expressions and not old_fields:
        if new_expressions or new_fields:
            return False
    if old_expressions:
        if len(new_expressions) < len(old_expressions):
            return False
        if not _structural_equal(new_expressions[: len(old_expressions)], old_expressions):
            return False
    if old_fields:
        if len(new_fields) < len(old_fields):
            return False
        if not _structural_equal(new_fields[: len(old_fields)], old_fields):
            return False
    return True


def _node_affinity_mutation_allowed(new_node_affinity: Any, old_node_affinity: Any) -> bool:
    """Port of validateNodeAffinityMutation for gated pods."""
    old_required = (
        old_node_affinity.get("requiredDuringSchedulingIgnoredDuringExecution")
        if isinstance(old_node_affinity, dict)
        else None
    )
    if old_node_affinity is None or old_required is None:
        return True
    old_terms = old_required.get("nodeSelectorTerms") if isinstance(old_required, dict) else None
    old_terms = old_terms if isinstance(old_terms, list) else []
    new_required = (
        new_node_affinity.get("requiredDuringSchedulingIgnoredDuringExecution")
        if isinstance(new_node_affinity, dict)
        else None
    )
    new_terms = (
        new_required.get("nodeSelectorTerms")
        if isinstance(new_required, dict)
        else None
    )
    new_terms = new_terms if isinstance(new_terms, list) else []
    if old_terms and len(old_terms) != len(new_terms):
        return False
    for index, old_term in enumerate(old_terms):
        if index >= len(new_terms) or not _term_has_only_additions(new_terms[index], old_term):
            return False
    return True


def _pod_update_violations(
    old_spec: dict[str, Any], new_spec: dict[str, Any]
) -> list[tuple[str, str]]:
    """Port of the spec checks in ValidatePodUpdate on defaulted copies."""
    violations: list[tuple[str, str]] = []

    for field in ("containers", "initContainers"):
        old_containers = old_spec.get(field)
        new_containers = new_spec.get(field)
        old_containers = old_containers if isinstance(old_containers, list) else []
        new_containers = new_containers if isinstance(new_containers, list) else []
        if len(old_containers) != len(new_containers):
            violations.append((f"/spec/{field}", "Direct Pod updates may not add or remove containers."))
            continue
        for index in range(len(old_containers)):
            old_container = old_containers[index]
            new_container = new_containers[index]
            if (
                not isinstance(old_container, dict)
                or not isinstance(new_container, dict)
                or old_container.get("name") != new_container.get("name")
            ):
                violations.append((
                    f"/spec/{field}/{index}",
                    "Direct Pod updates may not add, remove, or rename containers.",
                ))
                continue
            for key in _changed_keys(old_container, new_container):
                if key == "image":
                    continue
                if key == "resources":
                    violations.append((
                        f"/spec/{field}/{index}/resources",
                        "Direct Pod updates may not change container resources through the "
                        "normal update path; in-place resize is a separate pods/resize "
                        "subresource whose validation depends on live pod state.",
                    ))
                else:
                    violations.append((
                        f"/spec/{field}/{index}/{key}",
                        "Direct Pod updates may not change container fields other than image.",
                    ))

    old_deadline = old_spec.get("activeDeadlineSeconds")
    new_deadline = new_spec.get("activeDeadlineSeconds")
    if new_deadline is None:
        if old_deadline is not None:
            violations.append((
                "/spec/activeDeadlineSeconds",
                "Direct Pod spec.activeDeadlineSeconds must not be updated from a positive "
                "integer to a nil value.",
            ))
    elif old_deadline is None:
        pass  # nil to a positive value is allowed
    elif _is_int(old_deadline) and _is_int(new_deadline):
        if new_deadline > old_deadline:
            violations.append((
                "/spec/activeDeadlineSeconds",
                "Direct Pod spec.activeDeadlineSeconds may only be set or decreased.",
            ))
    elif not _structural_equal(old_deadline, new_deadline):
        violations.append((
            "/spec/activeDeadlineSeconds",
            "Direct Pod spec.activeDeadlineSeconds may only be set or decreased.",
        ))

    old_tolerations = old_spec.get("tolerations")
    new_tolerations = new_spec.get("tolerations")
    old_tolerations = old_tolerations if isinstance(old_tolerations, list) else []
    new_tolerations = new_tolerations if isinstance(new_tolerations, list) else []
    for index, old_toleration in enumerate(old_tolerations):
        identity = _toleration_identity(old_toleration)
        if not any(_toleration_identity(new_toleration) == identity for new_toleration in new_tolerations):
            violations.append((
                f"/spec/tolerations/{index}",
                "Direct Pod updates may not remove or modify an existing toleration except "
                "its tolerationSeconds; the original toleration entry must be preserved.",
            ))

    old_gates = _gate_names(old_spec.get("schedulingGates"))
    new_gates = _gate_names(new_spec.get("schedulingGates"))
    if new_gates - old_gates:
        violations.append((
            "/spec/schedulingGates",
            "Direct Pod schedulingGates may only be removed, not added.",
        ))

    gated = bool(old_gates)
    old_node_selector = old_spec.get("nodeSelector")
    new_node_selector = new_spec.get("nodeSelector")
    old_node_selector = old_node_selector if isinstance(old_node_selector, dict) else {}
    new_node_selector = new_node_selector if isinstance(new_node_selector, dict) else {}
    if gated and not _structural_equal(old_node_selector, new_node_selector):
        if not all(
            _structural_equal(new_node_selector.get(key), value)
            for key, value in old_node_selector.items()
        ):
            violations.append((
                "/spec/nodeSelector",
                "For scheduling-gated Pods, only additions to spec.nodeSelector are allowed "
                "(no mutations or deletions).",
            ))
    old_affinity = old_spec.get("affinity")
    new_affinity = new_spec.get("affinity")
    old_node_affinity = (
        old_affinity.get("nodeAffinity") if isinstance(old_affinity, dict) else None
    )
    new_node_affinity = (
        new_affinity.get("nodeAffinity") if isinstance(new_affinity, dict) else None
    )
    if gated and not _structural_equal(old_node_affinity, new_node_affinity):
        if not _node_affinity_mutation_allowed(new_node_affinity, old_node_affinity):
            violations.append((
                "/spec/affinity/nodeAffinity",
                "For scheduling-gated Pods, nodeAffinity required terms allow only additions "
                "(no added terms, mutations, or deletions).",
            ))

    old_grace = old_spec.get("terminationGracePeriodSeconds")
    new_grace = new_spec.get("terminationGracePeriodSeconds")
    repair = isinstance(old_grace, int) and old_grace < 0 and new_grace == 1
    if not repair and not _structural_equal(old_grace, new_grace):
        violations.append((
            "/spec/terminationGracePeriodSeconds",
            "Direct Pod spec.terminationGracePeriodSeconds is immutable except for the "
            "one-time repair to 1 from a previously negative value.",
        ))

    # Residual check: replicate the upstream munging of every allowed field
    # and report whatever still differs.
    munged = copy.deepcopy(new_spec)
    for field in ("containers", "initContainers"):
        old_containers = old_spec.get(field)
        new_containers = munged.get(field)
        old_containers = old_containers if isinstance(old_containers, list) else []
        new_containers = new_containers if isinstance(new_containers, list) else []
        if len(old_containers) != len(new_containers):
            continue
        munged_list: list[Any] = []
        for old_container, new_container in zip(old_containers, new_containers):
            if (
                isinstance(old_container, dict)
                and isinstance(new_container, dict)
                and old_container.get("name") == new_container.get("name")
            ):
                munged_container = copy.deepcopy(new_container)
                _copy_field(munged_container, old_container, "image")
                munged_list.append(munged_container)
            else:
                munged_list.append(new_container)
        if field in munged or munged_list:
            munged[field] = munged_list
    _copy_field(munged, old_spec, "activeDeadlineSeconds")
    _copy_field(munged, old_spec, "tolerations")
    _copy_field(munged, old_spec, "schedulingGates")
    _copy_field(munged, old_spec, "terminationGracePeriodSeconds")
    if gated:
        _copy_field(munged, old_spec, "nodeSelector")
        if old_affinity is not None or new_affinity is not None:
            munged_affinity = _munged_affinity(new_affinity, old_affinity)
            if munged_affinity is None:
                munged.pop("affinity", None)
            else:
                munged["affinity"] = munged_affinity
    for key in _changed_keys(old_spec, munged):
        already_reported = any(
            path == f"/spec/{key}" or path.startswith(f"/spec/{key}/")
            for path, _ in violations
        )
        if already_reported:
            continue
        if key == "ephemeralContainers":
            text = (
                "Direct Pod updates may not change ephemeralContainers through the normal "
                "update path; ephemeral containers are managed by the separate "
                "ephemeralcontainers subresource."
            )
        else:
            text = _RESIDUAL_POD_TEXT
        violations.append((f"/spec/{key}", text))

    return violations


def _pod_findings(
    rules: dict[str, dict[str, Any]],
    old_document: dict[str, Any],
    new_document: dict[str, Any],
    scenario_id: Any,
    resource: dict[str, str],
    minor: str,
) -> list[dict[str, Any]]:
    old_raw = _strip_nils(copy.deepcopy(_spec_of(old_document)))
    new_raw = _strip_nils(copy.deepcopy(_spec_of(new_document)))
    if _structural_equal(old_raw, new_raw):
        return []
    _apply_podspec_defaults(old_raw, pod_object=True)
    _apply_podspec_defaults(new_raw, pod_object=True)
    if _structural_equal(old_raw, new_raw):
        finding = _finding(
            rules, "conditional-update-risk", "/spec",
            "Direct Pod spec differs only by omission versus known pod-spec defaults "
            "(restartPolicy, dnsPolicy, schedulerName, terminationGracePeriodSeconds, "
            "securityContext, serviceAccount aliasing, requests defaulted from limits, or "
            "enableServiceLinks); whether the API server re-applies these defaults on the "
            "update path depends on the request mechanics, so the difference cannot be "
            "classified from rendered YAML.",
            scenario_id, resource, minor,
        )
        return [finding] if finding is not None else []
    findings: list[dict[str, Any]] = []
    for path, text in _pod_update_violations(old_raw, new_raw):
        finding = _finding(rules, "pod-update-restricted", path, text, scenario_id, resource, minor)
        if finding is not None:
            findings.append(finding)
    return findings


# --- entry point -----------------------------------------------------------


def compare(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    scenario: dict[str, Any],
    catalogue: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compare normalized workload object maps and return findings.

    Pure function: neither the object maps, the scenario, nor the catalogue
    are mutated. Only same-identity objects present in both revisions are
    compared; removals and graph relationships are handled by other policy
    modules. Every emitted finding carries the catalogue's registered ID,
    severity, evidence, and classification.
    """
    minor = _minor_of(scenario)
    supported = set(catalogue.get("kubernetes", {}).get("supported_minor_versions", []))
    if minor is None or minor not in supported:
        return []
    rules: dict[str, dict[str, Any]] = {
        rule["id"]: rule for rule in catalogue.get("rules", []) if isinstance(rule, dict)
    }
    scenario_id = scenario.get("id")
    baseline_objects = baseline.get("objects") or {}
    candidate_objects = candidate.get("objects") or {}
    findings: list[dict[str, Any]] = []

    for key in sorted(set(baseline_objects) & set(candidate_objects)):
        group, kind = key[0], key[1]
        if kind not in WORKLOAD_KINDS or group not in EXPECTED_API_VERSIONS:
            continue
        old_document = baseline_objects[key]["document"]
        new_document = candidate_objects[key]["document"]
        resource = {
            "group": group,
            "kind": kind,
            "namespace": key[2],
            "name": key[3],
        }
        expected = EXPECTED_API_VERSIONS[group]
        if (
            old_document.get("apiVersion") != expected
            or new_document.get("apiVersion") != expected
        ):
            finding = _finding(
                rules, "rule-coverage-partial", "/apiVersion",
                f"Workload update rules are audited for {expected}; the rendered {kind} "
                "declares a different apiVersion, so no stable-rule comparison was applied "
                "and no beta alias silently reuses an audited rule.",
                scenario_id, resource, minor,
            )
            if finding is not None:
                findings.append(finding)
            continue
        if group == "apps":
            if kind == "StatefulSet":
                findings.extend(
                    _statefulset_findings(rules, old_document, new_document, scenario_id, resource, minor)
                )
            elif kind == "ControllerRevision":
                findings.extend(
                    _controllerrevision_findings(rules, old_document, new_document, scenario_id, resource, minor)
                )
            else:
                rule_id = SELECTOR_RULE_IDS.get((group, kind))
                if rule_id is not None:
                    findings.extend(
                        _selector_findings(
                            rules, rule_id, kind, old_document, new_document,
                            scenario_id, resource, minor,
                        )
                    )
        elif group == "batch":
            if kind == "Job":
                findings.extend(
                    _job_findings(rules, old_document, new_document, scenario_id, resource, minor)
                )
            # CronJob jobTemplate changes affect future Jobs only; no
            # Job-template immutability is applied to them.
        elif kind == "Pod":
            findings.extend(
                _pod_findings(rules, old_document, new_document, scenario_id, resource, minor)
            )

    findings.sort(
        key=lambda finding: (
            finding["resource"]["group"],
            finding["resource"]["kind"],
            finding["resource"]["namespace"],
            finding["resource"]["name"],
            finding["id"],
            finding["path"],
        )
    )
    return findings
