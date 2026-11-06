"""Metadata regression tests for the manifest compatibility policy catalogue.

These tests validate the finite registry itself: stable IDs, declared
strategies, source provenance, version coverage, waiver eligibility, and the
documented conditional/inventory coverage. They deliberately import no runtime
comparison handlers; runner integration verifies emitted IDs against this
registry once the policy modules exist.
"""

import json
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[3]
POLICY = ROOT / "modules" / "manifest-compat" / "policy.json"

SEVERITIES = {"error", "warn", "info"}
EVIDENCE = {"api-rule", "local-graph", "declared-contract", "unverified"}
CLASSIFICATIONS = {
    "immutable", "selector", "reference", "contract", "risk",
    "coverage", "removal", "render-validation",
}
WAIVER_ELIGIBILITY = {"baseline-comparison-only", "never"}
STATUSES = {"active", "inventory"}

RESERVED_IDS = [
    "selector-template-mismatch",
    "selector-target-lost",
    "mutable-selector-changed",
    "required-reference-lost",
    "external-reference-unverified",
    "label-removed",
    "label-value-changed",
    "protected-label-changed",
    "resource-removed",
    "protected-resource-removed",
    "conditional-update-risk",
    "rule-coverage-partial",
    "patch-coverage-extrapolated",
    "stale-exception",
]


@pytest.fixture(scope="module")
def policy() -> dict[str, Any]:
    return json.loads(POLICY.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def rules(policy: dict[str, Any]) -> list[dict[str, Any]]:
    return policy["rules"]


@pytest.fixture(scope="module")
def rule_ids(rules: list[dict[str, Any]]) -> set[str]:
    return {rule["id"] for rule in rules}


class TestCatalogueShape:
    def test_policy_version_is_declared(self, policy: dict[str, Any]) -> None:
        assert isinstance(policy["policy_version"], str)
        assert policy["policy_version"]

    def test_reserved_ids_are_registered(self, rule_ids: set[str]) -> None:
        missing = [identifier for identifier in RESERVED_IDS if identifier not in rule_ids]
        assert not missing, f"reserved finding IDs missing from the registry: {missing}"

    def test_rule_ids_are_unique(self, rules: list[dict[str, Any]]) -> None:
        identifiers = [rule["id"] for rule in rules]
        duplicates = sorted({identifier for identifier in identifiers if identifiers.count(identifier) > 1})
        assert not duplicates, f"duplicate rule IDs: {duplicates}"

    def test_rule_ids_are_stable_identifiers(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            assert rule["id"] == rule["id"].strip()
            assert " " not in rule["id"], f"rule ID must be a stable identifier: {rule['id']}"

    def test_enum_fields_are_valid(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            identifier = rule["id"]
            assert rule["severity"] in SEVERITIES, identifier
            assert rule["evidence"] in EVIDENCE, identifier
            assert rule["classification"] in CLASSIFICATIONS, identifier
            assert rule["waiver_eligibility"] in WAIVER_ELIGIBILITY, identifier
            assert rule["status"] in STATUSES, identifier
            assert isinstance(rule["relational"], bool), identifier

    def test_strategies_are_declared(self, policy: dict[str, Any], rules: list[dict[str, Any]]) -> None:
        declared = set(policy["strategies"])
        for rule in rules:
            assert rule["strategy"] in declared, f"{rule['id']}: unknown strategy {rule['strategy']!r}"
        # Every declared strategy is used by at least one rule or documents
        # an explicitly reserved mechanism.
        used = {rule["strategy"] for rule in rules}
        unused = sorted(declared - used)
        assert not unused, f"declared but unused strategies: {unused}"

    def test_paths_are_json_pointer_shaped(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            for path in rule["paths"]:
                assert path == "" or not path.startswith("/"), f"{rule['id']}: absolute JSON Pointer {path!r}"

    def test_defaults_are_path_scoped(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            paths = rule["paths"]
            for key in rule.get("defaults", {}):
                assert any(key == path or key.startswith(path) for path in paths), (
                    f"{rule['id']}: default {key!r} is outside the rule's paths {paths}"
                )


class TestVersionCoverage:
    def test_supported_minors_are_audited(self, policy: dict[str, Any]) -> None:
        kubernetes = policy["kubernetes"]
        minors = kubernetes["supported_minor_versions"]
        assert minors == ["1.35", "1.36", "1.37"]
        assert set(kubernetes["audited_sources"]) == set(minors)
        assert kubernetes["same_minor_extrapolation"]

    def test_audited_sources_pin_full_commits(self, policy: dict[str, Any]) -> None:
        for minor, source in policy["kubernetes"]["audited_sources"].items():
            assert source["tag"], minor
            commit = source["commit"]
            assert len(commit) == 40 and all(c in "0123456789abcdef" for c in commit), minor

    def test_rule_versions_are_supported_and_nonempty(self, policy: dict[str, Any], rules: list[dict[str, Any]]) -> None:
        supported = set(policy["kubernetes"]["supported_minor_versions"])
        for rule in rules:
            versions = rule["versions"]
            assert versions, f"{rule['id']}: no version coverage"
            assert set(versions) <= supported, f"{rule['id']}: unsupported minors {set(versions) - supported}"

    def test_version_behavior_keys_are_declared_versions(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            extra = set(rule.get("version_behavior", {})) - set(rule["versions"])
            assert not extra, f"{rule['id']}: version_behavior for undeclared versions {extra}"

    def test_no_contradictory_overlapping_rules(self, rules: list[dict[str, Any]]) -> None:
        active = [rule for rule in rules if rule["status"] == "active"]
        seen: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for rule in active:
            for path in rule["paths"]:
                for version in rule["versions"]:
                    key = (rule["group"], rule["kind"], path, version)
                    other = seen.get(key)
                    if other is not None and other["severity"] != rule["severity"]:
                        # Same scope with different severity is only acceptable
                        # when the rules document their mutual exclusivity by
                        # cross-referencing each other's guards or rationale.
                        texts = " ".join(other["guards"] + [other.get("rationale", "")])
                        if rule["id"] in texts:
                            continue
                        raise AssertionError(
                            f"contradictory overlapping rules for {key}: "
                            f"{other['id']} ({other['severity']}) vs {rule['id']} ({rule['severity']})"
                        )
                    seen[key] = rule


class TestProvenance:
    def test_api_rules_cite_sources_for_every_version(self, policy: dict[str, Any], rules: list[dict[str, Any]]) -> None:
        supported = set(policy["kubernetes"]["supported_minor_versions"])
        for rule in rules:
            if rule["authority"] != "api-rule":
                continue
            sources = rule["sources"]
            assert sources, f"{rule['id']}: api-rule without sources"
            minors = set()
            for source in sources:
                assert source["minor"] in supported, f"{rule['id']}: source for unsupported minor"
                assert source["path"].endswith(".go"), f"{rule['id']}: source path is not Go source"
                assert source["symbol"], f"{rule['id']}: source without a symbol"
                minors.add(source["minor"])
            missing = set(rule["versions"]) - minors
            assert not missing, f"{rule['id']}: no source citation for versions {missing}"

    def test_repository_policy_rules_have_rationale(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            if rule["authority"] == "repository-policy":
                assert rule.get("rationale"), f"{rule['id']}: repository-policy without rationale"
                assert not rule.get("sources"), (
                    f"{rule['id']}: repository-policy must not fabricate an API-rejection source"
                )

    def test_api_rules_do_not_need_rationale(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            if rule["authority"] == "api-rule":
                assert rule.get("sources"), f"{rule['id']}: api-rule without sources"

    def test_authority_values(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            assert rule["authority"] in {"api-rule", "repository-policy"}, rule["id"]


class TestConditionalCoverage:
    def test_inventory_rules_are_documented(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            if rule["status"] == "inventory":
                assert rule.get("coverage_note"), f"{rule['id']}: inventory rule without coverage note"

    def test_unverified_api_rules_document_the_gap(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            if rule["authority"] == "api-rule" and rule["evidence"] == "unverified":
                assert rule.get("coverage_note"), f"{rule['id']}: unverified rule without coverage note"

    def test_warn_rules_cannot_be_waived(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            if rule["severity"] == "warn":
                assert rule["waiver_eligibility"] == "never", (
                    f"{rule['id']}: warning findings are never waiver-eligible"
                )

    def test_only_comparison_findings_are_waivable(self, rules: list[dict[str, Any]]) -> None:
        waivable = {rule["id"] for rule in rules if rule["waiver_eligibility"] == "baseline-comparison-only"}
        assert waivable, "at least one rule must be waivable"
        for rule in rules:
            if rule["waiver_eligibility"] == "baseline-comparison-only":
                assert rule["severity"] == "error", f"{rule['id']}: waivable rule must be error-severity"


class TestAuditedCorrections:
    """Pin the source-audited facts that contradict naive immutability assumptions."""

    def test_pod_tolerations_seconds_edits_allowed_everywhere(self, rules: list[dict[str, Any]]) -> None:
        rule = next(rule for rule in rules if rule["id"] == "pod-update-restricted")
        assert rule["versions"] == ["1.35", "1.36", "1.37"]
        assert any("tolerationSeconds" in guard for guard in rule["guards"]), (
            "pod update rule must explicitly allow existing tolerationSeconds edits in all audited versions"
        )

    def test_config_immutability_is_baseline_gated(self, rules: list[dict[str, Any]]) -> None:
        for identifier in ("configmap-immutable-data", "secret-immutable-data"):
            rule = next(rule for rule in rules if rule["id"] == identifier)
            assert rule["strategy"] == "baseline-gated-immutable", identifier

    def test_pvc_resize_is_conditional_not_frozen(self, rules: list[dict[str, Any]]) -> None:
        rule = next(rule for rule in rules if rule["id"] == "pvc-storage-resize-risk")
        assert rule["severity"] == "warn"
        assert rule["evidence"] == "unverified"
        assert not any(
            rule["id"].startswith("pvc") and "shrink" in rule["id"] for rule in rules
        ), "no universal PVC-shrink rule may exist"

    def test_job_template_rule_keeps_suspended_exceptions(self, rules: list[dict[str, Any]]) -> None:
        rule = next(rule for rule in rules if rule["id"] == "job-template-immutable")
        assert any("suspended" in guard for guard in rule["guards"])

    def test_service_rules_are_transition_scoped(self, rules: list[dict[str, Any]]) -> None:
        for identifier in (
            "service-cluster-ips-transition",
            "service-ip-families-transition",
            "service-load-balancer-class-immutable",
            "service-health-check-node-port-immutable",
        ):
            rule = next(rule for rule in rules if rule["id"] == identifier)
            assert rule["strategy"] in {"transition-validated", "conditional-immutable"}, identifier

    def test_pv_reclaim_policy_has_no_rule(self, rule_ids: set[str]) -> None:
        assert not any("reclaim" in identifier for identifier in rule_ids if identifier.startswith("pv-")), (
            "PV persistentVolumeReclaimPolicy is mutable; no rule may freeze it"
        )

    def test_csr_update_is_ignored_not_rejected(self, rules: list[dict[str, Any]]) -> None:
        rule = next(rule for rule in rules if rule["id"] == "csr-spec-ignored-update")
        assert rule["strategy"] == "ignored-update"
        assert any("ignored" in guard.lower() or "ineffective" in guard.lower() for guard in rule["guards"])

    def test_statefulset_allowlist_only_for_older_minors(self, rules: list[dict[str, Any]]) -> None:
        rule = next(rule for rule in rules if rule["id"] == "statefulset-spec-field-forbidden")
        assert rule["versions"] == ["1.35", "1.36"]
        direct = next(rule for rule in rules if rule["id"] == "statefulset-selector-immutable")
        assert direct["versions"] == ["1.35", "1.36", "1.37"]

    def test_certificate_and_migration_stable_rules_are_137_only(self, rules: list[dict[str, Any]]) -> None:
        for identifier in (
            "clustertrustbundle-signer-name-immutable",
            "podcertificaterequest-spec-immutable",
            "storageversionmigration-spec-immutable",
        ):
            rule = next(rule for rule in rules if rule["id"] == identifier)
            assert rule["versions"] == ["1.37"], identifier
            assert rule.get("coverage_note"), f"{identifier}: must document earlier beta-only forms"

    def test_cronjob_template_is_not_frozen(self, rule_ids: set[str]) -> None:
        assert "cronjob-jobtemplate-mutable" in rule_ids

    def test_controllerrevision_freezes_data_only(self, rules: list[dict[str, Any]]) -> None:
        rule = next(rule for rule in rules if rule["id"] == "controllerrevision-data-immutable")
        assert rule["paths"] == ["data"]


class TestRelationalMetadata:
    def test_relational_rules_are_declared(self, rules: list[dict[str, Any]]) -> None:
        relational = {rule["id"] for rule in rules if rule["relational"]}
        assert {"selector-target-lost", "required-reference-lost"} <= relational
        for rule in rules:
            if rule["relational"]:
                assert rule["family"] in {"relationships", "workloads"}, rule["id"]

    def test_render_validation_is_never_waivable(self, rules: list[dict[str, Any]]) -> None:
        for rule in rules:
            if rule["classification"] == "render-validation":
                assert rule["waiver_eligibility"] == "never", rule["id"]

    def test_graph_rules_document_consumer_anchor(self, rules: list[dict[str, Any]]) -> None:
        for identifier in ("selector-target-lost", "mutable-selector-changed", "required-reference-lost"):
            rule = next(rule for rule in rules if rule["id"] == identifier)
            assert rule.get("rationale") or rule["guards"], identifier
