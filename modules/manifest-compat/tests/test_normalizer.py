"""Regression tests for the rendered-manifest normalizer.

Covers the parsing matrix from the standing testing rules: multi-document and
List handling, duplicate mappings/identities, unknown scopes, namespaces,
stripped server metadata, effective Secret bytes, known defaults, numeric
quantities, order-sensitive arrays, and skip records for Helm hooks and CRDs.
"""

import base64
import copy
import importlib.util
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "modules" / "manifest-compat" / "normalizer.py"

spec = importlib.util.spec_from_file_location("manifest_normalizer_test", MODULE_PATH)
assert spec is not None and spec.loader is not None
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)

NormalizeError = normalizer.NormalizeError

SCENARIO: dict[str, Any] = {
    "id": "test-scenario",
    "renderer": "raw",
    "namespace": "rhoai",
    "kubernetesVersion": "1.36.6",
    "sources": ["rendered.yaml"],
}

SECRET_MARKER = "super-secret-value"


def normalize(content: str, scenario: dict[str, Any] | None = None) -> dict[str, Any]:
    return normalizer.normalize(
        content.encode("utf-8"), "rendered.yaml", scenario if scenario is not None else SCENARIO
    )


def objects_of(result: dict[str, Any]) -> dict[Any, dict[str, Any]]:
    return result["objects"]


class TestDocumentParsing:
    def test_multi_document_with_empty_separators(self) -> None:
        result = normalize(
            "---\n"
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\n"
            "# comment only, then an empty document\n"
            "---\n"
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n"
        )
        objects = objects_of(result)
        assert set(objects) == {("", "ConfigMap", "rhoai", "a"), ("", "ConfigMap", "rhoai", "b")}
        assert objects[("", "ConfigMap", "rhoai", "a")]["document_index"] == 1
        assert objects[("", "ConfigMap", "rhoai", "b")]["document_index"] == 2
        assert objects[("", "ConfigMap", "rhoai", "a")]["source"] == "rendered.yaml"

    def test_kind_list_recursion(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: List\nitems:\n"
            "- apiVersion: v1\n"
            "  kind: ConfigMap\n"
            "  metadata:\n"
            "    name: outer\n"
            "- apiVersion: v1\n"
            "  kind: List\n"
            "  items:\n"
            "  - apiVersion: v1\n"
            "    kind: ConfigMap\n"
            "    metadata:\n"
            "      name: inner\n"
        )
        objects = objects_of(result)
        assert ("", "ConfigMap", "rhoai", "outer") in objects
        assert ("", "ConfigMap", "rhoai", "inner") in objects

    def test_empty_list_is_valid(self) -> None:
        result = normalize("apiVersion: v1\nkind: List\nitems: []\n")
        assert objects_of(result) == {}
        assert result["coverage"]["object_count"] == 0

    def test_malformed_list_items_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="malformed items"):
            normalize("apiVersion: v1\nkind: List\nmetadata:\n  name: l\n")

    def test_list_item_non_object_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="non-object YAML document"):
            normalize("apiVersion: v1\nkind: List\nitems:\n- just-a-string\n")

    def test_non_object_document_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="non-object YAML document"):
            normalize("- one\n- two\n")

    def test_duplicate_mapping_keys_are_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="Cannot parse YAML"):
            normalize(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  name: b\n"
            )

    def test_non_string_mapping_key_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="Cannot parse YAML"):
            normalize("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n1: value\n")

    def test_unsupported_yaml_scalar_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="unsupported YAML scalar type"):
            normalize(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"
                "data:\n  when: 2024-01-01\n"
            )

    def test_missing_api_version_or_kind_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="missing apiVersion or kind"):
            normalize("metadata:\n  name: a\n")

    def test_invalid_multi_slash_api_version_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="invalid apiVersion"):
            normalize("apiVersion: a/b/c\nkind: ConfigMap\nmetadata:\n  name: a\n")

    def test_missing_name_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="missing metadata.name"):
            normalize("apiVersion: v1\nkind: ConfigMap\nmetadata: {}\n")

    def test_generate_name_only_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="generateName"):
            normalize(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  generateName: widget-\n"
            )

    def test_duplicate_identity_is_rejected(self) -> None:
        document = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"
        with pytest.raises(NormalizeError, match="duplicate resource identity"):
            normalize(document + "---\n" + document)

    def test_identical_duplicate_identity_is_still_rejected(self) -> None:
        document = (
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"
            "immutable: true\ndata:\n  k: v\n"
        )
        with pytest.raises(NormalizeError, match="duplicate resource identity"):
            normalize(document + "---\n" + document)

    def test_same_identity_different_api_version_is_duplicate(self) -> None:
        with pytest.raises(NormalizeError, match="duplicate resource identity"):
            normalize(
                "apiVersion: demo.example.com/v1\nkind: Widget\nmetadata:\n  name: a\n  namespace: wns\n"
                "---\napiVersion: demo.example.com/v2\nkind: Widget\nmetadata:\n  name: a\n  namespace: wns\n"
            )

    def test_api_version_stays_in_document_not_identity(self) -> None:
        result = normalize("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n")
        key = ("", "ConfigMap", "rhoai", "a")
        assert objects_of(result)[key]["document"]["apiVersion"] == "v1"

    def test_distinct_scenarios_keep_same_names_separate(self) -> None:
        content = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: shared\n"
        scenario_a = dict(SCENARIO, id="a")
        scenario_b = dict(SCENARIO, id="b")
        result_a = normalize(content, scenario_a)
        result_b = normalize(content, scenario_b)
        assert ("", "ConfigMap", "rhoai", "shared") in objects_of(result_a)
        assert ("", "ConfigMap", "rhoai", "shared") in objects_of(result_b)

    def test_scenario_is_not_mutated(self) -> None:
        scenario = copy.deepcopy(SCENARIO)
        snapshot = copy.deepcopy(SCENARIO)
        normalize("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n", scenario)
        assert scenario == snapshot


class TestNamespacesAndScopes:
    def test_explicit_namespace_wins_over_scenario(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: other\n"
        )
        assert ("", "ConfigMap", "other", "a") in objects_of(result)

    def test_scenario_namespace_used_for_namespaced_kind(self) -> None:
        result = normalize(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n"
        )
        assert ("apps", "Deployment", "rhoai", "api") in objects_of(result)

    def test_namespace_on_cluster_scoped_kind_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="cluster-scoped"):
            normalize(
                "apiVersion: storage.k8s.io/v1\nkind: StorageClass\n"
                "metadata:\n  name: fast\n  namespace: rhoai\n"
            )

    def test_invalid_namespace_value_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="invalid metadata.namespace"):
            normalize(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: Not A Ns\n"
            )

    def test_unknown_kind_without_scope_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="cannot determine whether"):
            normalize("apiVersion: demo.example.com/v1\nkind: Widget\nmetadata:\n  name: a\n")

    def test_unknown_kind_with_explicit_namespace_resolves(self) -> None:
        result = normalize(
            "apiVersion: demo.example.com/v1\nkind: Widget\nmetadata:\n  name: a\n  namespace: wns\n"
        )
        assert ("demo.example.com", "Widget", "wns", "a") in objects_of(result)

    def test_kindscopes_resolve_unknown_kind(self) -> None:
        scenario = dict(SCENARIO)
        scenario["kindScopes"] = [
            {"group": "demo.example.com", "kind": "Widget", "scope": "Namespaced"}
        ]
        result = normalize(
            "apiVersion: demo.example.com/v1\nkind: Widget\nmetadata:\n  name: a\n", scenario
        )
        assert ("demo.example.com", "Widget", "rhoai", "a") in objects_of(result)

    def test_rendered_crd_provides_scope(self) -> None:
        result = normalize(
            "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
            "metadata:\n  name: widgets.demo.example.com\n"
            "spec:\n  group: demo.example.com\n  scope: Namespaced\n  names:\n    kind: Widget\n"
            "---\napiVersion: demo.example.com/v1\nkind: Widget\nmetadata:\n  name: a\n"
        )
        assert ("demo.example.com", "Widget", "rhoai", "a") in objects_of(result)

    def test_kindscopes_conflicting_with_crd_is_rejected(self) -> None:
        scenario = dict(SCENARIO)
        scenario["kindScopes"] = [
            {"group": "demo.example.com", "kind": "Widget", "scope": "Cluster"}
        ]
        with pytest.raises(NormalizeError, match="kindScopes declares"):
            normalize(
                "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
                "metadata:\n  name: widgets.demo.example.com\n"
                "spec:\n  group: demo.example.com\n  scope: Namespaced\n  names:\n    kind: Widget\n"
                "---\napiVersion: demo.example.com/v1\nkind: Widget\nmetadata:\n  name: a\n  namespace: x\n",
                scenario,
            )

    def test_malformed_crd_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="CustomResourceDefinition is missing"):
            normalize(
                "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
                "metadata:\n  name: broken\nspec:\n  group: demo.example.com\n"
            )


class TestStripping:
    def test_server_metadata_and_status_are_stripped(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
            "  name: a\n  uid: aaa\n  resourceVersion: '42'\n  creationTimestamp: '2024-01-01T00:00:00Z'\n"
            "  managedFields:\n  - manager: kubectl\n  generation: 3\n  deletionTimestamp: '2024-02-01T00:00:00Z'\n"
            "  deletionGracePeriodSeconds: 30\n"
            "  labels:\n    keep: me\n"
            "  annotations:\n    kubectl.kubernetes.io/last-applied-configuration: '{}'\n"
            "    keep: this\n"
            "data:\n  k: v\nstatus:\n  observed: true\n"
        )
        document = objects_of(result)[("", "ConfigMap", "rhoai", "a")]["document"]
        assert "status" not in document
        metadata = document["metadata"]
        assert set(metadata) == {"name", "labels", "annotations"}
        assert metadata["labels"] == {"keep": "me"}
        assert metadata["annotations"] == {"keep": "this"}


class TestSecretsAndConfigMaps:
    def test_secret_data_is_canonicalized_and_sorted(self) -> None:
        raw = base64.b64encode(b"plain").decode("ascii")
        noncanonical = base64.b64encode(b"plain").decode("ascii")
        result = normalize(
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
            f"data:\n  z: {raw}\n  a: {noncanonical}\n"
        )
        document = objects_of(result)[("", "Secret", "rhoai", "s")]["document"]
        assert document["type"] == "Opaque"
        assert list(document["data"]) == ["a", "z"]
        assert base64.b64decode(document["data"]["a"]) == b"plain"

    def test_secret_string_data_overrides_data(self) -> None:
        raw = base64.b64encode(b"old").decode("ascii")
        override = base64.b64encode(SECRET_MARKER.encode("utf-8")).decode("ascii")
        result = normalize(
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
            f"data:\n  shared: {raw}\n"
            "stringData:\n  shared: super-secret-value\n  extra: another\n"
        )
        document = objects_of(result)[("", "Secret", "rhoai", "s")]["document"]
        assert base64.b64decode(document["data"]["shared"]) == SECRET_MARKER.encode("utf-8")
        assert base64.b64decode(document["data"]["extra"]) == b"another"
        assert "stringData" not in document

    def test_secret_explicit_type_is_preserved(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ntype: kubernetes.io/dockerconfigjson\ndata: {}\n"
        )
        document = objects_of(result)[("", "Secret", "rhoai", "s")]["document"]
        assert document["type"] == "kubernetes.io/dockerconfigjson"

    def test_secret_invalid_base64_is_rejected_without_leaking(self) -> None:
        with pytest.raises(NormalizeError, match="not valid base64") as excinfo:
            normalize(
                "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
                "data:\n  key: 'not@base64!'\n"
            )
        assert "not@base64!" not in str(excinfo.value)

    def test_configmap_invalid_binary_data_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="not valid base64"):
            normalize(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n"
                "binaryData:\n  key: 'not@base64!'\n"
            )

    def test_configmap_binary_data_is_canonicalized(self) -> None:
        raw = base64.b64encode(b"blob").decode("ascii")
        result = normalize(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n"
            f"binaryData:\n  blob: {raw}\n"
        )
        document = objects_of(result)[("", "ConfigMap", "rhoai", "c")]["document"]
        assert base64.b64decode(document["binaryData"]["blob"]) == b"blob"


class TestDefaultsAndQuantities:
    def test_pvc_volume_mode_and_quantity_defaults(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: p\n"
            "spec:\n  accessModes: [ReadWriteOnce]\n  resources:\n    requests:\n      storage: 1Gi\n"
        )
        document = objects_of(result)[("", "PersistentVolumeClaim", "rhoai", "p")]["document"]
        assert document["spec"]["volumeMode"] == "Filesystem"
        assert document["spec"]["resources"]["requests"]["storage"] == "1073741824"

    def test_explicit_default_equivalent_values_are_untouched(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: p\n"
            "spec:\n  volumeMode: Filesystem\n  resources:\n    requests:\n      storage: 1073741824\n"
        )
        document = objects_of(result)[("", "PersistentVolumeClaim", "rhoai", "p")]["document"]
        assert document["spec"]["volumeMode"] == "Filesystem"
        assert document["spec"]["resources"]["requests"]["storage"] == "1073741824"

    def test_quantity_suffixes_are_numeric(self) -> None:
        cases = {
            "1Ki": "1024", "1k": "1000", "1M": "1000000", "5G": "5000000000",
            "0.5Gi": "536870912", "1.5Gi": "1610612736", "1e3": "1000",
            "512": "512", "100m": "1/10",
        }
        for value, expected in cases.items():
            assert normalizer.canonical_quantity(value, "where") == expected, value

    def test_plain_yaml_integer_quantity(self) -> None:
        assert normalizer.canonical_quantity(512, "where") == "512"

    def test_invalid_quantity_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="cannot parse quantity"):
            normalizer.canonical_quantity("lots", "where")

    def test_unknown_quantity_suffix_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="unknown quantity suffix"):
            normalizer.canonical_quantity("1Xi", "where")

    def test_cpu_quantities_are_not_canonicalized(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n"
            "  - name: c\n    image: i\n    resources:\n      requests:\n        cpu: 250m\n"
        )
        document = objects_of(result)[("", "Pod", "rhoai", "p")]["document"]
        assert document["spec"]["containers"][0]["resources"]["requests"]["cpu"] == "250m"

    def test_storageclass_defaults(self) -> None:
        result = normalize(
            "apiVersion: storage.k8s.io/v1\nkind: StorageClass\nmetadata:\n  name: sc\n"
            "provisioner: p\n"
        )
        document = objects_of(result)[("storage.k8s.io", "StorageClass", "", "sc")]["document"]
        assert document["reclaimPolicy"] == "Delete"
        assert document["volumeBindingMode"] == "Immediate"

    def test_priorityclass_default(self) -> None:
        result = normalize(
            "apiVersion: scheduling.k8s.io/v1\nkind: PriorityClass\nmetadata:\n  name: pc\nvalue: 100\n"
        )
        document = objects_of(result)[("scheduling.k8s.io", "PriorityClass", "", "pc")]["document"]
        assert document["preemptionPolicy"] == "PreemptLowerPriority"

    def test_statefulset_defaults_including_claim_templates(self) -> None:
        result = normalize(
            "apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: s\n"
            "spec:\n  selector:\n    matchLabels: {app: s}\n"
            "  template:\n    metadata:\n      labels: {app: s}\n    spec:\n      containers: []\n"
            "  volumeClaimTemplates:\n  - metadata:\n      name: data\n    spec:\n"
            "      resources:\n        requests:\n          storage: 512Mi\n"
        )
        document = objects_of(result)[("apps", "StatefulSet", "rhoai", "s")]["document"]
        assert document["spec"]["podManagementPolicy"] == "OrderedReady"
        template = document["spec"]["volumeClaimTemplates"][0]
        assert template["spec"]["volumeMode"] == "Filesystem"
        assert template["spec"]["resources"]["requests"]["storage"] == "536870912"

    def test_job_completion_mode_default(self) -> None:
        result = normalize(
            "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: j\nspec:\n  template:\n"
            "    spec:\n      containers: []\n"
        )
        document = objects_of(result)[("batch", "Job", "rhoai", "j")]["document"]
        assert document["spec"]["completionMode"] == "NonIndexed"

    def test_resourcequota_scopes_are_a_set(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: ResourceQuota\nmetadata:\n  name: q\n"
            "spec:\n  scopes: [BestEffort, Terminating, PriorityClass]\n"
        )
        document = objects_of(result)[("", "ResourceQuota", "rhoai", "q")]["document"]
        assert document["spec"]["scopes"] == ["BestEffort", "PriorityClass", "Terminating"]

    def test_array_order_is_preserved(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n"
            "  - name: first\n    image: a\n  - name: second\n    image: b\n"
        )
        document = objects_of(result)[("", "Pod", "rhoai", "p")]["document"]
        assert [container["name"] for container in document["spec"]["containers"]] == ["first", "second"]


class TestLabelAndSelectorShapes:
    def test_invalid_labels_mapping_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="metadata.labels"):
            normalize(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  labels: not-a-map\n"
            )

    def test_non_string_label_value_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="metadata.labels"):
            normalize(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  labels: {k: 3}\n"
            )

    def test_invalid_template_labels_are_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="spec.template.metadata.labels"):
            normalize(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n"
                "spec:\n  template:\n    metadata:\n      labels: []\n"
            )

    def test_match_labels_non_map_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="spec.selector"):
            normalize(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n"
                "spec:\n  selector: {matchLabels: nope}\n"
            )

    def test_match_expression_missing_key_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="matchExpressions"):
            normalize(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n"
                "spec:\n  selector:\n    matchExpressions:\n    - operator: In\n      values: [a]\n"
            )

    def test_match_expression_bad_operator_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="operator"):
            normalize(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n"
                "spec:\n  selector:\n    matchExpressions:\n    - key: k\n      operator: Contains\n"
            )

    def test_in_expression_without_values_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="values"):
            normalize(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n"
                "spec:\n  selector:\n    matchExpressions:\n    - key: k\n      operator: In\n"
            )

    def test_valid_selector_forms_are_accepted(self) -> None:
        result = normalize(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n"
            "spec:\n  selector:\n    matchLabels: {app: d}\n"
            "    matchExpressions:\n    - key: tier\n      operator: In\n      values: [web]\n"
            "    - key: legacy\n      operator: DoesNotExist\n"
            "  template:\n    metadata:\n      labels: {app: d}\n"
            "    spec:\n      containers: []\n"
        )
        assert ("apps", "Deployment", "rhoai", "d") in objects_of(result)

    def test_service_plain_map_selector_is_accepted(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n"
            "spec:\n  selector: {app: d}\n  ports: []\n"
        )
        document = objects_of(result)[("", "Service", "rhoai", "s")]["document"]
        assert document["spec"]["selector"] == {"app": "d"}

    def test_nil_and_empty_selectors_stay_distinct(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: nil-selector\n"
            "spec:\n  ports: []\n"
            "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: empty-selector\n"
            "spec:\n  selector: {}\n  ports: []\n"
        )
        objects = objects_of(result)
        nil_selector = objects[("", "Service", "rhoai", "nil-selector")]["document"]["spec"]
        empty_selector = objects[("", "Service", "rhoai", "empty-selector")]["document"]["spec"]
        assert "selector" not in nil_selector
        assert empty_selector["selector"] == {}

    def test_networkpolicy_pod_selector_shape_is_validated(self) -> None:
        with pytest.raises(NormalizeError, match="spec.podSelector"):
            normalize(
                "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: n\n"
                "spec:\n  podSelector: {matchLabels: 3}\n"
            )


class TestSkipRecords:
    def test_helm_hook_is_skipped_with_identity(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: normal\n"
            "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: hooked\n"
            "  annotations:\n    helm.sh/hook: post-install\n"
        )
        objects = objects_of(result)
        assert ("", "ConfigMap", "rhoai", "normal") in objects
        assert ("", "ConfigMap", "rhoai", "hooked") not in objects
        assert [entry["reason"] for entry in result["skipped"]] == ["helm-hook"]
        hooked = result["skipped"][0]
        assert hooked["identity"] == {
            "group": "", "kind": "ConfigMap", "namespace": "rhoai", "name": "hooked",
        }
        assert hooked["document_index"] == 2
        assert result["coverage"]["skipped_counts"]["helm-hook"] == 1

    def test_crd_is_skipped_as_delegated(self) -> None:
        result = normalize(
            "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
            "metadata:\n  name: widgets.demo.example.com\n"
            "spec:\n  group: demo.example.com\n  scope: Namespaced\n  names:\n    kind: Widget\n"
        )
        assert objects_of(result) == {}
        assert [entry["reason"] for entry in result["skipped"]] == ["crd-delegated"]
        assert result["coverage"]["skipped_counts"]["crd-delegated"] == 1
        assert result["coverage"]["custom_kinds_from_crds"] == ["demo.example.com/Widget"]

    def test_coverage_counts_kinds(self) -> None:
        result = normalize(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"
            "---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n"
        )
        assert result["coverage"]["object_count"] == 2
        assert result["coverage"]["kind_counts"] == {"core/ConfigMap": 1, "apps/Deployment": 1}
