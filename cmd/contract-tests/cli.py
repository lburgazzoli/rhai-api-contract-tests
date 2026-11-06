#!/usr/bin/env python3
"""contract-tests: local runner for shared RHOAI and ODH contract checks.

This repository is the shared-tooling home. The runner currently wraps the
OpenAPI and static CRD compatibility modules, a coverage check that confirms
every API contract in a repository is registered, and a Kubernetes manifest
compatibility check that renders scenarios (raw YAML, Helm, Kustomize) and
compares them against immutable Git baselines.

The same invocation runs locally and in CI, so results are reproducible
without a cluster:

    python3 cmd/contract-tests/cli.py check \\
      --repo /path/to/provider/checkout \\
      --contract-set .rhoai/contracts.yaml \\
      --baseline-ref <full-git-sha> \\
      --output-dir /tmp/contract-report
"""

import argparse
import importlib.util
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

_CHECKER_PATH = Path(__file__).resolve().parents[2] / "modules" / "openapi-compat" / "checker.py"
_CRD_CHECKER_PATH = Path(__file__).resolve().parents[2] / "modules" / "crd-compat" / "checker.py"
_COVERAGE_PATH = Path(__file__).resolve().parents[2] / "modules" / "coverage" / "checker.py"
_MANIFEST_CHECKER_PATH = Path(__file__).resolve().parents[2] / "modules" / "manifest-compat" / "checker.py"


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_checker() -> ModuleType:
    return _load_module("openapi_compat_checker", _CHECKER_PATH)


def _load_crd_checker() -> ModuleType:
    return _load_module("crd_compat_checker", _CRD_CHECKER_PATH)


def _load_coverage() -> ModuleType:
    return _load_module("coverage_checker", _COVERAGE_PATH)


def _load_manifest_checker() -> ModuleType:
    return _load_module("manifest_compat_checker", _MANIFEST_CHECKER_PATH)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="contract-tests", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Run a registered contract's compatibility check")
    check.add_argument("--repo", type=Path, required=True, help="Path to the provider repository to check")
    check.add_argument("--contract-set", type=Path, required=True,
                        help="Path to the ContractSet descriptor, relative to --repo (e.g. .rhoai/contracts.yaml)")
    check.add_argument("--contract-id", help="Contract id to run; required if the descriptor registers more than one")
    check.add_argument("--baseline-ref", action="append",
                       help="Full resolved Git SHA; repeat for every supported baseline. Mutable refs are rejected. "
                            "The repository default: a contract's own baseline in the descriptor takes precedence, "
                            "and spec.baseline.refs is used when this is omitted")
    check.add_argument("--output-dir", type=Path, required=True,
                        help="New report directory; existing paths are never overwritten")
    check.add_argument("--enforce", action="store_true", help="Exit 1 for breaking changes; default is report-only")
    check.add_argument("--oasdiff", default=os.environ.get("OASDIFF"), help="Pinned oasdiff executable")
    check.add_argument("--yq", default=os.environ.get("YQ"), help="Repository's pinned yq executable")

    crd_check = subparsers.add_parser("crd-check", help="Compare CustomResourceDefinitions with immutable Git baselines")
    crd_check.add_argument("--repo", type=Path, required=True, help="Path to the provider repository to check")
    crd_check.add_argument("--crd-glob", required=True, help="Repository-relative glob selecting CustomResourceDefinition YAML files")
    crd_check.add_argument("--baseline-ref", action="append", required=True,
                           help="Full resolved Git SHA; repeat for every supported baseline. Mutable refs are rejected.")
    crd_check.add_argument("--output-dir", type=Path, required=True,
                           help="New report directory; existing paths are never overwritten")
    crd_check.add_argument("--enforce", action="store_true", help="Exit 1 for breaking changes; default is report-only")

    coverage = subparsers.add_parser(
        "coverage",
        help="Confirm every OpenAPI document (and optionally CRD) in the repository is registered",
    )
    coverage.add_argument("--repo", type=Path, required=True, help="Path to the provider repository to check")
    coverage.add_argument("--contract-set", type=Path, default=Path(".rhoai/contracts.yaml"),
                          help="Path to the ContractSet descriptor, relative to --repo (default .rhoai/contracts.yaml)")
    coverage.add_argument("--crd-glob", action="append", default=[],
                          help="Repository-relative glob used by the CRD check; repeat to cover several. "
                               "When given, every CRD manifest must match one of them")
    coverage.add_argument("--crd-exclude", action="append", default=[],
                          help="Repository-relative glob of CRD manifests that are deliberately not checked "
                               "(for example mocked CRDs used as test data); repeat as needed")
    coverage.add_argument("--baseline-ref", action="append", default=[],
                          help="The repository default baseline (full Git SHA); used only to flag per-contract "
                               "baselines that are newer than it")
    coverage.add_argument("--format", choices=("text", "json"), default="text")
    coverage.add_argument("--json-output", type=Path,
                          help="Also write the JSON report to this file, whatever --format prints "
                               "(the reusable workflow reads it to annotate gaps on the pull request)")
    coverage.add_argument("--report-only", action="store_true",
                          help="Exit 0 even when gaps are found; integrity errors still exit 2")
    coverage.add_argument("--yq", default=os.environ.get("YQ"), help="Repository's pinned yq executable")

    discover = subparsers.add_parser(
        "discover", help="Inventory the OpenAPI documents and CRDs in a repository and suggest contract shapes",
    )
    discover.add_argument("--repo", type=Path, required=True, help="Path to the repository to inventory")
    discover.add_argument("--format", choices=("text", "json"), default="text")
    discover.add_argument("--yq", default=os.environ.get("YQ"), help="Pinned yq executable")

    manifest_prepare = subparsers.add_parser(
        "manifest-prepare",
        help="Prepare the pinned Helm and Kustomize renderer modules in a tool cache (network-enabled)",
    )
    manifest_prepare.add_argument("--repo", type=Path, required=True, help="Path to the provider repository to check")
    manifest_prepare.add_argument("--manifest-set", type=Path, required=True,
                                  help="Path to the ManifestSet descriptor, relative to --repo "
                                       "(e.g. .rhoai/manifests.yaml)")
    manifest_prepare.add_argument("--scenario-id",
                                  help="Prepare only the renderers this scenario needs; default considers every scenario")
    manifest_prepare.add_argument("--tool-cache-dir", type=Path, required=True,
                                  help="Cache directory for the pinned go-run renderer modules; populated "
                                       "online with checksum verification and reused offline by manifest-check")

    manifest_check = subparsers.add_parser(
        "manifest-check",
        help="Compare rendered Kubernetes manifests with immutable Git baselines",
    )
    manifest_check.add_argument("--repo", type=Path, required=True, help="Path to the provider repository to check")
    manifest_check.add_argument("--manifest-set", type=Path, required=True,
                                help="Path to the ManifestSet descriptor, relative to --repo "
                                     "(e.g. .rhoai/manifests.yaml)")
    manifest_check.add_argument("--scenario-id", help="Run a single scenario by id; default runs every scenario")
    manifest_check.add_argument("--baseline-ref", action="append", required=True,
                                help="Full resolved Git SHA; repeat for every supported baseline. Mutable refs are rejected.")
    manifest_check.add_argument("--output-dir", type=Path, required=True,
                                help="New report directory; existing paths are never overwritten")
    manifest_check.add_argument("--tool-cache-dir", type=Path,
                                help="Cache directory holding the prepared pinned renderer modules; required "
                                     "when any selected scenario renders with Helm or Kustomize")
    manifest_check.add_argument("--enforce", action="store_true",
                                help="Exit 1 for breaking changes; default is report-only")

    args = parser.parse_args(argv)
    # The checker modules are loaded at runtime, so their return values are untyped here.
    code: int
    if args.command == "coverage":
        code = _load_coverage().run_coverage(args)
    elif args.command == "discover":
        code = _load_coverage().run_discover(args)
    elif args.command == "check":
        code = _load_checker().run_check(args)
    elif args.command == "crd-check":
        code = _load_crd_checker().run_check(args)
    elif args.command == "manifest-prepare":
        code = _load_manifest_checker().run_prepare(args)
    elif args.command == "manifest-check":
        code = _load_manifest_checker().run_check(args)
    else:
        parser.error(f"Unknown command {args.command!r}")
    return code


if __name__ == "__main__":
    sys.exit(main())
