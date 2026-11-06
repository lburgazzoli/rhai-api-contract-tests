"""Tests for revision snapshots and pinned offline manifest renderers.

Covers the frozen snapshot/prepare/render contract from the standing rules:

- candidate snapshots reflect tracked edits, untracked files, and deletions;
  baseline snapshots materialize exact Git blobs; both record hazards
  (symlinks, gitlinks, LFS pointers, non-regular files) without materializing
  them and never touch the provider checkout;
- ``prepare_tools`` records provenance and runs the only network-enabled
  commands through the pinned ``go run`` modules;
- ``render`` for raw/helm/kustomize scenarios runs strictly offline through
  the pinned ``go run`` commands (subprocess faked at ``renderers._run``),
  fails closed on hazards, remote references, forbidden template functions,
  absent inputs, nondeterminism, and output limits, and never leaks values or
  Secret contents into diagnostics.

Real-renderer integration tests against the actual Go toolchain are a later
CI task; nothing here requires Go, the network, or a cluster.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "modules" / "manifest-compat" / "renderers.py"
FIXTURES = ROOT / "modules" / "manifest-compat" / "tests" / "fixtures" / "renderers"

spec = importlib.util.spec_from_file_location("manifest_renderers_test", MODULE_PATH)
assert spec is not None and spec.loader is not None
renderers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderers)

RenderError = renderers.RenderError
MissingInputError = renderers.MissingInputError
HELM_PIN = renderers.HELM_PIN
KUSTOMIZE_PIN = renderers.KUSTOMIZE_PIN
REAL_RUN = renderers._run

LFS_POINTER = b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 3\n"
VALUES_SECRET_MARKER = "manifest-test-secret-marker"
KUSTOMIZE_SECRET_MARKER = "kustomize-secret-marker"


# --- Repository and scenario helpers ------------------------------------------


def git(repo: Path, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    })
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, check=True, input=input_bytes, env=env,
    )


def head_sha(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD").stdout.decode().strip()


def build_repo(
    tmp_path: Path,
    *,
    files: dict[str, str | bytes] | None = None,
    copies: dict[str, str] | None = None,
    name: str = "repo",
) -> Path:
    """A committed repository built from fixture trees plus inline files."""
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    for source, destination in (copies or {}).items():
        shutil.copytree(FIXTURES / source, repo / destination)
    for path, content in (files or {}).items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
    if files or copies:
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "init")
    return repo


def commit_extra_file(
    repo: Path, name: str, content: str | bytes, *, mode: str = "100644",
    working_copy: bool = True,
) -> None:
    """Commit one entry through update-index (tab names, gitlinks, symlinks)."""
    if mode == "160000":
        oid = head_sha(repo)
    else:
        data = content.encode() if isinstance(content, str) else content
        oid = git(repo, "hash-object", "-w", "--stdin", input_bytes=data).stdout.decode().strip()
        if working_copy:
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    git(repo, "update-index", "--add", "--cacheinfo", f"{mode},{oid},{name}")
    git(repo, "commit", "-qm", f"add {name!r}")


def files_by_name(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {r["file"]: r for r in records if "hazard" not in r}


def hazards_by_name(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {r["file"]: r for r in records if "hazard" in r}


def snap_candidate(
    repo: Path, tmp_path: Path, name: str = "snap",
) -> tuple[list[dict[str, Any]], Path]:
    destination = tmp_path / name
    return renderers.snapshot_candidate(repo, destination), destination


def snap_baseline(
    repo: Path, sha: str, tmp_path: Path, name: str = "base-snap",
) -> tuple[list[dict[str, Any]], Path]:
    destination = tmp_path / name
    return renderers.snapshot_baseline(repo, sha, destination), destination


def raw_scenario(sources: list[str], **overrides: Any) -> dict[str, Any]:
    scenario: dict[str, Any] = {
        "id": "raw-test", "renderer": "raw", "namespace": "rhoai",
        "kubernetesVersion": "1.36.6", "sources": sources,
    }
    scenario.update(overrides)
    return scenario


def helm_scenario(**overrides: Any) -> dict[str, Any]:
    scenario: dict[str, Any] = {
        "id": "helm-test", "renderer": "helm", "namespace": "rhoai",
        "kubernetesVersion": "1.36.6", "path": "charts/demo", "releaseName": "demo",
    }
    scenario.update(overrides)
    return scenario


def kustomize_scenario(**overrides: Any) -> dict[str, Any]:
    scenario: dict[str, Any] = {
        "id": "kust-test", "renderer": "kustomize", "namespace": "rhoai",
        "kubernetesVersion": "1.36.6", "path": "manifests/overlays/prod",
    }
    scenario.update(overrides)
    return scenario


def prepared_cache(tmp_path: Path, *renderer_names: str) -> Path:
    cache = tmp_path / "tool-cache"
    if not renderer_names:
        cache.mkdir(parents=True, exist_ok=True)
    for name in renderer_names:
        tool = renderers.PREPARED_TOOLS[name]
        module_dir = cache / "gomodcache" / f"{tool['module']}@v{tool['version']}"
        module_dir.mkdir(parents=True, exist_ok=True)
        (module_dir / "go.mod").write_text("module pin\n")
    return cache


def config_with(renderer_names: list[str]) -> dict[str, Any]:
    scenarios: list[dict[str, Any]] = []
    for name in renderer_names:
        scenarios.append({
            "id": f"scenario-{name}", "renderer": name, "namespace": "rhoai",
            "kubernetesVersion": "1.36.6", "path": "charts/demo", "releaseName": "demo",
        })
    tools = {f"{name}Version": renderers.PREPARED_TOOLS[name]["version"] for name in renderer_names}
    return {"scenarios": scenarios, "tools": tools}


def make_tgz(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


# --- Subprocess test double ----------------------------------------------------


def completed(argv: list[str], returncode: int, stdout: bytes, stderr: bytes
              ) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class FakeRunner:
    """Replacement for ``renderers._run``: no Go, no network; git passthrough.

    ``render_outputs`` is a list of ``(stdout, returncode, stderr)`` tuples or
    exceptions, cycled per render invocation; ``prepare_results`` maps a pin to
    the result of its ``go run <pin> version`` priming command;
    ``offline_prepare_results`` overrides the results of the offline
    verification pass (chosen by ``GOSUMDB=off`` in the command environment).
    """

    def __init__(
        self,
        *,
        go_output: str = "go version go1.27.0 linux/amd64",
        go_error: Exception | None = None,
        render_outputs: list[tuple[bytes, int, bytes] | Exception] | None = None,
        prepare_results: dict[str, tuple[bytes, int, bytes] | Exception] | None = None,
        offline_prepare_results: dict[str, tuple[bytes, int, bytes] | Exception] | None = None,
    ) -> None:
        self.go_output = go_output
        self.go_error = go_error
        self.render_outputs = render_outputs or [(b"", 0, b"")]
        self.prepare_results = prepare_results or {}
        self.offline_prepare_results = offline_prepare_results
        self.calls: list[dict[str, Any]] = []
        self.render_calls: list[dict[str, Any]] = []
        self.prepare_calls: list[dict[str, Any]] = []

    def __call__(
        self, argv: Any, *, cwd: Any = None, env: Any = None, timeout: float,
        stdout_limit: int, stderr_limit: int = renderers.MAX_DIAGNOSTIC_BYTES,
    ) -> subprocess.CompletedProcess[bytes]:
        command = [str(argument) for argument in argv]
        call = {
            "argv": command, "cwd": cwd,
            "env": dict(env) if env is not None else None,
            "timeout": timeout,
        }
        self.calls.append(call)
        if command[0] == "git":
            return REAL_RUN(
                command, cwd=cwd, env=env, timeout=timeout,
                stdout_limit=stdout_limit, stderr_limit=stderr_limit,
            )
        if command[:2] == ["go", "version"]:
            if self.go_error is not None:
                raise self.go_error
            return completed(command, 0, self.go_output.encode(), b"")
        if len(command) >= 4 and command[1] == "run" and command[3] == "version":
            self.prepare_calls.append(call)
            results = self.prepare_results
            if env is not None and env.get("GOSUMDB") == "off" and \
                    self.offline_prepare_results is not None:
                results = self.offline_prepare_results
            result = results.get(
                command[2], (b"version.BuildInfo{Version:\"pinned\"}", 0, b"")
            )
            if isinstance(result, Exception):
                raise result
            stdout, returncode, stderr = result
            return completed(command, returncode, stdout, stderr)
        self.render_calls.append(call)
        item = self.render_outputs[(len(self.render_calls) - 1) % len(self.render_outputs)]
        if isinstance(item, Exception):
            raise item
        stdout, returncode, stderr = item
        return completed(command, returncode, stdout, stderr)


def run_render(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, Any]],
    scenario: dict[str, Any], cache_dir: Path | None,
    **runner_kwargs: Any,
) -> tuple[bytes, FakeRunner]:
    runner = FakeRunner(**runner_kwargs)
    monkeypatch.setattr(renderers, "_run", runner)
    output = renderers.render(records, scenario, cache_dir)
    return output, runner


# --- Small unit tests -----------------------------------------------------------


class TestExclusionRules:
    @pytest.mark.parametrize("name,expected", [
        (".git/config", True),
        (".context/state.yaml", True),
        (".contract-tests/tool.py", True),
        ("charts/.git/refs", True),
        ("/etc/passwd", True),
        ("", True),
        ("charts/demo/Chart.yaml", False),
        ("context/state.yaml", False),
    ])
    def test_exclusion(self, name: str, expected: bool) -> None:
        assert renderers._is_excluded(name) is expected


class TestGoVersionParsing:
    def test_parses_full_version(self) -> None:
        assert renderers._parse_go_version("go version go1.27.0 linux/amd64") == (1, 27, 0)

    def test_parses_two_part_version(self) -> None:
        assert renderers._parse_go_version("go version go1.26 linux/amd64") == (1, 26, 0)

    def test_rejects_unparseable_output(self) -> None:
        with pytest.raises(RenderError, match="cannot determine"):
            renderers._parse_go_version("gopher")


class TestSanitizeDiagnostics:
    def test_truncates_to_five_lines(self) -> None:
        stderr = b"\n".join(f"line{i}".encode() for i in range(8))
        summary = renderers._sanitize_diagnostics(stderr, [])
        assert summary == " | ".join(f"line{i}" for i in range(5))

    def test_truncates_long_lines(self) -> None:
        long_line = "word " * 120
        summary = renderers._sanitize_diagnostics((long_line + "\n").encode(), [])
        assert len(summary) == 200
        assert summary == long_line[:200]

    def test_redacts_secrets(self) -> None:
        summary = renderers._sanitize_diagnostics(
            f"failed while reading {VALUES_SECRET_MARKER}".encode(), [VALUES_SECRET_MARKER]
        )
        assert VALUES_SECRET_MARKER not in summary
        assert "[redacted]" in summary

    def test_redacts_long_tokens(self) -> None:
        summary = renderers._sanitize_diagnostics(b"token: " + b"a" * 48, [])
        assert "aaaaaaaa" not in summary
        assert "[redacted]" in summary

    def test_empty_diagnostics(self) -> None:
        assert renderers._sanitize_diagnostics(b"   \n\n", []) == "(no diagnostics)"

    def test_replaces_private_roots(self) -> None:
        stderr = b"Error: '/tmp/tmpabc123/c1/manifests/base' must resolve to a file\n"
        summary = renderers._sanitize_diagnostics(
            stderr, [], private_roots=["/tmp/tmpabc123/c1"],
        )
        assert "/tmp/tmpabc123" not in summary
        assert "<private>" in summary

    def test_secret_straddling_truncation_boundary_is_redacted(self) -> None:
        # Replacement runs on the full excerpt before per-line truncation, so
        # a secret crossing the 200-character boundary cannot partially
        # survive as a fragment.
        padding = "x" * 190
        stderr = f"{padding}{VALUES_SECRET_MARKER}\n".encode()
        summary = renderers._sanitize_diagnostics(stderr, [VALUES_SECRET_MARKER])
        assert VALUES_SECRET_MARKER not in summary
        assert VALUES_SECRET_MARKER[:8] not in summary
        assert "[redacted]" in summary

    def test_private_root_straddling_truncation_boundary_is_replaced(self) -> None:
        padding = "x" * 190
        stderr = f"{padding}/tmp/tmpabc123/c1/base\n".encode()
        summary = renderers._sanitize_diagnostics(
            stderr, [], private_roots=["/tmp/tmpabc123/c1"],
        )
        assert "/tmp/tmpabc123" not in summary
        assert "<private>" in summary

    def test_private_roots_replaced_before_secret_redaction(self) -> None:
        stderr = b"Error: cannot read /tmp/tmpabc123/c1/secret-values.yaml: marker\n"
        summary = renderers._sanitize_diagnostics(
            stderr, ["marker"], private_roots=["/tmp/tmpabc123/c1"],
        )
        assert "/tmp/tmpabc123" not in summary
        assert "<private>" in summary
        assert "marker" not in summary


class TestTemplateScan:
    @pytest.mark.parametrize("template", [
        '{{ lookup "v1" "ConfigMap" .Release.Namespace "cm" }}',
        "{{ tpl .Values.text . }}",
        '{{- lookup "v1" "x" .Release.Namespace "y" -}}',
        '{{ $x := lookup "v1" "a" "b" "c" }}',
        '{{ printf "%v" (lookup "v1" "x" .Release.Namespace "y") }}',
        '{{ include (tpl "demo.tpl" .) . }}',
    ])
    def test_rejects_forbidden_functions(self, template: str) -> None:
        with pytest.raises(RenderError) as excinfo:
            renderers._scan_template_text(template.encode(), "t.yaml")
        assert "lookup" in str(excinfo.value) or "tpl" in str(excinfo.value)

    @pytest.mark.parametrize("template", [
        "plain text mentioning lookup and tpl outside actions",
        '{{ "lookup" }}',
        "{{ 'tpl' }}",
        "{{/* lookup and tpl are mentioned in this comment */}}",
        '{{ .Values.lookupName | default "none" | quote }}',
        "{{ $lookup := .Values.x }}",
        "{{ $tpl }}",
        "{{ mylookup }}",
        "{{ mytpl }}",
        "{{ toYaml .Values.resources | nindent 12 }}",
        '{{ include "demo.labels" . | nindent 4 }}',
        "{{ `raw text mentioning lookup` }}",
        '{{ if eq .Values.a "lookup" }}yes{{ end }}',
        "{{ .Release.Name }}",
        "{{ .Files.Get \"config\" }}",
    ])
    def test_allows_benign_templates(self, template: str) -> None:
        renderers._scan_template_text(template.encode(), "t.yaml")

    def test_unclosed_action_fails_closed(self) -> None:
        with pytest.raises(RenderError, match="unclosed action"):
            renderers._scan_template_text(b"{{ lookup", "t.yaml")

    def test_unterminated_string_fails_closed(self) -> None:
        with pytest.raises(RenderError, match="unterminated string"):
            renderers._scan_template_text(b'{{ "abc }}', "t.yaml")

    def test_unterminated_comment_fails_closed(self) -> None:
        with pytest.raises(RenderError, match="unterminated comment"):
            renderers._scan_template_text(b"{{/* dangling }}", "t.yaml")

    def test_non_utf8_fails_closed(self) -> None:
        with pytest.raises(RenderError, match="not valid UTF-8"):
            renderers._scan_template_text(b"{{ \xff }}", "t.yaml")


# --- Candidate snapshots --------------------------------------------------------


class TestCandidateSnapshot:
    def test_copies_tracked_files_with_digests_and_permissions(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n", "dir/b.yaml": "y: 2\n"})
        records, destination = snap_candidate(repo, tmp_path)
        files = files_by_name(records)
        assert set(files) == {"a.yaml", "dir/b.yaml"}
        assert [r["file"] for r in records] == sorted(files)
        record = files["a.yaml"]
        assert record["root"] == str(destination)
        assert record["path"] == str(destination / "a.yaml")
        assert (destination / "a.yaml").read_bytes() == b"x: 1\n"
        assert record["sha256"] == hashlib.sha256(b"x: 1\n").hexdigest()
        assert stat.S_IMODE(os.stat(destination / "a.yaml").st_mode) == 0o600
        assert stat.S_IMODE(os.stat(destination).st_mode) == 0o700

    def test_reflects_local_edits(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        (repo / "a.yaml").write_text("edited: true\n")
        records, _ = snap_candidate(repo, tmp_path)
        assert (files_by_name(records)["a.yaml"]["path"]).endswith("a.yaml")
        content = Path(files_by_name(records)["a.yaml"]["path"]).read_bytes()
        assert content == b"edited: true\n"

    def test_includes_untracked_files(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        (repo / "new.yaml").write_text("n: 1\n")
        records, _ = snap_candidate(repo, tmp_path)
        assert set(files_by_name(records)) == {"a.yaml", "new.yaml"}

    def test_includes_untracked_files_without_commits(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path)
        (repo / "new.yaml").write_text("n: 1\n")
        records, _ = snap_candidate(repo, tmp_path)
        assert set(files_by_name(records)) == {"new.yaml"}

    def test_skips_locally_deleted_tracked_files(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n", "b.yaml": "y: 2\n"})
        (repo / "a.yaml").unlink()
        records, _ = snap_candidate(repo, tmp_path)
        assert set(files_by_name(records)) == {"b.yaml"}

    def test_excludes_ignored_files(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n", ".gitignore": "ignored.txt\n"})
        (repo / "ignored.txt").write_text("secret\n")
        records, _ = snap_candidate(repo, tmp_path)
        assert set(files_by_name(records)) == {".gitignore", "a.yaml"}

    def test_excludes_reserved_directories(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        for name in (".context/state", ".contract-tests/tool", "sub/.git/config"):
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("ignored\n")
        records, _ = snap_candidate(repo, tmp_path)
        assert set(files_by_name(records)) == {"a.yaml"}

    def test_symlink_is_a_hazard(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        os.symlink("a.yaml", repo / "link.yaml")
        git(repo, "add", "link.yaml")
        git(repo, "commit", "-qm", "symlink")
        records, destination = snap_candidate(repo, tmp_path)
        assert set(hazards_by_name(records)) == {"link.yaml"}
        assert hazards_by_name(records)["link.yaml"]["hazard"] == "symlink"
        assert not (destination / "link.yaml").exists()
        assert set(files_by_name(records)) == {"a.yaml"}

    def test_untracked_symlink_is_a_hazard(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        os.symlink("a.yaml", repo / "link.yaml")
        records, destination = snap_candidate(repo, tmp_path)
        assert set(hazards_by_name(records)) == {"link.yaml"}
        assert not (destination / "link.yaml").exists()

    def test_symlink_ancestor_directory_is_a_hazard(self, tmp_path: Path) -> None:
        # lstat and O_NOFOLLOW protect only the final path component: a
        # tracked directory replaced locally by a symlink must not let its
        # indexed descendants be copied from outside the checkout.
        repo = build_repo(tmp_path, files={"pkg/inner.txt": "original\n"})
        outside = tmp_path / "outside"
        (outside / "pkg").mkdir(parents=True)
        (outside / "pkg" / "inner.txt").write_text("should never be copied\n")
        shutil.rmtree(repo / "pkg")
        os.symlink(outside / "pkg", repo / "pkg")
        records, destination = snap_candidate(repo, tmp_path)
        hazards = hazards_by_name(records)
        assert hazards["pkg/inner.txt"]["hazard"] == "symlink-ancestor"
        assert set(files_by_name(records)) == set()
        assert not (destination / "pkg").exists()

    def test_gitlink_is_a_hazard(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        commit_extra_file(repo, "vendor/submodule", "", mode="160000", working_copy=False)
        records, destination = snap_candidate(repo, tmp_path)
        assert hazards_by_name(records)["vendor/submodule"]["hazard"] == "gitlink"
        assert not (destination / "vendor").exists()

    def test_lfs_pointer_is_a_hazard(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        (repo / "blob.bin").write_bytes(LFS_POINTER)
        records, destination = snap_candidate(repo, tmp_path)
        assert hazards_by_name(records)["blob.bin"]["hazard"] == "lfs-pointer"
        assert not (destination / "blob.bin").exists()

    def test_non_regular_file_is_a_hazard(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"pipe.yaml": "x: 1\n"})
        (repo / "pipe.yaml").unlink()
        os.mkfifo(repo / "pipe.yaml")
        records, _ = snap_candidate(repo, tmp_path)
        assert hazards_by_name(records)["pipe.yaml"]["hazard"] == "non-regular"

    def test_file_name_with_tab(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        commit_extra_file(repo, "weird\tname.yaml", "tab: true\n")
        records, _ = snap_candidate(repo, tmp_path)
        files = files_by_name(records)
        assert "weird\tname.yaml" in files
        content = Path(files["weird\tname.yaml"]["path"]).read_bytes()
        assert content == b"tab: true\n"

    def test_unicode_file_name(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"ünïcode.yaml": "x: 1\n"})
        records, _ = snap_candidate(repo, tmp_path)
        assert set(files_by_name(records)) == {"ünïcode.yaml"}

    def test_destination_must_be_fresh(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        destination = tmp_path / "snap"
        destination.mkdir()
        (destination / "keepme").write_text("owned\n")
        with pytest.raises(RenderError, match="cannot be created"):
            renderers.snapshot_candidate(repo, destination)
        assert (destination / "keepme").read_text() == "owned\n"

    def test_failed_snapshot_cleans_destination(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n", "b.yaml": "y: 2\n"})
        destination = tmp_path / "snap"
        real = renderers._copy_candidate_entry

        def failing(repo_arg: Path, name: str, mode: str | None, dest_arg: Path,
                    dir_cache: dict[str, bool]) -> Any:
            if name == "b.yaml":
                raise RenderError("injected copy failure")
            return real(repo_arg, name, mode, dest_arg, dir_cache)

        monkeypatch.setattr(renderers, "_copy_candidate_entry", failing)
        with pytest.raises(RenderError, match="injected copy failure"):
            renderers.snapshot_candidate(repo, destination)
        assert not destination.exists()

    def test_provider_checkout_untouched(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        (repo / "untracked.yaml").write_text("u: 1\n")
        os.symlink("a.yaml", repo / "link.yaml")
        before_status = git(repo, "status", "--porcelain").stdout
        before_head = head_sha(repo)
        snap_candidate(repo, tmp_path)
        assert git(repo, "status", "--porcelain").stdout == before_status
        assert head_sha(repo) == before_head

    def test_repo_must_be_a_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "file"
        target.write_text("not a repo\n")
        with pytest.raises(RenderError, match="not a directory"):
            renderers.snapshot_candidate(target, tmp_path / "snap")


# --- Baseline snapshots ----------------------------------------------------------


class TestBaselineSnapshot:
    def test_materializes_exact_committed_blobs(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n", "dir/b.yaml": "y: 2\n"})
        sha = head_sha(repo)
        (repo / "a.yaml").write_text("tampered\n")
        (repo / "dir" / "b.yaml").unlink()
        records, destination = snap_baseline(repo, sha, tmp_path)
        files = files_by_name(records)
        assert set(files) == {"a.yaml", "dir/b.yaml"}
        assert (destination / "a.yaml").read_bytes() == b"x: 1\n"
        assert (destination / "dir" / "b.yaml").read_bytes() == b"y: 2\n"
        assert files["a.yaml"]["sha256"] == hashlib.sha256(b"x: 1\n").hexdigest()
        assert stat.S_IMODE(os.stat(destination / "a.yaml").st_mode) == 0o600
        assert stat.S_IMODE(os.stat(destination).st_mode) == 0o700

    def test_symlink_is_a_hazard(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        os.symlink("a.yaml", repo / "link.yaml")
        git(repo, "add", "link.yaml")
        git(repo, "commit", "-qm", "symlink")
        records, destination = snap_baseline(repo, head_sha(repo), tmp_path)
        assert set(hazards_by_name(records)) == {"link.yaml"}
        assert hazards_by_name(records)["link.yaml"]["hazard"] == "symlink"
        assert set(files_by_name(records)) == {"a.yaml"}

    def test_gitlink_is_a_hazard(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        commit_extra_file(repo, "vendor/submodule", "", mode="160000", working_copy=False)
        records, _ = snap_baseline(repo, head_sha(repo), tmp_path)
        assert hazards_by_name(records)["vendor/submodule"]["hazard"] == "gitlink"

    def test_lfs_pointer_is_a_hazard(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n", "blob.bin": "overwrite me\n"})
        oid = git(repo, "hash-object", "-w", "--stdin", input_bytes=LFS_POINTER).stdout.decode().strip()
        git(repo, "update-index", "--cacheinfo", f"100644,{oid},blob.bin")
        git(repo, "commit", "-qm", "lfs")
        records, destination = snap_baseline(repo, head_sha(repo), tmp_path)
        assert hazards_by_name(records)["blob.bin"]["hazard"] == "lfs-pointer"
        assert not (destination / "blob.bin").exists()

    def test_rejects_short_sha(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        with pytest.raises(RenderError, match="full 40- or 64-character"):
            renderers.snapshot_baseline(repo, head_sha(repo)[:8], tmp_path / "snap")

    def test_rejects_mutable_refs(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        for ref in ("main", "HEAD", "v1.0.0"):
            with pytest.raises(RenderError, match="full 40- or 64-character"):
                renderers.snapshot_baseline(repo, ref, tmp_path / "snap")

    def test_rejects_uppercase_sha(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        with pytest.raises(RenderError, match="full 40- or 64-character"):
            renderers.snapshot_baseline(repo, head_sha(repo).upper(), tmp_path / "snap")

    def test_rejects_non_commit_objects(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        tree = git(repo, "rev-parse", "HEAD^{tree}").stdout.decode().strip()
        with pytest.raises(RenderError, match="cannot resolve revision"):
            renderers.snapshot_baseline(repo, tree, tmp_path / "snap")
        blob = git(repo, "rev-parse", "HEAD:a.yaml").stdout.decode().strip()
        with pytest.raises(RenderError, match="cannot resolve revision"):
            renderers.snapshot_baseline(repo, blob, tmp_path / "snap")

    def test_full_sha_must_resolve_to_itself(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        sha = head_sha(repo)
        (repo / "b.yaml").write_text("y: 2\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "second")
        other = head_sha(repo)
        real_git = renderers._git

        def fake_git(repo_arg: Path, args: Any, *, check: bool = True) -> Any:
            if args[0] == "rev-parse":
                return completed(["git", *args], 0, (other + "\n").encode(), b"")
            return real_git(repo_arg, args, check=check)

        monkeypatch.setattr(renderers, "_git", fake_git)
        with pytest.raises(RenderError, match="resolves to a different commit"):
            renderers.snapshot_baseline(repo, sha, tmp_path / "snap")

    def test_rejects_empty_repository(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path)
        with pytest.raises(RenderError, match="cannot resolve revision"):
            renderers.snapshot_baseline(repo, "0" * 40, tmp_path / "snap")

    def test_destination_must_be_fresh(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        destination = tmp_path / "snap"
        destination.mkdir()
        with pytest.raises(RenderError, match="cannot be created"):
            renderers.snapshot_baseline(repo, head_sha(repo), destination)

    def test_failed_snapshot_cleans_destination(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "x: 1\n"})
        destination = tmp_path / "snap"
        real_git = renderers._git

        def failing(repo_arg: Path, args: Any, *, check: bool = True) -> Any:
            if args[0] == "cat-file":
                raise RenderError("git cat-file failed in baseline snapshot")
            return real_git(repo_arg, args, check=check)

        monkeypatch.setattr(renderers, "_git", failing)
        with pytest.raises(RenderError, match="git cat-file failed"):
            renderers.snapshot_baseline(repo, head_sha(repo), destination)
        assert not destination.exists()

    def test_repo_must_be_a_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "file"
        target.write_text("not a repo\n")
        with pytest.raises(RenderError, match="not a directory"):
            renderers.snapshot_baseline(target, "0" * 40, tmp_path / "snap")


# --- Tool preparation --------------------------------------------------------------


class TestPrepareTools:
    def test_raw_only_needs_no_cache(self) -> None:
        config = {
            "scenarios": [raw_scenario(["a.yaml"])],
            "tools": {},
        }
        provenance = renderers.prepare_tools(config, None)
        assert provenance["needed"] == []
        assert provenance["tools"] == []
        assert provenance["go"] is None
        assert provenance["cache"] is None
        assert provenance["provider_content_rendered"] is False

    def test_go_renderers_require_a_cache(self, tmp_path: Path) -> None:
        with pytest.raises(RenderError, match="tool cache directory is required"):
            renderers.prepare_tools(config_with(["helm"]), None)

    def test_rejects_unpinned_tool_version(self, tmp_path: Path) -> None:
        config = config_with(["helm"])
        config["tools"]["helmVersion"] = "4.0.0"
        with pytest.raises(RenderError, match="must be pinned to '4.3.1'"):
            renderers.prepare_tools(config, tmp_path / "cache")

    def test_requires_scenario_list(self) -> None:
        with pytest.raises(RenderError, match="no scenario list"):
            renderers.prepare_tools({"tools": {}}, None)

    def test_preparation_environment_is_isolated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("HELM_DRIVER", "configmaps")
        monkeypatch.setenv("KUSTOMIZE_PLUGIN", "x")
        monkeypatch.setenv("GOPROXY", "https://proxy.example.invalid")
        monkeypatch.setenv("GOPRIVATE", "*")
        monkeypatch.setenv("GOSUMDB", "off")
        cache = tmp_path / "cache"
        runner = FakeRunner()
        monkeypatch.setattr(renderers, "_run", runner)
        renderers.prepare_tools(config_with(["helm"]), cache)
        assert runner.prepare_calls, "prepare must prime the pinned module"
        env = runner.prepare_calls[0]["env"]
        assert env["GOSUMDB"] == "sum.golang.org"
        assert env["GOPRIVATE"] == ""
        assert env["GOPROXY"] == "https://proxy.example.invalid"
        assert "HELM_DRIVER" not in env
        assert "KUSTOMIZE_PLUGIN" not in env
        assert env["GOWORK"] == "off"
        assert env["GOENV"] == "off"
        assert env["GOTOOLCHAIN"] == "local"
        assert env["GOMODCACHE"] == str(cache / "gomodcache")
        assert env["GOCACHE"] == str(cache / "gocache")
        assert env["GOPATH"] == str(cache / "gopath")
        assert env["HOME"] != os.environ["HOME"]
        assert not Path(env["HOME"]).exists()

    def test_prepares_both_renderers_with_provenance(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cache = tmp_path / "cache"
        runner = FakeRunner()
        monkeypatch.setattr(renderers, "_run", runner)
        provenance = renderers.prepare_tools(config_with(["kustomize", "helm"]), cache)
        assert provenance["needed"] == ["helm", "kustomize"]
        tools = {tool["renderer"]: tool for tool in provenance["tools"]}
        assert set(tools) == {"helm", "kustomize"}
        assert tools["helm"]["module"] == "helm.sh/helm/v4"
        assert tools["helm"]["version"] == "4.3.1"
        assert tools["helm"]["pin"] == HELM_PIN
        assert tools["helm"]["command"] == ["go", "run", HELM_PIN, "version"]
        assert tools["helm"]["go_minimum"] == "1.26.0"
        assert tools["kustomize"]["module"] == "sigs.k8s.io/kustomize/kustomize/v5"
        assert tools["kustomize"]["version"] == "5.8.3"
        assert tools["kustomize"]["pin"] == KUSTOMIZE_PIN
        assert tools["kustomize"]["go_minimum"] == "1.27.0"
        assert "checksum database" in tools["helm"]["checksum_verification"]
        assert provenance["go"]["minimum"] == "1.27.0"
        assert provenance["go"]["observed"] == "go version go1.27.0 linux/amd64"
        assert provenance["provider_content_rendered"] is False
        assert provenance["cache"]["root"] == str(cache)
        for name in ("gomodcache", "gocache", "gopath"):
            assert (cache / name).is_dir()
        recorded = json.loads((cache / "prepared.json").read_text())
        assert recorded["tools"] == {"helm": HELM_PIN, "kustomize": KUSTOMIZE_PIN}
        assert recorded["go"] == "go version go1.27.0 linux/amd64"
        assert [call["argv"] for call in runner.prepare_calls] == [
            ["go", "run", HELM_PIN, "version"],
            ["go", "run", KUSTOMIZE_PIN, "version"],
            ["go", "run", HELM_PIN, "version"],
            ["go", "run", KUSTOMIZE_PIN, "version"],
        ]
        # The first pass primes online through the checksum database; the
        # second proves the cache renders offline via the cache-rooted
        # file proxy with the checksum database disabled.
        for call in runner.prepare_calls[:2]:
            assert call["env"]["GOSUMDB"] == "sum.golang.org"
        for call in runner.prepare_calls[2:]:
            assert call["env"]["GOSUMDB"] == "off"
            assert call["env"]["GOPROXY"] == (
                cache / "gomodcache" / "cache" / "download"
            ).as_uri()

    def test_old_toolchain_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner(go_output="go version go1.25.4 linux/amd64")
        monkeypatch.setattr(renderers, "_run", runner)
        with pytest.raises(RenderError, match="too old"):
            renderers.prepare_tools(config_with(["helm"]), tmp_path / "cache")

    def test_kustomize_requires_go_1_27(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner(go_output="go version go1.26.9 linux/amd64")
        monkeypatch.setattr(renderers, "_run", runner)
        with pytest.raises(RenderError, match="too old"):
            renderers.prepare_tools(config_with(["kustomize"]), tmp_path / "cache")

    def test_helm_accepts_go_1_26(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner(go_output="go version go1.26.4 linux/amd64")
        monkeypatch.setattr(renderers, "_run", runner)
        provenance = renderers.prepare_tools(config_with(["helm"]), tmp_path / "cache")
        assert provenance["go"]["minimum"] == "1.26.0"

    def test_unparseable_go_version_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner(go_output="gopher")
        monkeypatch.setattr(renderers, "_run", runner)
        with pytest.raises(RenderError, match="cannot determine"):
            renderers.prepare_tools(config_with(["helm"]), tmp_path / "cache")

    def test_missing_go_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner(go_error=OSError("exec: go: not found"))
        monkeypatch.setattr(renderers, "_run", runner)
        with pytest.raises(RenderError, match="cannot run go"):
            renderers.prepare_tools(config_with(["helm"]), tmp_path / "cache")

    def test_prepare_failure_reported(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner(prepare_results={HELM_PIN: (b"", 3, b"boom\n")})
        monkeypatch.setattr(renderers, "_run", runner)
        with pytest.raises(RenderError, match="cannot prepare.*boom"):
            renderers.prepare_tools(config_with(["helm"]), tmp_path / "cache")

    def test_offline_verification_failure_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A cache that primes online but cannot render offline fails prepare."""
        runner = FakeRunner(offline_prepare_results={HELM_PIN: (b"", 1, b"proxy off\n")})
        monkeypatch.setattr(renderers, "_run", runner)
        with pytest.raises(RenderError, match="cannot run offline.*proxy off"):
            renderers.prepare_tools(config_with(["helm"]), tmp_path / "cache")

    def test_prepare_timeout_reported(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner(prepare_results={HELM_PIN: subprocess.TimeoutExpired(["go"], 900)})
        monkeypatch.setattr(renderers, "_run", runner)
        with pytest.raises(RenderError, match="900-second timeout"):
            renderers.prepare_tools(config_with(["helm"]), tmp_path / "cache")

    def test_cache_location_must_be_a_directory(self, tmp_path: Path) -> None:
        cache = tmp_path / "cache"
        cache.write_text("occupied\n")
        with pytest.raises(RenderError, match="not a directory"):
            renderers.prepare_tools(config_with(["helm"]), cache)


# --- Helm rendering ------------------------------------------------------------------


class TestHelmRender:
    def test_renders_with_pinned_argv_and_ordered_values(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, destination = snap_candidate(repo, tmp_path)
        scenario = helm_scenario(
            valuesFiles=["charts/demo/values-prod.yaml", "charts/demo/values.yaml"],
            setValues={"replicas": "2", "image.tag": "stable"},
            apiVersions=["batch/v1", "policy/v1beta1"],
        )
        output, runner = run_render(
            monkeypatch, records, scenario, prepared_cache(tmp_path, "helm"),
        )
        assert output == b""
        expected = [
            "go", "run", HELM_PIN, "template", "demo", str(destination / "charts/demo"),
            "--dry-run=client",
            "--namespace", "rhoai",
            "--kube-version", "1.36.6",
            "--include-crds",
            "--skip-schema-validation",
            "--api-versions", "batch/v1",
            "--api-versions", "policy/v1beta1",
            "--values", str(destination / "charts/demo/values-prod.yaml"),
            "--values", str(destination / "charts/demo/values.yaml"),
            "--set-string", "image.tag=stable",
            "--set-string", "replicas=2",
            "--is-upgrade",
        ]
        assert [call["argv"] for call in runner.render_calls] == [expected, expected]
        assert len(runner.calls) == 3  # go version + two passes

    def test_install_mode_omits_is_upgrade(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, destination = snap_candidate(repo, tmp_path)
        _, runner = run_render(
            monkeypatch, records, helm_scenario(releaseMode="install"),
            prepared_cache(tmp_path, "helm"),
        )
        argv = runner.render_calls[0]["argv"]
        assert "--is-upgrade" not in argv
        assert argv[:5] == ["go", "run", HELM_PIN, "template", "demo"]

    def test_offline_isolated_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("HELM_DRIVER", "configmaps")
        monkeypatch.setenv("KUSTOMIZE_PLUGIN_HOME", "/tmp/x")
        monkeypatch.setenv("GOPROXY", "https://proxy.example.invalid")
        monkeypatch.setenv("GOPRIVATE", "*")
        monkeypatch.setenv("GONOPROXY", "example.invalid")
        monkeypatch.setenv("GONOSUMDB", "example.invalid")
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        cache = prepared_cache(tmp_path, "helm")
        _, runner = run_render(monkeypatch, records, helm_scenario(), cache)
        envs = [call["env"] for call in runner.render_calls]
        assert len(envs) == 2
        for env in envs:
            # Strictly offline: the module proxy is the cache's own download
            # directory, which no network request can reach.
            assert env["GOPROXY"] == (
                tmp_path / "tool-cache" / "gomodcache" / "cache" / "download"
            ).as_uri()
            assert env["GOSUMDB"] == "off"
            # Inherited proxy-bypass settings would send matching modules to
            # direct (network) VCS resolution; they are cleared.
            assert env["GOPRIVATE"] == ""
            assert env["GONOPROXY"] == ""
            assert env["GONOSUMDB"] == ""
            assert env["GOWORK"] == "off"
            assert env["GOENV"] == "off"
            assert env["GOTOOLCHAIN"] == "local"
            assert env["CGO_ENABLED"] == "0"
            assert "HELM_DRIVER" not in env
            assert "KUSTOMIZE_PLUGIN_HOME" not in env
            assert env["GOMODCACHE"] == str(cache / "gomodcache")
            assert env["GOCACHE"] == str(cache / "gocache")
            assert env["GOPATH"] == str(cache / "gopath")
            assert env["HOME"] != os.environ["HOME"]
            assert env["TMPDIR"] == env["HOME"]
        assert envs[0]["HOME"] != envs[1]["HOME"]
        assert not Path(envs[0]["HOME"]).exists()
        assert not Path(envs[1]["HOME"]).exists()

    def test_document_order_differences_are_deterministic(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        first = b"kind: ConfigMap\nmetadata:\n  name: a\n---\nkind: ConfigMap\nmetadata:\n  name: b\n"
        second = b"kind: ConfigMap\nmetadata:\n  name: b\n---\nkind: ConfigMap\nmetadata:\n  name: a\n"
        output, _ = run_render(
            monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "helm"),
            render_outputs=[(first, 0, b""), (second, 0, b"")],
        )
        assert output == first

    def test_nondeterministic_output_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="not deterministic"):
            run_render(
                monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "helm"),
                render_outputs=[(b"kind: A\n", 0, b""), (b"kind: B\n", 0, b"")],
            )

    def test_subprocess_failure_redacts_values_secrets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        scenario = helm_scenario(valuesFiles=["charts/demo/values-prod.yaml"])
        stderr = f"Error: chart failed near {VALUES_SECRET_MARKER}\n".encode()
        with pytest.raises(RenderError) as excinfo:
            run_render(
                monkeypatch, records, scenario, prepared_cache(tmp_path, "helm"),
                render_outputs=[(b"", 1, stderr)],
            )
        message = str(excinfo.value)
        assert VALUES_SECRET_MARKER not in message
        assert "[redacted]" in message

    def test_subprocess_failure_redacts_chart_and_subchart_defaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Chart defaults are as likely to be echoed by a failing template as
        # selected values are, so every values.yaml under the chart (including
        # vendored subcharts) contributes redaction markers.
        repo = build_repo(
            tmp_path,
            copies={"chart": "charts/demo"},
            files={
                "charts/demo/values.yaml": "secretValue: chart-defaults-secret-marker\n",
                "charts/demo/charts/sub/values.yaml": "token: subchart-defaults-secret-marker\n",
            },
        )
        records, _ = snap_candidate(repo, tmp_path)
        stderr = (
            b"Error: template failed near chart-defaults-secret-marker "
            b"and subchart-defaults-secret-marker\n"
        )
        with pytest.raises(RenderError) as excinfo:
            run_render(
                monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "helm"),
                render_outputs=[(b"", 1, stderr)],
            )
        message = str(excinfo.value)
        assert "chart-defaults-secret-marker" not in message
        assert "subchart-defaults-secret-marker" not in message
        assert "[redacted]" in message

    def test_subprocess_failure_redacts_archived_subchart_defaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Vendored chart archives are unpacked in memory by helm; their
        # values.yaml members are chart defaults like any other.
        archive = make_tgz({
            "archived/Chart.yaml": b"apiVersion: v2\nname: archived\nversion: 1.0.0\n",
            "archived/values.yaml": b"secretValue: archived-subchart-secret-marker\n",
        })
        repo = build_repo(tmp_path, files={
            "charts/demo/Chart.yaml": (
                "apiVersion: v2\nname: demo\nversion: 0.1.0\ndependencies:\n"
                "  - name: archived\n    version: 1.0.0\n"
            ),
            "charts/demo/templates/cm.yaml": "kind: ConfigMap\n",
            "charts/demo/charts/archived-1.0.0.tgz": archive,
        })
        records, _ = snap_candidate(repo, tmp_path)
        stderr = b"Error: template failed near archived-subchart-secret-marker\n"
        with pytest.raises(RenderError) as excinfo:
            run_render(
                monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "helm"),
                render_outputs=[(b"", 1, stderr)],
            )
        message = str(excinfo.value)
        assert "archived-subchart-secret-marker" not in message
        assert "[redacted]" in message

    def test_timeout_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="timeout"):
            run_render(
                monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "helm"),
                render_outputs=[subprocess.TimeoutExpired(["go"], 120)],
            )

    def test_output_size_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        monkeypatch.setattr(renderers, "MAX_RENDER_OUTPUT_BYTES", 32)
        with pytest.raises(RenderError, match="MiB of output"):
            run_render(
                monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "helm"),
                render_outputs=[(b"x" * 64, 0, b"")],
            )

    def test_document_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        monkeypatch.setattr(renderers, "MAX_RENDER_DOCUMENTS", 2)
        output = b"kind: A\n---\nkind: B\n---\nkind: C\n"
        with pytest.raises(RenderError, match="document limit"):
            run_render(
                monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "helm"),
                render_outputs=[(output, 0, b"")],
            )

    def test_invalid_yaml_output_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="not valid YAML"):
            run_render(
                monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "helm"),
                render_outputs=[(b"key: [unclosed\n", 0, b"")],
            )

    def test_unprepared_cache_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="does not contain"):
            run_render(
                monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "kustomize"),
            )

    def test_cache_required(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="requires a prepared tool cache"):
            renderers.render(records, helm_scenario(), None)

    def test_absent_chart_is_missing_input(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(MissingInputError) as excinfo:
            renderers.render(
                records, helm_scenario(path="charts/absent"), prepared_cache(tmp_path, "helm"),
            )
        assert excinfo.value.missing == ["charts/absent"]
        assert excinfo.value.matched == []

    def test_missing_chart_yaml(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"charts/demo/templates/cm.yaml": "kind: ConfigMap\n"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="has no Chart.yaml"):
            renderers.render(records, helm_scenario(), prepared_cache(tmp_path, "helm"))

    def test_missing_values_file_is_missing_input(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        scenario = helm_scenario(valuesFiles=["charts/demo/absent-values.yaml"])
        with pytest.raises(MissingInputError) as excinfo:
            renderers.render(records, scenario, prepared_cache(tmp_path, "helm"))
        assert excinfo.value.missing == ["charts/demo/absent-values.yaml"]
        assert excinfo.value.matched == ["charts/demo"]

    def test_values_file_hazard_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        os.symlink("values.yaml", repo / "charts/demo/values-link.yaml")
        records, _ = snap_candidate(repo, tmp_path)
        scenario = helm_scenario(valuesFiles=["charts/demo/values-link.yaml"])
        with pytest.raises(RenderError, match="cannot be safely materialized"):
            renderers.render(records, scenario, prepared_cache(tmp_path, "helm"))

    def test_chart_directory_hazard_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        os.symlink("/etc/passwd", repo / "charts/demo/templates/link.yaml")
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="cannot be safely materialized"):
            renderers.render(records, helm_scenario(), prepared_cache(tmp_path, "helm"))

    def test_remote_dependency_rejected(self, tmp_path: Path) -> None:
        chart_yaml = (
            "apiVersion: v2\nname: demo\nversion: 0.1.0\ndependencies:\n"
            "  - name: sub\n    version: 0.1.0\n    repository: https://charts.example.com\n"
        )
        repo = build_repo(
            tmp_path, copies={"chart": "charts/demo"},
            files={"charts/demo/Chart.yaml": chart_yaml},
        )
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="declares repository"):
            renderers.render(records, helm_scenario(), prepared_cache(tmp_path, "helm"))

    def test_absent_dependency_rejected(self, tmp_path: Path) -> None:
        chart_yaml = (
            "apiVersion: v2\nname: demo\nversion: 0.1.0\ndependencies:\n"
            "  - name: ghost\n    version: 0.1.0\n"
        )
        repo = build_repo(
            tmp_path, copies={"chart": "charts/demo"},
            files={"charts/demo/Chart.yaml": chart_yaml},
        )
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="not vendored"):
            renderers.render(records, helm_scenario(), prepared_cache(tmp_path, "helm"))

    def test_dependency_alias_accepted(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chart_yaml = (
            "apiVersion: v2\nname: demo\nversion: 0.1.0\ndependencies:\n"
            "  - name: ghost\n    version: 0.1.0\n    alias: sub\n"
        )
        repo = build_repo(
            tmp_path, copies={"chart": "charts/demo"},
            files={"charts/demo/Chart.yaml": chart_yaml},
        )
        records, _ = snap_candidate(repo, tmp_path)
        output, _ = run_render(
            monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "helm"),
        )
        assert output == b""

    def test_chart_without_name_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(
            tmp_path, files={"charts/demo/Chart.yaml": "apiVersion: v2\nversion: 0.1.0\n"},
        )
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="must declare a name"):
            renderers.render(records, helm_scenario(), prepared_cache(tmp_path, "helm"))

    def test_lookup_in_archived_subchart_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, copies={"chart-tgz": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="'lookup'"):
            renderers.render(records, helm_scenario(), prepared_cache(tmp_path, "helm"))

    def test_tpl_in_nested_archive_rejected(self, tmp_path: Path) -> None:
        nested = make_tgz({
            "nested/Chart.yaml": b"apiVersion: v2\nname: nested\nversion: 0.1.0\n",
            "nested/templates/tpl.yaml": b"v: {{ tpl .Values.text . }}\n",
        })
        outer = make_tgz({
            "archived/Chart.yaml": b"apiVersion: v2\nname: archived\nversion: 1.0.0\n",
            "archived/templates/cm.yaml": b"kind: ConfigMap\n",
            "archived/charts/nested-0.1.0.tgz": nested,
        })
        repo = build_repo(tmp_path, files={
            "charts/demo/Chart.yaml": (
                "apiVersion: v2\nname: demo\nversion: 0.1.0\ndependencies:\n"
                "  - name: archived\n    version: 1.0.0\n"
            ),
            "charts/demo/templates/cm.yaml": "kind: ConfigMap\n",
            "charts/demo/charts/archived-1.0.0.tgz": outer,
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError) as excinfo:
            renderers.render(records, helm_scenario(), prepared_cache(tmp_path, "helm"))
        message = str(excinfo.value)
        assert "'tpl'" in message
        assert "nested" in message

    @pytest.mark.parametrize("template_name", ["_helpers.tpl", "NOTES.txt", "unused.yaml"])
    def test_forbidden_functions_in_any_template_file_rejected(
        self, tmp_path: Path, template_name: str,
    ) -> None:
        forbidden = b'name: x\ndata:\n  value: {{ lookup "v1" "cm" .Release.Namespace "x" }}\n'
        repo = build_repo(
            tmp_path, copies={"chart": "charts/demo"},
            files={f"charts/demo/templates/{template_name}": forbidden},
        )
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="'lookup'"):
            renderers.render(records, helm_scenario(), prepared_cache(tmp_path, "helm"))

    def test_scenario_field_validation(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        cache = prepared_cache(tmp_path, "helm")
        cases: list[tuple[dict[str, Any], str]] = [
            ({**helm_scenario(), "releaseName": None}, "releaseName"),
            ({k: v for k, v in helm_scenario().items() if k != "releaseName"}, "releaseName"),
            ({k: v for k, v in helm_scenario().items() if k != "namespace"}, "namespace"),
            ({k: v for k, v in helm_scenario().items() if k != "kubernetesVersion"}, "kubernetesVersion"),
            ({**helm_scenario(), "releaseMode": "bogus"}, "releaseMode"),
            ({**helm_scenario(), "setValues": {"key": 1}}, "setValues"),
            ({**helm_scenario(), "apiVersions": [1]}, "apiVersions"),
            (helm_scenario(path="../charts/demo"), "repo-relative"),
            (helm_scenario(valuesFiles=["../escape.yaml"]), "repo-relative"),
        ]
        for scenario, expected in cases:
            with pytest.raises(RenderError, match=expected):
                renderers.render(records, scenario, cache)

    def test_zero_documents_is_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"chart": "charts/demo"})
        records, _ = snap_candidate(repo, tmp_path)
        output, _ = run_render(
            monkeypatch, records, helm_scenario(), prepared_cache(tmp_path, "helm"),
            render_outputs=[(b"", 0, b"")],
        )
        assert output == b""


# --- Kustomize rendering ----------------------------------------------------------------


class TestKustomizeRender:
    def test_renders_with_pinned_argv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"kustomize": "manifests"})
        records, destination = snap_candidate(repo, tmp_path)
        output, runner = run_render(
            monkeypatch, records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
        )
        assert output == b""
        expected = ["go", "run", KUSTOMIZE_PIN, "build", str(destination / "manifests/overlays/prod")]
        assert [call["argv"] for call in runner.render_calls] == [expected, expected]
        assert len(runner.calls) == 3

    def test_offline_isolated_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("KUSTOMIZE_PLUGIN", "x")
        monkeypatch.setenv("GOPROXY", "https://proxy.example.invalid")
        monkeypatch.setenv("GOPRIVATE", "*")
        monkeypatch.setenv("GONOPROXY", "example.invalid")
        repo = build_repo(tmp_path, copies={"kustomize": "manifests"})
        records, _ = snap_candidate(repo, tmp_path)
        _, runner = run_render(
            monkeypatch, records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
        )
        for call in runner.render_calls:
            env = call["env"]
            assert env["GOPROXY"] == (
                tmp_path / "tool-cache" / "gomodcache" / "cache" / "download"
            ).as_uri()
            assert env["GOSUMDB"] == "off"
            assert env["GOPRIVATE"] == ""
            assert env["GONOPROXY"] == ""
            assert env["GONOSUMDB"] == ""
            assert env["GOTOOLCHAIN"] == "local"
            assert "KUSTOMIZE_PLUGIN" not in env
            assert env["HOME"] != os.environ["HOME"]

    def test_remote_base_rejected(self, tmp_path: Path) -> None:
        for index, remote in enumerate((
            "https://github.com/example/repo//base",
            "git@github.com:org/repo.git//base",
        )):
            repo = build_repo(tmp_path, name=f"repo-{index}", files={
                "manifests/overlays/prod/kustomization.yaml": f"resources:\n  - {remote}\n",
            })
            records, _ = snap_candidate(repo, tmp_path, name=f"snap-{index}")
            with pytest.raises(RenderError, match="remote reference"):
                renderers.render(
                    records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
                )

    def test_path_escape_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml":
                "resources:\n  - ../../../../etc\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="escapes the repository snapshot"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    @pytest.mark.parametrize("field", ["helmCharts", "helmGlobals"])
    def test_helm_inflator_rejected(self, tmp_path: Path, field: str) -> None:
        content = f"{field}:\n  - name: something\n" if field == "helmCharts" else f"{field}:\n  chartHome: charts\n"
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml": content,
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="Helm-in-Kustomize"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_exec_plugin_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml": (
                "resources:\n  - deployment.yaml\n"
                "transformers:\n"
                "  - |\n"
                "    apiVersion: cfg.kustomize.io/v1beta1\n"
                "    kind: exec\n"
            ),
            "manifests/overlays/prod/deployment.yaml": "kind: Deployment\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="exec plugins are not supported"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_missing_resource_inside_kustomization_is_render_error(self, tmp_path: Path) -> None:
        # The kustomization exists, so a missing nested reference is a broken
        # (partially present) input set, not an absent one: it must stay a
        # plain render error so a baseline cannot declare it new.
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml":
                "resources:\n  - nonexistent.yaml\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="does not exist in the snapshot"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_missing_component_inside_kustomization_is_render_error(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml":
                "components:\n  - ../../components/missing\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="does not exist in the snapshot"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_components_and_bases_recursed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/base/kustomization.yaml": "resources:\n  - deployment.yaml\n",
            "manifests/base/deployment.yaml": "kind: Deployment\n",
            "manifests/components/app/kustomization.yaml":
                "kind: Component\napiVersion: kustomize.config.k8s.io/v1alpha1\n",
            "manifests/overlays/prod/kustomization.yaml":
                "bases:\n  - ../../base\ncomponents:\n  - ../../components/app\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        output, _ = run_render(
            monkeypatch, records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
        )
        assert output == b""

    def test_absent_path_is_missing_input(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"unrelated.yaml": "x: 1\n"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(MissingInputError) as excinfo:
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))
        assert excinfo.value.missing == ["manifests/overlays/prod"]

    def test_directory_without_kustomization_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"manifests/overlays/prod/deployment.yaml": "kind: Deployment\n"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="contains no kustomization file"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_kustomization_yml_variant(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/base/kustomization.yaml": "resources:\n  - deployment.yaml\n",
            "manifests/base/deployment.yaml": "kind: Deployment\n",
            "manifests/overlays/prod/kustomization.yml": "resources:\n  - ../../base\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        output, _ = run_render(
            monkeypatch, records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
        )
        assert output == b""

    def test_kustomization_symlink_hazard_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"manifests/overlays/prod/deployment.yaml": "kind: Deployment\n"})
        os.symlink("elsewhere.yaml", repo / "manifests/overlays/prod/kustomization.yaml")
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="cannot be safely materialized"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_missing_env_file_inside_kustomization_is_render_error(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml": (
                "configMapGenerator:\n  - name: cfg\n    envs:\n      - nope.env\n"
            ),
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="does not exist in the snapshot"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_crds_glob_without_match_is_render_error(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml": "crds:\n  - '*.nomatch'\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="matches no files"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_remote_strategic_merge_patch_rejected(self, tmp_path: Path) -> None:
        # The pinned kustomize fetches URLs named in patchesStrategicMerge;
        # offline rendering must have no network path at all, so remote
        # entries are rejected before any subprocess runs.
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml":
                "patchesStrategicMerge:\n  - https://example.invalid/patch.yaml\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="remote reference"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_missing_strategic_merge_patch_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml":
                "patchesStrategicMerge:\n  - absent-patch.yaml\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="does not exist in the snapshot"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_inline_strategic_merge_patch_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The pinned kustomize parses each patchesStrategicMerge entry as
        # inline patch content first and falls back to file paths, so YAML
        # mapping entries are legitimate and must not be treated as
        # references.
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml": (
                "resources: []\n"
                "patchesStrategicMerge:\n"
                "  - |-\n"
                "      apiVersion: v1\n"
                "      kind: ConfigMap\n"
                "      metadata:\n"
                "        name: cfg\n"
                "  - file-patch.yaml\n"
            ),
            "manifests/overlays/prod/file-patch.yaml": "kind: ConfigMap\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        output, runner_fn = run_render(
            monkeypatch, records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
        )
        assert output == b""
        assert len(runner_fn.render_calls) == 2

    def test_strategic_merge_patch_hazard_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml":
                "patchesStrategicMerge:\n  - patch.yaml\n",
        })
        os.symlink("/etc/passwd", repo / "manifests/overlays/prod/patch.yaml")
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="cannot be safely materialized"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_generator_files_key_path_alias_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # kustomize's file sources accept "key=path" aliases; the scanner
        # must validate the path half, not the whole entry.
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml": (
                "resources: []\nconfigMapGenerator:\n  - name: cfg\n    files:\n"
                "      - settings=settings.ini\n"
            ),
            "manifests/overlays/prod/settings.ini": "[main]\nkey=value\n",
        })
        records, _ = snap_candidate(repo, tmp_path)
        output, runner_fn = run_render(
            monkeypatch, records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
        )
        assert output == b""
        assert len(runner_fn.render_calls) == 2

    def test_generator_files_alias_with_missing_path_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml": (
                "resources: []\nconfigMapGenerator:\n  - name: cfg\n    files:\n"
                "      - settings=absent.ini\n"
            ),
        })
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="does not exist in the snapshot"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_repository_root_path_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, copies={"kustomize": "manifests"})
        records, _ = snap_candidate(repo, tmp_path)
        for index, path_value in enumerate((".", "./", "./.")):
            with pytest.raises(RenderError, match="repository root"):
                renderers.render(
                    records, kustomize_scenario(path=path_value),
                    prepared_cache(tmp_path, "kustomize"),
                )

    def test_subprocess_failure_hides_snapshot_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Snapshot roots are random per run; error text quoting them would
        # make failing reports non-deterministic and leak local paths.
        repo = build_repo(tmp_path, copies={"kustomize": "manifests"})
        records, destination = snap_candidate(repo, tmp_path)
        stderr = f"Error: '{destination}/manifests/base' must resolve to a file\n".encode()
        with pytest.raises(RenderError) as excinfo:
            run_render(
                monkeypatch, records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
                render_outputs=[(b"", 1, stderr)],
            )
        message = str(excinfo.value)
        assert str(destination) not in message
        assert "<private>" in message

    def test_crds_glob_hazard_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml": "crds:\n  - 'crds/*.yaml'\n",
        })
        crds_dir = repo / "manifests/overlays/prod/crds"
        crds_dir.mkdir(parents=True)
        os.symlink("/etc/passwd", crds_dir / "bad.yaml")
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="cannot be safely materialized"):
            renderers.render(records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"))

    def test_nondeterministic_output_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"kustomize": "manifests"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="not deterministic"):
            run_render(
                monkeypatch, records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
                render_outputs=[(b"kind: A\n", 0, b""), (b"kind: B\n", 0, b"")],
            )

    def test_secret_literals_redacted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, files={
            "manifests/overlays/prod/kustomization.yaml": (
                "secretGenerator:\n  - name: db\n    literals:\n"
                f"      - PASSWORD={KUSTOMIZE_SECRET_MARKER}\n"
            ),
        })
        records, _ = snap_candidate(repo, tmp_path)
        stderr = f"Error: build failed at {KUSTOMIZE_SECRET_MARKER}\n".encode()
        with pytest.raises(RenderError) as excinfo:
            run_render(
                monkeypatch, records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
                render_outputs=[(b"", 1, stderr)],
            )
        message = str(excinfo.value)
        assert KUSTOMIZE_SECRET_MARKER not in message
        assert "[redacted]" in message

    def test_zero_documents_is_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = build_repo(tmp_path, copies={"kustomize": "manifests"})
        records, _ = snap_candidate(repo, tmp_path)
        output, _ = run_render(
            monkeypatch, records, kustomize_scenario(), prepared_cache(tmp_path, "kustomize"),
            render_outputs=[(b"", 0, b"")],
        )
        assert output == b""


# --- Raw rendering -----------------------------------------------------------------------


class TestRawRender:
    def test_joins_sources_in_file_order(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A\n", "b.yaml": "kind: B\n"})
        records, _ = snap_candidate(repo, tmp_path)
        output = renderers.render(records, raw_scenario(["b.yaml", "a.yaml"]), None)
        assert output == b"kind: A\n---\nkind: B\n"

    def test_glob_sources_sorted_and_deduplicated(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A\n", "b.yaml": "kind: B\n"})
        records, _ = snap_candidate(repo, tmp_path)
        output = renderers.render(records, raw_scenario(["*.yaml", "a.yaml", "b.yaml"]), None)
        assert output == b"kind: A\n---\nkind: B\n"

    def test_missing_trailing_newline_added(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A"})
        records, _ = snap_candidate(repo, tmp_path)
        assert renderers.render(records, raw_scenario(["a.yaml"]), None) == b"kind: A\n"

    def test_empty_source_is_zero_document_success(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"empty.yaml": ""})
        records, _ = snap_candidate(repo, tmp_path)
        assert renderers.render(records, raw_scenario(["empty.yaml"]), None) == b""

    def test_all_sources_missing_is_missing_input(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A\n"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(MissingInputError) as excinfo:
            renderers.render(records, raw_scenario(["missing.yaml"]), None)
        assert excinfo.value.missing == ["missing.yaml"]
        assert excinfo.value.matched == []

    def test_partially_missing_sources_report_both(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A\n", "b.yaml": "kind: B\n"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(MissingInputError) as excinfo:
            renderers.render(records, raw_scenario(["a.yaml", "missing.yaml", "*.yaml"]), None)
        assert excinfo.value.missing == ["missing.yaml"]
        assert excinfo.value.matched == ["a.yaml", "b.yaml"]

    def test_hazard_source_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A\n"})
        os.symlink("a.yaml", repo / "link.yaml")
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="cannot be safely materialized"):
            renderers.render(records, raw_scenario(["link.yaml"]), None)

    def test_escaped_sources_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A\n"})
        records, _ = snap_candidate(repo, tmp_path)
        for pattern in ("../secret.yaml", "/etc/passwd", ""):
            with pytest.raises(RenderError, match="repo-relative"):
                renderers.render(records, raw_scenario([pattern]), None)

    def test_empty_sources_list_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A\n"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="sources list"):
            renderers.render(records, raw_scenario([]), None)

    def test_invalid_yaml_rejected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "key: [unclosed\n"})
        records, _ = snap_candidate(repo, tmp_path)
        with pytest.raises(RenderError, match="not valid YAML"):
            renderers.render(records, raw_scenario(["a.yaml"]), None)

    def test_output_size_limit(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        repo = build_repo(tmp_path, files={"big.yaml": "x" * 64})
        records, _ = snap_candidate(repo, tmp_path)
        monkeypatch.setattr(renderers, "MAX_RENDER_OUTPUT_BYTES", 32)
        with pytest.raises(RenderError, match="output limit"):
            renderers.render(records, raw_scenario(["big.yaml"]), None)

    def test_document_limit(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A\n", "b.yaml": "kind: B\n"})
        records, _ = snap_candidate(repo, tmp_path)
        monkeypatch.setattr(renderers, "MAX_RENDER_DOCUMENTS", 1)
        with pytest.raises(RenderError, match="document limit"):
            renderers.render(records, raw_scenario(["*.yaml"]), None)

    def test_input_file_size_limit(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A\n"})
        records, _ = snap_candidate(repo, tmp_path)
        monkeypatch.setattr(renderers, "MAX_INPUT_FILE_BYTES", 4)
        with pytest.raises(RenderError, match="input size limit"):
            renderers.render(records, raw_scenario(["a.yaml"]), None)

    def test_digest_tamper_detected(self, tmp_path: Path) -> None:
        repo = build_repo(tmp_path, files={"a.yaml": "kind: A\n"})
        records, destination = snap_candidate(repo, tmp_path)
        (destination / "a.yaml").write_bytes(b"kind: TAMPERED\n")
        with pytest.raises(RenderError, match="changed after the snapshot was taken"):
            renderers.render(records, raw_scenario(["a.yaml"]), None)


# --- Snapshot record validation ------------------------------------------------------------


class TestSnapshotRecordValidation:
    def test_records_must_be_mappings(self) -> None:
        with pytest.raises(RenderError, match="not a mapping"):
            renderers.render(["not-a-record"], raw_scenario(["a.yaml"]), None)

    def test_records_require_file_and_root(self) -> None:
        with pytest.raises(RenderError, match="missing 'file' or 'root'"):
            renderers.render([{"path": "/x/a.yaml"}], raw_scenario(["a.yaml"]), None)

    def test_records_require_path(self) -> None:
        with pytest.raises(RenderError, match="missing 'path'"):
            renderers.render(
                [{"file": "a.yaml", "root": "/r"}], raw_scenario(["a.yaml"]), None
            )

    def test_multiple_roots_rejected(self) -> None:
        records = [
            {"file": "a.yaml", "root": "/one", "path": "/one/a.yaml"},
            {"file": "b.yaml", "root": "/two", "path": "/two/b.yaml"},
        ]
        with pytest.raises(RenderError, match="multiple roots"):
            renderers.render(records, raw_scenario(["*.yaml"]), None)

    def test_empty_snapshot_is_missing_input(self) -> None:
        with pytest.raises(MissingInputError):
            renderers.render([], raw_scenario(["a.yaml"]), None)

    def test_scenario_must_be_mapping(self) -> None:
        with pytest.raises(RenderError, match="scenario must be a mapping"):
            renderers.render([], "not-a-scenario", None)

    def test_unsupported_renderer_rejected(self) -> None:
        scenario = raw_scenario(["a.yaml"]) | {"renderer": "flux"}
        with pytest.raises(RenderError, match="unsupported renderer"):
            renderers.render([], scenario, None)

    def test_selected_hazard_record_rejected(self) -> None:
        records = [{"file": "a.yaml", "root": "/r", "hazard": "symlink"}]
        with pytest.raises(RenderError, match="cannot be safely materialized"):
            renderers.render(records, raw_scenario(["a.yaml"]), None)
