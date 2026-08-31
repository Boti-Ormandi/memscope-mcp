"""Behavioral tests for the release trust-boundary validator."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
import warnings
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(
    os.environ.get(
        "RELEASE_VALIDATOR",
        Path(__file__).parents[1] / "scripts" / "validate_release.py",
    )
)
PROJECT_NAME = "memscope-mcp"
pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="release validator requires Python 3.11+")


def run(*arguments: str, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(arguments),
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def git(repository: Path, *arguments: str) -> str:
    result = run("git", *arguments, cwd=repository)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def pyproject_text(name: str = PROJECT_NAME, version: str = "1.2.3", *, dynamic_version: bool = False) -> str:
    dynamic = 'dynamic = ["version"]\n' if dynamic_version else f'version = "{version}"\n'
    return f'[project]\nname = "{name}"\n{dynamic}'


def write_pyproject(
    repository: Path,
    name: str = PROJECT_NAME,
    version: str = "1.2.3",
    *,
    dynamic_version: bool = False,
) -> None:
    (repository / "pyproject.toml").write_text(
        pyproject_text(name, version, dynamic_version=dynamic_version),
        encoding="utf-8",
    )


def initialize_repository(
    path: Path,
    *,
    name: str = PROJECT_NAME,
    version: str = "1.2.3",
    dynamic_version: bool = False,
) -> tuple[Path, str]:
    path.mkdir()
    git(path, "init", "--initial-branch=main")
    git(path, "config", "user.name", "Release Tests")
    git(path, "config", "user.email", "release-tests@example.invalid")
    write_pyproject(path, name, version, dynamic_version=dynamic_version)
    git(path, "add", "pyproject.toml")
    git(path, "commit", "-m", "source")
    head = git(path, "rev-parse", "HEAD")
    git(path, "update-ref", "refs/remotes/origin/main", head)
    return path, head


def commit_project(repository: Path, *, name: str = PROJECT_NAME, version: str = "1.2.3") -> str:
    write_pyproject(repository, name, version)
    git(repository, "add", "pyproject.toml")
    git(repository, "commit", "--allow-empty", "-m", f"source {version}")
    return git(repository, "rev-parse", "HEAD")


def source_environment(event_name: str, github_ref: str, github_sha: str) -> dict[str, str]:
    return {
        **os.environ,
        "GITHUB_EVENT_NAME": event_name,
        "GITHUB_REF": github_ref,
        "GITHUB_SHA": github_sha,
    }


def invoke_source(
    repository: Path, event_name: str, github_ref: str, github_sha: str
) -> subprocess.CompletedProcess[str]:
    return run(
        sys.executable,
        os.fspath(SCRIPT),
        "source",
        cwd=repository,
        env=source_environment(event_name, github_ref, github_sha),
    )


def create_annotated_tag(repository: Path, tag: str) -> None:
    git(repository, "tag", "-a", tag, "-m", f"release {tag}")


def create_misnamed_tag_object(repository: Path, ref_name: str, embedded_name: str, commit: str) -> None:
    tag_document = (
        f"object {commit}\n"
        "type commit\n"
        f"tag {embedded_name}\n"
        "tagger Release Tests <release-tests@example.invalid> 946684800 +0000\n"
        "\n"
        "mismatched embedded tag name\n"
    )
    result = subprocess.run(
        ["git", "hash-object", "-t", "tag", "-w", "--stdin"],
        cwd=repository,
        input=tag_document.encode(),
        check=False,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    git(repository, "update-ref", f"refs/tags/{ref_name}", result.stdout.decode().strip())


def assert_failure(result: subprocess.CompletedProcess[str], concept: str) -> None:
    assert result.returncode == 1, result.stdout + result.stderr
    assert concept.lower() in result.stderr.lower(), result.stderr


def test_valid_annotated_release(tmp_path: Path) -> None:
    repository, head = initialize_repository(tmp_path / "repo")
    create_annotated_tag(repository, "v1.2.3")

    result = invoke_source(repository, "push", "refs/tags/v1.2.3", head)

    assert result.returncode == 0, result.stderr
    assert "project=memscope-mcp version=1.2.3 tag=v1.2.3" in result.stdout
    assert head in result.stdout


def test_zero_version_is_a_valid_canonical_release_boundary(tmp_path: Path) -> None:
    repository, head = initialize_repository(tmp_path / "repo", version="0.0.0")
    create_annotated_tag(repository, "v0.0.0")

    result = invoke_source(repository, "push", "refs/tags/v0.0.0", head)

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "tag",
    [
        "v01.2.3",
        "v1.02.3",
        "v1.2.03",
        "v1.2.3rc1",
        "v1.2.3+build",
        "v1.2",
    ],
)
def test_noncanonical_release_tags_are_rejected(tmp_path: Path, tag: str) -> None:
    repository, head = initialize_repository(tmp_path / "repo")
    create_annotated_tag(repository, tag)

    result = invoke_source(repository, "push", f"refs/tags/{tag}", head)

    assert_failure(result, "canonical vX.Y.Z")


def test_lightweight_release_tag_is_rejected(tmp_path: Path) -> None:
    repository, head = initialize_repository(tmp_path / "repo")
    git(repository, "tag", "v1.2.3")

    result = invoke_source(repository, "push", "refs/tags/v1.2.3", head)

    assert_failure(result, "annotated tag object")


def test_annotated_tag_embedded_name_must_match_ref(tmp_path: Path) -> None:
    repository, head = initialize_repository(tmp_path / "repo")
    create_misnamed_tag_object(repository, "v1.2.3", "v1.2.4", head)

    result = invoke_source(repository, "push", "refs/tags/v1.2.3", head)

    assert_failure(result, "embedded name must agree")


def test_release_tag_and_project_version_must_agree(tmp_path: Path) -> None:
    repository, head = initialize_repository(tmp_path / "repo", version="1.2.4")
    create_annotated_tag(repository, "v1.2.3")

    result = invoke_source(repository, "push", "refs/tags/v1.2.3", head)

    assert_failure(result, "does not agree with checkout project version")


def test_release_project_name_is_fixed(tmp_path: Path) -> None:
    repository, head = initialize_repository(tmp_path / "repo", name="other-project")
    create_annotated_tag(repository, "v1.2.3")

    result = invoke_source(repository, "push", "refs/tags/v1.2.3", head)

    assert_failure(result, "[project].name must be exactly")


def test_dynamic_project_version_is_rejected(tmp_path: Path) -> None:
    repository, head = initialize_repository(tmp_path / "repo", dynamic_version=True)
    create_annotated_tag(repository, "v1.2.3")

    result = invoke_source(repository, "push", "refs/tags/v1.2.3", head)

    assert_failure(result, "dynamic project version")


def test_release_event_sha_must_equal_tagged_commit(tmp_path: Path) -> None:
    repository, old_commit = initialize_repository(tmp_path / "repo")
    head = commit_project(repository)
    git(repository, "update-ref", "refs/remotes/origin/main", head)
    create_annotated_tag(repository, "v1.2.3")

    result = invoke_source(repository, "push", "refs/tags/v1.2.3", old_commit)

    assert_failure(result, "does not equal event SHA")


def test_release_checkout_head_must_equal_event_sha(tmp_path: Path) -> None:
    repository, tagged_commit = initialize_repository(tmp_path / "repo")
    create_annotated_tag(repository, "v1.2.3")
    newer_commit = commit_project(repository)
    git(repository, "update-ref", "refs/remotes/origin/main", newer_commit)

    result = invoke_source(repository, "push", "refs/tags/v1.2.3", tagged_commit)

    assert_failure(result, "checkout HEAD")


def test_release_commit_outside_origin_main_is_rejected(tmp_path: Path) -> None:
    repository, main_commit = initialize_repository(tmp_path / "repo")
    release_commit = commit_project(repository)
    create_annotated_tag(repository, "v1.2.3")
    assert git(repository, "rev-parse", "refs/remotes/origin/main") == main_commit

    result = invoke_source(repository, "push", "refs/tags/v1.2.3", release_commit)

    assert_failure(result, "outside current origin/main ancestry")


def test_manual_testpypi_from_exact_current_main_is_valid(tmp_path: Path) -> None:
    repository, head = initialize_repository(tmp_path / "repo")

    result = invoke_source(repository, "workflow_dispatch", "refs/heads/main", head)

    assert result.returncode == 0, result.stderr
    assert "event=workflow_dispatch" in result.stdout


def test_manual_testpypi_rejects_non_main_ref(tmp_path: Path) -> None:
    repository, head = initialize_repository(tmp_path / "repo")

    result = invoke_source(repository, "workflow_dispatch", "refs/heads/feature", head)

    assert_failure(result, "must use refs/heads/main")


def test_manual_testpypi_rejects_stale_main_checkout(tmp_path: Path) -> None:
    repository, old_main = initialize_repository(tmp_path / "repo")
    head = commit_project(repository)
    assert git(repository, "rev-parse", "refs/remotes/origin/main") == old_main

    result = invoke_source(repository, "workflow_dispatch", "refs/heads/main", head)

    assert_failure(result, "exact current origin/main")


def test_manual_testpypi_rejects_event_sha_mismatch(tmp_path: Path) -> None:
    repository, old_commit = initialize_repository(tmp_path / "repo")
    head = commit_project(repository)
    git(repository, "update-ref", "refs/remotes/origin/main", head)

    result = invoke_source(repository, "workflow_dispatch", "refs/heads/main", old_commit)

    assert_failure(result, "checkout HEAD")


def metadata_text(name: str = PROJECT_NAME, version: str = "1.2.3", *, duplicate_name: bool = False) -> bytes:
    extra_name = f"Name: {name}\n" if duplicate_name else ""
    return f"Metadata-Version: 2.4\nName: {name}\n{extra_name}Version: {version}\n\n".encode()


def add_tar_bytes(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mode = 0o644
    archive.addfile(member, io.BytesIO(data))


def write_wheel(
    dist: Path,
    *,
    filename: str = "memscope_mcp-1.2.3-py3-none-any.whl",
    metadata_path: str = "memscope_mcp-1.2.3.dist-info/METADATA",
    metadata_name: str = PROJECT_NAME,
    metadata_version: str = "1.2.3",
    duplicate_metadata_name: bool = False,
    extra_entries: list[tuple[str, bytes]] | None = None,
) -> Path:
    wheel = dist / filename
    entries = [
        (
            metadata_path,
            metadata_text(metadata_name, metadata_version, duplicate_name=duplicate_metadata_name),
        ),
        ("memscope_mcp/__init__.py", b""),
    ]
    entries.extend(extra_entries or [])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                archive.writestr(name, data)
    return wheel


def write_sdist(
    dist: Path,
    *,
    filename: str = "memscope_mcp-1.2.3.tar.gz",
    root: str = "memscope_mcp-1.2.3",
    pkg_name: str = PROJECT_NAME,
    pkg_version: str = "1.2.3",
    embedded_name: str = PROJECT_NAME,
    embedded_version: str = "1.2.3",
    extra_entries: list[tuple[str, bytes]] | None = None,
) -> Path:
    sdist = dist / filename
    entries = [
        (f"{root}/PKG-INFO", metadata_text(pkg_name, pkg_version)),
        (f"{root}/pyproject.toml", pyproject_text(embedded_name, embedded_version).encode()),
        (f"{root}/memscope_mcp/__init__.py", b""),
    ]
    entries.extend(extra_entries or [])
    with tarfile.open(sdist, "w:gz") as archive:
        for name, data in entries:
            add_tar_bytes(archive, name, data)
    return sdist


def initialize_artifacts(path: Path) -> tuple[Path, Path]:
    repository = path / "repo"
    repository.mkdir()
    write_pyproject(repository)
    dist = repository / "dist"
    dist.mkdir()
    return repository, dist


def invoke_artifacts(repository: Path) -> subprocess.CompletedProcess[str]:
    return run(sys.executable, os.fspath(SCRIPT), "artifacts", "--dist", "dist", cwd=repository)


def test_valid_artifacts_emit_identity_filenames_and_hashes(tmp_path: Path) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    wheel = write_wheel(dist)
    sdist = write_sdist(dist)

    result = invoke_artifacts(repository)

    assert result.returncode == 0, result.stderr
    assert "project=memscope-mcp version=1.2.3" in result.stdout
    assert f"{wheel.name} sha256=" in result.stdout
    assert f"{sdist.name} sha256=" in result.stdout
    assert result.stdout.count("sha256=") == 2


@pytest.mark.parametrize(
    ("case", "concept"),
    [
        ("wheel-filename-name", "wheel filename project name"),
        ("wheel-filename-version", "wheel filename version"),
        ("wheel-metadata-name", "wheel METADATA project name"),
        ("wheel-metadata-version", "wheel METADATA version"),
        ("sdist-filename-name", "sdist filename"),
        ("sdist-filename-version", "sdist filename"),
        ("sdist-pkg-name", "sdist PKG-INFO project name"),
        ("sdist-pkg-version", "sdist PKG-INFO version"),
        ("embedded-name", "embedded sdist pyproject.toml project name"),
        ("embedded-version", "embedded sdist pyproject.toml version"),
    ],
)
def test_artifact_identity_disagreement_is_rejected(tmp_path: Path, case: str, concept: str) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    wheel_arguments: dict[str, str] = {}
    sdist_arguments: dict[str, str] = {}
    if case == "wheel-filename-name":
        wheel_arguments["filename"] = "other_project-1.2.3-py3-none-any.whl"
    elif case == "wheel-filename-version":
        wheel_arguments["filename"] = "memscope_mcp-1.2.4-py3-none-any.whl"
    elif case == "wheel-metadata-name":
        wheel_arguments["metadata_name"] = "other-project"
    elif case == "wheel-metadata-version":
        wheel_arguments["metadata_version"] = "1.2.4"
    elif case == "sdist-filename-name":
        sdist_arguments["filename"] = "other_project-1.2.3.tar.gz"
    elif case == "sdist-filename-version":
        sdist_arguments["filename"] = "memscope_mcp-1.2.4.tar.gz"
    elif case == "sdist-pkg-name":
        sdist_arguments["pkg_name"] = "other-project"
    elif case == "sdist-pkg-version":
        sdist_arguments["pkg_version"] = "1.2.4"
    elif case == "embedded-name":
        sdist_arguments["embedded_name"] = "other-project"
    elif case == "embedded-version":
        sdist_arguments["embedded_version"] = "1.2.4"

    write_wheel(dist, **wheel_arguments)
    write_sdist(dist, **sdist_arguments)

    result = invoke_artifacts(repository)

    assert_failure(result, concept)


def test_duplicate_metadata_header_is_rejected_as_ambiguous(tmp_path: Path) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    write_wheel(dist, duplicate_metadata_name=True)
    write_sdist(dist)

    result = invoke_artifacts(repository)

    assert_failure(result, "exactly one Name header")


def test_multiple_wheel_metadata_members_are_rejected_as_ambiguous(tmp_path: Path) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    write_wheel(dist, extra_entries=[("other-1.2.3.dist-info/METADATA", metadata_text())])
    write_sdist(dist)

    result = invoke_artifacts(repository)

    assert_failure(result, "exactly the expected METADATA member")


def test_multiple_sdist_pkg_info_members_are_rejected_as_ambiguous(tmp_path: Path) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    write_wheel(dist)
    write_sdist(dist, extra_entries=[("memscope_mcp-1.2.3/nested/PKG-INFO", metadata_text())])

    result = invoke_artifacts(repository)

    assert_failure(result, "exactly the expected PKG-INFO member")


def test_missing_embedded_sdist_pyproject_is_rejected(tmp_path: Path) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    write_wheel(dist)
    with tarfile.open(dist / "memscope_mcp-1.2.3.tar.gz", "w:gz") as archive:
        add_tar_bytes(archive, "memscope_mcp-1.2.3/PKG-INFO", metadata_text())

    result = invoke_artifacts(repository)

    assert_failure(result, "missing expected embedded pyproject.toml")


@pytest.mark.parametrize("archive_kind", ["wheel", "sdist"])
def test_malformed_archives_are_rejected(tmp_path: Path, archive_kind: str) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    if archive_kind == "wheel":
        (dist / "memscope_mcp-1.2.3-py3-none-any.whl").write_bytes(b"not a zip archive")
        write_sdist(dist)
    else:
        write_wheel(dist)
        (dist / "memscope_mcp-1.2.3.tar.gz").write_bytes(b"not a tar archive")

    result = invoke_artifacts(repository)

    assert_failure(result, f"malformed {archive_kind} archive")


@pytest.mark.parametrize("archive_kind", ["wheel", "sdist"])
def test_duplicate_archive_members_are_rejected(tmp_path: Path, archive_kind: str) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    if archive_kind == "wheel":
        duplicate = ("memscope_mcp-1.2.3.dist-info/METADATA", metadata_text())
        write_wheel(dist, extra_entries=[duplicate])
        write_sdist(dist)
    else:
        duplicate = ("memscope_mcp-1.2.3/PKG-INFO", metadata_text())
        write_wheel(dist)
        write_sdist(dist, extra_entries=[duplicate])

    result = invoke_artifacts(repository)

    assert_failure(result, f"duplicate {archive_kind} archive member")


@pytest.mark.parametrize("archive_kind", ["wheel", "sdist"])
def test_unsafe_archive_paths_are_rejected_without_extraction(tmp_path: Path, archive_kind: str) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    outside = repository / "escaped.txt"
    if archive_kind == "wheel":
        write_wheel(dist, extra_entries=[("../escaped.txt", b"unsafe")])
        write_sdist(dist)
    else:
        write_wheel(dist)
        write_sdist(dist, extra_entries=[("memscope_mcp-1.2.3/../escaped.txt", b"unsafe")])

    result = invoke_artifacts(repository)

    assert_failure(result, f"unsafe {archive_kind} archive path")
    assert not outside.exists()


def test_missing_distribution_is_rejected(tmp_path: Path) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    write_wheel(dist)

    result = invoke_artifacts(repository)

    assert_failure(result, "exactly one wheel and one sdist")


def test_extra_distribution_entry_is_rejected(tmp_path: Path) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    write_wheel(dist)
    write_sdist(dist)
    (dist / "checksums.txt").write_text("unexpected", encoding="utf-8")

    result = invoke_artifacts(repository)

    assert_failure(result, "unexpected distribution entries")


def test_wrong_distribution_extension_is_rejected(tmp_path: Path) -> None:
    repository, dist = initialize_artifacts(tmp_path)
    write_wheel(dist)
    (dist / "memscope_mcp-1.2.3.zip").write_bytes(b"wrong distribution")

    result = invoke_artifacts(repository)

    assert_failure(result, "unexpected distribution entries")
