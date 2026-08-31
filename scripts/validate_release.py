#!/usr/bin/env python3
"""Validate release source state and built distribution identity."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from email import policy
from email.parser import Parser
from pathlib import Path
from typing import NoReturn

import tomllib

PROJECT_NAME = "memscope-mcp"
TAG_PATTERN = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
SHA_PATTERN = re.compile(r"[0-9a-fA-F]{40}\Z")
WHEEL_PART_PATTERN = re.compile(r"[A-Za-z0-9_.]+\Z")
MAX_METADATA_SIZE = 1024 * 1024


class ValidationError(Exception):
    """A release invariant was not satisfied."""


@dataclass(frozen=True)
class ProjectIdentity:
    name: str
    normalized_name: str
    version: str

    @property
    def distribution_component(self) -> str:
        return self.normalized_name.replace("-", "_")


@dataclass(frozen=True)
class DistributionFiles:
    wheel: Path
    sdist: Path


def fail(message: str) -> NoReturn:
    raise ValidationError(message)


def normalize_project_name(name: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    if not normalized or not normalized[0].isalnum() or not normalized[-1].isalnum():
        fail(f"invalid project name: {name!r}")
    return normalized


def load_project_identity(data: bytes, context: str) -> ProjectIdentity:
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        fail(f"{context} is not valid UTF-8 TOML: {exc}")

    project = document.get("project")
    if not isinstance(project, dict):
        fail(f"{context} must contain a [project] table")

    dynamic = project.get("dynamic", [])
    if not isinstance(dynamic, list) or not all(isinstance(item, str) for item in dynamic):
        fail(f"{context} [project].dynamic must be a list of strings")
    if "version" in dynamic:
        fail(f"{context} uses forbidden dynamic project version metadata")

    name = project.get("name")
    version = project.get("version")
    if not isinstance(name, str) or not name:
        fail(f"{context} must define a static [project].name string")
    if not isinstance(version, str) or not version:
        fail(f"{context} must define a static [project].version string")
    if VERSION_PATTERN.fullmatch(version) is None:
        fail(f"{context} project version must be canonical X.Y.Z without leading zeros or suffixes: {version!r}")

    return ProjectIdentity(name=name, normalized_name=normalize_project_name(name), version=version)


def load_checkout_identity(repository: Path) -> ProjectIdentity:
    pyproject = repository / "pyproject.toml"
    try:
        identity = load_project_identity(pyproject.read_bytes(), "checkout pyproject.toml")
    except OSError as exc:
        fail(f"cannot read checkout pyproject.toml: {exc}")
    if identity.name != PROJECT_NAME:
        fail(f"checkout [project].name must be exactly {PROJECT_NAME!r}, got {identity.name!r}")
    return identity


def run_git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        fail(f"cannot execute Git: {exc}")


def git_output(repository: Path, concept: str, *arguments: str) -> str:
    result = run_git(repository, *arguments)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        fail(f"cannot resolve {concept}: {detail}")
    return result.stdout.strip()


def resolve_commit(repository: Path, revision: str, concept: str) -> str:
    resolved = git_output(
        repository,
        concept,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{revision}^{{commit}}",
    )
    if SHA_PATTERN.fullmatch(resolved) is None:
        fail(f"Git returned an invalid object ID for {concept}: {resolved!r}")
    return resolved.lower()


def require_event_sha(repository: Path) -> tuple[str, str, str]:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    github_ref = os.environ.get("GITHUB_REF", "")
    github_sha = os.environ.get("GITHUB_SHA", "")
    if not event_name:
        fail("GITHUB_EVENT_NAME is required")
    if not github_ref:
        fail("GITHUB_REF is required")
    if SHA_PATTERN.fullmatch(github_sha) is None:
        fail("GITHUB_SHA must be a full 40-hex event SHA")

    event_commit = resolve_commit(repository, github_sha, "event SHA")
    if event_commit != github_sha.lower():
        fail(f"event SHA must identify a commit directly, got {github_sha}")
    return event_name, github_ref, event_commit


def annotated_tag_commit(repository: Path, tag_name: str) -> str:
    tag_ref = f"refs/tags/{tag_name}"
    object_type = git_output(repository, "release tag object type", "cat-file", "-t", tag_ref)
    if object_type != "tag":
        fail(f"release tag {tag_name!r} must be an annotated tag object; found {object_type!r}")

    tag_document = git_output(repository, "annotated tag object", "cat-file", "-p", tag_ref)
    headers: dict[str, str] = {}
    for line in tag_document.splitlines():
        if not line:
            break
        key, separator, value = line.partition(" ")
        if not separator:
            fail(f"annotated tag {tag_name!r} contains a malformed object header")
        if key in {"object", "type", "tag"}:
            if key in headers:
                fail(f"annotated tag {tag_name!r} contains duplicate {key!r} headers")
            headers[key] = value

    if headers.get("tag") != tag_name:
        fail(f"annotated tag embedded name must agree with ref name {tag_name!r}; found {headers.get('tag')!r}")
    if headers.get("type") != "commit":
        fail(f"annotated tag {tag_name!r} must point directly to a commit; found type {headers.get('type')!r}")
    target = headers.get("object", "")
    if SHA_PATTERN.fullmatch(target) is None:
        fail(f"annotated tag {tag_name!r} has an invalid target object ID")

    peeled = resolve_commit(repository, tag_ref, "peeled release tag commit")
    if peeled != target.lower():
        fail(f"annotated tag {tag_name!r} target and peeled commit disagree")
    return peeled


def validate_source(repository: Path) -> None:
    repository = repository.resolve()
    identity = load_checkout_identity(repository)
    event_name, github_ref, event_commit = require_event_sha(repository)
    head_commit = resolve_commit(repository, "HEAD", "checkout HEAD")
    main_commit = resolve_commit(repository, "refs/remotes/origin/main", "current origin/main")

    if event_name == "workflow_dispatch":
        if github_ref != "refs/heads/main":
            fail(f"manual TestPyPI rehearsal must use refs/heads/main, got {github_ref!r}")
        if head_commit != event_commit:
            fail(f"manual TestPyPI checkout HEAD {head_commit} does not equal event SHA {event_commit}")
        if event_commit != main_commit:
            fail(
                "manual TestPyPI rehearsal requires exact current origin/main: "
                f"event SHA {event_commit}, origin/main {main_commit}"
            )
        print(
            f"source valid: project={identity.normalized_name} version={identity.version} "
            f"event=workflow_dispatch commit={event_commit}"
        )
        return

    if event_name != "push":
        fail(f"unsupported release event {event_name!r}; only tag push and workflow_dispatch are allowed")
    tag_prefix = "refs/tags/"
    if not github_ref.startswith(tag_prefix):
        fail(f"production release push must use a tag ref, got {github_ref!r}")
    tag_name = github_ref.removeprefix(tag_prefix)
    match = TAG_PATTERN.fullmatch(tag_name)
    if match is None:
        fail(f"production release tag must be canonical vX.Y.Z without leading zeros or suffixes: {tag_name!r}")
    tag_version = ".".join(match.groups())
    if tag_version != identity.version:
        fail(f"release tag version {tag_version!r} does not agree with checkout project version {identity.version!r}")

    tagged_commit = annotated_tag_commit(repository, tag_name)
    if tagged_commit != event_commit:
        fail(f"peeled release tag commit {tagged_commit} does not equal event SHA {event_commit}")
    if head_commit != event_commit:
        fail(f"release checkout HEAD {head_commit} does not equal event SHA {event_commit}")

    ancestry = run_git(repository, "merge-base", "--is-ancestor", tagged_commit, main_commit)
    if ancestry.returncode == 1:
        fail(f"production tagged commit {tagged_commit} is outside current origin/main ancestry")
    if ancestry.returncode != 0:
        detail = ancestry.stderr.strip() or ancestry.stdout.strip() or f"exit {ancestry.returncode}"
        fail(f"cannot verify production origin/main ancestry: {detail}")

    print(
        f"source valid: project={identity.normalized_name} version={identity.version} "
        f"tag={tag_name} commit={tagged_commit}"
    )


def validate_archive_path(name: str, archive_kind: str) -> None:
    if not name or "\x00" in name or "\\" in name:
        fail(f"unsafe {archive_kind} archive path: {name!r}")
    candidate = name[:-1] if name.endswith("/") else name
    if not candidate or candidate.startswith("/") or re.match(r"[A-Za-z]:", candidate):
        fail(f"unsafe {archive_kind} archive path: {name!r}")
    components = candidate.split("/")
    if any(component in {"", ".", ".."} for component in components):
        fail(f"unsafe {archive_kind} archive path: {name!r}")


def parse_core_metadata(data: bytes, context: str) -> tuple[str, str]:
    if len(data) > MAX_METADATA_SIZE:
        fail(f"{context} exceeds the {MAX_METADATA_SIZE}-byte metadata limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{context} is not valid UTF-8: {exc}")
    message = Parser(policy=policy.default).parsestr(text)
    if message.defects:
        fail(f"{context} is malformed: {message.defects[0]}")

    values: dict[str, str] = {}
    for field in ("Name", "Version"):
        occurrences = message.get_all(field, [])
        if len(occurrences) != 1:
            fail(f"{context} must contain exactly one {field} header; found {len(occurrences)}")
        value = str(occurrences[0]).strip()
        if not value:
            fail(f"{context} contains an empty {field} header")
        values[field] = value
    return values["Name"], values["Version"]


def validate_metadata_identity(data: bytes, context: str, identity: ProjectIdentity) -> None:
    name, version = parse_core_metadata(data, context)
    normalized_name = normalize_project_name(name)
    if normalized_name != identity.normalized_name:
        fail(
            f"{context} project name {name!r} normalizes to {normalized_name!r}, expected {identity.normalized_name!r}"
        )
    if version != identity.version:
        fail(f"{context} version {version!r} does not agree with checkout version {identity.version!r}")


def select_distribution_files(dist_directory: Path) -> DistributionFiles:
    if not dist_directory.is_dir():
        fail(f"distribution directory does not exist or is not a directory: {dist_directory}")
    try:
        entries = sorted(dist_directory.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        fail(f"cannot list distribution directory {dist_directory}: {exc}")

    files = [entry for entry in entries if entry.is_file() and not entry.is_symlink()]
    non_files = [entry.name for entry in entries if not entry.is_file() or entry.is_symlink()]
    wheels = [entry for entry in files if entry.name.endswith(".whl")]
    sdists = [entry for entry in files if entry.name.endswith(".tar.gz")]
    recognized = {entry.name for entry in wheels + sdists}
    extras = non_files + [entry.name for entry in files if entry.name not in recognized]

    if extras:
        fail(f"unexpected distribution entries; expected only one wheel and one sdist: {extras}")
    if len(wheels) != 1 or len(sdists) != 1:
        fail(
            "distribution directory must contain exactly one wheel and one sdist; "
            f"found {len(wheels)} wheel(s) and {len(sdists)} sdist(s)"
        )
    return DistributionFiles(wheel=wheels[0], sdist=sdists[0])


def validate_wheel_filename(filename: str, identity: ProjectIdentity) -> None:
    if not filename.endswith(".whl"):
        fail(f"wheel filename must end in .whl: {filename!r}")
    parts = filename[:-4].split("-")
    if len(parts) not in {5, 6}:
        fail(f"wheel filename is malformed: {filename!r}")
    distribution, version = parts[0], parts[1]
    tag_parts = parts[-3:]
    build = parts[2] if len(parts) == 6 else None
    if distribution != identity.distribution_component:
        fail(f"wheel filename project name {distribution!r} does not agree with {identity.distribution_component!r}")
    if version != identity.version:
        fail(f"wheel filename version {version!r} does not agree with checkout version {identity.version!r}")
    if build is not None and re.fullmatch(r"[0-9][A-Za-z0-9_.]*", build) is None:
        fail(f"wheel filename contains an invalid build tag: {filename!r}")
    if any(WHEEL_PART_PATTERN.fullmatch(part) is None for part in tag_parts):
        fail(f"wheel filename contains an invalid compatibility tag: {filename!r}")


def validate_wheel(wheel: Path, identity: ProjectIdentity) -> None:
    validate_wheel_filename(wheel.name, identity)
    expected_metadata = f"{identity.distribution_component}-{identity.version}.dist-info/METADATA"
    try:
        with zipfile.ZipFile(wheel, "r") as archive:
            infos = archive.infolist()
            names: set[str] = set()
            for info in infos:
                validate_archive_path(info.filename, "wheel")
                if info.filename in names:
                    fail(f"duplicate wheel archive member: {info.filename!r}")
                names.add(info.filename)
            metadata_members = [name for name in names if name.endswith(".dist-info/METADATA")]
            if metadata_members != [expected_metadata]:
                fail(
                    "wheel must contain exactly the expected METADATA member "
                    f"{expected_metadata!r}; found {sorted(metadata_members)}"
                )
            info = archive.getinfo(expected_metadata)
            if info.is_dir() or info.file_size > MAX_METADATA_SIZE:
                fail(f"wheel METADATA member is not a bounded regular file: {expected_metadata!r}")
            metadata = archive.read(info)
    except ValidationError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        fail(f"malformed wheel archive {wheel.name!r}: {exc}")

    validate_metadata_identity(metadata, "wheel METADATA", identity)


def read_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo, context: str) -> bytes:
    if not member.isfile() or member.size > MAX_METADATA_SIZE:
        fail(f"{context} must be a bounded regular file")
    stream = archive.extractfile(member)
    if stream is None:
        fail(f"cannot read {context}")
    try:
        return stream.read(MAX_METADATA_SIZE + 1)
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot read {context}: {exc}")


def validate_sdist_filename(filename: str, identity: ProjectIdentity) -> str:
    expected = f"{identity.distribution_component}-{identity.version}.tar.gz"
    if filename != expected:
        fail(f"sdist filename {filename!r} does not agree with expected identity {expected!r}")
    return expected.removesuffix(".tar.gz")


def validate_sdist(sdist: Path, identity: ProjectIdentity) -> None:
    root = validate_sdist_filename(sdist.name, identity)
    expected_pkg_info = f"{root}/PKG-INFO"
    expected_pyproject = f"{root}/pyproject.toml"
    try:
        with tarfile.open(sdist, "r:gz") as archive:
            members: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                validate_archive_path(member.name, "sdist")
                if member.name in members:
                    fail(f"duplicate sdist archive member: {member.name!r}")
                if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    fail(f"unsupported or unsafe sdist archive member type: {member.name!r}")
                if member.name != root and not member.name.startswith(f"{root}/"):
                    fail(f"sdist archive member is outside expected root {root!r}: {member.name!r}")
                members[member.name] = member

            pkg_info_matches = [name for name in members if name.endswith("/PKG-INFO")]
            if pkg_info_matches != [expected_pkg_info]:
                fail(
                    "sdist must contain exactly the expected PKG-INFO member "
                    f"{expected_pkg_info!r}; found {sorted(pkg_info_matches)}"
                )
            if expected_pyproject not in members:
                fail(f"sdist is missing expected embedded pyproject.toml member {expected_pyproject!r}")
            pkg_info = read_tar_member(archive, members[expected_pkg_info], "sdist PKG-INFO")
            embedded_pyproject = read_tar_member(
                archive,
                members[expected_pyproject],
                "embedded sdist pyproject.toml",
            )
    except ValidationError:
        raise
    except (OSError, EOFError, tarfile.TarError) as exc:
        fail(f"malformed sdist archive {sdist.name!r}: {exc}")

    validate_metadata_identity(pkg_info, "sdist PKG-INFO", identity)
    embedded_identity = load_project_identity(embedded_pyproject, "embedded sdist pyproject.toml")
    if embedded_identity.name != identity.name:
        fail(
            f"embedded sdist pyproject.toml project name {embedded_identity.name!r} "
            f"does not exactly agree with checkout name {identity.name!r}"
        )
    if embedded_identity.version != identity.version:
        fail(
            f"embedded sdist pyproject.toml version {embedded_identity.version!r} "
            f"does not agree with checkout version {identity.version!r}"
        )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        fail(f"cannot hash distribution file {path}: {exc}")
    return digest.hexdigest()


def validate_artifacts(repository: Path, dist_directory: Path) -> None:
    repository = repository.resolve()
    if not dist_directory.is_absolute():
        dist_directory = repository / dist_directory
    identity = load_checkout_identity(repository)
    distributions = select_distribution_files(dist_directory)
    validate_wheel(distributions.wheel, identity)
    validate_sdist(distributions.sdist, identity)
    print(f"artifacts valid: project={identity.normalized_name} version={identity.version}")
    for path in (distributions.wheel, distributions.sdist):
        print(f"{path.name} sha256={sha256(path)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    source = subparsers.add_parser("source", help="validate checkout and Git release identity")
    source.add_argument("--repository", type=Path, default=Path.cwd())

    artifacts = subparsers.add_parser("artifacts", help="validate freshly built distributions")
    artifacts.add_argument("--repository", type=Path, default=Path.cwd())
    artifacts.add_argument("--dist", type=Path, default=Path("dist"))
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        if arguments.command == "source":
            validate_source(arguments.repository)
        else:
            validate_artifacts(arguments.repository, arguments.dist)
    except ValidationError as exc:
        print(f"release validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
