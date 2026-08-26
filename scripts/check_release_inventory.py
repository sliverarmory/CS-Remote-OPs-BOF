#!/usr/bin/env python3

import argparse
import json
import pathlib
import tarfile
from typing import Any


EXPECTED_PACKAGE_COUNT = 51


def canonical_repo_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    if normalized.lower().endswith(".git"):
        normalized = normalized[:-4]
    return normalized.lower()


def load_inventory(path: pathlib.Path) -> list[str]:
    names = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    if len(names) != EXPECTED_PACKAGE_COUNT:
        raise ValueError(
            f"canonical inventory must contain {EXPECTED_PACKAGE_COUNT} names, found {len(names)}"
        )
    if names != sorted(set(names)):
        raise ValueError("canonical inventory must be unique and sorted")
    return names


def safe_member_name(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    path = pathlib.PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe archive member path: {name!r}")
    return path.as_posix()


def commands_for_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    commands = manifest.get("commands")
    if commands is None:
        commands = [manifest]
    if not isinstance(commands, list) or not commands:
        raise ValueError("extension manifest has no commands")
    if not all(isinstance(command, dict) for command in commands):
        raise ValueError("extension manifest commands must be objects")
    return commands


def package_name_for_manifest(manifest: dict[str, Any]) -> str:
    commands = commands_for_manifest(manifest)
    package_name = manifest.get("package_name") or manifest.get("command_name")
    if package_name is None:
        package_name = commands[0].get("command_name")
    if not isinstance(package_name, str) or not package_name:
        raise ValueError("extension manifest has no package identity")
    return package_name


def validate_archive(
    archive: pathlib.Path,
    expected_name: str,
    tag: str | None,
    repo_url: str,
) -> dict[str, Any]:
    with tarfile.open(archive, "r:gz") as package:
        files: dict[str, tarfile.TarInfo] = {}
        for member in package.getmembers():
            name = safe_member_name(member.name)
            if member.isdir():
                continue
            if not member.isfile() or member.issym() or member.islnk() or member.isdev():
                raise ValueError(f"{archive.name}: non-regular member {name}")
            if name in files:
                raise ValueError(f"{archive.name}: duplicate member {name}")
            files[name] = member

        if "extension.json" not in files or "LICENSE" not in files:
            raise ValueError(f"{archive.name}: extension.json and LICENSE must be at archive root")
        manifest_file = package.extractfile(files["extension.json"])
        if manifest_file is None:
            raise ValueError(f"{archive.name}: cannot read extension.json")
        manifest_bytes = manifest_file.read()
        manifest = json.loads(manifest_bytes)
        if not isinstance(manifest, dict):
            raise ValueError(f"{archive.name}: extension.json must contain an object")

        package_name = package_name_for_manifest(manifest)
        if package_name != expected_name:
            raise ValueError(
                f"{archive.name}: manifest package {package_name!r} does not match {expected_name!r}"
            )
        if canonical_repo_url(str(manifest.get("repo_url", ""))) != canonical_repo_url(repo_url):
            raise ValueError(f"{archive.name}: unexpected repo_url {manifest.get('repo_url')!r}")
        if tag is not None and manifest.get("version") != tag:
            raise ValueError(
                f"{archive.name}: manifest version {manifest.get('version')!r} does not match {tag!r}"
            )

        referenced_files: set[str] = set()
        command_names: list[str] = []
        for command in commands_for_manifest(manifest):
            command_name = command.get("command_name")
            if not isinstance(command_name, str) or not command_name:
                raise ValueError(f"{archive.name}: command_name is missing")
            command_names.append(command_name)
            for file_entry in command.get("files", []):
                if not isinstance(file_entry, dict):
                    raise ValueError(f"{archive.name}: files entry is not an object")
                referenced_files.add(safe_member_name(str(file_entry.get("path", ""))))

        if len(command_names) != len(set(command_names)):
            raise ValueError(f"{archive.name}: duplicate signed command identity")
        expected_members = {"extension.json", "LICENSE", *referenced_files}
        if set(files) != expected_members:
            missing = sorted(expected_members - set(files))
            extra = sorted(set(files) - expected_members)
            raise ValueError(f"{archive.name}: archive inventory mismatch missing={missing} extra={extra}")
        for filename in referenced_files:
            if files[filename].size == 0:
                raise ValueError(f"{archive.name}: referenced file is empty: {filename}")

        return {
            "package_name": package_name,
            "commands": command_names,
            "manifest_bytes": len(manifest_bytes),
            "members": sorted(files),
        }


def verify_index(
    index_path: pathlib.Path,
    repo_url: str,
    inventory: set[str],
) -> tuple[list[str], str]:
    index = json.loads(index_path.read_text())
    matches: list[dict[str, Any]] = []
    for category in ("aliases", "extensions"):
        entries = index.get(category, [])
        if not isinstance(entries, list):
            raise ValueError(f"index field {category!r} is not an array")
        for entry in entries:
            if canonical_repo_url(str(entry.get("repo_url", ""))) == canonical_repo_url(repo_url):
                matches.append(entry)
    if not matches:
        raise ValueError("signed index has no entries for package repository")

    command_names = [str(entry.get("command_name", "")) for entry in matches]
    if any(not name for name in command_names) or len(command_names) != len(set(command_names)):
        raise ValueError("signed index package identities are missing or duplicated")
    missing = sorted(set(command_names) - inventory)
    if missing:
        raise ValueError(f"canonical inventory omits signed-index siblings: {missing}")

    public_keys = {str(entry.get("public_key", "")) for entry in matches}
    if "" in public_keys or len(public_keys) != 1:
        raise ValueError("signed-index siblings do not share exactly one package public key")
    return sorted(command_names), public_keys.pop()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", required=True, type=pathlib.Path)
    parser.add_argument("--packages-dir", required=True, type=pathlib.Path)
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--tag")
    parser.add_argument("--index", type=pathlib.Path)
    parser.add_argument("--require-signatures", action="store_true")
    parser.add_argument("--public-key-out", type=pathlib.Path)
    args = parser.parse_args()

    inventory = load_inventory(args.inventory)
    package_files = {path.name for path in args.packages_dir.iterdir() if path.is_file()}
    expected_archives = {f"{name}.tar.gz" for name in inventory}
    expected_signatures = {f"{name}.minisig" for name in inventory}
    expected_files = expected_archives | (expected_signatures if args.require_signatures else set())
    if package_files != expected_files:
        missing = sorted(expected_files - package_files)
        extra = sorted(package_files - expected_files)
        raise ValueError(f"release file inventory mismatch missing={missing} extra={extra}")

    validated = []
    for name in inventory:
        validated.append(
            validate_archive(
                args.packages_dir / f"{name}.tar.gz",
                name,
                args.tag,
                args.repo_url,
            )
        )

    indexed_names: list[str] = []
    package_public_key = ""
    if args.index is not None:
        indexed_names, package_public_key = verify_index(
            args.index,
            args.repo_url,
            set(inventory),
        )
        if args.public_key_out is not None:
            args.public_key_out.write_text(package_public_key + "\n")
    elif args.public_key_out is not None:
        raise ValueError("--public-key-out requires --index")

    print(
        json.dumps(
            {
                "archives": len(validated),
                "signatures": len(expected_signatures) if args.require_signatures else 0,
                "indexed_siblings": len(indexed_names),
                "package_public_key": package_public_key,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
