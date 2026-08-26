#!/usr/bin/env python3

import argparse
import json
import pathlib
import re


STRICT_VERSION = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
REQUIRED_PUBLISHED_BASELINE = "v0.1.3"


def parse_version(value: str) -> tuple[int, int, int]:
    match = STRICT_VERSION.fullmatch(value)
    if match is None:
        raise ValueError(
            f"release version must be vMAJOR.MINOR.PATCH without leading zeroes: {value!r}"
        )
    return tuple(int(component) for component in match.groups())


def require_newer(candidate_tag: str, releases: list[object]) -> str:
    candidate = parse_version(candidate_tag)
    published: list[tuple[tuple[int, int, int], str]] = []
    for release in releases:
        if not isinstance(release, dict):
            raise ValueError("every release inventory entry must be an object")
        if release.get("draft") or release.get("prerelease"):
            continue
        tag = release.get("tag_name")
        if isinstance(tag, str) and STRICT_VERSION.fullmatch(tag):
            published.append((parse_version(tag), tag))

    if REQUIRED_PUBLISHED_BASELINE not in {tag for _, tag in published}:
        raise ValueError(
            f"required immutable published baseline {REQUIRED_PUBLISHED_BASELINE} is missing"
        )
    highest_version, highest_tag = max(published)
    if candidate <= highest_version:
        raise ValueError(
            f"candidate {candidate_tag} must be higher than published stable release {highest_tag}"
        )
    return highest_tag


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--releases-json", required=True, type=pathlib.Path)
    args = parser.parse_args()

    releases = json.loads(args.releases_json.read_text())
    if not isinstance(releases, list):
        raise ValueError("release inventory must be a JSON array")
    print(require_newer(args.candidate, releases))


if __name__ == "__main__":
    main()
