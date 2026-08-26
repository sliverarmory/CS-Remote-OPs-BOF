#!/usr/bin/env python3

import importlib.util
import pathlib


MODULE_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "check_release_version.py"
SPEC = importlib.util.spec_from_file_location("check_release_version", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def main() -> None:
    assert MODULE.parse_version("v0.1.4") == (0, 1, 4)
    assert MODULE.parse_version("v10.20.30") == (10, 20, 30)
    for invalid in ("0.1.4", "v00.1.4", "v0.01.4", "v0.1.04", "v0.1", "v0.1.4-rc1"):
        try:
            MODULE.parse_version(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid version {invalid}")

    releases = [
        {"tag_name": "v0.1.2", "draft": False, "prerelease": False},
        {"tag_name": "v0.1.3", "draft": False, "prerelease": False},
        {"tag_name": "v9.0.0", "draft": True, "prerelease": False},
        {"tag_name": "v8.0.0", "draft": False, "prerelease": True},
        {"tag_name": "not-semver", "draft": False, "prerelease": False},
    ]
    assert MODULE.require_newer("v0.1.4", releases) == "v0.1.3"
    for stale in ("v0.1.3", "v0.1.2", "v0.0.99"):
        try:
            MODULE.require_newer(stale, releases)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted non-increasing release {stale}")

    for malformed in ([[]], ["v0.1.3"], [None]):
        try:
            MODULE.require_newer("v0.1.4", malformed)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted malformed release inventory {malformed!r}")

    try:
        MODULE.require_newer(
            "v0.1.4",
            [{"tag_name": "v0.1.2", "draft": False, "prerelease": False}],
        )
    except ValueError:
        pass
    else:
        raise AssertionError("accepted inventory without immutable v0.1.3 baseline")
    print("release version tests passed")


if __name__ == "__main__":
    main()
