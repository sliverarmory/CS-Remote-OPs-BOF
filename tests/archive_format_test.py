#!/usr/bin/env python3

import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.check_release_inventory import validate_archive  # noqa: E402


class ArchiveFormatTest(unittest.TestCase):
    def write_archive(self, path: pathlib.Path, prefix: str) -> None:
        manifest = json.dumps(
            {
                "name": "Test Extension",
                "package_name": "test-extension",
                "version": "v1.2.3",
                "repo_url": "https://github.com/sliverarmory/test-extension",
                "commands": [
                    {
                        "command_name": "test-extension",
                        "files": [{"os": "windows", "arch": "amd64", "path": "test.x64.o"}],
                    }
                ],
            }
        ).encode()
        members = {
            "extension.json": manifest,
            "LICENSE": b"test license\n",
            "test.x64.o": b"object bytes\n",
        }
        with tarfile.open(path, "w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(prefix + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

    def test_sliver_compatible_member_prefix_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            compatible = root / "compatible.tar.gz"
            incompatible = root / "incompatible.tar.gz"
            self.write_archive(compatible, "./")
            self.write_archive(incompatible, "")

            validate_archive(
                compatible,
                "test-extension",
                "v1.2.3",
                "https://github.com/sliverarmory/test-extension",
            )
            with self.assertRaisesRegex(ValueError, "Sliver-incompatible member path"):
                validate_archive(
                    incompatible,
                    "test-extension",
                    "v1.2.3",
                    "https://github.com/sliverarmory/test-extension",
                )


if __name__ == "__main__":
    unittest.main()
