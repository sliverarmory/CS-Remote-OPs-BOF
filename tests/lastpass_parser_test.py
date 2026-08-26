#!/usr/bin/env python3

import importlib.util
import pathlib


MODULE_PATH = pathlib.Path(__file__).parents[1] / "Remote" / "lastpass" / "process_lp_files.py"
SPEC = importlib.util.spec_from_file_location("process_lp_files", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def main() -> None:
    assert MODULE.parse_glocalkey("<MSG>y\":\"SECRET</MSG>\n", "1234") == ["SECRET"]
    assert MODULE.parse_glocalkey("<MSG>y\":\"SECRET\",\"guard</MSG>\n", "1234") == ["SECRET"]
    assert MODULE.parse_filename("/tmp/lp_1234_PRIV_KEY.txt") == ("1234", "PRIV_KEY")
    assert MODULE.parse_filename("/tmp/not-a-lastpass-record") is None
    print("lastpass parser tests passed")


if __name__ == "__main__":
    main()
