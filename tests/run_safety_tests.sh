#!/usr/bin/env bash

set -euo pipefail

REPOROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TESTDIR=$(mktemp -d)
trap 'rm -rf -- "$TESTDIR"' EXIT

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    "$REPOROOT/tests/ghost_task_safety_test.c" \
    -o "$TESTDIR/ghost_task_safety_test"
"$TESTDIR/ghost_task_safety_test"

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    "$REPOROOT/tests/lastpass_safety_test.c" \
    -o "$TESTDIR/lastpass_safety_test"
"$TESTDIR/lastpass_safety_test"
