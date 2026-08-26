#!/usr/bin/env bash

set -euo pipefail

REPOROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
INVENTORY="$REPOROOT/armory-package-inventory.txt"
EXECUTOR_INVENTORY="$REPOROOT/armory-package-executors.txt"
PKGS="$REPOROOT/packages"
EXPECTED_PACKAGE_COUNT=51
TMPDIR_BUILD=$(mktemp -d)
trap 'rm -rf -- "$TMPDIR_BUILD"' EXIT

for required_inventory in "$INVENTORY" "$EXECUTOR_INVENTORY"; do
    if [[ ! -f "$required_inventory" ]]; then
        echo "ERROR: canonical package metadata is missing: $required_inventory" >&2
        exit 1
    fi
done

LC_ALL=C sort -u "$INVENTORY" > "$TMPDIR_BUILD/expected.txt"
if ! cmp -s "$INVENTORY" "$TMPDIR_BUILD/expected.txt"; then
    echo "ERROR: package inventory must be unique and LC_ALL=C sorted" >&2
    diff -u "$INVENTORY" "$TMPDIR_BUILD/expected.txt" || true
    exit 1
fi

inventory_count=$(wc -l < "$INVENTORY" | tr -d ' ')
if [[ "$inventory_count" -ne "$EXPECTED_PACKAGE_COUNT" ]]; then
    echo "ERROR: expected $EXPECTED_PACKAGE_COUNT canonical packages, found $inventory_count" >&2
    exit 1
fi

LC_ALL=C sort -u -t $'\t' -k1,1 "$EXECUTOR_INVENTORY" > "$TMPDIR_BUILD/expected-executors.tsv"
if ! cmp -s "$EXECUTOR_INVENTORY" "$TMPDIR_BUILD/expected-executors.tsv"; then
    echo "ERROR: package executor inventory must have unique, LC_ALL=C-sorted package names" >&2
    diff -u "$EXECUTOR_INVENTORY" "$TMPDIR_BUILD/expected-executors.tsv" || true
    exit 1
fi
if ! awk -F $'\t' '
    NF != 2 || $1 !~ /^[A-Za-z0-9._-]+$/ || ($2 != "reflektor" && $2 != "coff-loader") { exit 1 }
' "$EXECUTOR_INVENTORY"; then
    echo "ERROR: executor inventory entries must be <package><TAB><reflektor|coff-loader>" >&2
    exit 1
fi
if [[ $(wc -l < "$EXECUTOR_INVENTORY" | tr -d ' ') -ne "$EXPECTED_PACKAGE_COUNT" ]]; then
    echo "ERROR: executor inventory must contain $EXPECTED_PACKAGE_COUNT packages" >&2
    exit 1
fi
cut -f1 "$EXECUTOR_INVENTORY" > "$TMPDIR_BUILD/executor-packages.txt"
if ! diff -u "$INVENTORY" "$TMPDIR_BUILD/executor-packages.txt"; then
    echo "ERROR: executor inventory package identities do not match canonical inventory" >&2
    exit 1
fi

find "$REPOROOT/src/Remote" "$REPOROOT/src/Injection" \
    -mindepth 2 -maxdepth 2 -name Makefile -type f -print0 \
    | LC_ALL=C sort -z > "$TMPDIR_BUILD/makefiles.nul"
find "$REPOROOT/src/Remote" "$REPOROOT/src/Injection" \
    -mindepth 2 -maxdepth 2 -name extension.json -type f -print0 \
    | LC_ALL=C sort -z > "$TMPDIR_BUILD/manifests.nul"

while IFS= read -r -d '' makefile; do
    manifest="$(dirname -- "$makefile")/extension.json"
    if [[ ! -f "$manifest" ]]; then
        echo "ERROR: Makefile has no extension.json: $makefile" >&2
        exit 1
    fi
done < "$TMPDIR_BUILD/makefiles.nul"

while IFS= read -r -d '' manifest; do
    makefile="$(dirname -- "$manifest")/Makefile"
    if [[ ! -f "$makefile" ]]; then
        echo "ERROR: extension.json has no Makefile: $manifest" >&2
        exit 1
    fi

    package_name=$(jq -er '.package_name // .command_name // .commands[0].command_name' "$manifest")
    bof_executor=$(jq -er '
        (if (.commands | type) == "array" then .commands else [.] end) as $commands
        | ($commands | map(.bof_executor) | unique) as $executors
        | if ($commands | length > 0)
            and ($commands | all(.[];
                (.depends_on == "coff-loader")
                and (.bof_executor == "reflektor" or .bof_executor == "coff-loader")))
            and ($executors | length == 1)
          then $executors[0]
          else error("commands must share an explicit supported bof_executor and coff-loader fallback")
          end
    ' "$manifest")
    bof_dir=$(dirname -- "$manifest")
    bof_name=$(basename -- "$bof_dir")
    bof_type=$(basename -- "$(dirname -- "$bof_dir")")
    printf '%s\t%s\t%s\n' "$package_name" "$bof_type" "$bof_name" >> "$TMPDIR_BUILD/packages.tsv"
    printf '%s\t%s\n' "$package_name" "$bof_executor" >> "$TMPDIR_BUILD/discovered-executors.tsv"
done < "$TMPDIR_BUILD/manifests.nul"

cut -f1 "$TMPDIR_BUILD/packages.tsv" | LC_ALL=C sort > "$TMPDIR_BUILD/discovered.txt"
if ! diff -u "$INVENTORY" "$TMPDIR_BUILD/discovered.txt"; then
    echo "ERROR: source manifests do not match the canonical package inventory" >&2
    exit 1
fi

duplicate_names=$(cut -f1 "$TMPDIR_BUILD/packages.tsv" | LC_ALL=C sort | uniq -d)
if [[ -n "$duplicate_names" ]]; then
    echo "ERROR: duplicate package_name values:" >&2
    printf '%s\n' "$duplicate_names" >&2
    exit 1
fi

LC_ALL=C sort -t $'\t' -k1,1 "$TMPDIR_BUILD/discovered-executors.tsv" > "$TMPDIR_BUILD/discovered-executors.sorted.tsv"
if ! diff -u "$EXECUTOR_INVENTORY" "$TMPDIR_BUILD/discovered-executors.sorted.tsv"; then
    echo "ERROR: source manifests do not match the canonical executor inventory" >&2
    exit 1
fi

case "$PKGS" in
    "$REPOROOT/packages") rm -rf -- "$PKGS" ;;
    *)
        echo "ERROR: refusing to clean unexpected package path: $PKGS" >&2
        exit 1
        ;;
esac
mkdir -p "$PKGS"

LC_ALL=C sort -t $'\t' -k1,1 "$TMPDIR_BUILD/packages.tsv" > "$TMPDIR_BUILD/packages.sorted.tsv"
while IFS=$'\t' read -r package_name bof_type bof_name; do
    echo "::group::$package_name"
    "$REPOROOT/make_bof.sh" "$bof_name" "$bof_type"
    echo "::endgroup::"
done < "$TMPDIR_BUILD/packages.sorted.tsv"

find "$PKGS" -maxdepth 1 -type f -name '*.tar.gz' -exec basename {} .tar.gz \; \
    | LC_ALL=C sort > "$TMPDIR_BUILD/built.txt"
if ! diff -u "$INVENTORY" "$TMPDIR_BUILD/built.txt"; then
    echo "ERROR: built archives do not match the canonical package inventory" >&2
    exit 1
fi

unexpected=$(find "$PKGS" -mindepth 1 -maxdepth 1 -type f ! -name '*.tar.gz' -print)
if [[ -n "$unexpected" ]]; then
    echo "ERROR: unsigned build produced unexpected files:" >&2
    printf '%s\n' "$unexpected" >&2
    exit 1
fi

"$REPOROOT/scripts/check_restored_objects.sh"

echo "[+] Built and inventoried $EXPECTED_PACKAGE_COUNT unsigned packages"
