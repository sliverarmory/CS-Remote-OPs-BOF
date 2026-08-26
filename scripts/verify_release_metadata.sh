#!/usr/bin/env bash

set -euo pipefail

METADATA_DIR=${1:?usage: verify_release_metadata.sh <release-metadata-dir>}
ARMORY_INDEX_PUBLIC_KEY=${ARMORY_INDEX_PUBLIC_KEY:?ARMORY_INDEX_PUBLIC_KEY must be set}
PACKAGE_REPO_URL=${PACKAGE_REPO_URL:?PACKAGE_REPO_URL must be set}
EXPECTED_INDEXED_SIBLINGS=47
EXPECTED_CANONICAL_PACKAGES=51
TMPDIR_METADATA=$(mktemp -d)
trap 'rm -rf -- "$TMPDIR_METADATA"' EXIT

required_files=(
    SHA256SUMS
    armory-index-public-key.txt
    armory-package-inventory.txt
    armory-release-tag.txt
    armory.json
    armory.minisig
    package-public-key.txt
    package-source-commit.txt
)

for filename in "${required_files[@]}"; do
    path="$METADATA_DIR/$filename"
    if [[ ! -f "$path" || -L "$path" ]]; then
        echo "ERROR: required release metadata is missing or not a regular file: $path" >&2
        exit 1
    fi
done

find "$METADATA_DIR" -mindepth 1 -maxdepth 1 -print0 \
    | while IFS= read -r -d '' path; do basename -- "$path"; done \
    | LC_ALL=C sort > "$TMPDIR_METADATA/actual-files"
printf '%s\n' "${required_files[@]}" | LC_ALL=C sort > "$TMPDIR_METADATA/expected-files"
if ! diff -u "$TMPDIR_METADATA/expected-files" "$TMPDIR_METADATA/actual-files"; then
    echo "ERROR: release metadata artifact has an unexpected file inventory" >&2
    exit 1
fi

(
    cd "$METADATA_DIR"
    sha256sum --check SHA256SUMS >&2
)

if [[ $(<"$METADATA_DIR/armory-index-public-key.txt") != "$ARMORY_INDEX_PUBLIC_KEY" ]]; then
    echo "ERROR: carried Armory index public key does not match the pinned key" >&2
    exit 1
fi

index_release_tag=$(<"$METADATA_DIR/armory-release-tag.txt")
if [[ ! "$index_release_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "ERROR: carried Armory index tag is not strict semver: $index_release_tag" >&2
    exit 1
fi

package_source_commit=$(<"$METADATA_DIR/package-source-commit.txt")
if [[ ! "$package_source_commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: carried package source commit is not a full Git SHA-1" >&2
    exit 1
fi
if [[ -n ${EXPECTED_SOURCE_COMMIT:-} && "$package_source_commit" != "$EXPECTED_SOURCE_COMMIT" ]]; then
    echo "ERROR: carried package source commit $package_source_commit does not match $EXPECTED_SOURCE_COMMIT" >&2
    exit 1
fi
if [[ -n ${EXPECTED_INDEX_RELEASE_TAG:-} && "$index_release_tag" != "$EXPECTED_INDEX_RELEASE_TAG" ]]; then
    echo "ERROR: carried Armory index tag $index_release_tag does not match $EXPECTED_INDEX_RELEASE_TAG" >&2
    exit 1
fi

minisign -Vm "$METADATA_DIR/armory.json" \
    -x "$METADATA_DIR/armory.minisig" \
    -P "$ARMORY_INDEX_PUBLIC_KEY" >&2

inventory="$METADATA_DIR/armory-package-inventory.txt"
LC_ALL=C sort -c "$inventory"
if [[ $(wc -l < "$inventory" | tr -d ' ') -ne "$EXPECTED_CANONICAL_PACKAGES" ]]; then
    echo "ERROR: canonical inventory must contain $EXPECTED_CANONICAL_PACKAGES packages" >&2
    exit 1
fi

package_public_key=$(jq -er --arg repo "$PACKAGE_REPO_URL" --argjson expected "$EXPECTED_INDEXED_SIBLINGS" '
    [((.aliases // []) + (.extensions // []))[]
        | select((.repo_url | ascii_downcase | rtrimstr("/") | rtrimstr(".git")) == ($repo | ascii_downcase))] as $entries
    | ($entries | map(.command_name) | sort) as $names
    | ($entries | map(.public_key) | unique) as $keys
    | if ($entries | length) == $expected
        and ($names | length) == ($names | unique | length)
        and ($keys | length) == 1
        and ($keys[0] | type == "string" and length > 0)
      then $keys[0]
      else error("unexpected signed-index sibling count, identity, or package key")
      end
' "$METADATA_DIR/armory.json")

if [[ $(<"$METADATA_DIR/package-public-key.txt") != "$package_public_key" ]]; then
    echo "ERROR: carried package public key does not match the signed index" >&2
    exit 1
fi

jq -r --arg repo "$PACKAGE_REPO_URL" '
    ((.aliases // []) + (.extensions // []))[]
    | select((.repo_url | ascii_downcase | rtrimstr("/") | rtrimstr(".git")) == ($repo | ascii_downcase))
    | .command_name
' "$METADATA_DIR/armory.json" | LC_ALL=C sort > "$TMPDIR_METADATA/indexed-packages"
if missing=$(comm -23 "$TMPDIR_METADATA/indexed-packages" "$inventory") && [[ -n "$missing" ]]; then
    echo "ERROR: canonical inventory omits signed-index siblings:" >&2
    printf '%s\n' "$missing" >&2
    exit 1
fi

printf '%s\n' "$package_public_key"
