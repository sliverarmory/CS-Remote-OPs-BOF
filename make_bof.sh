#!/usr/bin/env bash

set -euo pipefail

REPOROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BOF=${1:?usage: make_bof.sh <bof-name> <Remote|Injection>}
BOFTYPE=${2:?usage: make_bof.sh <bof-name> <Remote|Injection>}
SRCDIR="$REPOROOT/src/$BOFTYPE/$BOF"
OUTDIR="$REPOROOT/$BOFTYPE/$BOF"
PKGS="$REPOROOT/packages"
ARTIFACTS="$SRCDIR/artifacts"
MANIFEST_SOURCE="$SRCDIR/extension.json"
LICENSE_SOURCE="$REPOROOT/LICENSE"

case "$BOFTYPE" in
    Remote|Injection) ;;
    *)
        echo "ERROR: unsupported BOF type: $BOFTYPE" >&2
        exit 1
        ;;
esac

for required in "$SRCDIR" "$SRCDIR/Makefile" "$MANIFEST_SOURCE" "$LICENSE_SOURCE"; do
    if [[ ! -e "$required" ]]; then
        echo "ERROR: required package input is missing: $required" >&2
        exit 1
    fi
done

jq -e . "$MANIFEST_SOURCE" >/dev/null
jq -e '
    (if (.commands | type) == "array" then .commands else [.] end) as $commands
    | (.name | type == "string" and length > 0)
      and (.version | type == "string" and length > 0)
      and ($commands | length > 0)
      and ($commands | all(.[];
          (.command_name | type == "string" and length > 0)
          and (.help | type == "string" and length > 0)
          and (.entrypoint | type == "string" and length > 0)
          and (.depends_on == "coff-loader")
          and (.bof_executor == "reflektor" or .bof_executor == "coff-loader")
          and (.files | type == "array" and length > 0)))
' "$MANIFEST_SOURCE" >/dev/null

PACKAGE_NAME=$(jq -er '.package_name // .command_name // .commands[0].command_name' "$MANIFEST_SOURCE")
if [[ ! "$PACKAGE_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "ERROR: unsafe package_name in $MANIFEST_SOURCE: $PACKAGE_NAME" >&2
    exit 1
fi

VERSION=${PACKAGE_VERSION:-}
if [[ -z "$VERSION" ]]; then
    VERSION=$(git -C "$REPOROOT" describe --tags --abbrev=0 2>/dev/null || true)
fi
VERSION=${VERSION:-v0.0.0-dev}

mapfile -t PACKAGE_FILES < <(
    jq -r '
        (if (.commands | type) == "array" then .commands else [.] end)
        | .[].files[].path
    ' "$MANIFEST_SOURCE" | LC_ALL=C sort -u
)

for relative_path in "${PACKAGE_FILES[@]}"; do
    case "$relative_path" in
        ""|/*|../*|*/../*|*"/"*)
            echo "ERROR: package file must be a safe archive-root filename: $relative_path" >&2
            exit 1
            ;;
    esac
done

mkdir -p "$OUTDIR"
for relative_path in "${PACKAGE_FILES[@]}"; do
    rm -f -- "$OUTDIR/$relative_path"
done

case "$ARTIFACTS" in
    "$REPOROOT"/src/Remote/*/artifacts|"$REPOROOT"/src/Injection/*/artifacts)
        rm -rf -- "$ARTIFACTS"
        ;;
    *)
        echo "ERROR: refusing to clean unexpected artifacts path: $ARTIFACTS" >&2
        exit 1
        ;;
esac
mkdir -p "$ARTIFACTS" "$PKGS"

echo "[+] Compiling: $BOFTYPE/$BOF"
make -C "$SRCDIR"

ARCHIVE_MEMBERS=(./extension.json ./LICENSE)
for relative_path in "${PACKAGE_FILES[@]}"; do
    source_path="$OUTDIR/$relative_path"
    if [[ ! -f "$source_path" || -L "$source_path" ]]; then
        echo "ERROR: build did not produce a regular package file: $source_path" >&2
        exit 1
    fi
    cp -- "$source_path" "$ARTIFACTS/$relative_path"
    ARCHIVE_MEMBERS+=("./$relative_path")
done

jq --arg version "$VERSION" '.version = $version' "$MANIFEST_SOURCE" > "$ARTIFACTS/extension.json"
cp -- "$LICENSE_SOURCE" "$ARTIFACTS/LICENSE"

ARCHIVE="$PKGS/$PACKAGE_NAME.tar.gz"
rm -f -- "$ARCHIVE"
tar -C "$ARTIFACTS" -czf "$ARCHIVE" "${ARCHIVE_MEMBERS[@]}"

echo "[+] Created: $ARCHIVE"
tar -tzf "$ARCHIVE"
