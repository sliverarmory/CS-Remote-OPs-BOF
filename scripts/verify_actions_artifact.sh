#!/usr/bin/env bash

set -euo pipefail

ARTIFACT_ID=${1:?usage: verify_actions_artifact.sh <id> <sha256> <name>}
ARTIFACT_DIGEST=${2:?usage: verify_actions_artifact.sh <id> <sha256> <name>}
ARTIFACT_NAME=${3:?usage: verify_actions_artifact.sh <id> <sha256> <name>}
GH_TOKEN=${GH_TOKEN:?GH_TOKEN must be set}
GITHUB_REPOSITORY=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}
GITHUB_RUN_ID=${GITHUB_RUN_ID:?GITHUB_RUN_ID must be set}

if [[ ! "$ARTIFACT_ID" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: invalid Actions artifact ID: $ARTIFACT_ID" >&2
    exit 1
fi
if [[ ! "$ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: invalid Actions artifact SHA-256: $ARTIFACT_DIGEST" >&2
    exit 1
fi

artifact_json=$(gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$ARTIFACT_ID")
jq -e \
    --argjson artifact_id "$ARTIFACT_ID" \
    --argjson run_id "$GITHUB_RUN_ID" \
    --arg name "$ARTIFACT_NAME" \
    --arg digest "sha256:$ARTIFACT_DIGEST" '
        .id == $artifact_id
        and .name == $name
        and .expired == false
        and .digest == $digest
        and .workflow_run.id == $run_id
    ' <<<"$artifact_json" >/dev/null
