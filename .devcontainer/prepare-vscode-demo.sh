#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

workspace=${RUMPELPOD_VSCODE_WORKSPACE:-$HOME/.local/share/rumpelpod/anyhow-demo}
if [ -d "$workspace/.git" ]; then
    exit 0
fi
if [ -e "$workspace" ]; then
    echo "VS Code demo workspace exists but is not a Git repository: $workspace" >&2
    exit 1
fi

source=${RUMPELPOD_VSCODE_DEMO_SOURCE:-}
if [ -z "$source" ]; then
    set -- "$HOME"/.cargo/registry/src/*/anyhow-1.0.102
    if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
        echo "expected one cached anyhow 1.0.102 source directory" >&2
        exit 1
    fi
    source=$1
fi
if [ ! -d "$source" ]; then
    echo "VS Code demo source is not a directory: $source" >&2
    exit 1
fi

parent=$(dirname "$workspace")
mkdir -p "$parent"
staging=$(mktemp -d "$parent/.anyhow-demo.XXXXXX")
cleanup() {
    if [ -n "$staging" ] && [ -e "$staging" ]; then
        if ! rm -rf "$staging"; then
            echo "could not remove staged VS Code demo workspace: $staging" >&2
        fi
    fi
}
trap cleanup EXIT

cp -a "$source/." "$staging/"
rm -f "$staging/.cargo-ok" "$staging/.cargo_vcs_info.json"
mkdir -p "$staging/.devcontainer"
cat > "$staging/.devcontainer/devcontainer.json" <<'EOF'
{
    "build": {
        "dockerfile": "Dockerfile"
    },
    "workspaceFolder": "/workspace/anyhow",
    "containerUser": "root",
    "userEnvProbe": "none"
}
EOF
cat > "$staging/.devcontainer/Dockerfile" <<'EOF'
FROM rust:1.96.1-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
EOF

git -C "$staging" init --quiet --initial-branch main
git -C "$staging" config user.name 'Rumpelpod VS Code'
git -C "$staging" config user.email 'rumpelpod-vscode@localhost'
git -C "$staging" add --all
git -C "$staging" commit --quiet -m 'Seed anyhow demo workspace'
mv "$staging" "$workspace"
staging=
