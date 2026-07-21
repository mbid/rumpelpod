#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Materialize credentials from cloud/<name>/ directories into the
# standard locations (~/.kube/, ~/.ssh/) before systemd starts.

set -eu

USER_HOME="/home/${USER:-user}"
CLOUD_DIR="${WORKSPACE:-/workspaces/rumpelpod}/cloud"

# User services start under a separately-created systemd manager and do not
# inherit the container process environment. Persist only the agent keys that
# the daemon and browser terminals are intended to receive.
/usr/local/bin/write-rumpelpod-agent-environment "${USER:-user}"

# Copy the first kubeconfig found to ~/.kube/config for interactive use.
for kc in "$CLOUD_DIR"/*/kubeconfig; do
    [ -f "$kc" ] || continue
    mkdir -p "$USER_HOME/.kube"
    cp "$kc" "$USER_HOME/.kube/config"
    chmod 600 "$USER_HOME/.kube/config"
    chown "${USER:-user}:${USER:-user}" "$USER_HOME/.kube/config"
    break
done

# Copy macOS SSH credentials if present.
for dir in "$CLOUD_DIR"/*/; do
    [ -f "$dir/ssh_config" ] || continue
    mkdir -p "$USER_HOME/.ssh"
    [ -f "$dir/id_ed25519" ] && cp "$dir/id_ed25519" "$USER_HOME/.ssh/macos_id" && chmod 600 "$USER_HOME/.ssh/macos_id"
    cat "$dir/ssh_config" >> "$USER_HOME/.ssh/config"
    [ -f "$dir/known_hosts" ] && cat "$dir/known_hosts" >> "$USER_HOME/.ssh/known_hosts"
    chmod 700 "$USER_HOME/.ssh"
    chown -R "${USER:-user}:${USER:-user}" "$USER_HOME/.ssh"
done

exec /sbin/init
