#!/bin/sh
# Materialize credentials from env vars into files before systemd starts.
# Each env var holds a base64-encoded blob; if unset, the corresponding
# file is simply not created.

USER_HOME="/home/${USER:-dev}"

# -- macOS SSH access --
if [ -n "$MACOS_SSH_PRIVATE_KEY" ]; then
    mkdir -p "$USER_HOME/.ssh"
    echo "$MACOS_SSH_PRIVATE_KEY" | base64 -d > "$USER_HOME/.ssh/macos_id"
    chmod 600 "$USER_HOME/.ssh/macos_id"
    echo "$MACOS_SSH_CONFIG" | base64 -d >> "$USER_HOME/.ssh/config"
    echo "$MACOS_SSH_KNOWN_HOSTS" | base64 -d >> "$USER_HOME/.ssh/known_hosts"
    chmod 700 "$USER_HOME/.ssh"
    chown -R "${USER:-dev}:${USER:-dev}" "$USER_HOME/.ssh"
fi

# -- Kubernetes cluster access (Hetzner K3s or EKS) --
if [ -n "$RUMPELPOD_K8S_KUBECONFIG" ]; then
    mkdir -p "$USER_HOME/.kube"
    echo "$RUMPELPOD_K8S_KUBECONFIG" | base64 -d > "$USER_HOME/.kube/config"
    chmod 600 "$USER_HOME/.kube/config"
    chown -R "${USER:-dev}:${USER:-dev}" "$USER_HOME/.kube"
fi

exec /sbin/init
