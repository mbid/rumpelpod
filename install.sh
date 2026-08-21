#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Install rumpelpod by piping to sh:
#   curl -fsSL https://raw.githubusercontent.com/nvidia/rumpelpod/master/install.sh | sh
set -eu

REPO="nvidia/rumpelpod"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

confirm() {
    prompt="$1"

    # stdin contains this script for the documented curl-to-sh invocation.
    # The controlling terminal keeps answers separate from script contents.
    if ! ( : </dev/tty ) 2>/dev/null; then
        echo "No interactive terminal is available; answering no to: $prompt" >&2
        return 1
    fi

    while true; do
        printf '%s [y/N] ' "$prompt" >/dev/tty
        if ! IFS= read -r answer </dev/tty; then
            echo "Could not read a response; answering no to: $prompt" >&2
            return 1
        fi
        case "$answer" in
            y | Y | yes | YES | Yes) return 0 ;;
            n | N | no | NO | No | '') return 1 ;;
            *) echo "Please answer yes or no." >/dev/tty ;;
        esac
    done
}

shell_quote() {
    escaped="$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
    printf "'%s'" "$escaped"
}

configure_path() {
    case ":${PATH:-}:" in
        *":$INSTALL_DIR:"*) return ;;
    esac

    shell_name="${SHELL:-}"
    shell_name="${shell_name##*/}"
    case "$shell_name" in
        bash)
            shell_config="$HOME/.bashrc"
            path_command="export PATH=$(shell_quote "$INSTALL_DIR"):\"\$PATH\""
            ;;
        zsh)
            shell_config="${ZDOTDIR:-$HOME}/.zshrc"
            path_command="export PATH=$(shell_quote "$INSTALL_DIR"):\"\$PATH\""
            ;;
        fish)
            shell_config="${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish"
            path_command="fish_add_path --path --prepend $(shell_quote "$INSTALL_DIR")"
            ;;
        sh | dash | ksh | mksh)
            shell_config="$HOME/.profile"
            path_command="export PATH=$(shell_quote "$INSTALL_DIR"):\"\$PATH\""
            ;;
        '')
            echo "Could not determine your shell. Add $INSTALL_DIR to PATH manually."
            return
            ;;
        *)
            echo "Shell '$shell_name' is not supported for automatic PATH setup."
            echo "Add $INSTALL_DIR to PATH manually."
            return
            ;;
    esac

    if [ -f "$shell_config" ] && grep -F "$path_command" "$shell_config" >/dev/null 2>&1; then
        echo "$INSTALL_DIR is already configured in $shell_config."
        return
    fi

    if confirm "Add $INSTALL_DIR to PATH in $shell_config?"; then
        config_dir="${shell_config%/*}"
        mkdir -p "$config_dir"
        {
            printf '\n%s\n' '# Added by the rumpelpod installer.'
            printf '%s\n' "$path_command"
        } >> "$shell_config"
        echo "Updated $shell_config. Log in again or source that file to use rumpel."
    else
        echo "Add $INSTALL_DIR to PATH before running rumpel."
    fi
}

configure_service() {
    if confirm "Install and start the rumpelpod background service?"; then
        echo "Running system-install..."
        "$INSTALL_DIR/rumpel" system-install
    else
        echo "Skipped background service installation."
        echo "Run $INSTALL_DIR/rumpel system-install when you are ready."
    fi
}

detect_binary() {
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)
            case "$arch" in
                x86_64)  echo "rumpel-linux-amd64" ;;
                aarch64) echo "rumpel-linux-arm64" ;;
                *)       echo "Unsupported architecture: $arch" >&2; exit 1 ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                arm64) echo "rumpel-darwin-arm64" ;;
                *)     echo "Unsupported architecture: $arch" >&2; exit 1 ;;
            esac
            ;;
        *)
            echo "Unsupported OS: $os" >&2
            exit 1
            ;;
    esac
}

latest_version() {
    # GitHub redirects /releases/latest to /releases/tag/<tag>.
    url="$(curl -fsIS -o /dev/null -w '%{redirect_url}' \
        "https://github.com/$REPO/releases/latest")"
    version="${url##*/}"
    if [ -z "$version" ]; then
        echo "Failed to determine latest version" >&2
        exit 1
    fi
    echo "$version"
}

main() {
    binary="$(detect_binary)"
    version="$(latest_version)"
    tarball="rumpel-${version}.tar.gz"
    url="https://github.com/$REPO/releases/download/${version}/${tarball}"

    mkdir -p "$INSTALL_DIR"
    # A profile entry must keep working after the user changes directories.
    INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd -P)"

    echo "Installing rumpelpod $version to $INSTALL_DIR"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    curl -fSL -o "$tmpdir/$tarball" "$url"
    tar xzf "$tmpdir/$tarball" -C "$INSTALL_DIR"
    ln -sf "$binary" "$INSTALL_DIR/rumpel"

    configure_path
    configure_service

    echo "Done."
}

main
