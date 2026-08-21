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
        printf '%s [Y/n] ' "$prompt" >/dev/tty
        if ! IFS= read -r answer </dev/tty; then
            echo "Could not read a response; answering no to: $prompt" >&2
            return 1
        fi
        case "$answer" in
            y | Y | yes | YES | Yes | '') return 0 ;;
            n | N | no | NO | No) return 1 ;;
            *) echo "Please answer yes or no." >/dev/tty ;;
        esac
    done
}

shell_quote() {
    escaped="$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
    printf "'%s'" "$escaped"
}

path_export_command() {
    quoted_path="$(shell_quote "$INSTALL_DIR")"
    quoted_path_entry="$(shell_quote ":$INSTALL_DIR:")"
    printf '%s' "case \":\$PATH:\" in *${quoted_path_entry}*) ;; *) export PATH=${quoted_path}:\"\$PATH\" ;; esac"
}

path_is_configured() {
    [ -f "$1" ] && grep -Fqx "$2" "$1" >/dev/null 2>&1
}

write_path_config() {
    target_config="$1"
    target_command="$2"
    target_dir="${target_config%/*}"
    mkdir -p "$target_dir"
    {
        printf '\n%s\n' '# Added by the rumpelpod installer.'
        printf '%s\n' "$target_command"
    } >> "$target_config"
}

print_path_reload_hint() {
    echo "To use rumpel, open a new terminal or run:"
    echo '  exec "$SHELL" -l'
}

configure_bash_path() {
    bash_path_command="$1"

    # Bash separates login and non-login startup, so one file cannot cover both.
    if [ -f "$HOME/.bash_profile" ]; then
        bash_login_config="$HOME/.bash_profile"
    elif [ -f "$HOME/.bash_login" ]; then
        bash_login_config="$HOME/.bash_login"
    else
        bash_login_config="$HOME/.profile"
    fi
    bash_interactive_config="$HOME/.bashrc"

    if path_is_configured "$bash_login_config" "$bash_path_command"; then
        bash_login_update=0
    else
        bash_login_update=1
    fi
    if path_is_configured "$bash_interactive_config" "$bash_path_command"; then
        bash_interactive_update=0
    else
        bash_interactive_update=1
    fi

    case "$bash_login_update:$bash_interactive_update" in
        0:0)
            echo "$INSTALL_DIR is already configured in $bash_login_config and $bash_interactive_config."
            print_path_reload_hint
            return
            ;;
        0:1) bash_config_summary="$bash_interactive_config" ;;
        1:0) bash_config_summary="$bash_login_config" ;;
        1:1) bash_config_summary="$bash_login_config and $bash_interactive_config" ;;
        *)
            echo "Unexpected Bash configuration state" >&2
            exit 1
            ;;
    esac

    if confirm "Add $INSTALL_DIR to PATH in $bash_config_summary?"; then
        if [ "$bash_login_update" -eq 1 ]; then
            write_path_config "$bash_login_config" "$bash_path_command"
        fi
        if [ "$bash_interactive_update" -eq 1 ]; then
            write_path_config "$bash_interactive_config" "$bash_path_command"
        fi
        echo "Updated $bash_config_summary."
        print_path_reload_hint
    else
        echo "Add $INSTALL_DIR to PATH before running rumpel."
    fi
}

configure_path() {
    case ":${PATH:-}:" in
        *":$INSTALL_DIR:"*) return ;;
    esac

    shell_name="${SHELL:-}"
    shell_name="${shell_name##*/}"
    case "$shell_name" in
        bash)
            path_command="$(path_export_command)"
            configure_bash_path "$path_command"
            return
            ;;
        zsh)
            shell_config="${ZDOTDIR:-$HOME}/.zshrc"
            path_command="$(path_export_command)"
            ;;
        fish)
            shell_config="${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish"
            path_command="fish_add_path --path --prepend $(shell_quote "$INSTALL_DIR")"
            ;;
        sh | dash | ksh | mksh)
            shell_config="$HOME/.profile"
            path_command="$(path_export_command)"
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

    if path_is_configured "$shell_config" "$path_command"; then
        echo "$INSTALL_DIR is already configured in $shell_config."
        print_path_reload_hint
        return
    fi

    if confirm "Add $INSTALL_DIR to PATH in $shell_config?"; then
        write_path_config "$shell_config" "$path_command"
        echo "Updated $shell_config."
        print_path_reload_hint
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
