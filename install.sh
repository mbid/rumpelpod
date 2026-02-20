#!/bin/sh
# Install rumpelpod by piping to sh:
#   curl -fsSL https://raw.githubusercontent.com/mbid/rumpelpod/master/install.sh | sh
set -eu

REPO="mbid/rumpelpod"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

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

    echo "Installing rumpelpod $version to $INSTALL_DIR"

    mkdir -p "$INSTALL_DIR"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    curl -fSL -o "$tmpdir/$tarball" "$url"
    tar xzf "$tmpdir/$tarball" -C "$INSTALL_DIR"
    ln -sf "$binary" "$INSTALL_DIR/rumpel"

    echo "Running system-install..."
    "$INSTALL_DIR/rumpel" system-install

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *) echo "Add $INSTALL_DIR to your PATH to use rumpel." ;;
    esac

    echo "Done."
}

main
