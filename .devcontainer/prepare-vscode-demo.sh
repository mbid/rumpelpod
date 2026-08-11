#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

workspace=${RUMPELPOD_VSCODE_WORKSPACE:-/workspaces/anyhow-demo}
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
    "containerUser": "user",
    "userEnvProbe": "none",
    "forwardPorts": [8000, 8001],
    "portsAttributes": {
        "8000": {
            "label": "Anyhow primary preview",
            "protocol": "http",
            "onAutoForward": "openPreview"
        },
        "8001": {
            "label": "Anyhow secondary preview",
            "protocol": "http",
            "onAutoForward": "openPreview"
        }
    },
    "postStartCommand": {
        "primaryPreview": "RUMPELPOD_PREVIEW_PORT=8000 RUMPELPOD_PREVIEW_PAGE=index.html sh .devcontainer/start-preview.sh",
        "secondaryPreview": "RUMPELPOD_PREVIEW_PORT=8001 RUMPELPOD_PREVIEW_PAGE=secondary.html sh .devcontainer/start-preview.sh"
    },
    "waitFor": "postStartCommand"
}
EOF
# Claude refuses --dangerously-skip-permissions under root, so demo pods
# need a non-root user even though the pod itself is the sandbox.
cat > "$staging/.devcontainer/Dockerfile" <<'EOF'
FROM rust:1.96.1-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git python3 sudo \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash user \
    && echo 'user ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/user
EOF
cat > "$staging/.devcontainer/preview.py" <<'EOF'
#!/usr/bin/env python3

import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PREVIEW_DIRECTORY = Path(__file__).parent
PREVIEW_PORT = int(sys.argv[1])
PREVIEW_PAGE = sys.argv[2]


class PreviewHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PREVIEW_DIRECTORY, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/":
            self.path = f"/{PREVIEW_PAGE}"
        super().do_GET()


server = ThreadingHTTPServer(("0.0.0.0", PREVIEW_PORT), PreviewHandler)
server.serve_forever()
EOF
cat > "$staging/.devcontainer/start-preview.sh" <<'EOF'
#!/bin/sh

set -eu

preview_port=${RUMPELPOD_PREVIEW_PORT:-8000}
preview_page=${RUMPELPOD_PREVIEW_PAGE:-index.html}
preview_state_dir=${RUMPELPOD_PREVIEW_STATE_DIR:-/tmp}
preview_pid_file="$preview_state_dir/anyhow-preview-$preview_port.pid"
preview_log="$preview_state_dir/anyhow-preview-$preview_port.log"

case "$preview_port" in
    ''|*[!0-9]*)
        echo "invalid preview port: $preview_port" >&2
        exit 1
        ;;
esac
mkdir -p "$preview_state_dir"

preview_is_ready() {
    python3 - "$preview_port" <<'PY'
import sys
import urllib.error
import urllib.request


url = f"http://127.0.0.1:{sys.argv[1]}/"
try:
    with urllib.request.urlopen(url, timeout=0.2) as response:
        content = response.read().decode("utf-8")
except (OSError, UnicodeDecodeError, urllib.error.URLError):
    sys.exit(1)
if response.status != 200 or "Rumpelpod preview ready" not in content:
    sys.exit(1)
PY
}

preview_process_matches() {
    python3 - "$1" "$preview_port" "$preview_page" <<'PY'
import os
import sys
from pathlib import Path


process = Path("/proc") / sys.argv[1]
expected = [
    b".devcontainer/preview.py",
    sys.argv[2].encode(),
    sys.argv[3].encode(),
]
try:
    arguments = (process / "cmdline").read_bytes().split(b"\0")
    working_directory = Path(os.readlink(process / "cwd")).resolve()
except OSError:
    sys.exit(1)
if (
    not any(arguments[index:index + len(expected)] == expected
            for index in range(len(arguments)))
    or working_directory != Path.cwd().resolve()
):
    sys.exit(1)
PY
}

wait_until_ready() {
    preview_pid=$1
    attempts=0
    while [ "$attempts" -lt 50 ]; do
        if preview_is_ready; then
            return 0
        fi
        if ! kill -0 "$preview_pid" 2>/dev/null; then
            return 1
        fi
        attempts=$((attempts + 1))
        sleep 0.1
    done
    return 1
}

if preview_is_ready; then
    exit 0
fi

if [ -f "$preview_pid_file" ]; then
    IFS= read -r preview_pid < "$preview_pid_file"
    case "$preview_pid" in
        ''|*[!0-9]*)
            echo "invalid preview server PID in $preview_pid_file" >&2
            exit 1
            ;;
    esac
    if kill -0 "$preview_pid" 2>/dev/null \
        && preview_process_matches "$preview_pid"; then
        if wait_until_ready "$preview_pid"; then
            exit 0
        fi
        echo "preview server PID $preview_pid did not become ready" >&2
        exit 1
    fi
    rm -f "$preview_pid_file"
fi

nohup python3 .devcontainer/preview.py "$preview_port" "$preview_page" \
    </dev/null >"$preview_log" 2>&1 &
preview_pid=$!
printf '%s\n' "$preview_pid" > "$preview_pid_file"
if wait_until_ready "$preview_pid"; then
    exit 0
fi

status=0
if kill -0 "$preview_pid" 2>/dev/null; then
    if ! kill "$preview_pid" 2>/dev/null; then
        echo "could not stop failed preview server PID $preview_pid" >&2
    fi
fi
wait "$preview_pid" || status=$?
rm -f "$preview_pid_file"
echo "preview server failed to become ready (status $status)" >&2
if [ -s "$preview_log" ]; then
    cat "$preview_log" >&2
fi
exit 1
EOF
cat > "$staging/.devcontainer/index.html" <<'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Anyhow live preview</title>
    <style>
        :root {
            color-scheme: light dark;
            font-family: system-ui, sans-serif;
        }
        body {
            display: grid;
            min-height: 100vh;
            margin: 0;
            place-items: center;
            background: #18212f;
            color: #f5f7fa;
        }
        main {
            max-width: 38rem;
            margin: 2rem;
            padding: 2.5rem;
            border: 1px solid #46566f;
            border-radius: 1rem;
            background: #222e40;
            box-shadow: 0 1rem 3rem #0005;
        }
        code {
            color: #8dd8ff;
        }
    </style>
</head>
<body>
    <main>
        <h1>Anyhow pod preview</h1>
        <p>This page is served by <code>.devcontainer/preview.py</code>
           from inside the rumpelpod.</p>
        <p>Port 8000 uses <code>onAutoForward: openPreview</code>, so the
           Rumpelpod extension opens it in VS Code automatically.</p>
        <span hidden>Rumpelpod preview ready</span>
    </main>
</body>
</html>
EOF
cat > "$staging/.devcontainer/secondary.html" <<'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Anyhow secondary preview</title>
    <style>
        :root {
            color-scheme: light dark;
            font-family: system-ui, sans-serif;
        }
        body {
            display: grid;
            min-height: 100vh;
            margin: 0;
            place-items: center;
            background: #173229;
            color: #f5f7fa;
        }
        main {
            max-width: 38rem;
            margin: 2rem;
            padding: 2.5rem;
            border: 1px solid #4d806c;
            border-radius: 1rem;
            background: #21483b;
            box-shadow: 0 1rem 3rem #0005;
        }
        code {
            color: #8fffcf;
        }
    </style>
</head>
<body>
    <main>
        <h1>Secondary anyhow preview</h1>
        <p>This second server uses the same Python file server with
           <code>RUMPELPOD_PREVIEW_PORT=8001</code>.</p>
        <p>Both forwarded ports should open as tabs in the pod review's
           editor group.</p>
        <span hidden>Rumpelpod preview ready</span>
    </main>
</body>
</html>
EOF

git -C "$staging" init --quiet --initial-branch main
git -C "$staging" config user.name 'Rumpelpod VS Code'
git -C "$staging" config user.email 'rumpelpod-vscode@localhost'
git -C "$staging" add --all
git -C "$staging" commit --quiet -m 'Seed anyhow demo workspace'
mv "$staging" "$workspace"
staging=
