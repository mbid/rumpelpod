# Rumpelpod

Run LLM agents in isolated Docker containers with filesystem isolation.

## Features

- **Isolation**: Runs in Docker with gVisor (runsc) by default for strong syscall-level isolation
- **Filesystem safety**: Uses overlay filesystems so agent changes don't affect your host
- **Git integration**: Each pod gets its own working copy synced with your repo
- **Multiple models**: Supports Claude (Opus, Sonnet, Haiku) and Grok (3-mini, 4.1-fast)

## Installation

```bash
cargo install --path .
rumpel system-install  # Sets up systemd daemon for git sync
```

Requires Docker with gVisor runtime (`runsc`). Alternative runtimes: `runc`, `sysbox-runc`.

## Quick Start

Create a `.devcontainer/devcontainer.json` in your project root:

```json
{
    "image": "my-project-dev:latest",
    "workspaceFolder": "/home/dev/my-project",
    "containerUser": "dev",
    "runArgs": ["--runtime=runsc"]
}
```

And a `.rumpelpod.toml` for agent settings:

```toml
[agent]
model = "claude-sonnet-4.5"
```

Run an agent:

```bash
rumpel agent my-task
```

Or get an interactive shell:

```bash
rumpel enter my-shell
```

## Commands

| Command | Description |
|---------|-------------|
| `rumpel agent <name>` | Run an LLM agent in a pod |
| `rumpel enter <name>` | Enter a pod interactively (or run a command) |
| `rumpel list` | List pods for the current repository |
| `rumpel review <name>` | Review changes in a pod using git difftool |
| `rumpel delete <name>` | Delete a pod |
| `rumpel system-install` | Install the systemd daemon |
| `rumpel system-uninstall` | Uninstall the systemd daemon |

## Configuration

Pod behavior is configured using a combination of `.devcontainer/devcontainer.json` (for container settings) and `.rumpelpod.toml` (for agent and pod-specific settings).

### Dev Container Settings (`.devcontainer/devcontainer.json`)

The following standard fields are supported:

- **image**: Docker image to use for the pod.
- **workspaceFolder**: Path where the repository will be mounted inside the container.
- **containerUser** or **remoteUser**: User to run as inside the container.
- **runArgs**: Additional Docker arguments. Used to set the runtime (e.g., `--runtime=runsc`) or network (e.g., `--network=host`).

### Pod Settings (`.rumpelpod.toml`)

- **host**: Remote Docker host specification (e.g., `user@host:port`).
- **agent**:
  - **model**: Default model for `rumpel agent` (e.g., `claude-opus-4.5`, `claude-sonnet-4.5`, `gemini-3-pro-preview`, `grok-4.1-fast-reasoning`).
  - **thinking-budget**: Thinking budget in tokens for supported models.
  - **anthropic-websearch**: Enable/disable web search for Anthropic models.

## How It Works

The agent runs autonomously without asking for permissions. Safety comes from the pod isolation: all filesystem changes are isolated via overlays, and the container runs with gVisor for syscall-level protection.

Project-specific instructions can be provided in an `AGENTS.md` file.
