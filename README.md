# Sandbox

Run LLM agents in isolated Docker containers with filesystem sandboxing.

## Features

- **Isolation**: Runs in Docker with gVisor (runsc) by default for strong syscall-level isolation
- **Filesystem safety**: Uses overlay filesystems so agent changes don't affect your host
- **Git integration**: Each sandbox gets its own working copy synced with your repo
- **Multiple models**: Supports Claude (Opus, Sonnet, Haiku) and Grok (3-mini, 4.1-fast)

## Installation

```bash
cargo install --path .
sandbox system-install  # Sets up systemd daemon for git sync
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

And a `.sandbox.toml` for agent settings:

```toml
[agent]
model = "claude-sonnet-4.5"
```

Run an agent:

```bash
sandbox agent my-task
```

Or get an interactive shell:

```bash
sandbox enter my-shell
```

## Commands

| Command | Description |
|---------|-------------|
| `sandbox agent <name>` | Run an LLM agent in a sandbox |
| `sandbox enter <name>` | Enter a sandbox interactively (or run a command) |
| `sandbox list` | List sandboxes for the current repository |
| `sandbox review <name>` | Review changes in a sandbox using git difftool |
| `sandbox delete <name>` | Delete a sandbox |
| `sandbox system-install` | Install the systemd daemon |
| `sandbox system-uninstall` | Uninstall the systemd daemon |

## Configuration

Sandbox behavior is configured using a combination of `.devcontainer/devcontainer.json` (for container settings) and `.sandbox.toml` (for agent and other sandbox-specific settings).

### Dev Container Settings (`.devcontainer/devcontainer.json`)

The following standard fields are supported:

- **image**: Docker image to use for the sandbox.
- **workspaceFolder**: Path where the repository will be mounted inside the container.
- **containerUser** or **remoteUser**: User to run as inside the container.
- **runArgs**: Additional Docker arguments. Used to set the runtime (e.g., `--runtime=runsc`) or network (e.g., `--network=host`).

### Sandbox Settings (`.sandbox.toml`)

- **host**: Remote Docker host specification (e.g., `user@host:port`).
- **agent**:
  - **model**: Default model for `sandbox agent` (e.g., `claude-opus-4.5`, `claude-sonnet-4.5`, `gemini-3-pro-preview`, `grok-4.1-fast-reasoning`).
  - **thinking-budget**: Thinking budget in tokens for supported models.
  - **anthropic-websearch**: Enable/disable web search for Anthropic models.

## How It Works

The agent runs autonomously without asking for permissions. Safety comes from the sandbox: all filesystem changes are isolated via overlays, and the container runs with gVisor for syscall-level protection.

Project-specific instructions can be provided in an `AGENTS.md` file.
