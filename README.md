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

Create a `.sandbox.toml` in your project root:

```toml
env = ["ANTHROPIC_API_KEY"]
```

Create a `Dockerfile` for your project environment (must accept `USER_NAME`, `USER_ID`, `GROUP_ID` build args).

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
| `sandbox delete <name>` | Delete a sandbox |
| `sandbox system-install` | Install the systemd daemon |
| `sandbox system-uninstall` | Uninstall the systemd daemon |

## Configuration

The `.sandbox.toml` file configures sandbox behavior:

```toml
# Environment variables passed to container (must be set on host)
env = ["ANTHROPIC_API_KEY", "XAI_API_KEY"]

# Container runtime: runsc (default), runc, sysbox-runc
runtime = "runsc"

# Overlay strategy: overlayfs (default) or copy
overlay-mode = "overlayfs"

# Mounts
[[mounts.readonly]]
host = "~/.gitconfig"

[[mounts.overlay]]
host = "~/.cargo/registry"
container = "~/.cargo/registry"

# Image configuration (defaults to ./Dockerfile)
[image]
tag = "my-image:latest"
# Or build from Dockerfile:
# [image.build]
# dockerfile = "Dockerfile"
# context = "."

# Agent settings
[agent]
model = "sonnet"  # opus, sonnet, haiku, grok-3-mini, grok-4.1-fast
```

### Mount Types

- **readonly**: Host files visible in container, no writes allowed
- **overlay**: Copy-on-write; writes stay in container
- **unsafe-write**: Writes propagate to host (use with caution)

## How It Works

The agent runs autonomously without asking for permissions. Safety comes from the sandbox: all filesystem changes are isolated via overlays, and the container runs with gVisor for syscall-level protection.

Project-specific instructions can be provided in an `AGENTS.md` file.
