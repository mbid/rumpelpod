# Rumpelpod

Run LLM coding agents in isolated containers.

## Table of Contents

- [Status](#status)
- [What Is This?](#what-is-this)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Commands](#commands)
- [How It Works](#how-it-works)
  - [Git Synchronization](#git-synchronization)
  - [Isolation](#isolation)
  - [Agent Autonomy](#agent-autonomy)
- [Supported Models](#supported-models)
- [Comparison With Other Tools](#comparison-with-other-tools)

## Status

Rumpelpod is in active development and used daily by its authors. The
interface is subject to change.

## What Is This?

Rumpelpod spawns isolated Docker containers ("pods") for running LLM coding
agents against your repositories. Each pod gets its own working copy of
your code, synced via git. The agent can execute commands, edit files, and
install packages freely -- safety comes from the container isolation, not
from permission dialogs.

The typical workflow:

1. You give the agent a task.
2. The agent works autonomously inside its pod.
3. You review the changes with `rumpel review` and merge what you want.

Multiple pods can run concurrently against the same repository on separate
branches.

## Installation

Build from source:

```bash
cargo install --path .
```

Install the background daemon:

```bash
rumpel system-install
```

The daemon manages pod lifecycle and git synchronization. It runs as a
systemd service on Linux and a launchd agent on macOS.

Requirements:
- Docker with gVisor runtime (`runsc`). Alternative runtimes: `runc`,
  `sysbox-runc`.
- Git

## Getting Started

Create a `.devcontainer/devcontainer.json` in your project:

```json
{
    "image": "my-project-dev:latest",
    "workspaceFolder": "/home/dev/my-project",
    "containerUser": "dev",
    "runArgs": ["--runtime=runsc"]
}
```

Run an LLM agent in a pod:

```bash
rumpel agent my-task
```

Or enter a pod interactively:

```bash
rumpel enter my-shell
```

Or launch Claude Code inside a pod:

```bash
rumpel claude my-pod
```

Review the agent's changes:

```bash
rumpel review my-task
```

## Configuration

Pod behavior is configured with two files:

### `.devcontainer/devcontainer.json`

Container settings following the [Dev Containers specification](https://containers.dev/).
The following fields are supported:

| Field | Description |
|-------|-------------|
| `image` | Docker image to use |
| `build.dockerfile` | Build from a Dockerfile instead of pulling an image |
| `workspaceFolder` | Where the repository appears inside the container |
| `containerUser` / `remoteUser` | User to run as inside the container |
| `runArgs` | Docker arguments (e.g. `--runtime=runsc`, `--network=host`) |
| `forwardPorts` | Ports to forward from the container |
| `remoteEnv` / `containerEnv` | Environment variables |
| `mounts` | Additional volume or bind mounts |
| `overrideCommand` | Whether to replace the image CMD with `sleep infinity` |
| Lifecycle commands | `onCreateCommand`, `postCreateCommand`, `updateContentCommand`, `postStartCommand`, `postAttachCommand` |

Intentionally unsupported: Features, Docker Compose, `initializeCommand`,
`workspaceMount`. See `docs/devcontainer.md` for a detailed comparison with
the official specification.

### `.rumpelpod.toml`

Optional. Agent and pod-specific settings:

```toml
host = "ssh://user@host"

[agent]
model = "claude-sonnet-4-5"
thinking-budget = 10000
anthropic-websearch = true
```

| Field | Description |
|-------|-------------|
| `host` | Remote Docker host (`ssh://user@host:port`) |
| `agent.model` | Default model for `rumpel agent` |
| `agent.thinking-budget` | Thinking budget in tokens |
| `agent.anthropic-websearch` | Enable web search for Anthropic models |
| `agent.anthropic-base-url` | Custom API endpoint for Anthropic |

### `AGENTS.md`

Project-specific instructions for LLM agents. Placed in the repository
root. Agents read this file for context about the project's conventions,
architecture, and how to run tests.

## Commands

| Command | Description |
|---------|-------------|
| `rumpel enter <name>` | Enter a pod interactively, or run a command with `-- CMD` |
| `rumpel agent <name>` | Run an LLM agent in a pod |
| `rumpel claude <name>` | Launch Claude Code in a persistent screen session inside a pod |
| `rumpel list` | List pods for the current repository |
| `rumpel review <name>` | Review changes using git difftool |
| `rumpel cp <src> <dest>` | Copy files between host and pod (`pod:path` syntax) |
| `rumpel stop <name>` | Stop a pod without removing it |
| `rumpel delete <name>` | Delete a pod (refuses if unmerged commits exist unless `--force`) |
| `rumpel recreate <name>` | Snapshot dirty files, destroy container, recreate with snapshot |
| `rumpel ports <name>` | Show forwarded ports |
| `rumpel image build` | Build the devcontainer image from its Dockerfile |
| `rumpel image fetch` | Pull the devcontainer image from its registry |
| `rumpel system-install` | Install the background daemon |
| `rumpel system-uninstall` | Uninstall the background daemon |

## How It Works

### Git Synchronization

Rumpelpod uses a three-repository architecture:

```
Host repo  --->  Gateway repo (bare)  <--->  Pod repos
              refs/heads/host/*             refs/heads/rumpelpod/<branch>@<pod>
```

Your host branches are pushed to a gateway bare repository via git hooks.
Pods clone from the gateway through a built-in HTTP server. Pod branches
are namespaced (`rumpelpod/<branch>@<pod>`) so multiple pods can work
on separate branches without conflicts.

Because the workspace is cloned via git rather than bind-mounted,
gitignored and untracked files are not present inside pods. Lifecycle
commands like `npm install` regenerate them.

### Isolation

Containers run with gVisor (`runsc`) by default, which intercepts syscalls
at the kernel boundary. The pod filesystem is an overlay -- changes inside
the pod do not affect the host. If the agent breaks something, delete the
pod and start over.

Network, process, and filesystem isolation are provided by Docker.
Remote Docker hosts are supported via SSH, with automatic port forwarding
for services running inside pods.

### Agent Autonomy

The built-in agent (`rumpel agent`) and the Claude Code integration
(`rumpel claude`) both run without permission prompts. The agent has
access to bash, file editing, and file creation tools. For Claude Code,
`--dangerously-skip-permissions` is enabled by default with a hook that
auto-approves tool use.

This is the core design choice: rather than mediating every action through
a permission dialog, rumpelpod relies on the container boundary for safety.
The agent can do anything it wants inside the pod; you review the result.

## Supported Models

Rumpelpod's built-in agent (`rumpel agent`) supports multiple providers:

**Anthropic** (requires `ANTHROPIC_API_KEY`):
- `claude-opus-4-5` (default), `claude-opus-4-6`, `claude-sonnet-4-5`,
  `claude-haiku-4-5`

**Google Gemini** (requires `GEMINI_API_KEY`):
- `gemini-2.5-flash`, `gemini-3-flash-preview`, `gemini-3-pro-preview`

**xAI** (requires `XAI_API_KEY`):
- `grok-4-1-fast-reasoning`, `grok-4-1-fast-non-reasoning`

Custom model strings can be passed with `--custom-anthropic-model`,
`--custom-gemini-model`, or `--custom-xai-model`.

The Claude Code integration (`rumpel claude`) uses whatever model you
configure in Claude Code itself.

## Comparison With Other Tools

Rumpelpod is a local CLI tool for developers who want to run coding agents
against their repositories with container isolation and git-based change
management. Here is how it compares to other approaches:

**Git worktrees** are the simplest way to run multiple agents in parallel.
Each agent gets its own worktree on a separate branch. The downside is that
agents run directly on the host with no isolation -- they can access your
filesystem, network, and other processes.

**Dev Container CLI** provides container lifecycle management from
`devcontainer.json` files. Rumpelpod builds on the same configuration
format but adds git synchronization, named pod management, and an
integrated agent runner. The Dev Container CLI is a building block;
rumpelpod is the full workflow.

**Docker Sandboxes** (Docker Desktop) runs coding agents in microVMs with
network allow/deny lists. It focuses on single-agent use and mounts your
workspace directly. Rumpelpod uses git-based sync instead of bind mounts,
supports multiple concurrent named pods, and runs on Linux servers without
Docker Desktop.

**E2B**, **Daytona**, **Runloop**, and similar cloud platforms provide
hosted sandboxed environments for AI agents, typically accessed via API or
SDK. They target platform builders integrating agent execution into their
products. Rumpelpod is self-hosted and designed for individual developers
working from their terminal.

**AgentFS** (Turso) provides a copy-on-write overlay filesystem backed by
SQLite. It isolates file changes but does not provide process or network
isolation. Rumpelpod uses Docker's overlay filesystem combined with gVisor
for full container isolation.

**Anthropic's sandbox-runtime** enforces filesystem and network
restrictions at the OS level using bubblewrap (Linux) or seatbelt (macOS)
without containers. It is lighter weight but provides less isolation than
gVisor, and does not manage working copies or multiple concurrent
instances.
