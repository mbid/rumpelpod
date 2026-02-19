# Rumpelpod

Manage multiple independent workspaces of a repository in Docker containers, on local or remote hosts.
Designed for running LLM coding agents.

## Table of Contents

- [What Is This?](#what-is-this)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Commands](#commands)
- [How It Works](#how-it-works)
  - [Git Synchronization](#git-synchronization)
  - [Containers and Isolation](#containers-and-isolation)
- [Comparison With Other Tools](#comparison-with-other-tools)

## What Is This?

Rumpelpod manages named, independent workspaces ("pods") of your repository inside Docker containers.
Each pod gets its own working copy synced via git, so multiple agents (or humans) can work on the same repository concurrently without interfering with each other or the host.

Containers can run on the local Docker daemon or on a remote host via SSH.
Rumpelpod handles git synchronization, port forwarding, and container lifecycle across both.

This is mainly used for running LLM coding agents.
The typical workflow:

1. Launch Claude Code in a pod with `rumpel claude my-task`.
2. The agent works autonomously inside its container.
3. You review the changes with `rumpel review my-task` (opens your configured git difftool) and merge what you want.

There is also a minimal built-in agent (`rumpel agent`) that talks directly to the Anthropic, Gemini, and xAI APIs.

Rumpelpod piggy-backs on existing tooling: containers are configured with standard `devcontainer.json` files and built with Docker.
If your project already has a dev container configuration, rumpelpod can use it directly.

## Installation

Download the latest tarball from [GitHub Releases](https://github.com/mbid/rumpelpod/releases) and extract all binaries into a directory on your PATH:

```bash
tar xzf rumpel-v*.tar.gz -C ~/.local/bin/
```

The tarball contains statically linked binaries for Linux amd64, Linux arm64, and macOS arm64.
All of them must be in the same directory; rumpelpod copies the matching Linux binary into containers for git hooks, so both Linux architectures are needed even if your host is only one of them.
Symlink `rumpel` to the one matching your host platform:

```bash
ln -sf rumpel-linux-amd64 ~/.local/bin/rumpel    # on x86_64 Linux
ln -sf rumpel-darwin-arm64 ~/.local/bin/rumpel    # on Apple Silicon
```

Then install the background daemon:

```bash
rumpel system-install
```

The daemon manages pod lifecycle and git synchronization.
It runs as a systemd user service on Linux and a launchd user agent on macOS.

Requirements:
- Docker (local or remote via SSH)
- Git

## Getting Started

Create a `.devcontainer/devcontainer.json` in your project:

```json
{
    "image": "my-project-dev:latest",
    "workspaceFolder": "/home/dev/my-project",
    "containerUser": "dev"
}
```

Launch Claude Code in a pod:

```bash
rumpel claude my-task
```

Or enter a pod interactively:

```bash
rumpel enter my-shell
```

Review the agent's changes:

```bash
rumpel review my-task
```

To run pods on a remote Docker host, pass `--host`:

```bash
rumpel claude my-task --host ssh://user@build-server
```

## Configuration

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


### `AGENTS.md`

Project-specific instructions for LLM agents.
Placed in the repository root.
Agents read this file for context about the project's conventions, architecture, and how to run tests.

## Commands

| Command | Description |
|---------|-------------|
| `rumpel claude <name>` | Launch Claude Code in a persistent screen session inside a pod |
| `rumpel enter <name>` | Enter a pod interactively, or run a command with `[-- CMD]` |
| `rumpel list` | List pods for the current repository |
| `rumpel review <name>` | Review changes using your configured git difftool |
| `rumpel cp <src> <dest>` | Copy files between host and pod (`pod:path` syntax) |
| `rumpel stop <name>` | Stop a pod without removing it |
| `rumpel delete <name>` | Delete a pod (refuses if unmerged commits exist unless `--force`) |
| `rumpel recreate <name>` | Snapshot dirty files, destroy container, recreate with snapshot |
| `rumpel ports <name>` | Show forwarded ports |
| `rumpel image build` | Build the devcontainer image from its Dockerfile |
| `rumpel image fetch` | Pull the devcontainer image from its registry |
| `rumpel system-install` | Install the background daemon |
| `rumpel system-uninstall` | Uninstall the background daemon |

Most commands accept `--host ssh://user@host` to target a remote Docker daemon.

## How It Works

### Git Synchronization

Host branches are automatically synced into pods via git hooks.
Inside each pod, the host branches appear as the `host` remote.
Each pod works on its own branch, and pod branches are pushed back to the host as `rumpelpod/<branch>@<pod>`.

Because the workspace is cloned via git rather than bind-mounted, gitignored and untracked files are not present inside pods.
Lifecycle commands like `npm install` regenerate them, but for faster pod creation it helps to bake a checkout and warm build cache into the Docker image:

```dockerfile
RUN git clone https://github.com/you/your-project /workspaces/your-project
WORKDIR /workspaces/your-project
RUN cargo build; true
```

Cached build artifacts in `target/` will survive into the pod.

### Containers and Isolation

Rumpelpod creates standard Docker containers.
It does not enforce a particular isolation level.
That is a property of the container runtime and the Docker host.
You can use `runArgs` in your `devcontainer.json` to select a runtime that fits your security requirements, for example [gVisor](https://gvisor.dev/) (`--runtime=runsc`), [Kata Containers](https://katacontainers.io/) (`--runtime=kata-runtime`), or [Sysbox](https://github.com/nestybox/sysbox) (`--runtime=sysbox-runc`).

Running pods on a dedicated remote host provides physical separation from your development machine.
Rumpelpod handles SSH tunneling for the Docker API and port forwarding for services running inside pods.

## Comparison With Other Tools

Cloud platforms like [Devin](https://devin.ai/), [Codex](https://openai.com/codex/) (OpenAI), [Copilot Coding Agent](https://docs.github.com/en/copilot/concepts/agents/coding-agent/about-coding-agent), and [Ona](https://ona.com/) (formerly Gitpod) run coding agents in hosted environments, typically triggered through GitHub.
They manage the infrastructure for you, but agents interact with your code through the forge: pull requests, issue comments, CI checks.
With rumpelpod, pods run on your own machines (local or remote) and you use your normal local tools.
There is no forge in the loop.

[Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) (Docker Desktop) runs agents in microVMs with file synchronization between host and sandbox.
Rumpelpod uses git-based sync instead, supports multiple concurrent named pods per repository, and works on headless Linux servers without Docker Desktop.

The [Dev Container CLI](https://github.com/devcontainers/cli) provides container lifecycle management from `devcontainer.json` files.
Rumpelpod builds on the same configuration format but adds git synchronization, named pod management, remote Docker support, and agent integration.

Git worktrees are the simplest way to run multiple agents in parallel, but agents run directly on the host with no isolation, and managing many worktrees by hand gets tedious.
