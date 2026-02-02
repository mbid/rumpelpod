# devcontainer.json Implementation Status

This document tracks our implementation of the [Dev Container specification](https://containers.dev/implementors/json_reference/).

## Currently Implemented

The following properties from `devcontainer.json` are fully implemented:

### Image/Build Configuration
| Property | Status | Notes |
|----------|--------|-------|
| `image` | ✅ | Container image to use |
| `build.dockerfile` | ✅ | Path to Dockerfile |
| `build.context` | ✅ | Build context path |
| `build.args` | ✅ | Docker build arguments |
| `build.target` | ✅ | Multi-stage build target |
| `build.cacheFrom` | ✅ | Cache source images |
| `build.options` | ✅ | Additional build options |
| `dockerfile` (legacy) | ✅ | Deprecated, use `build.dockerfile` |
| `context` (legacy) | ✅ | Deprecated, use `build.context` |

### Container Configuration
| Property | Status | Notes |
|----------|--------|-------|
| `workspaceFolder` | ⚠️ Partial | Path inside container for workspace (see notes below) |
| `containerUser` | ✅ | User to run container as |
| `remoteUser` | ✅ | User for dev tools (falls back to `containerUser`) |
| `containerEnv` | ✅ | Environment variables with `${localEnv:VAR}` substitution |
| `runArgs` | ⚠️ Partial | Only `--runtime` and `--network=host` are extracted |

#### `workspaceFolder` Implementation Notes

**Default Value:** The spec defines a default of `/workspaces/${localWorkspaceFolderBasename}` for image/Dockerfile scenarios. We should honor this default when `workspaceFolder` is not explicitly set.

**Repo Initialization:** Unlike VS Code Dev Containers which bind-mount the host workspace, we use Git-based synchronization. This means:

1. **Detection:** On sandbox creation, check if `workspaceFolder` already contains a Git repository
2. **Initialization:** If no repo exists at `workspaceFolder`:
   - Clone the repository from host via our git-http bridge
   - This happens on first sandbox creation for that image
3. **Updates:** On each `sandbox enter`, sync recent commits from host to container

**Future Optimization (Image Pre-baking):**
For faster sandbox startup, we could detect that an image doesn't have a repo at `workspaceFolder` and create a derived image with the repo pre-cloned:
1. Start temporary container from base image
2. Clone current repo state into `workspaceFolder`  
3. Commit container as new image: `sandbox-<base-image-hash>-<repo-hash>`
4. Use this pre-baked image for subsequent sandboxes

This optimization is deferred; the initial implementation will clone on each sandbox creation.

### Metadata
| Property | Status | Notes |
|----------|--------|-------|
| `name` | ✅ | Parsed but not displayed in UI |

---

## Unsupported Features (Will Not Implement)

These features are intentionally not supported. When detected in `devcontainer.json`, we should **print a warning** and ignore them.

| Property | Reason |
|----------|--------|
| `workspaceMount` | Defeats sandbox isolation; we use Git-based sync instead of bind mounts |
| `appPort` | Use `forwardPorts` instead; publishing ports bypasses our port management |
| `dockerComposeFile` | Out of scope; use dedicated Docker Compose tooling |
| `service` | Docker Compose specific |
| `runServices` | Docker Compose specific |

**Implementation:** In `DevContainer::load()` or config merging, check for these fields and emit warnings:
```
warning: devcontainer.json contains 'workspaceMount' which is not supported by sandbox
         (sandbox uses Git-based synchronization for isolation)
```

---

## Features Needing Implementation

### Priority 1: Container Runtime Options

These properties affect container security and functionality. They're parsed but not passed to Docker.

#### `privileged`
**Type:** `boolean`  
**Default:** `false`

Run the container in privileged mode (`--privileged`). Required for Docker-in-Docker and some debugging scenarios.

**Implementation:** Pass `--privileged` flag to `docker run` / `ContainerCreateBody.host_config.privileged`.

**Security Note:** Has significant security implications. Should warn users when enabled, especially with gVisor.

---

#### `init`
**Type:** `boolean`  
**Default:** `false`

Use the [tini init process](https://github.com/krallin/tini) to handle zombie processes (`--init`).

**Implementation:** Set `ContainerCreateBody.host_config.init = true`.

**Use Case:** Prevents zombie process accumulation in long-running containers.

---

#### `capAdd`
**Type:** `string[]`  
**Default:** `[]`

Linux capabilities to add to the container. Most commonly used for debugging.

**Example:**
```json
{
  "capAdd": ["SYS_PTRACE"]
}
```

**Implementation:** Set `ContainerCreateBody.host_config.cap_add`.

**Common Values:**
- `SYS_PTRACE` - Required for debuggers (C++, Go, Rust)
- `NET_ADMIN` - Network configuration
- `SYS_ADMIN` - Various admin operations

---

#### `securityOpt`
**Type:** `string[]`  
**Default:** `[]`

Security options for the container.

**Example:**
```json
{
  "securityOpt": ["seccomp=unconfined"]
}
```

**Implementation:** Set `ContainerCreateBody.host_config.security_opt`.

**Common Values:**
- `seccomp=unconfined` - Disable seccomp filtering (needed for some debuggers)
- `apparmor=unconfined` - Disable AppArmor

---

#### `runArgs` (Full Support)
**Type:** `string[]`  
**Default:** `[]`

Additional arguments to pass to `docker run`. Currently we only extract `--runtime` and `--network`.

**Implementation:** Parse and forward all safe arguments. Some arguments may need to be blocked for security (e.g., `--pid=host`).

**Example:**
```json
{
  "runArgs": [
    "--cap-add=SYS_PTRACE",
    "--security-opt", "seccomp=unconfined",
    "--device=/dev/fuse"
  ]
}
```

**Testing:** `tests/cli/devcontainer/runtime_options.rs`

---

### Priority 2: Lifecycle Commands

These commands run at different points in the container lifecycle. The spec defines a specific execution order.

#### Execution Order
1. `initializeCommand` - On host, before container creation
2. `onCreateCommand` - In container, after first creation
3. `updateContentCommand` - In container, when content updates
4. `postCreateCommand` - In container, after container assigned to user
5. `postStartCommand` - In container, each time container starts
6. `postAttachCommand` - In container, each time a tool attaches

#### `initializeCommand`
**Type:** `string | string[] | object`  
**Runs:** On **host machine** during initialization

**Example:**
```json
{
  "initializeCommand": "npm install"
}
```

**Implementation:**
- Execute on host before container creation
- Run from the workspace folder
- Support string (shell), array (no shell), and object (parallel) formats

**Security:** Runs with user's host permissions. Should require explicit opt-in or confirmation.

---

#### `onCreateCommand`
**Type:** `string | string[] | object`  
**Runs:** In container after first creation

First command that runs inside the container. Used for one-time setup that can be cached/prebuilt.

**Example:**
```json
{
  "onCreateCommand": "pip install -r requirements.txt"
}
```

**Implementation:**
- Execute in container after creation
- Only runs once (first creation)
- Store execution status in container metadata

---

#### `updateContentCommand`
**Type:** `string | string[] | object`  
**Runs:** In container when new content is available

Runs after `onCreateCommand` when source tree has new content.

**Example:**
```json
{
  "updateContentCommand": "npm install"
}
```

**Implementation:** Execute when workspace content changes (e.g., after git pull).

---

#### `postCreateCommand`
**Type:** `string | string[] | object`  
**Runs:** In container after assigned to user

Final setup command. Has access to user-specific secrets.

**Example:**
```json
{
  "postCreateCommand": {
    "server": "npm start",
    "db": ["mysql", "-u", "root"]
  }
}
```

**Implementation:**
- Execute after container is ready
- Support parallel execution with object syntax
- Each key runs in parallel

---

#### `postStartCommand`
**Type:** `string | string[] | object`  
**Runs:** In container, each time container starts

**Example:**
```json
{
  "postStartCommand": "nohup bash -c 'npm run watch &'"
}
```

**Implementation:** Execute each time container starts (including restarts).

---

#### `postAttachCommand`
**Type:** `string | string[] | object`  
**Runs:** In container, each time a tool attaches

**Example:**
```json
{
  "postAttachCommand": "cat /tmp/welcome.txt"
}
```

**Implementation:** Execute each time `sandbox enter` is called.

---

#### `waitFor`
**Type:** `enum`  
**Default:** `updateContentCommand`  
**Values:** `initializeCommand`, `onCreateCommand`, `updateContentCommand`, `postCreateCommand`, `postStartCommand`, `postAttachCommand`

Which lifecycle command to wait for before considering the container ready.

**Implementation:** Block `sandbox enter` until the specified command completes.

**Testing:** `tests/cli/devcontainer/lifecycle_commands.rs`

---

### Priority 3: Port Forwarding

#### `forwardPorts`
**Type:** `(number | string)[]`  
**Default:** `[]`

Ports that should be forwarded from the container to the local machine.

**Example:**
```json
{
  "forwardPorts": [3000, "db:5432"]
}
```

**Multi-Sandbox Port Allocation:**

When multiple sandboxes are running for the same repository, port conflicts must be handled:

1. **Port Registry:** The daemon maintains a registry of forwarded ports per sandbox
2. **Automatic Allocation:** If the requested local port is in use by another sandbox:
   - Allocate the next available port in a defined range (e.g., 10000-65535)
   - Store the mapping: `sandbox-name -> {container_port: local_port}`
3. **Port Query:** `sandbox ports <sandbox-name>` shows the port mappings:
   ```
   CONTAINER    LOCAL      LABEL
   3000         3000       Application
   5432         15432      Database (remapped: 5432 in use by sandbox-1)
   ```
4. **Sticky Allocation:** Once a port is allocated to a sandbox, prefer reusing it on restart

**Implementation for Local Docker:**
- Use `socat` or SSH local forwarding to forward from localhost to container
- Don't use `--publish` (would conflict across sandboxes and bypass gVisor network isolation)

**Implementation for Remote Docker:**
- All port forwarding goes through SSH tunnel to the developer's machine
- Chain: `localhost:local_port` → SSH tunnel → `remote_host` → container network → `container:container_port`
- The daemon's SSH connection to the remote host sets up `-L local_port:container_ip:container_port` for each forwarded port

**Testing:** `tests/cli/devcontainer/ports.rs`

---

#### `appPort` (Legacy)
**Type:** `number | string | (number | string)[]`  
**Default:** `[]`

Publishes ports when container runs. Unlike `forwardPorts`, requires application to listen on `0.0.0.0`.

**Status:** ⚠️ **DISCOURAGED** - Use `forwardPorts` instead.

**Why:** Publishing ports (`--publish`) bypasses our port management and can cause conflicts between sandboxes. It also doesn't work well with gVisor's network isolation.

---

#### `portsAttributes`
**Type:** `object`  
**Default:** `{}`

Port-specific configuration for forwarded ports.

**Example:**
```json
{
  "portsAttributes": {
    "3000": {
      "label": "Application",
      "protocol": "https",
      "onAutoForward": "openBrowser"
    }
  }
}
```

**Properties:**
- `label` - Display name (shown in `sandbox ports` output)
- `protocol` - `http` or `https` (for URL display)
- `onAutoForward` - Action when port detected: `notify`, `openBrowser`, `openBrowserOnce`, `openPreview`, `silent`, `ignore`
- `requireLocalPort` - Must use same port number locally (error if unavailable)
- `elevateIfNeeded` - Auto-elevate for low ports (< 1024)

**Implementation:** Store attributes in daemon database, apply when setting up forwarding.

---

#### `otherPortsAttributes`
**Type:** `object`  
**Default:** `{}`

Default attributes for ports not explicitly configured in `portsAttributes`.

**Example:**
```json
{
  "otherPortsAttributes": {
    "onAutoForward": "silent"
  }
}
```

**Testing:** `tests/cli/devcontainer/ports.rs`

---

### Priority 4: Environment Variables

#### `remoteEnv`
**Type:** `object`  
**Default:** `{}`

Environment variables for dev tools and processes (like terminals), but not the container itself.

**Key Difference from `containerEnv`:**
- `containerEnv`: Set at container creation, static, available to all processes
- `remoteEnv`: Set when tools attach, can be dynamic, can reference container variables

**Example:**
```json
{
  "remoteEnv": {
    "PATH": "${containerEnv:PATH}:/custom/bin",
    "LOCAL_HOME": "${localEnv:HOME}"
  }
}
```

**Implementation:** Apply these variables when executing commands via `sandbox enter` and `sandbox agent`. Both commands run processes inside the container and should have access to these environment variables.

---

#### `updateRemoteUserUID`
**Type:** `boolean`  
**Default:** `true` (on Linux)

Update the container user's UID/GID to match the local user's UID/GID. Prevents permission problems with bind mounts.

**Implementation:**
1. Detect local user's UID/GID
2. If container user differs, run `usermod`/`groupmod` on container start
3. Only applies on Linux

---

#### `userEnvProbe`
**Type:** `enum`  
**Default:** `loginInteractiveShell`  
**Values:** `none`, `interactiveShell`, `loginShell`, `loginInteractiveShell`

How to probe for user environment variables.

**Implementation:**
- `none`: Don't probe
- `interactiveShell`: Source `~/.bashrc`, `/etc/bash.bashrc`
- `loginShell`: Source `~/.profile`, `/etc/profile`
- `loginInteractiveShell`: Source all of the above

---

### Priority 5: Mounts and Volumes

#### `mounts`
**Type:** `string | object[]`  
**Default:** `[]`

Additional mounts for the container. Accepts Docker `--mount` format strings or structured objects.

**String Format:**
```json
{
  "mounts": [
    "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"
  ]
}
```

**Object Format:**
```json
{
  "mounts": [
    {
      "type": "bind",
      "source": "/var/run/docker.sock",
      "target": "/var/run/docker.sock"
    },
    {
      "type": "volume",
      "source": "my-data",
      "target": "/data"
    },
    {
      "type": "tmpfs",
      "target": "/tmp"
    }
  ]
}
```

**Implementation:**
1. Parse both string and object formats
2. Substitute variables (`${localWorkspaceFolder}`, `${localEnv:VAR}`)
3. Add to `ContainerCreateBody.host_config.mounts`

**Security Consideration:** Should validate mount sources to prevent escaping sandbox.

**Remote Docker Hosts:** ❌ **NOT SUPPORTED** for `bind` mounts. When using a remote Docker host:
- `bind` mounts would reference paths on the *remote* host, not the developer's machine
- This is unlikely to be the intended behavior and could cause confusion
- Only `volume` and `tmpfs` mounts are supported for remote hosts
- Should error with a clear message if bind mounts are specified with remote Docker

**Testing:** `tests/cli/devcontainer/mounts.rs`

---

### Priority 6: Dev Container Features

#### `features`
**Type:** `object`  
**Default:** `{}`

Dev Container Features to install. Features are reusable, shareable units of container configuration.

**Example:**
```json
{
  "features": {
    "ghcr.io/devcontainers/features/node:1": {
      "version": "18"
    },
    "ghcr.io/devcontainers/features/docker-in-docker:2": {}
  }
}
```

**Implementation:**
This is a significant feature requiring:
1. Feature resolution (from OCI registries)
2. Feature dependency resolution
3. Feature installation scripts execution
4. Dockerfile generation with feature layers

**Reference:** [Dev Container Features Specification](https://containers.dev/implementors/features/)

---

#### `overrideFeatureInstallOrder`
**Type:** `string[]`  
**Default:** `[]`

Override the automatic feature installation order.

**Example:**
```json
{
  "overrideFeatureInstallOrder": [
    "ghcr.io/devcontainers/features/common-utils",
    "ghcr.io/devcontainers/features/node"
  ]
}
```

---

### Priority 7: Other Properties

#### `overrideCommand`
**Type:** `boolean`  
**Default:** `true` (image/Dockerfile), `false` (Docker Compose)

Whether to override the container's default command with a sleep loop.

**Current Behavior:** We always run `sleep infinity`. This property would allow using the image's CMD.

**Implementation:** If `false`, don't override the container command.

---

#### `shutdownAction`
**Type:** `enum`  
**Default:** `stopContainer` (image/Dockerfile), `stopCompose` (Docker Compose)  
**Values:** `none`, `stopContainer`, `stopCompose`

What happens when the dev container tool disconnects.

**Implementation:**
- `none`: Leave container running
- `stopContainer`: Stop the container
- `stopCompose`: Stop all compose services

---

#### `customizations`
**Type:** `object`

Tool-specific customizations. Each tool uses a unique key.

**Example:**
```json
{
  "customizations": {
    "vscode": {
      "extensions": ["rust-lang.rust-analyzer"],
      "settings": {
        "editor.formatOnSave": true
      }
    }
  }
}
```

**Implementation:** Define a `sandbox` key for our tool-specific settings:
```json
{
  "customizations": {
    "sandbox": {
      "agent": {
        "model": "claude-sonnet-4-5"
      }
    }
  }
}
```

---

#### `hostRequirements`
**Type:** `object`

Minimum host requirements for the container.

**Example:**
```json
{
  "hostRequirements": {
    "cpus": 4,
    "memory": "8gb",
    "storage": "32gb",
    "gpu": true
  }
}
```

**Properties:**
- `cpus` - Minimum CPU cores
- `memory` - Minimum RAM (with `tb`, `gb`, `mb`, `kb` suffix)
- `storage` - Minimum storage
- `gpu` - GPU requirement: `true`, `false`, `"optional"`, or `{ "cores": N, "memory": "Xgb" }`

**Implementation:** 
- Check host capabilities before starting
- For remote Docker, query remote host
- Warn or fail if requirements not met

---

## Variable Substitution

The following variables can be used in string values:

| Variable | Description |
|----------|-------------|
| `${localEnv:VAR}` | Host environment variable |
| `${localEnv:VAR:default}` | Host env var with default |
| `${containerEnv:VAR}` | Container environment variable (only in `remoteEnv`) |
| `${containerEnv:VAR:default}` | Container env var with default |
| `${localWorkspaceFolder}` | Absolute path to workspace on host |
| `${containerWorkspaceFolder}` | Path to workspace in container |
| `${localWorkspaceFolderBasename}` | Workspace folder name on host |
| `${containerWorkspaceFolderBasename}` | Workspace folder name in container |
| `${devcontainerId}` | Unique, stable identifier for the dev container |

**Currently Implemented:** `${localEnv:VAR}` in `containerEnv`

**Needs Implementation:** All other variables and contexts.

---

## Testing Strategy

Tests for devcontainer.json features are organized in `tests/cli/devcontainer/` with one file per feature group:

| File | Features Tested |
|------|-----------------|
| `env.rs` | ✅ `containerEnv`, `${localEnv}` substitution |
| `image.rs` | ✅ `build.*` options, image caching |
| `unsupported.rs` | Warnings for `workspaceMount`, `appPort`, `dockerComposeFile`, etc. |
| `runtime_options.rs` | `privileged`, `init`, `capAdd`, `securityOpt`, `runArgs` |
| `lifecycle_commands.rs` | `onCreateCommand`, `postCreateCommand`, `postStartCommand`, `postAttachCommand`, `waitFor` |
| `ports.rs` | `forwardPorts`, `portsAttributes`, multi-sandbox port allocation |
| `remote_env.rs` | `remoteEnv`, `userEnvProbe`, `updateRemoteUserUID` |
| `mounts.rs` | `mounts` (volumes, tmpfs; bind blocked for remote) |
| `workspace.rs` | `workspaceFolder` defaults, repo initialization |

### Test Patterns

Each test file should follow the pattern established in `env.rs` and `image.rs`:

```rust
// tests/cli/devcontainer/lifecycle_commands.rs

use crate::common::{sandbox_command, TestDaemon, TestRepo};

fn write_devcontainer_with_lifecycle(repo: &TestRepo, commands: &str) {
    // Helper to create devcontainer.json with specific lifecycle commands
}

#[test]
fn post_create_command_runs_once() {
    // Verify postCreateCommand runs on first enter but not subsequent enters
}

#[test]
fn post_start_command_runs_each_start() {
    // Verify postStartCommand runs each time container starts
}

#[test]
fn lifecycle_command_failure_stops_chain() {
    // Verify that if onCreateCommand fails, postCreateCommand doesn't run
}
```

### Testing Remote Docker

For features that behave differently with remote Docker hosts:
- Use `TestDaemon::start_with_remote()` (to be implemented)
- Or mock the SSH tunnel behavior
- Specifically test: port forwarding, mount restrictions

---

## Implementation Recommendations

### Phase 0: Warnings for Unsupported Features
Emit warnings when `devcontainer.json` contains unsupported properties:
- `workspaceMount`, `appPort`, `dockerComposeFile`, `service`, `runServices`

### Phase 1: Security & Debugging
1. `privileged`, `capAdd`, `securityOpt` - Essential for debugging
2. `init` - Good practice for process management
3. Full `runArgs` support

### Phase 2: Developer Experience
1. Lifecycle commands (`postCreateCommand`, etc.)
2. Port forwarding with multi-sandbox support
3. `remoteEnv` for `sandbox enter` and `sandbox agent`

### Phase 3: Advanced Features
1. Dev Container Features
2. `mounts` (volume/tmpfs only; no bind mounts for remote)
3. `hostRequirements` for cloud deployments

### Phase 4: Compatibility
1. `customizations.sandbox` namespace
2. Full variable substitution
3. `userEnvProbe` for environment detection
