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
| `workspaceFolder` | ✅ | Path inside container for workspace |
| `containerUser` | ✅ | User to run container as |
| `remoteUser` | ✅ | User for dev tools (falls back to `containerUser`) |
| `containerEnv` | ✅ | Environment variables with `${localEnv:VAR}` substitution |
| `runArgs` | ⚠️ Partial | Only `--runtime` and `--network=host` are extracted |

### Metadata
| Property | Status | Notes |
|----------|--------|-------|
| `name` | ✅ | Parsed but not displayed in UI |

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

---

### Priority 2: Mounts and Volumes

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

---

#### `workspaceMount`
**Type:** `string`  
**Default:** Auto-generated

Override the default workspace mount. Must be used together with `workspaceFolder`.

**Example:**
```json
{
  "workspaceMount": "source=${localWorkspaceFolder}/sub-folder,target=/workspace,type=bind",
  "workspaceFolder": "/workspace"
}
```

**Implementation:** Replace our default workspace mount with the specified one.

---

### Priority 3: Lifecycle Commands

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

---

### Priority 4: Port Forwarding

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

**Implementation:**
- For local Docker: Use `--publish` or SSH tunnel
- For remote Docker: Set up SSH port forwarding
- The `"db:5432"` syntax refers to other services in Docker Compose scenarios

---

#### `appPort` (Legacy)
**Type:** `number | string | (number | string)[]`  
**Default:** `[]`

Publishes ports when container runs. Unlike `forwardPorts`, requires application to listen on `0.0.0.0`.

**Implementation:** Add to `ContainerCreateBody.host_config.port_bindings`.

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
- `label` - Display name
- `protocol` - `http` or `https`
- `onAutoForward` - Action when port detected: `notify`, `openBrowser`, `openBrowserOnce`, `openPreview`, `silent`, `ignore`
- `requireLocalPort` - Must use same port number locally
- `elevateIfNeeded` - Auto-elevate for low ports (< 1024)

**Implementation:** Store attributes and apply when setting up port forwarding.

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

---

### Priority 5: Environment Variables

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

**Implementation:** Apply these variables when executing commands via `sandbox enter`.

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

### Priority 7: Docker Compose Support

#### `dockerComposeFile`
**Type:** `string | string[]`

Path(s) to Docker Compose file(s).

**Example:**
```json
{
  "dockerComposeFile": ["docker-compose.yml", "docker-compose.dev.yml"],
  "service": "app",
  "workspaceFolder": "/workspace"
}
```

**Implementation:**
1. Parse and merge compose files
2. Start services using Docker Compose
3. Attach to the specified service
4. Support compose file variable substitution

---

#### `service`
**Type:** `string`  
**Required when using Docker Compose**

The service to connect to in Docker Compose.

---

#### `runServices`
**Type:** `string[]`  
**Default:** All services

Which services to start from the Docker Compose configuration.

**Example:**
```json
{
  "dockerComposeFile": "docker-compose.yml",
  "service": "app",
  "runServices": ["app", "db"]
}
```

---

### Priority 8: Other Properties

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

## Implementation Recommendations

### Phase 1: Security & Debugging
1. `privileged`, `capAdd`, `securityOpt` - Essential for debugging
2. `init` - Good practice for process management
3. Full `runArgs` support

### Phase 2: Developer Experience
1. Lifecycle commands (`postCreateCommand`, etc.)
2. `mounts` for persistent data
3. Port forwarding

### Phase 3: Advanced Features
1. Dev Container Features
2. Docker Compose support
3. `hostRequirements` for cloud deployments

### Phase 4: Compatibility
1. `customizations.sandbox` namespace
2. Full variable substitution
3. `remoteEnv` and environment probing
