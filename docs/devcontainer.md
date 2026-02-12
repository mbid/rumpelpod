# devcontainer.json Implementation Status

This document tracks our implementation of the
[Dev Container specification](https://containers.dev/implementors/json_reference/).

Rumpelpod does not bind-mount the host workspace. Instead it uses Git-based
synchronization: the repo is cloned into the container via a git-http bridge
on first creation and synced on each `rumpel enter`.

---

## Implemented and Working

These properties are fully wired up to Docker and/or used at runtime.

### Image / Build

| Property | Notes |
|----------|-------|
| `image` | Container image reference |
| `build.dockerfile` | Dockerfile path relative to devcontainer.json |
| `build.context` | Build context directory (default ".") |
| `build.args` | Docker build arguments (only `${localEnv}` substitution) |
| `build.target` | Multi-stage build target stage |
| `build.cacheFrom` | Cache source images |
| `build.options` | Additional `docker build` CLI flags |
| `dockerfile` (legacy) | Merged into `build.dockerfile` |
| `context` (legacy) | Merged into `build.context` |

### Container Configuration

| Property | Notes |
|----------|-------|
| `workspaceFolder` | Container workspace path; defaults to `/workspaces/<basename>` |
| `containerUser` | User for container operations |
| `remoteUser` | User for dev tools; falls back to `containerUser` |
| `containerEnv` | Environment variables on the container; supports `${localEnv}` |
| `remoteEnv` | Environment injected into `rumpel enter`/`rumpel agent` exec sessions only; supports `${containerEnv}` |
| `runArgs` | Docker CLI arguments; `--network`, `--runtime`, `--device`, `--label`, `--cap-add`, `--security-opt` extracted |
| `privileged` | Passed as `--privileged` to Docker |
| `init` | Passed as `--init` to Docker (tini) |
| `capAdd` | Merged with caps from `runArgs`, passed to Docker |
| `securityOpt` | Merged with opts from `runArgs`, passed to Docker |
| `mounts` | String and object formats; volume and tmpfs supported; bind mounts blocked on remote Docker |
| `forwardPorts` | Ports forwarded from container to host; multi-pod remapping supported |
| `portsAttributes` | Labels and metadata for forwarded ports |

### Lifecycle Commands

| Property | Notes |
|----------|-------|
| `onCreateCommand` | Runs once after first container creation |
| `postCreateCommand` | Runs after onCreateCommand on first creation |
| `postStartCommand` | Runs each time the container starts |
| `postAttachCommand` | Runs each time `rumpel enter` is called |
| `waitFor` | Parsed, but all commands run synchronously before attach anyway (see tasks below) |

All lifecycle commands support string, array, and object (parallel) formats.
Failure in an earlier command prevents later commands from running.

### Variable Substitution

| Variable | Scope |
|----------|-------|
| `${localEnv:VAR}` / `${localEnv:VAR:default}` | All string properties (resolved at config load) |
| `${localWorkspaceFolder}` | All string properties |
| `${localWorkspaceFolderBasename}` | All string properties |
| `${containerWorkspaceFolder}` | Properties resolved after workspace is known |
| `${containerWorkspaceFolderBasename}` | Properties resolved after workspace is known |
| `${devcontainerId}` | Stable SHA-256 hash of (repo_path, pod_name) |
| `${containerEnv:VAR}` | `remoteEnv` only (resolved via `docker exec printenv`) |

### Metadata

| Property | Notes |
|----------|-------|
| `name` | Parsed; not displayed in UI |
| `otherPortsAttributes` | Parsed; not used for anything yet |
| `hostRequirements` | Parsed; not validated or enforced |

---

## Intentionally Unsupported

These emit a warning when detected and are ignored.

| Property | Reason |
|----------|--------|
| `workspaceMount` | Defeats pod isolation; we use Git-based sync |
| `appPort` | Use `forwardPorts`; publishing ports bypasses port management |
| `dockerComposeFile` | Out of scope |
| `service` | Docker Compose specific |
| `runServices` | Docker Compose specific |

---

## Not Yet Implemented

Properties that are deserialized but not wired up to anything.

### High Priority

| Property | Impact |
|----------|--------|
| `features` | Many real-world devcontainers depend on Features for toolchain setup |
| `overrideFeatureInstallOrder` | Companion to `features` |
| `initializeCommand` | Host-side command before container creation; common in devcontainers |
| `updateContentCommand` | Command after content changes (e.g. after git sync) |
| `overrideCommand` | When `false`, container CMD should run instead of `sleep infinity` |

### Medium Priority

| Property | Impact |
|----------|--------|
| `updateRemoteUserUID` | UID/GID sync to avoid permission mismatches |
| `userEnvProbe` | Shell type for environment probing (`loginInteractiveShell` etc.) |

### Low Priority

| Property | Impact |
|----------|--------|
| `shutdownAction` | What to do on disconnect (`none` / `stopContainer`) |
| `customizations` | Parsed but no `rumpelpod` namespace defined |

### Behavioral Gaps

| Behavior | Current State |
|----------|---------------|
| `waitFor` background semantics | All lifecycle commands run synchronously; the spec allows attaching before later commands finish |
| `otherPortsAttributes` | Parsed but not applied as defaults for unconfigured ports |

---

## Implementation Tasks

Each task below is self-contained (1-2 commits) and includes a prompt
suitable for pasting into a coding agent.

---

### Task 1: `initializeCommand` -- host-side command execution

**What:** The `initializeCommand` runs on the *host machine* before the
container is created. It is the only lifecycle command that runs outside
the container. Currently it is deserialized and variable-substituted but
never executed.

**Where:** `src/enter.rs` -- after loading the devcontainer config, before
sending the pod launch request to the daemon.

**Prompt:**
```
Implement initializeCommand support for devcontainer.json in rumpelpod.

Context: initializeCommand is a lifecycle command that runs on the HOST
machine (not in the container) before the container is created. It is
deserialized into DevContainer.initialize_command (src/devcontainer.rs:157)
and gets variable substitution, but is never actually executed.

Requirements:
1. In src/enter.rs, after loading/resolving the devcontainer config but
   BEFORE sending the pod launch to the daemon, execute initializeCommand
   on the host.
2. The command runs from the repo root directory.
3. Support all three formats: string (via shell), array (direct exec),
   and object (parallel -- each key runs concurrently, all must succeed).
4. If initializeCommand fails, abort with a clear error. Do not create
   the container.
5. Only ${localEnv} and ${localWorkspaceFolder*} variables are available
   (not container variables, since the container does not exist yet).
6. initializeCommand should run on EVERY rumpel enter, not just first
   creation. This matches the spec: "A command to run locally before
   anything else. Runs on every start."

Add integration tests in tests/cli/devcontainer/lifecycle_commands.rs:
- initialize_command_runs_before_container: Set initializeCommand to
  create a file on the host; verify it exists before container runs.
- initialize_command_failure_aborts: Set initializeCommand to `exit 1`;
  verify the pod is never created.
- initialize_command_formats: Test string, array, and object formats.

Look at how postStartCommand is executed in src/daemon.rs for reference
on running lifecycle commands, but note that initializeCommand runs on
the host (std::process::Command), not via docker exec.

Run ./pipeline after committing.
```

---

### Task 2: `updateContentCommand` -- run after content sync

**What:** The `updateContentCommand` runs inside the container after
source content has been updated (e.g. after git sync). It sits between
`onCreateCommand` and `postCreateCommand` in the lifecycle. Currently
deserialized but never executed.

**Where:** `src/daemon.rs` -- in the pod creation/re-entry flow, after
git sync completes but before `postCreateCommand`.

**Prompt:**
```
Implement updateContentCommand support for devcontainer.json in rumpelpod.

Context: updateContentCommand runs inside the container when content
has been updated. Per the spec, the lifecycle order is:
  initializeCommand -> onCreateCommand -> updateContentCommand ->
  postCreateCommand -> postStartCommand -> postAttachCommand

The field is deserialized at src/devcontainer.rs:165 and gets variable
substitution, but is never executed. onCreateCommand is executed at
src/daemon.rs (search for on_create_command). postCreateCommand runs
right after it.

Requirements:
1. Execute updateContentCommand after onCreateCommand but before
   postCreateCommand during first pod creation.
2. Also execute updateContentCommand on subsequent rumpel enter calls
   AFTER git sync completes (this is the main use case -- re-running
   "npm install" etc. after new commits are synced).
3. On first creation: onCreateCommand -> updateContentCommand ->
   postCreateCommand (all three).
4. On re-entry: updateContentCommand only (onCreateCommand and
   postCreateCommand already ran).
5. If updateContentCommand fails, propagate the error (stop later
   commands from running).
6. Use the same run_lifecycle_command() helper used by the other
   lifecycle commands.

Add integration tests in tests/cli/devcontainer/lifecycle_commands.rs:
- update_content_command_runs_after_on_create: On first creation, verify
  updateContentCommand runs after onCreateCommand (use marker files with
  timestamps or sequence numbers).
- update_content_command_runs_on_reentry: On second rumpel enter, verify
  updateContentCommand runs again (write a counter to a file).
- update_content_command_failure_stops_chain: If it fails, verify
  postCreateCommand does not run.

Run ./pipeline after committing.
```

---

### Task 3: `overrideCommand` -- respect container CMD

**What:** When `overrideCommand` is `false`, the container should use
its own CMD/ENTRYPOINT instead of `sleep infinity`. The default is `true`
for image/Dockerfile scenarios. Currently we always use `sleep infinity`
(see `src/daemon.rs` container creation, the `cmd` field).

**Where:** `src/daemon.rs` -- container creation logic.

**Prompt:**
```
Implement overrideCommand support for devcontainer.json in rumpelpod.

Context: The overrideCommand property (default: true for image/Dockerfile)
controls whether the container's CMD is overridden with a keep-alive
command. Currently we always set cmd to ["sleep", "infinity"] in
src/daemon.rs during container creation (search for "sleep" in that file).
The property is parsed at src/devcontainer.rs:64 but never read.

Requirements:
1. When overrideCommand is true (or absent, since the default is true),
   keep current behavior: cmd = ["sleep", "infinity"].
2. When overrideCommand is false, do NOT set cmd at all -- let Docker
   use the image's CMD/ENTRYPOINT.
3. The container must still stay running for lifecycle commands and
   rumpel enter to work. If the image CMD exits, the container stops
   and we cannot exec into it. This is expected -- it is the user's
   responsibility to ensure their CMD keeps running (e.g. a server).
4. Lifecycle commands (postStartCommand etc.) still run via docker exec
   after the container starts. They must wait for the container to be
   in "running" state.

Add integration tests in tests/cli/devcontainer/runtime_options.rs:
- override_command_false: Set overrideCommand to false with an image
  whose CMD runs "sleep infinity" (so the container stays alive). Verify
  the container is running and rumpel enter works. Check that PID 1 is
  NOT "sleep infinity" started by us (inspect the container or check
  /proc/1/cmdline).
- override_command_default_true: Without setting overrideCommand, verify
  PID 1 is "sleep".

Run ./pipeline after committing.
```

---

### Task 4: Dev Container Features installation

**What:** The `features` property installs reusable toolchain components
from OCI registries (e.g. `ghcr.io/devcontainers/features/node:1`).
This is the biggest missing feature. Many real-world devcontainers depend
on Features for language runtimes, tools, etc.

This task covers the core feature installation flow. Advanced features
like `overrideFeatureInstallOrder` and feature options can follow later.

**Where:** `src/image.rs` (image building) and possibly a new
`src/features.rs` module.

**Prompt:**
```
Implement basic Dev Container Features support for rumpelpod.

Context: Dev Container Features are OCI artifacts that contain install
scripts. When a devcontainer.json specifies features like:
  "features": {
    "ghcr.io/devcontainers/features/node:1": { "version": "20" }
  }
the implementation must fetch the feature tarball from the OCI registry,
extract it, and run its install.sh during image build.

The features field is parsed at src/devcontainer.rs:92 as
HashMap<String, serde_json::Value> but never used. Image building happens
in src/image.rs.

Read the Features spec: https://containers.dev/implementors/features/

Requirements:
1. Create src/features.rs for feature resolution and installation logic.
2. Feature resolution: Parse the feature ID (e.g.
   "ghcr.io/devcontainers/features/node:1") into registry/repo/tag.
   Fetch the OCI manifest and download the tarball layer.
3. Feature installation: For each feature, generate a Dockerfile snippet
   that:
   a. COPYs the feature's files into the image
   b. Sets environment variables from the feature's devcontainer-feature.json
   c. Runs install.sh with the user's options as environment variables
      (e.g. VERSION=20)
4. Integration with image building: When features are present, generate
   a derived Dockerfile that starts FROM the base image (or the user's
   Dockerfile build result) and appends feature installation layers.
   Build this derived image instead.
5. Feature options are passed as environment variables to install.sh
   (uppercased key names, e.g. "version" -> "VERSION").
6. Respect overrideFeatureInstallOrder if set; otherwise install in the
   order listed in devcontainer.json.
7. Cache: The derived image hash should incorporate the feature IDs,
   versions, and options so that changing features triggers a rebuild.

Add integration tests in a new tests/cli/devcontainer/features.rs:
- feature_node_install: Use the official node feature to install Node.js.
  Verify `node --version` works inside the container.
- feature_with_options: Install a feature with specific options (e.g.
  node version 20). Verify the correct version is installed.
- feature_cached_on_rebuild: Second pod creation with same features
  reuses the cached image.

This is a large task. Focus on getting the basic flow working with
a single well-known feature (ghcr.io/devcontainers/features/node).
Edge cases (feature dependencies via installsAfter, containerEnv
contributions from features, etc.) can be follow-up work.

Run ./pipeline after committing.
```

---

### Task 5: `updateRemoteUserUID` -- UID/GID sync

**What:** When `updateRemoteUserUID` is `true` (the default on Linux),
the container user's UID/GID should be updated to match the host user.
This prevents permission mismatches with mounted volumes and Git-synced
files. Currently parsed at `src/devcontainer.rs:56` but never used.

**Where:** `src/daemon.rs` -- after container creation, before lifecycle
commands.

**Prompt:**
```
Implement updateRemoteUserUID support for devcontainer.json in rumpelpod.

Context: The updateRemoteUserUID property (default: true on Linux)
updates the remoteUser's UID/GID inside the container to match the host
user. This prevents "permission denied" errors when the container user
and host user have different UIDs. The property is parsed at
src/devcontainer.rs:56 but never read.

Requirements:
1. Detect the host user's UID and GID (std::process::Command "id -u"
   and "id -g", or libc getuid/getgid).
2. After the container starts but before running lifecycle commands,
   if updateRemoteUserUID is true (or unset, since default is true):
   a. Get the remoteUser (or containerUser) name from devcontainer config.
   b. Run `id -u <user>` in the container to get the current UID.
   c. If the UIDs differ, run usermod/groupmod to update them:
      - `groupmod -g <host_gid> <group>`
      - `usermod -u <host_uid> <user>`
      - `chown -R <host_uid>:<host_gid> /home/<user>` (fix home dir)
   d. Also fix ownership of the workspace folder.
3. When updateRemoteUserUID is explicitly false, skip all of this.
4. Only run on Linux hosts (check std::env::consts::OS).
5. If usermod/groupmod are not available in the container, log a warning
   and continue (some minimal images lack these tools).

Add integration tests in tests/cli/devcontainer/runtime_options.rs:
- update_remote_user_uid_matches_host: Create a container with a user
  whose UID differs from the host. Verify that after entry, the user's
  UID inside the container matches the host UID.
- update_remote_user_uid_disabled: Set updateRemoteUserUID to false.
  Verify the container user's UID is unchanged.

Run ./pipeline after committing.
```

---

### Task 6: `userEnvProbe` -- shell environment probing

**What:** The `userEnvProbe` property controls which shell initialization
files are sourced when probing for user environment variables. This
affects how `remoteEnv` variables like `PATH` are resolved. Currently
parsed but not used.

**Where:** `src/enter.rs` or `src/daemon.rs` -- wherever `remoteEnv` is
resolved and exec sessions are set up.

**Prompt:**
```
Implement userEnvProbe support for devcontainer.json in rumpelpod.

Context: userEnvProbe (default: loginInteractiveShell) controls which
shell initialization files are sourced when running commands in the
container. This is important because many tools add themselves to PATH
via .bashrc or .profile. The property is parsed at
src/devcontainer.rs:60 as an enum (None, InteractiveShell, LoginShell,
LoginInteractiveShell) but never read.

Currently, rumpel enter runs docker exec with a plain command. This
means .bashrc/.profile are not sourced, so tools installed by Features
or lifecycle commands that modify PATH via shell init files are not
found.

Requirements:
1. When executing commands via rumpel enter, wrap them according to
   userEnvProbe:
   - none: Execute directly (current behavior)
   - interactiveShell: bash -ic '<command>'
   - loginShell: bash -lc '<command>'
   - loginInteractiveShell (default): bash -lic '<command>'
2. Apply the same wrapping to lifecycle commands that run inside the
   container (postStartCommand, postAttachCommand, etc.).
3. If bash is not available, fall back to sh with appropriate flags.
4. The probed environment should be captured and merged with remoteEnv.

Add integration tests in tests/cli/devcontainer/remote_env.rs:
- user_env_probe_login_shell: Add a PATH entry in the container user's
  .profile. With userEnvProbe: loginShell, verify the PATH entry is
  visible in rumpel enter.
- user_env_probe_none: Same setup but with userEnvProbe: none. Verify
  the PATH entry is NOT visible.

Run ./pipeline after committing.
```

---

### Task 7: `shutdownAction` -- cleanup on disconnect

**What:** The `shutdownAction` property controls what happens when the
last tool disconnects from the container. Default is `stopContainer`.
Currently parsed but not used -- containers are always left running.

**Where:** `src/daemon.rs` -- pod lifecycle management.

**Prompt:**
```
Implement shutdownAction support for devcontainer.json in rumpelpod.

Context: shutdownAction (default: stopContainer for image/Dockerfile)
controls what happens when the dev container tool disconnects. Values
are "none" (leave running) and "stopContainer" (stop it). The property
is parsed at src/devcontainer.rs:68 but never read.

Currently rumpelpod always leaves containers running. The rumpel rm
command removes them explicitly. shutdownAction:stopContainer would
auto-stop the container when the last rumpel enter session exits.

Requirements:
1. Track active sessions per pod in the daemon (increment on enter,
   decrement on exit/disconnect).
2. When the last session for a pod exits and shutdownAction is
   stopContainer (or unset, since that is the default): stop the
   container via docker stop.
3. When shutdownAction is none: leave the container running.
4. The container should be stopped, not removed. A subsequent
   rumpel enter should restart it.
5. Handle edge cases: daemon restart (lose session count -- default
   to leaving containers as-is).

Add integration tests in tests/cli/devcontainer/lifecycle_commands.rs:
- shutdown_action_stop: Set shutdownAction to stopContainer. After
  rumpel enter exits, verify the container is stopped (docker inspect
  shows State.Running = false).
- shutdown_action_none: Set shutdownAction to none. After rumpel enter
  exits, verify the container is still running.

Run ./pipeline after committing.
```

---

### Task 8: `waitFor` -- background lifecycle commands

**What:** The `waitFor` property controls which lifecycle command must
complete before the user can attach. Commands after the `waitFor` target
should run in the background. Currently all commands run synchronously,
which happens to satisfy the test but does not match the spec for cases
where you want early attach.

**Where:** `src/daemon.rs` -- lifecycle command execution during pod
creation and re-entry.

**Prompt:**
```
Implement proper waitFor semantics for devcontainer.json in rumpelpod.

Context: The waitFor property (default: updateContentCommand) controls
which lifecycle command to wait for before allowing the user to connect.
Commands after the waitFor target run in the background.

Currently all lifecycle commands run synchronously before the enter
completes. This means the user always waits for everything. The spec
says that if waitFor is e.g. onCreateCommand, then postCreateCommand
and later should run in the background while the user is already
attached.

The lifecycle order is:
  initializeCommand -> onCreateCommand -> updateContentCommand ->
  postCreateCommand -> postStartCommand -> postAttachCommand

waitFor is parsed at src/devcontainer.rs:181.

Requirements:
1. Lifecycle commands up to and including the waitFor target run
   synchronously (block the enter).
2. Commands after the waitFor target are spawned in the background.
   Their output should still be logged (to daemon logs or stderr).
3. If a background lifecycle command fails, log the error but do not
   kill the user's session.
4. Default waitFor is updateContentCommand. Since we do not yet
   implement updateContentCommand, the effective default blocks until
   onCreateCommand (or postCreateCommand if updateContentCommand is
   absent).
5. Handle the edge case where waitFor references a command that is
   not set -- wait for the next earlier command that exists.

Add integration tests in tests/cli/devcontainer/lifecycle_commands.rs:
- wait_for_on_create_attaches_early: Set waitFor to onCreateCommand
  and postCreateCommand to "sleep 10 && echo done > /tmp/marker".
  Verify that rumpel enter returns quickly (before postCreateCommand
  finishes). Then wait and verify the marker file eventually appears.
- wait_for_default_waits_for_all: Without waitFor, verify all
  commands complete before enter returns (current behavior, since
  updateContentCommand is not set).

Run ./pipeline after committing.
```

---

### Task 9: `hostRequirements` -- validate host resources

**What:** The `hostRequirements` property specifies minimum CPU, memory,
storage, and GPU requirements. Currently parsed but not validated.

**Where:** `src/daemon.rs` or `src/enter.rs` -- before creating the
container.

**Prompt:**
```
Implement hostRequirements validation for devcontainer.json in rumpelpod.

Context: hostRequirements specifies minimum host resources. It is parsed
at src/devcontainer.rs:188 (cpus, memory, storage, gpu fields) but never
checked. For a cloud-hosted agent runner, this is useful for selecting
appropriate instance types or warning when resources are insufficient.

Requirements:
1. Before creating a container, check hostRequirements against the
   Docker host's actual resources.
2. For local Docker: use sysinfo or /proc to check CPU count and
   memory. For storage, check available disk space on the Docker root.
3. For remote Docker: query the remote host via docker info or SSH.
4. Memory/storage strings use suffixes: "tb", "gb", "mb", "kb"
   (case-insensitive). Parse these into bytes for comparison.
5. If requirements are not met, print a warning but still proceed
   (do not hard-fail -- the user may know better).
6. GPU requirements: if gpu is true or a detailed object, check for
   nvidia-smi or equivalent. If not available, warn.

Add integration tests in tests/cli/devcontainer/runtime_options.rs:
- host_requirements_met: Set hostRequirements to values below the test
  host's actual resources (e.g. cpus: 1, memory: "128mb"). Verify no
  warning is printed and the pod starts normally.
- host_requirements_not_met: Set hostRequirements to absurd values
  (e.g. cpus: 9999, memory: "999tb"). Verify a warning is printed on
  stderr but the pod still starts.

Run ./pipeline after committing.
```

---

### Task 10: `otherPortsAttributes` -- default port attributes

**What:** The `otherPortsAttributes` property provides default attributes
(label, protocol, onAutoForward) for ports not explicitly listed in
`portsAttributes`. Currently parsed but not applied.

**Where:** `src/daemon.rs` -- wherever port forwarding attributes are
read.

**Prompt:**
```
Implement otherPortsAttributes support for devcontainer.json in rumpelpod.

Context: otherPortsAttributes provides default attributes for forwarded
ports that are not explicitly configured in portsAttributes. For example:
  "portsAttributes": { "3000": { "label": "App" } },
  "otherPortsAttributes": { "onAutoForward": "silent" }
means port 3000 gets label "App", and all other ports get
onAutoForward: silent.

The property is parsed at src/devcontainer.rs:36 but never read in the
daemon. Search src/daemon.rs for how portsAttributes is used (look for
ports_attributes) and apply otherPortsAttributes as the fallback.

Requirements:
1. When looking up attributes for a forwarded port, first check
   portsAttributes[port]. If not found, use otherPortsAttributes.
2. Apply this in the rumpel ports command output (labels) and in
   any auto-forwarding behavior.

Add integration test in tests/cli/devcontainer/ports.rs:
- other_ports_attributes_label: Set otherPortsAttributes with a label.
  Forward a port not in portsAttributes. Verify `rumpel ports` shows
  the label from otherPortsAttributes.

Run ./pipeline after committing.
```

---

## Testing

Tests live in `tests/cli/devcontainer/` with one file per feature group:

| File | Coverage |
|------|----------|
| `env.rs` | `containerEnv`, `${localEnv}` substitution |
| `image.rs` | `build.*` options, image caching, `rumpel image build/fetch` |
| `variables.rs` | All variable substitution patterns |
| `unsupported.rs` | Warnings for unsupported properties |
| `runtime_options.rs` | `privileged`, `init`, `capAdd`, `securityOpt`, `runArgs` |
| `lifecycle_commands.rs` | `onCreateCommand`, `postCreateCommand`, `postStartCommand`, `postAttachCommand`, `waitFor`, command formats, failure propagation |
| `ports.rs` | `forwardPorts`, `portsAttributes`, multi-pod remapping, remote SSH |
| `remote_env.rs` | `remoteEnv`, `${containerEnv}`, agent visibility |
| `mounts.rs` | Volume, tmpfs, string format, persistence, bind block on remote |
| `workspace.rs` | `workspaceFolder` defaults, custom paths, repo initialization |
| `malformed_checkout.rs` | Git state recovery (detached HEAD, dirty index, merge/rebase) |

Unit tests for variable substitution and mount parsing are in
`src/devcontainer.rs` (the `#[cfg(test)] mod tests` block).
