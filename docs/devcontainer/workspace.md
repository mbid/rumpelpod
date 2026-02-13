# Workspace Handling: Rumpelpod vs. the Dev Container Specification

This document compares how rumpelpod handles workspace-related
devcontainer.json properties against the official Dev Container CLI
(the reference implementation of the specification).

---

## Architectural Difference: Bind Mount vs. Git Sync

The standard devcontainer CLI bind-mounts the host workspace directory
into the container. The host filesystem and the container filesystem
share the same files in real time -- any change on either side is
immediately visible on the other.

Rumpelpod does not use bind mounts for the workspace. Instead it
clones the repository into the container via an internal git-http
bridge on first creation and syncs changes via `git fetch` on each
`rumpel enter`. Changes made inside the container are pushed back
to the host through a gateway repository and a git
`reference-transaction` hook.

This design decision has several consequences:

1. **No live filesystem sync.** Changes on the host are not visible
   inside the container until the next `rumpel enter` (which runs
   `git fetch`). Changes inside the container are synced back via
   git push triggered by the reference-transaction hook.

2. **Multiple copies of the same repo can run in parallel.** Each
   pod gets its own independent clone. Two pods created from the
   same repo can have different branches checked out and different
   working trees without conflicting with each other.

3. **Remote Docker and Kubernetes.** Because there is no bind mount,
   the Docker engine does not need access to the host filesystem.
   This means rumpelpod can target a remote Docker host over SSH
   or (in the future) a Kubernetes cluster, scenarios where host
   bind mounts are impossible.

4. **Some devcontainer.json assumptions break.** Properties and
   patterns that rely on the host and container sharing a filesystem
   (e.g. `workspaceMount`, bind-mount overlays, watching for host
   file changes) do not apply.

---

## Property Comparison

| Property | Standard CLI | Rumpelpod | Notes |
|---|---|---|---|
| `workspaceFolder` (image/Dockerfile) | Default: `/workspaces/<basename>` of the host folder. Configurable. | Default: `/workspaces/<basename>` of the repo root. Configurable. | **Compatible.** Both default to the same convention. Rumpelpod resolves it in `DevContainer::container_repo_path()` at `src/devcontainer.rs:601`. The standard CLI computes it in `getWorkspaceConfiguration()` at `src/spec-node/utils.ts:405-407`. |
| `workspaceFolder` (Compose) | Default: `/` (the container root). Configurable. | Not applicable -- Docker Compose is unsupported. | Rumpelpod does not support `dockerComposeFile`. The Compose default of `/` is irrelevant. |
| `workspaceMount` | Overrides the auto-generated bind mount. Docker `--mount` syntax. When present (even as empty string), the auto-generated workspace bind mount is suppressed. Only for image/Dockerfile mode. | **Intentionally unsupported.** Emits a warning and is ignored. Listed in `warn_unsupported_fields()` at `src/devcontainer.rs:561`. | Rumpelpod does not bind-mount the workspace at all, so there is no auto-generated mount to override. Supporting `workspaceMount` would contradict the git-based sync architecture. |
| `mounts` (additional) | Additional bind, volume, or tmpfs mounts. Supports bind mounts from the host filesystem. | Volume and tmpfs mounts are supported. **Bind mounts from the host are blocked when targeting a remote Docker host** (the host filesystem is not available on the remote machine). | Partial support. Local Docker bind mounts work; remote Docker bind mounts are rejected at runtime. |

### workspaceFolder: Detailed Comparison

The standard CLI's `workspaceFolder` default depends on the container
type:

- **Image or Dockerfile:** `/workspaces/<basename>` where `<basename>`
  is the host folder name (after git-root resolution and worktree
  handling). See `src/spec-node/utils.ts:375,405-407`.

- **Docker Compose:** `/` (the container root). The Compose service
  defines its own volumes, so the CLI does not generate a workspace
  mount. See `src/spec-node/dockerCompose.ts:116-118`.

Rumpelpod only handles the image/Dockerfile case and defaults to
`/workspaces/<basename>` where `<basename>` is the repository root
directory name (`src/devcontainer.rs:601-612`). This matches the spec
for that scenario.

When `workspaceFolder` is explicitly set in devcontainer.json, both
implementations use the configured value directly. Rumpelpod also
supports variable substitution in the value (`${devcontainerId}`,
`${localWorkspaceFolderBasename}`, etc.) resolved in
`resolve_daemon_vars()` at `src/daemon.rs:168`.

### workspaceMount: Why It Is Unsupported

The standard CLI uses `workspaceMount` to customize or suppress the
auto-generated bind mount of the host workspace. Common use cases:

- Mounting a Docker volume instead of a bind mount for better
  performance on macOS.
- Mounting the workspace as read-only.
- Suppressing the workspace mount entirely (empty string) to manage
  mounts exclusively through `mounts` or Compose volumes.

None of these use cases apply to rumpelpod because:

1. There is no auto-generated bind mount to override.
2. The workspace content arrives via git clone, not via a mount.
3. Supporting `workspaceMount` would require abandoning git-based
   sync for that container, which would break multi-pod isolation
   and remote Docker support.

If a devcontainer.json contains `workspaceMount`, rumpelpod prints
a warning to stderr and ignores the property.

---

## Config File Discovery

### Standard CLI

The standard CLI searches for config files in this order
(`src/spec-configuration/configurationCommonUtils.ts:47-51`):

1. `.devcontainer/devcontainer.json`
2. `.devcontainer.json`

Additionally, the CLI accepts a `--config` flag that specifies an
explicit path to a devcontainer.json file. This enables the
**multi-root config** pattern where multiple configurations live
under `.devcontainer/<subfolder>/devcontainer.json`. The user (or
tool) selects which subfolder config to use via `--config`. The CLI
itself does not automatically enumerate subfolders; it relies on the
caller to specify the config path.

### Rumpelpod

Rumpelpod searches for config files in the same order
(`src/devcontainer.rs:528-546`):

1. `.devcontainer/devcontainer.json`
2. `.devcontainer.json`

### Differences

| Aspect | Standard CLI | Rumpelpod |
|---|---|---|
| `.devcontainer/devcontainer.json` | Supported | Supported |
| `.devcontainer.json` | Supported | Supported |
| `--config <path>` (explicit config) | Supported -- user passes arbitrary path | **Not supported** -- no equivalent flag |
| Multi-root subfolder selection | Delegated to caller via `--config` | Not applicable (no `--config` flag) |

The primary gap is the lack of a `--config` flag or equivalent
mechanism to select an alternate devcontainer.json. This means repos
that use `.devcontainer/subfolder/devcontainer.json` for multiple
configurations cannot choose between them in rumpelpod. Only the
default search path is used.

---

## Implications for devcontainer.json Portability

A devcontainer.json that works with VS Code or the standard CLI may
need adjustments for rumpelpod. The following table summarizes the
portability concerns specific to workspace handling.

| Pattern | Portable? | Workaround |
|---|---|---|
| Default `workspaceFolder` (omitted) | Yes | N/A |
| Explicit `workspaceFolder: "/app"` | Yes | N/A |
| `workspaceMount` to use a Docker volume | No | Remove `workspaceMount`. Rumpelpod uses git sync instead. Volume mounts for caches can go in `mounts`. |
| `workspaceMount: ""` to suppress auto-mount | No | Remove `workspaceMount`. There is no auto-mount to suppress. |
| Host file watchers (e.g. live-reload) | No | Changes sync through git, not the filesystem. File watchers inside the container will see changes after `rumpel enter` syncs, not in real time. |
| Multi-root config (`.devcontainer/foo/devcontainer.json`) | No | Move the desired config to `.devcontainer/devcontainer.json` or `.devcontainer.json`. |
| `postCreateCommand` that expects host files at a bind-mount path | Partially | The files are present (cloned via git), but only tracked files are available. Untracked host files and files in `.gitignore` are not synced. |
| Docker Compose with `workspaceFolder: "/"` | No | Docker Compose is unsupported. Use image or Dockerfile mode instead. |

### Files Not Available via Git Sync

Because the workspace is cloned via git rather than bind-mounted,
the following host files are not present in the container:

- Files in `.gitignore` (e.g. `node_modules/`, `.env`, build
  artifacts)
- Untracked files that have not been committed
- Files outside the repository root
- Symlinks that point outside the repository

Lifecycle commands like `onCreateCommand: "npm install"` work
correctly because they run inside the container after the clone
and regenerate ignored files. But workflows that depend on
pre-existing ignored files from the host (e.g. a pre-populated
`.env` or a pre-built `node_modules/`) will not find them.
