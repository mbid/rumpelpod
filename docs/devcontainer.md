# devcontainer.json: Rumpelpod vs the Spec

Comparison of rumpelpod's devcontainer.json implementation against the
[official devcontainer CLI](https://github.com/devcontainers/cli) (the
reference implementation of the
[Dev Container specification](https://containers.dev/implementors/json_reference/)).

Detailed per-feature comparisons live in `docs/devcontainer/`.


## Bugs

Confirmed incorrect behaviors that should be fixed.

### `dockerFile` (capital F) legacy property silently ignored

The official spec uses `"dockerFile"` (capital F) as the legacy top-level
property name for specifying a Dockerfile. Rumpelpod's struct uses
`#[serde(rename_all = "camelCase")]` on a field named `dockerfile`, which
produces the JSON key `"dockerfile"` (all lowercase). A devcontainer.json
with `"dockerFile": "Dockerfile"` is silently ignored -- the field does not
deserialize. This affects any devcontainer.json written for VS Code or the
official CLI that uses the legacy property.

Fix: add `#[serde(alias = "dockerFile")]` to the field.

See: `docs/devcontainer/image_and_build.md`

### `remoteEnv` not passed to lifecycle commands

The official CLI merges `remoteEnv` with the probed shell environment and
passes the result to all lifecycle commands (onCreateCommand through
postAttachCommand). Rumpelpod only passes the probed environment
(`probe_user_env`) to lifecycle commands. `remoteEnv` is only injected
during `rumpel enter` and `rumpel agent`.

A `postCreateCommand` that depends on a `remoteEnv` variable will fail or
behave differently than in the official CLI.

See: `docs/devcontainer/environment.md`

### `remoteEnv` null values not supported

The spec defines `remoteEnv` as `Record<string, string | null>`. Setting a
value to `null` unsets the variable. Rumpelpod types `remoteEnv` as
`HashMap<String, String>` -- a JSON `null` value will cause a parse error
or be silently dropped.

Fix: change type to `HashMap<String, Option<String>>` and exclude null
entries from the environment passed to `docker exec`.

See: `docs/devcontainer/environment.md`

### `${env:VAR}` alias not supported

The official CLI treats `${env:VAR}` as an alias for `${localEnv:VAR}`.
Rumpelpod's `resolve_variable` only handles the `localEnv:` prefix. The
bare `env:` prefix falls through to the default match arm and leaves the
variable as unresolved literal text. The spec does not document this alias,
but devcontainer.json files written for VS Code commonly use it.

Fix: add `"env"` as a case alongside `"localEnv"` in `resolve_variable`.

See: `docs/devcontainer/variable_substitution.md`,
`docs/devcontainer/environment.md`

### Default value parsing divergence

For `${localEnv:UNSET:default:extra}`, the official CLI uses `"default"` as
the fallback (splits on `:`, takes segment 1). Rumpelpod uses
`"default:extra"` (splits once on `:`, takes the entire remainder). Default
values containing colons are rare, but the behavior differs from the
reference implementation.

See: `docs/devcontainer/variable_substitution.md`


## Gaps

Things we could implement but don't.

### `containerUser` not passed to docker create

The official CLI passes `containerUser` as `-u <user>` to `docker run`,
setting the PID-1 user. Rumpelpod omits the `user` field from
`ContainerCreateBody` entirely -- PID-1 always runs as the image's USER
directive. The `containerUser` value is only used as a fallback in the
`user()` method for `docker exec` sessions.

Severity: low. Rumpelpod overrides CMD to `sleep infinity`, so PID-1 is not
application code. The gap would matter if someone sets `containerUser` to a
different user than the image USER expecting services in the entrypoint to
run as that user -- but rumpelpod replaces the entrypoint.

See: `docs/devcontainer/user_management.md`

### `updateRemoteUserUID` parsed but not implemented

When true (default on Linux), the official CLI builds a derived image that
changes the remote user's UID/GID to match the local user. Rumpelpod parses
the field but never reads it. No UID/GID modification is performed.

Severity: low. The primary workspace uses git sync, so UID mismatches on
workspace files do not occur. Volume mounts with pre-existing content could
still have permission issues.

See: `docs/devcontainer/user_management.md`

### `hostRequirements.gpu` not enforced

The official CLI checks for Docker GPU support and adds `--gpus all` when
`hostRequirements.gpu` is true or required. Rumpelpod parses the
`hostRequirements` struct but never reads it -- no GPU detection, no
`--gpus all` injection.

A devcontainer.json with `"hostRequirements": { "gpu": true }` silently
gets no GPU access in rumpelpod.

See: `docs/devcontainer/runtime.md`

### Image metadata merging not implemented

The official CLI reads a `devcontainer.metadata` label from Docker images
and merges it with devcontainer.json. This allows base images (e.g.
Microsoft's devcontainer images) to ship default settings like `remoteUser`,
`containerEnv`, lifecycle commands, etc. Rumpelpod does not read this label.

For image-based devcontainers, only properties explicitly in
devcontainer.json take effect. Pre-built images with embedded configuration
will not have their settings applied.

See: `docs/devcontainer/image_and_build.md`

### `runArgs` flags silently dropped

The official CLI passes `runArgs` verbatim as raw `docker run` CLI
arguments. Rumpelpod uses the bollard API and can only map recognized flags
to bollard struct fields. Recognized: `--network`, `--runtime`, `--device`,
`--label`, `--cap-add`, `--security-opt`, `--privileged`, `--init`.
Everything else is silently dropped, including `-u`, `-v`, `-p`, `-e`,
`--gpus`, `--memory`, `--cpus`, `--shm-size`, `--pid`, `--ipc`, `--dns`,
`--add-host`, `--ulimit`, `--restart`.

This is an inherent limitation of using the bollard API. Adding support
requires explicitly mapping each flag.

See: `docs/devcontainer/runtime.md`

### No `--config` flag for multi-root configs

The official CLI accepts `--config <path>` to select an alternate
devcontainer.json. Rumpelpod only searches the default paths
(`.devcontainer/devcontainer.json`, `.devcontainer.json`). Repos using
`.devcontainer/<subfolder>/devcontainer.json` for multiple configs cannot
choose between them.

See: `docs/devcontainer/workspace.md`

### `image` property not substituted

The CLI substitutes all string properties recursively, including `image`.
Rumpelpod does not apply variable substitution to `image`. A
devcontainer.json with `"image": "${localEnv:REGISTRY}/myimage"` would work
in the CLI but not in rumpelpod.

See: `docs/devcontainer/variable_substitution.md`

### Default build context differs

When `build.context` is omitted, the CLI defaults to the Dockerfile's
parent directory. Rumpelpod defaults to `"."` (the devcontainer.json
directory). Results differ only when the Dockerfile is outside the
devcontainer.json directory and context is not explicitly set.

See: `docs/devcontainer/image_and_build.md`

### Port range keys in `portsAttributes` not supported

The spec allows range patterns like `"40000-55000"` as keys in
`portsAttributes`. Rumpelpod uses `HashMap::get()` with the port number as
a string, requiring exact match. The official CLI also does not implement
range matching (defers to VS Code), so this is a gap in both.

See: `docs/devcontainer/port_forwarding.md`

### `external` property on mount objects not supported

The official CLI supports `external: true` on mount objects to indicate
volumes should not be managed by the tool. Rumpelpod's `MountObject` does
not have this field. Low impact since rumpelpod does not manage volume
lifecycle.

See: `docs/devcontainer/mounts.md`

### `userEnvProbe` is bash-only with no caching

Rumpelpod only probes via bash (the CLI also supports pwsh). Rumpelpod
re-probes on every entry (the CLI caches results). Neither is likely to
cause issues in practice.

See: `docs/devcontainer/user_management.md`


## Architectural Limitations

Things rumpelpod inherently cannot or should not support due to its design
(git-based sync, multi-pod, remote Docker, bollard API).

### `workspaceMount`

Rumpelpod uses git-based sync instead of bind-mounting the host workspace.
There is no auto-generated bind mount to override, so `workspaceMount` is
meaningless. Parsed, warned, ignored.

### `initializeCommand`

Runs on the host machine before container creation. Does not generalize to
remote Docker or Kubernetes, where the "host" concept does not apply.
Parsed, warned, ignored.

### Bind mounts on remote Docker

Bind mount source paths reference the host filesystem. When Docker runs on
a remote machine, the host filesystem is not available. Rumpelpod blocks
bind mounts on remote Docker hosts with a clear error message.

### `appPort`

Bypasses rumpelpod's port management (SQLite tracking, multi-pod remapping,
SSH tunnel forwarding). Users should use `forwardPorts` instead.
Parsed, warned, ignored.

### Docker Compose (`dockerComposeFile`, `service`, `runServices`)

Rumpelpod operates on single containers. Docker Compose orchestration is
out of scope. Parsed, warned, ignored.

### Gitignored/untracked files not available in container

Because the workspace is cloned via git (not bind-mounted), files in
`.gitignore`, untracked files, and files outside the repository root are not
present in the container. Lifecycle commands like `npm install` work because
they regenerate these files, but workflows depending on pre-existing host
files (e.g. a pre-populated `.env`) will not find them.


## Intentional Deviations

Behaviors that deliberately differ from the spec.

### `shutdownAction` not implemented

Containers always stay running between sessions. Cleanup is explicit via
`rumpel rm`. The official CLI defaults to stopping containers on disconnect.

### `updateContentCommand` runs on every entry

The official CLI runs `updateContentCommand` only when content changes
(based on container creation timestamps). Rumpelpod runs it on every
`rumpel enter` because git sync may have pulled new commits. This is more
correct for the git-sync model but slower for expensive commands.

### `overrideCommand=false` runs image CMD directly

The official CLI wraps the image CMD in a sleep-loop entrypoint. Rumpelpod
either sets CMD to `sleep infinity` (true) or omits CMD entirely (false),
letting the image CMD/ENTRYPOINT run unmodified. If the image CMD exits,
the container stops (unlike the CLI which keeps it alive).

### Features not supported

Dev Container Features (`features`, `overrideFeatureInstallOrder`) are
intentionally unsupported. Use a Dockerfile instead.

### `devcontainerId` format differs

The CLI produces a 52-character base-32 hash; rumpelpod produces a
64-character hex hash. Both use SHA-256 but with different inputs (CLI uses
container labels; rumpelpod uses repo path + pod name). The IDs are only
used within each tool's own infrastructure, so cross-tool compatibility is
not needed.


## Stale Documentation (fixed in this review)

- `overrideCommand` was listed as "Not Yet Implemented" but is implemented
  in `daemon.rs` at the container creation step.
- `otherPortsAttributes` was described as "parsed but not used" but is used
  as a label fallback in `setup_port_forwarding`.
