# Devcontainer User Management: Spec vs Rumpelpod

Comparison of the four user management properties defined by the
devcontainer specification against rumpelpod's implementation.

Reference sources:
- Official devcontainer CLI: https://github.com/devcontainers/cli
  (spec-node/singleContainer.ts, spec-node/containerFeatures.ts,
  spec-common/injectHeadless.ts)
- Rumpelpod: src/devcontainer.rs, src/daemon.rs, src/enter.rs


## Summary Table

| Property              | Spec Default                | Spec Behavior                                                          | Rumpelpod Behavior                                                            | Conformance |
|-----------------------|-----------------------------|------------------------------------------------------------------------|-------------------------------------------------------------------------------|-------------|
| containerUser         | image USER (or root)        | Passed as `docker run -u <user>`. Sets the PID-1 user.                 | NOT passed to `docker create`. Container runs as image USER. Used only in fallback chain for exec user. | Partial     |
| remoteUser            | falls back to containerUser | Used for exec/tool sessions. Last-writer-wins from image metadata.     | Combined with containerUser via `user()` helper (remoteUser preferred). Used for all exec and lifecycle commands. | Partial     |
| updateRemoteUserUID   | true (Linux)                | Builds a derived image that changes remoteUser's UID/GID to match the local user. | Parsed and deserialized but never read or acted upon. No UID/GID modification. | Not implemented |
| userEnvProbe          | loginInteractiveShell       | Sources shell init files to capture env vars (PATH etc.). Caches results. | Fully implemented. Probes via `bash <flags> 'env -0'`, diffs against base env. Used for lifecycle commands and enter. | Conformant  |


## Detailed Comparison


### containerUser

**Spec behavior (official CLI):**

The official CLI passes `containerUser` as `-u <user>` to `docker run`,
which sets the PID-1 user inside the container. The resolution order is:
1. Last `containerUser` in image metadata (last-writer-wins across
   features and devcontainer.json).
2. Compose service `user` field (for Docker Compose).
3. The image's USER directive.

This is implemented in `singleContainer.ts`:
```typescript
const containerUserArgs = containerUser ? ['-u', containerUser] : [];
// ...passed into docker run args
```

**Rumpelpod behavior:**

Rumpelpod does NOT pass a user to `docker create`. In `daemon.rs`,
`create_container()` builds a `ContainerCreateBody` that omits the
`user` field entirely:

```rust
let config = ContainerCreateBody {
    image: Some(image.0.clone()),
    hostname: Some(pod_name.0.clone()),
    // ... no user field
    ..Default::default()
};
```

The container's PID-1 process always runs as whatever user the image's
USER directive specifies. The `containerUser` value is only used as a
fallback in the `user()` method:

```rust
pub fn user(&self) -> Option<&str> {
    self.remote_user
        .as_deref()
        .or(self.container_user.as_deref())
}
```

This `user()` result is used for `docker exec` sessions (lifecycle
commands, enter, agent tool execution), not for the container's main
process.

**Gap:** If `containerUser` differs from the image USER, the spec says
PID-1 should run as `containerUser`, but rumpelpod will run PID-1 as
the image USER regardless.


### remoteUser

**Spec behavior (official CLI):**

`remoteUser` is used for tool processes -- terminals, lifecycle
commands after the container starts, exec sessions. It does NOT affect
`docker run -u`. The resolution order is:
1. Last `remoteUser` in image metadata (last-writer-wins).
2. Falls back to `containerUser`.

The official CLI treats `containerUser` and `remoteUser` as distinct:
`containerUser` affects `docker run -u`, while `remoteUser` affects
`docker exec -u` for tool processes.

**Rumpelpod behavior:**

Rumpelpod collapses `containerUser` and `remoteUser` into a single
value via the `user()` method, preferring `remoteUser`. This single
value is used for:

- All `docker exec` calls (lifecycle commands, `rumpel enter`, agent
  tool execution)
- Git operations inside the container
- Mount ownership (`chown` of volume/tmpfs targets)

The `resolve_user()` function then validates this merged value:
```rust
fn resolve_user(docker: &Docker, user: Option<String>, image: &str) -> Result<String> {
    if let Some(user) = user {
        return Ok(user);
    }
    // Falls back to image USER, rejects root
}
```

Rumpelpod also enforces a security policy that the official CLI does
not: it refuses to run pods as root (UID 0). If neither `remoteUser`
nor `containerUser` is set and the image USER is root (or absent),
rumpelpod returns an error.

**Gap:** The distinction between "container process user" and "tool
process user" is lost. In practice this rarely matters because
rumpelpod overrides the container command to `sleep infinity` anyway,
so PID-1 is not application code. The main scenario where this could
matter is if a user sets `containerUser: root` (to run services as
root) with `remoteUser: devuser` (to exec as a normal user). Rumpelpod
would use `devuser` for exec but run the container as the image USER,
ignoring the explicit `containerUser: root`.


### updateRemoteUserUID

**Spec behavior (official CLI):**

When `updateRemoteUserUID` is true (the default on Linux), the official
CLI builds a derived image using `updateUID.Dockerfile` that:
1. Reads the local user's UID/GID via `cliHost.getuid()` / `getgid()`.
2. Modifies the `remoteUser`'s entry in `/etc/passwd` and `/etc/group`
   to match those IDs.
3. Recursively chowns the user's home directory.

This ensures that bind-mounted files owned by the host user (e.g. UID
1000) are also owned by the container user, avoiding permission
mismatches.

The implementation is in `containerFeatures.ts`:
```typescript
'--build-arg', `REMOTE_USER=${remoteUser}`,
'--build-arg', `NEW_UID=${await cliHost.getuid!()}`,
'--build-arg', `NEW_GID=${await cliHost.getgid!()}`,
```

The feature is gated on:
- `updateRemoteUserUIDDefault` not being `'never'`
- `updateRemoteUserUID` being explicitly true, or the default being `'on'`
- The host platform being Linux (or macOS if `updateRemoteUserUIDOnMacOS` is set)

**Rumpelpod behavior:**

The `update_remote_user_uid` field is parsed from `devcontainer.json`
into `Option<bool>` but is never read by any code path. No UID/GID
modification is performed. A codebase search confirms no code references
`update_remote_user_uid` outside of struct definition, serialization,
and variable substitution passthrough.

**Gap:** This is a real gap, but its practical impact depends on the
file synchronization mechanism:

- Rumpelpod uses git-based sync (git HTTP server) rather than bind
  mounts. Files inside the container are owned by whichever user
  performed the `git clone`, which is the resolved exec user. So for
  the primary workspace, UID mismatches do not occur.

- Volume mounts (`mounts` in devcontainer.json) could still have UID
  mismatches. Rumpelpod already runs `chown <user> <mount-targets>`
  after container creation to work around Docker's default root
  ownership of volume mounts, but this only fixes the top-level
  directory, not pre-existing content.

- Named volumes persist across container rebuilds. If the volume was
  first populated by a user with a different UID, subsequent containers
  may see permission errors on those files.


### userEnvProbe

**Spec behavior (official CLI):**

The official CLI probes the user's shell init files to discover
environment variables (especially PATH modifications from tools like
nvm, pyenv, cargo, etc.). The implementation:

1. Determines the shell type from the setting (default:
   `loginInteractiveShell`).
2. Runs the user's shell with appropriate flags (`-lic`, `-lc`, `-ic`,
   or `-c`) to source init files.
3. Captures the environment via `/proc/self/environ` or `printenv`.
4. Caches the result in a session data folder to avoid re-probing.
5. Merges the probed PATH with the container's base PATH.

The probed environment is then used for lifecycle commands and tool
processes. The official CLI has a 10-second timeout and process tree
diagnostics if probing is slow.

**Rumpelpod behavior:**

Rumpelpod implements `userEnvProbe` with equivalent semantics:

1. The `UserEnvProbe` enum maps to the same shell flags:
   - `loginInteractiveShell` -> `-lic` (exec) / `-li` (interactive)
   - `loginShell` -> `-lc` / `-l`
   - `interactiveShell` -> `-ic` / `-i`
   - `none` -> skip probing

2. The `probe_user_env()` function in `daemon.rs`:
   - Checks if bash is available.
   - Gets the base environment via `env -0` (NUL-delimited).
   - Gets the probed environment via `bash <flags> 'env -0'`.
   - Returns only variables that are new or changed (excluding
     `_`, `SHLVL`, `BASH_EXECUTION_STRING`).

3. The probed env is used in three places:
   - Lifecycle commands (passed via `-e` flags on `docker exec`).
   - `rumpel enter` (passed via `-e` flags, interactive shells get
     probe flags directly).
   - Agent tool execution (passed via `-e` flags).

4. `rumpel enter` additionally uses `shell_flags_interactive()` to
   launch the interactive shell with the right flags so that init
   files are sourced directly (e.g. `bash -li`).

**Differences from the official CLI:**
- No caching. Rumpelpod re-probes on every container re-entry. This
  adds latency but ensures the result is always fresh.
- No timeout or process tree diagnostics for slow probes.
- No PATH merging logic. Rumpelpod takes the probed PATH as-is rather
  than merging it with the container's base PATH.
- Only supports bash. The official CLI also handles pwsh and other
  shells.


## Gaps Summary

### 1. containerUser not passed to docker create

**Severity:** Low

Rumpelpod overrides the container command to `sleep infinity`, so the
PID-1 user only affects file ownership of container-level processes.
Since rumpelpod uses git-based sync rather than bind mounts, and all
exec operations use the resolved user, the practical impact is minimal.

The gap would matter if a devcontainer.json specifies `containerUser`
that differs from the image USER, expecting services started by the
entrypoint to run as that user. Since rumpelpod replaces the entrypoint,
this scenario does not apply.

### 2. containerUser and remoteUser conflated

**Severity:** Low

The spec distinguishes between the user running the container process
(`containerUser`) and the user for tool sessions (`remoteUser`).
Rumpelpod merges them into a single "exec user" with `remoteUser`
taking precedence. Since the container command is always `sleep
infinity`, the distinction between "container user" and "remote user"
is academic in rumpelpod's architecture.

### 3. updateRemoteUserUID not implemented

**Severity:** Low-to-Medium

The primary workspace uses git-based sync, so UID mismatches on the
workspace directory do not occur. However:

- Volume mounts with pre-existing content may have permission issues
  if the container user's UID does not match the file owner.
- Users migrating from VS Code devcontainers (which has this enabled
  by default) may encounter unexpected permission errors on volume
  mounts.

If rumpelpod ever adds bind mount support for local Docker hosts,
this gap would become high severity.

### 4. userEnvProbe: no caching

**Severity:** Low

Re-probing on every entry adds a small amount of latency (typically
under 500ms) but ensures results are always current. The official
CLI caches to avoid re-probing on re-attach, which matters more for
VS Code where re-attach is frequent and instantaneous startup is
expected.

### 5. userEnvProbe: no PATH merging

**Severity:** Low

The official CLI merges the probed PATH with the container's base
PATH to avoid losing system paths. Rumpelpod takes the full probed
PATH as a diff against the base, so paths that exist in both the
base and probed environments are not duplicated. This difference
is unlikely to cause issues in practice since the probed shell
already inherits the base PATH.

### 6. userEnvProbe: bash-only

**Severity:** Low

Rumpelpod only probes via bash. The official CLI also supports pwsh.
Most devcontainer images include bash, so this is rarely an issue.
The `probe_user_env()` function already checks for bash availability
and gracefully skips probing if it is not found.
