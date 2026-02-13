# Devcontainer Environment Variable Handling: Spec vs Rumpelpod

Comparison of the official devcontainer CLI (reference implementation) and
rumpelpod's handling of environment-related properties: `containerEnv`,
`remoteEnv`, the variable substitution system, and `userEnvProbe`.

## Summary

Both implementations support `containerEnv`, `remoteEnv`, and variable
substitution, but differ in several details:

- **containerEnv** is handled similarly: both pass variables via Docker's
  environment mechanism at container creation time.
- **remoteEnv** diverges: the official CLI passes it to lifecycle commands,
  while rumpelpod only provides probed env (from `userEnvProbe`) to lifecycle
  commands -- `remoteEnv` is only injected during `rumpel enter` and
  `rumpel agent`.
- **Null values** in `remoteEnv` (to unset variables) are supported by the
  spec but not by rumpelpod.
- **`${env:VAR}`** as an alias for `${localEnv:VAR}` is supported by the
  official CLI but not by rumpelpod.
- **Two-phase substitution** is implemented in both, but rumpelpod uses a
  different architecture (daemon-side second pass vs. container inspection
  in the official CLI).

## containerEnv

### Official CLI behavior

`containerEnv` values are passed as `-e KEY=VALUE` arguments to `docker run`.
They become part of the container's environment, visible to all processes
including the ENTRYPOINT, CMD, and any `docker exec` session.

Variable substitution is applied before passing values to Docker.
`containerEnv` supports `${localEnv:VAR}`, `${localWorkspaceFolder}`,
`${containerWorkspaceFolder}`, and `${devcontainerId}`.

### Rumpelpod behavior

`containerEnv` is read from `devcontainer.json` and passed to the bollard
Docker API's `ContainerCreateBody.env` field as `KEY=VALUE` strings. This is
functionally equivalent to the official CLI's `-e` flags on `docker run`.

Variable substitution is applied in two phases:
1. Client side (`enter.rs:load_and_resolve`): resolves `${localEnv:VAR}`.
2. Daemon side (`daemon.rs:resolve_daemon_vars`): resolves
   `${containerWorkspaceFolder}`, `${containerWorkspaceFolderBasename}`,
   `${localWorkspaceFolder}`, `${localWorkspaceFolderBasename}`, and
   `${devcontainerId}`.

**Verdict**: Functionally equivalent. Both apply `containerEnv` at container
creation time, making variables available to all processes.

## remoteEnv

### Official CLI behavior

`remoteEnv` is merged with the probed user environment (`userEnvProbe`) and
passed to:
- All lifecycle commands (onCreateCommand through postAttachCommand)
- Tool/terminal sessions (VS Code terminals, exec sessions)

The merge order is: probed shell env, then CLI-level `remoteEnv` overrides,
then devcontainer.json `remoteEnv`. Later values win.

The type is `Record<string, string | null>`. A null value means "unset this
variable" -- it removes the variable from the environment even if it was set
by shell init files or `containerEnv`.

`remoteEnv` supports `${containerEnv:VAR}` substitution (resolved after the
container is running) in addition to all other variable types.

### Rumpelpod behavior

`remoteEnv` is used in two different code paths:

1. **`rumpel enter`** (`enter.rs`): Resolves `${containerEnv:VAR}` via
   `docker exec printenv`, merges with probed env, and passes all variables
   as `-e KEY=VALUE` flags to `docker exec`.

2. **`rumpel agent`** (`agent/mod.rs`): Resolves only `${localEnv:VAR}`
   eagerly. The resolved `remoteEnv` HashMap is then passed to each agent
   implementation, which includes it in `docker exec` calls for bash, edit,
   and write operations.

3. **Lifecycle commands** (`daemon.rs`): Only the probed env
   (`probe_user_env`) is passed to lifecycle commands. `remoteEnv` is NOT
   included. The daemon receives the full `DevContainer` struct but only
   uses `probed_env` when constructing the env for `run_lifecycle_command`.

**Verdict**: Partial gap. Lifecycle commands do not receive `remoteEnv`,
diverging from the spec. The `rumpel enter` and `rumpel agent` paths
correctly apply `remoteEnv` to exec sessions.

## remoteEnv Null Values (Unsetting Variables)

### Official CLI behavior

The spec defines `remoteEnv` as `Record<string, string | null>`. Setting a
value to `null` unsets the variable:

```json
{
  "remoteEnv": {
    "UNWANTED_VAR": null
  }
}
```

This removes `UNWANTED_VAR` from the environment, even if it was set by
`containerEnv` or shell init files.

### Rumpelpod behavior

`remoteEnv` is typed as `Option<HashMap<String, String>>` in
`devcontainer.rs`. The value type is `String`, not `Option<String>`.
A JSON `null` value cannot be deserialized into a Rust `String` -- it would
cause a parse error or be silently dropped by serde.

There is no code path that handles null values to unset environment
variables.

**Verdict**: Gap. Rumpelpod does not support null values in `remoteEnv`.
Setting a value to `null` in devcontainer.json will either cause a parse
error or be silently ignored, rather than unsetting the variable.

## userEnvProbe

### Official CLI behavior

`userEnvProbe` controls how the tool discovers environment variables from
the container user's shell init files. Options: `none`, `interactiveShell`,
`loginShell`, `loginInteractiveShell` (default: `loginInteractiveShell`).

The probed environment is merged with `remoteEnv` and provided to both
lifecycle commands and tool sessions. The official CLI caches the probed
environment to avoid re-probing on each exec.

### Rumpelpod behavior

Rumpelpod implements `userEnvProbe` with the same options and the same
default (`loginInteractiveShell`). The `probe_user_env` function in
`daemon.rs`:

1. Runs `env -0` to capture the base environment (no shell init files).
2. Runs `bash <flags> 'env -0'` to capture the probed environment.
3. Diffs the two to find variables that are new or changed.
4. Skips `_`, `SHLVL`, and `BASH_EXECUTION_STRING`.

The probed env is returned to the client and used in two ways:
- Passed to lifecycle commands via `docker exec -e` flags.
- Returned in `LaunchResult.probed_env` for the client to merge with
  `remoteEnv`.

Rumpelpod does not cache the probed environment between sessions.

**Verdict**: Largely equivalent. Both probe the shell environment and diff
against the base. Rumpelpod lacks caching but is otherwise functionally
similar.

## Variable Substitution Comparison

### Supported variables

| Variable                             | Official CLI | Rumpelpod | Notes                                      |
|--------------------------------------|-------------|-----------|---------------------------------------------|
| `${localEnv:VAR}`                    | Yes         | Yes       | Resolved client-side in both                |
| `${localEnv:VAR:default}`            | Yes         | Yes       | Default when VAR is unset                   |
| `${env:VAR}` (alias for localEnv)    | Yes         | No        | See below                                   |
| `${env:VAR:default}`                 | Yes         | No        | Same gap as `${env:VAR}`                    |
| `${containerEnv:VAR}`               | Yes         | Yes       | Resolved post-creation in both              |
| `${containerEnv:VAR:default}`        | Yes         | Yes       | Default when VAR is unset                   |
| `${localWorkspaceFolder}`            | Yes         | Yes       |                                             |
| `${localWorkspaceFolderBasename}`    | Yes         | Yes       |                                             |
| `${containerWorkspaceFolder}`        | Yes         | Yes       |                                             |
| `${containerWorkspaceFolderBasename}`| Yes         | Yes       |                                             |
| `${devcontainerId}`                  | Yes         | Yes       | Different hash algorithms (see below)       |

### ${env:VAR} alias

The official CLI treats `${env:VAR}` as an alias for `${localEnv:VAR}` in
`replaceWithContext` (variableSubstitution.ts, line 96-98):

```typescript
case 'env':
case 'localEnv':
    return lookupValue(isWindows, context.env, args, match, context.configFile);
```

Rumpelpod's `resolve_variable` function in `devcontainer.rs` only checks
for `localEnv:` and `containerEnv:` prefixes. The bare `env:` prefix is not
handled and falls through to the default `_ => None` case, leaving
`${env:VAR}` as unresolved literal text.

**Verdict**: Gap. `${env:VAR}` references in devcontainer.json will not be
resolved by rumpelpod.

### ${containerEnv:VAR} resolution

The official CLI resolves `${containerEnv:VAR}` in a separate substitution
phase (`containerSubstitute`) after the container is running. It reads the
container's environment from `docker inspect` (the `Config.Env` array) and
substitutes all `${containerEnv:VAR}` references.

Rumpelpod resolves `${containerEnv:VAR}` by running
`docker exec <container> printenv <VAR>` against the running container.
This is done in `enter.rs:resolve_remote_env` and uses the
`ContainerEnvSource` field in `SubstitutionContext`.

Key difference: the official CLI reads the full environment from
`docker inspect` (a single API call), while rumpelpod runs a separate
`docker exec printenv` for each variable reference. This is functionally
correct but less efficient when many `${containerEnv:VAR}` references exist.

Also, rumpelpod only resolves `${containerEnv:VAR}` in the `remoteEnv`
values (via `resolve_remote_env`). Other properties like `mounts` or
`runArgs` that might contain `${containerEnv:VAR}` would not have those
references resolved (the container does not exist yet when those are
processed). The official CLI also resolves `${containerEnv:VAR}` in the
full config object after the container starts.

**Verdict**: Partial gap. `${containerEnv:VAR}` works in `remoteEnv` values,
but is not resolved in the full config re-substitution that the official CLI
performs after container creation.

### Two-phase substitution

The spec implies a two-phase approach:

1. **Before container creation**: Resolve `${localEnv:VAR}`,
   `${localWorkspaceFolder}`, `${localWorkspaceFolderBasename}`, and
   `${devcontainerId}`.
2. **After container creation**: Resolve `${containerEnv:VAR}`,
   `${containerWorkspaceFolder}`, and `${containerWorkspaceFolderBasename}`.

The official CLI implements this with:
- `substitute()` for phase 1 (before container creation)
- `beforeContainerSubstitute()` for `${devcontainerId}` (needs container
  labels)
- `containerSubstitute()` for phase 2 (after container is running)

Rumpelpod implements this differently:
- Phase 1 (`enter.rs:load_and_resolve`): Resolves `${localEnv:VAR}` on
  the client side before sending to the daemon.
- Phase 2 (`daemon.rs:resolve_daemon_vars`): Resolves
  `${containerWorkspaceFolder}`, `${containerWorkspaceFolderBasename}`,
  `${localWorkspaceFolder}`, `${localWorkspaceFolderBasename}`, and
  `${devcontainerId}` on the daemon side before container creation.
- Phase 3 (`enter.rs:resolve_remote_env`): Resolves `${containerEnv:VAR}`
  in `remoteEnv` values after the container is running.

Note that rumpelpod resolves `${containerWorkspaceFolder}` and
`${devcontainerId}` before container creation (in phase 2), which is correct
because these values are derived from configuration, not from the running
container.

**Verdict**: Architecturally different but functionally equivalent for the
common case. The main gap is that phase 3 only applies to `remoteEnv`, not
to the full config.

### ${devcontainerId} computation

The official CLI computes `devcontainerId` as a SHA-256 hash of the
container's label set (sorted JSON), encoded in base-32, padded to 52
characters.

Rumpelpod computes it as a SHA-256 hash of a JSON object containing
`rumpelpod.name` and `rumpelpod.repo_path`, encoded in hexadecimal (64
characters).

The values are not compatible between the two implementations, but this is
acceptable since `devcontainerId` is only used within a single tool's
ecosystem (e.g., for naming volumes).

### build.args restricted context

Both implementations restrict `build.args` to only `${localEnv:VAR}`
substitution, per the spec. Rumpelpod creates a restricted
`SubstitutionContext` with only `resolve_local_env: true` for build args.
The official CLI does the same by only running the pre-container
substitution phase on build args.

**Verdict**: Equivalent.

## Gaps and Bugs

### 1. `${env:VAR}` alias not supported

**Severity**: Medium.
**Location**: `devcontainer.rs:resolve_variable`, line 983 default match arm.
**Impact**: devcontainer.json files that use `${env:VAR}` (common in VS Code
documentation examples) will silently leave the variable unresolved.
**Fix**: Add `env:` as a case alongside `localEnv:` in `resolve_variable`.

### 2. remoteEnv null values not supported

**Severity**: Low-Medium.
**Location**: `devcontainer.rs` line 44 -- `HashMap<String, String>` type.
**Impact**: Cannot unset inherited environment variables. Attempting to set a
`remoteEnv` value to `null` in JSON will cause a deserialization error.
**Fix**: Change type to `Option<HashMap<String, Option<String>>>` or
`HashMap<String, serde_json::Value>` and handle null values by excluding
those keys from the env passed to `docker exec`.

### 3. remoteEnv not passed to lifecycle commands

**Severity**: Medium.
**Location**: `daemon.rs` -- lifecycle commands only receive probed env.
**Impact**: Lifecycle commands (onCreateCommand, postCreateCommand, etc.)
will not see `remoteEnv` variables. This means a `postCreateCommand` that
depends on a `remoteEnv` variable will fail or behave differently than in
the official CLI.
**Fix**: Resolve and merge `remoteEnv` in the daemon before running
lifecycle commands.

### 4. ${containerEnv:VAR} only resolved in remoteEnv

**Severity**: Low.
**Location**: `enter.rs:resolve_remote_env` is the only call site.
**Impact**: If `${containerEnv:VAR}` appears in properties other than
`remoteEnv` (e.g., `mounts`), it will remain as unresolved literal text.
The official CLI re-substitutes the entire config after the container starts.
In practice this is unlikely to matter since `mounts` are needed before the
container exists.
**Fix**: Not needed for most use cases. For full spec compliance, add a
post-creation substitution pass.

### 5. Per-variable docker exec for containerEnv resolution

**Severity**: Low (performance only).
**Location**: `devcontainer.rs:read_container_env_var`.
**Impact**: Each `${containerEnv:VAR}` reference triggers a separate
`docker exec printenv VAR` call. With many references, this adds latency.
**Fix**: Batch-read the container environment with a single `docker exec
env -0` call and cache the result.

## Behavioral Differences

### Lifecycle command environment

| Context               | Official CLI env source          | Rumpelpod env source        |
|-----------------------|---------------------------------|-----------------------------|
| onCreateCommand       | probed env + remoteEnv          | probed env only             |
| updateContentCommand  | probed env + remoteEnv          | probed env only             |
| postCreateCommand     | probed env + remoteEnv          | probed env only             |
| postStartCommand      | probed env + remoteEnv          | probed env only             |
| postAttachCommand     | probed env + remoteEnv          | probed env only             |
| Tool session / enter  | probed env + remoteEnv          | probed env + remoteEnv      |
| Agent exec            | N/A                             | remoteEnv (localEnv-resolved) |

### Environment probing

| Aspect                    | Official CLI                  | Rumpelpod                    |
|---------------------------|-------------------------------|------------------------------|
| Probe method              | Shell exec + /proc/self/environ | `env -0` diff via docker exec |
| Caching                   | Yes (file-based per session)  | No                           |
| Default probe type        | loginInteractiveShell         | loginInteractiveShell        |
| Fallback when bash absent | Falls back to printenv        | Skips probe, returns empty   |

### Agent-specific behavior

The `rumpel agent` path resolves `${localEnv:VAR}` eagerly in `mod.rs`
before the pod launches, then each agent implementation (anthropic.rs,
gemini.rs, xai.rs) calls `resolve_remote_env` after the container is running
to resolve `${containerEnv:VAR}`. The resolved `remoteEnv` is then merged
with the probed env via `merge_env`.

This is consistent with `rumpel enter`, which also calls
`resolve_remote_env` followed by `merge_env`. Both paths handle the
two-phase resolution of remoteEnv correctly.
