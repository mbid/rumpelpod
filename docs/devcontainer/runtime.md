# Runtime Options: Rumpelpod vs Official devcontainer CLI

This document compares rumpelpod's handling of devcontainer.json runtime
properties against the official devcontainer CLI (the reference implementation
at https://github.com/devcontainers/cli).

The official CLI source was consulted at `src/spec-node/singleContainer.ts`
and `src/spec-configuration/configuration.ts`.

---

## Feature Comparison Table

| Property           | Official CLI                                  | Rumpelpod                                     | Status              |
|--------------------|-----------------------------------------------|-----------------------------------------------|---------------------|
| overrideCommand    | Default true (image/Dockerfile), false (compose). When true, overrides CMD with a sleep loop. When false, appends image CMD/ENTRYPOINT to the sleep loop entrypoint. | Default true. When true, sets CMD to `sleep infinity`. When false, sets CMD to None (image CMD/ENTRYPOINT runs directly). | Implemented (docs stale) |
| shutdownAction     | Default stopContainer (image/Dockerfile), stopCompose (compose). Stops or removes container on disconnect. | Parsed but intentionally not implemented. Containers always stay running; `rumpel rm` removes them. | Intentional deviation |
| runArgs            | Passed verbatim as raw `docker run` arguments. `-u`/`--user` is extracted to determine UID mapping user. | Selectively extracted: `--network`, `--runtime`, `--device`, `--label`, `--cap-add`, `--security-opt`, `--privileged`, `--init`. Unrecognized flags are silently dropped. | Partial -- see analysis below |
| init               | Adds `--init` to docker run.                  | Adds init to bollard HostConfig. Also extracted from runArgs. First-class property takes precedence. | Implemented |
| privileged         | Adds `--privileged` to docker run.            | Adds privileged to bollard HostConfig. Also extracted from runArgs. Also forced on when deterministic test mode is active. | Implemented |
| capAdd             | Each entry becomes `--cap-add`.               | Merged with caps extracted from runArgs, passed to bollard HostConfig. | Implemented |
| securityOpt        | Each entry becomes `--security-opt`.          | Merged with opts extracted from runArgs, passed to bollard HostConfig. | Implemented |
| name               | Display name for the dev container. Informational only. | Parsed, not displayed in any UI. | Parsed, unused |
| hostRequirements   | cpus, memory, storage parsed. GPU requirements trigger `--gpus all` if Docker supports it. Non-optional GPU logs a warning if no GPU found. | Parsed into typed structs (cpus, memory, storage, gpu). Not enforced, not logged, no `--gpus all`. | Parsed, not enforced |

---

## overrideCommand Analysis

### Documentation vs Code Discrepancy

The existing `docs/devcontainer.md` lists `overrideCommand` under
"Not Yet Implemented" with the note:

> When `false`, container CMD should run instead of `sleep infinity`

However, the code in `src/daemon.rs` (around line 1084) **does implement it**:

```rust
// Default is true per the devcontainer spec (for image/Dockerfile configs).
let override_command = dc.override_command.unwrap_or(true);

let config = ContainerCreateBody {
    // ...
    cmd: if override_command {
        Some(vec!["sleep".to_string(), "infinity".to_string()])
    } else {
        None
    },
    // ...
};
```

**Verdict:** The documentation is stale. `overrideCommand` is implemented and
working. When true (the default), CMD is set to `["sleep", "infinity"]`. When
false, CMD is set to `None`, allowing the image's CMD/ENTRYPOINT to run.

### Behavioral Difference from Official CLI

The official CLI's approach is more sophisticated. It always overrides the
entrypoint to `/bin/sh` and builds a shell script that:

1. Prints "Container started"
2. Sets up a signal trap for graceful shutdown
3. Runs any custom entrypoints from Features
4. Executes a `while sleep 1 & wait $!; do :; done` loop

When `overrideCommand` is false, the official CLI appends the image's
original CMD and ENTRYPOINT to this shell command via `exec "$@"`, so
the user's CMD runs within the managed entrypoint wrapper.

Rumpelpod's approach is simpler: it either sets CMD to `sleep infinity`
(override true) or omits CMD entirely (override false). This means:

- When false, the image's original ENTRYPOINT and CMD run unmodified
  (no wrapper, no signal trap).
- If the image's CMD exits, the container stops. The official CLI's
  sleep loop would keep the container alive even after CMD exits.
- There is no Feature entrypoint chaining (rumpelpod does not support
  Features anyway).

For rumpelpod's use case (agent runner, no Features), this simpler
approach is adequate.

---

## shutdownAction: Intentional Deviation

Rumpelpod intentionally does not implement `shutdownAction`. The property is
parsed (the `ShutdownAction` enum exists in `src/devcontainer.rs`) but never
read in daemon code.

**Rationale:** Rumpelpod always leaves containers running between sessions.
Cleanup is explicit via `rumpel rm`. Implementing shutdownAction would require
session tracking in the daemon to know when "the last session disconnects."
The explicit cleanup model is simpler and less surprising for an agent runner
where containers may be reused across many sessions.

The official CLI defaults:
- `stopContainer` for image/Dockerfile configs
- `stopCompose` for Docker Compose configs
- `none` leaves the container running

---

## runArgs Parsing Comparison

This is the most significant behavioral difference between the two
implementations.

### Official CLI: Pass-through

The official CLI passes `runArgs` **verbatim** as raw `docker run` CLI
arguments. They appear in the argument list between other generated flags
and the image name:

```typescript
const args = [
    'run',
    // ... other generated flags ...
    ...(config.runArgs || []),
    // ... extraRunArgs (GPU etc.) ...
    // ... entrypoint and image ...
];
```

The only special extraction the official CLI does from `runArgs` is:
- `-u` / `--user` / `-u=<val>` / `--user=<val>`: extracted by
  `findUserArg()` to determine the container user for UID mapping.

Everything else in runArgs is passed through unchanged.

### Rumpelpod: Selective Extraction

Rumpelpod uses the bollard Docker API (not the Docker CLI), so it cannot
pass raw CLI arguments. Instead, it parses `runArgs` and maps recognized
flags to bollard `HostConfig` fields:

| Flag extracted     | Mapped to                     |
|--------------------|-------------------------------|
| `--network`        | `HostConfig.network_mode`     |
| `--runtime`        | `HostConfig.runtime`          |
| `--device`         | `HostConfig.devices`          |
| `--label`          | Container labels              |
| `--cap-add`        | `HostConfig.cap_add` (merged with `capAdd`) |
| `--security-opt`   | `HostConfig.security_opt` (merged with `securityOpt`) |
| `--privileged`     | `HostConfig.privileged`       |
| `--init`           | `HostConfig.init`             |

Both `--key=value` and `--key value` (space-separated) forms are supported
for all flags.

### Flags NOT Handled by Rumpelpod

The following `docker run` flags that users might put in `runArgs` are
**silently dropped** by rumpelpod:

| Flag               | Official CLI | Rumpelpod | Impact |
|--------------------|--------------|-----------|--------|
| `-u` / `--user`    | Extracted for UID mapping | Dropped | Cannot override container user via runArgs. Must use `containerUser`. |
| `-v` / `--volume`  | Passed through | Dropped | Cannot add volumes via runArgs. Must use `mounts`. |
| `-p` / `--publish` | Passed through | Dropped | Cannot publish ports via runArgs. Must use `forwardPorts`. |
| `-e` / `--env`     | Passed through | Dropped | Cannot set env vars via runArgs. Must use `containerEnv`. |
| `--gpus`           | Passed through (also auto-added for hostRequirements.gpu) | Dropped | No GPU passthrough via runArgs. |
| `--memory` / `-m`  | Passed through | Dropped | No memory limits via runArgs. |
| `--cpus`           | Passed through | Dropped | No CPU limits via runArgs. |
| `--shm-size`       | Passed through | Dropped | No shared memory configuration. |
| `--tmpfs`          | Passed through | Dropped | Must use `mounts` with type tmpfs. |
| `--pid`            | Passed through | Dropped | No PID namespace configuration. |
| `--ipc`            | Passed through | Dropped | No IPC namespace configuration. |
| `--hostname`       | Passed through | Dropped | Hostname is always set to pod name. |
| `--dns`            | Passed through | Dropped | No DNS configuration. |
| `--add-host`       | Passed through | Dropped | No /etc/hosts entries. |
| `--ulimit`         | Passed through | Dropped | No ulimit configuration. |
| `--storage-opt`    | Passed through | Dropped | No storage driver options. |
| `--restart`        | Passed through | Dropped | No restart policy (containers always stay running). |

This is an inherent limitation of using the bollard API rather than shelling
out to `docker run`. Adding support for additional flags requires explicitly
mapping each one to the corresponding bollard struct field.

---

## hostRequirements and GPU Support

### Official CLI

The official CLI's `extraRunArgs()` function in `singleContainer.ts` checks
`config.hostRequirements.gpu`:

1. If GPU is required or optional, check Docker GPU support via
   `checkDockerSupportForGPU()`.
2. If GPU support is found, add `--gpus all` to the docker run arguments.
3. If GPU is required but not found, log a warning.
4. If GPU is optional and not found, silently continue.

CPU, memory, and storage requirements are parsed and merged (via
`mergeHostRequirements`) but are primarily informational for client tooling.

### Rumpelpod

Rumpelpod parses `hostRequirements` into typed structs:

```rust
pub struct HostRequirements {
    pub cpus: Option<u32>,
    pub memory: Option<String>,
    pub storage: Option<String>,
    pub gpu: Option<GpuRequirement>,
}
```

The `GpuRequirement` enum handles `true`/`false`, `"optional"`, and detailed
objects with cores/memory.

However, **none of these values are read or acted upon** in `daemon.rs`.
There is no GPU detection, no `--gpus all` injection, and no logging of
requirements.

### Gap

The most impactful gap is GPU support. A devcontainer.json with
`"hostRequirements": { "gpu": true }` will silently get no GPU access in
rumpelpod, whereas the official CLI would add `--gpus all`.

---

## Gaps and Intentional Deviations Summary

### Intentional Deviations

| Area | Deviation | Rationale |
|------|-----------|-----------|
| shutdownAction | Not implemented, containers always stay running | Explicit cleanup via `rumpel rm` is simpler for an agent runner |
| runArgs pass-through | Selective extraction instead of pass-through | Bollard API requires structured input, not raw CLI args |
| overrideCommand=false | Image CMD/ENTRYPOINT runs directly without wrapper | No Features support, so no entrypoint chaining needed |

### Gaps (Not Yet Implemented)

| Area | Gap | Severity |
|------|-----|----------|
| runArgs `-u`/`--user` | Not extracted; cannot override user via runArgs | Low -- `containerUser` serves the same purpose |
| hostRequirements.gpu | Not enforced; no `--gpus all` injection | Medium -- GPU workloads silently get no GPU |
| hostRequirements logging | Requirements not logged at all | Low -- informational only |
| runArgs unrecognized flags | Silently dropped | Medium -- users may not realize flags are ignored |

### Documentation Bug

`docs/devcontainer.md` lists `overrideCommand` under "Not Yet Implemented"
but it is in fact fully implemented in `src/daemon.rs`. The documentation
should be updated to move it to the "Implemented and Working" section.
