# Port Forwarding: Rumpelpod vs Official devcontainer CLI

This document compares rumpelpod's port forwarding implementation against the
official devcontainer CLI (github.com/devcontainers/cli) as of the source at
`/tmp/devcontainer-cli`.

---

## Feature Comparison Table

| Feature | Official CLI | Rumpelpod | Notes |
|---------|-------------|-----------|-------|
| `forwardPorts` (numbers) | Supported. Array of port numbers. | Supported. Numbers become Docker `-p 127.0.0.1:PORT:PORT/tcp` bindings. | Equivalent behavior for simple numeric ports. |
| `forwardPorts` (strings, e.g. `"db:5432"`) | Supported. Strings like `"host:port"` forwarded as-is. | Parsed: the container port is extracted from after `:`. The host part is discarded. | See "String format in forwardPorts" below. |
| `forwardPorts` merging across image metadata | Set union via `mergeForwardPorts()` using `localhost:PORT` normalization. | Not applicable. Rumpelpod does not merge image metadata layers. | Rumpelpod reads a single devcontainer.json; no feature/metadata merging. |
| `appPort` | Supported for image/Dockerfile mode only. Numbers become `127.0.0.1:PORT:PORT`, strings passed raw to `-p`. | Intentionally unsupported. Emits a warning and is ignored. | Correct per deprecation. The official spec treats `appPort` as legacy. |
| `portsAttributes` (exact port keys) | `Record<string, PortAttributes>`. Keys are port number strings. Attributes: `label`, `onAutoForward`, `elevateIfNeeded`. | Supported. `HashMap<String, PortAttributes>` keyed by port number strings. Attributes: `label`, `protocol`, `onAutoForward`, `requireLocalPort`, `elevateIfNeeded`. | Rumpelpod parses more fields than the official CLI (`protocol`, `requireLocalPort`), but only `label` is actively used. |
| `portsAttributes` (port range keys, e.g. `"40000-55000"`) | Spec allows range patterns as keys. CLI does not implement range matching in its own code (defers to VS Code). | Not supported. Keys are looked up by exact port number string. | Gap: range-pattern keys like `"40000-55000"` are silently ignored. |
| `otherPortsAttributes` | Supported. Used as fallback during metadata merging. | Parsed and used as label fallback in `setup_port_forwarding`. | Rumpelpod falls back to `otherPortsAttributes` for label lookup. |
| `onAutoForward` values | `notify`, `openBrowser`, `openBrowserOnce`, `openPreview`, `silent`, `ignore`. | Enum with all six values defined. Not behaviorally implemented (no auto-forwarding detection). | Parsed but not acted on. Rumpelpod does not auto-detect listening ports. |
| Host bind address | `127.0.0.1` for numeric `appPort` entries. | Always `127.0.0.1` for all forwarded ports. | Match. Both bind to localhost only. |
| Multi-pod port remapping | Not applicable (CLI manages one container). | Supported. When a local port is taken by another pod, Docker auto-assigns a different host port. | Rumpelpod-specific feature. See dedicated section below. |
| Remote SSH port forwarding | Not applicable (CLI is local-only). | Supported. SSH `-L` tunnels forward local ports through to Docker host ports on remote machines. | Rumpelpod-specific feature. See dedicated section below. |

---

## Detailed Analysis

### forwardPorts

**Official CLI behavior:** The `forwardPorts` array accepts numbers and strings.
Numbers like `3000` mean "forward container port 3000". Strings like `"db:5432"`
mean "forward port 5432 from a service named `db`" (relevant in Docker Compose
scenarios where multiple services share a network). During image metadata
merging, `forwardPorts` from all layers are combined via set union, using
`localhost:PORT` as a normalization key to deduplicate.

**Rumpelpod behavior:** Numbers are handled identically. For string entries, the
`resolve_port_number()` function at `src/daemon.rs:1146` splits on `:` and
parses the part after the colon as the container port number. The host/service
name before the colon is discarded. This means `"db:5432"` is treated as
"forward container port 5432", which is correct for single-container scenarios
but does not support cross-service forwarding (which requires Docker Compose,
which rumpelpod does not support anyway).

There is no metadata merging because rumpelpod reads a single
devcontainer.json file and does not process Dev Container Features that might
contribute additional `forwardPorts` entries.

The forwarded ports are published on the Docker container via `-p` bindings
(always binding to `127.0.0.1`), then recorded in the SQLite database with
their container-port-to-local-port mapping.

### appPort

**Official CLI behavior:** Legacy property for image/Dockerfile mode. Numeric
values become `127.0.0.1:PORT:PORT` Docker `-p` arguments. Strings are passed
as raw `-p` arguments, allowing custom host:container mappings. Not available in
Docker Compose mode.

**Rumpelpod behavior:** Listed in `warn_unsupported_fields()` at
`src/devcontainer.rs:562`. When present, a warning is printed to stderr and the
property is ignored. This is intentional -- `appPort` bypasses rumpelpod's port
management (the SQLite-based tracking of allocated ports and multi-pod
remapping), so directing users to `forwardPorts` is the correct approach.

### portsAttributes

**Official CLI behavior:** `Record<string, PortAttributes>` where keys are port
number strings (e.g. `"3000"`) or port range patterns (e.g. `"40000-55000"`).
The CLI defines `PortAttributes` with three fields: `label`, `onAutoForward`,
and `elevateIfNeeded`. Port range matching is not implemented in the CLI itself
but is used by VS Code's port forwarding UI.

**Rumpelpod behavior:** Parsed as `HashMap<String, PortAttributes>` at
`src/devcontainer.rs:32`. The `PortAttributes` struct has five fields: `label`,
`protocol`, `onAutoForward`, `requireLocalPort`, and `elevateIfNeeded`. Of
these, only `label` is actively used -- it is looked up in
`setup_port_forwarding()` at `src/daemon.rs:1276` and stored in the database
alongside the port mapping. The `rumpel ports` command (at `src/ports.rs:16`)
displays the label in its output.

Port range keys (e.g. `"40000-55000"`) are not matched. The lookup at
`src/daemon.rs:1277` uses `ports_attributes.get(&container_port.to_string())`,
which requires an exact string match. A range key would only match if the port
number happened to be literally the string `"40000-55000"`, which is never the
case.

### otherPortsAttributes

**Official CLI behavior:** Provides default `PortAttributes` for ports not
explicitly listed in `portsAttributes`. During metadata merging, the last
(most derived) layer's `otherPortsAttributes` wins.

**Rumpelpod behavior:** Parsed at `src/devcontainer.rs:36`. Used in
`setup_port_forwarding()` at `src/daemon.rs:1276-1280` as a fallback: when a
port's number is not found in `portsAttributes`, `otherPortsAttributes` is
checked for a `label`. The docs at `docs/devcontainer.md:78` previously stated
this was "parsed but not used", but this is outdated -- the code does use it as
a label fallback. There is also a passing integration test
(`other_ports_attributes_label` in `tests/cli/devcontainer/ports.rs:209`) that
verifies this behavior.

The fallback only applies to the `label` field. Other attributes from
`otherPortsAttributes` (like `onAutoForward`) are parsed but not acted upon.

### String Format in forwardPorts

**Official CLI:** Strings like `"db:5432"` are supported as entries in
`forwardPorts`. In non-Compose scenarios, they are typically just `"5432"` (a
port number as a string). The CLI passes them through for the tool layer (e.g.
VS Code) to handle.

**Rumpelpod:** The `resolve_port_number()` function handles two string formats:

1. A plain number string (e.g. `"5432"`) -- parsed directly via `str::parse()`.
2. A `host:port` string (e.g. `"db:5432"`) -- split on `:`, the right side
   is parsed as the port number.

If parsing fails (non-numeric values), the port spec is skipped with a warning.
This correctly handles the common cases but discards the host/service name,
which is acceptable since Docker Compose (the only scenario where service names
matter) is not supported.

### Port Ranges in portsAttributes Keys

**Spec:** The `portsAttributes` keys can be port ranges like `"40000-55000"`,
meaning the attributes apply to any port in that range.

**Official CLI:** Defines `portsAttributes` as `Record<string, PortAttributes>`
without special range handling in its own code. Range interpretation is
delegated to the consuming tool (VS Code).

**Rumpelpod:** No range matching. The lookup is a simple `HashMap::get()` with
the port number as a string key. Ports that fall within a range key will not
pick up those attributes.

---

## Gaps

| Gap | Severity | Description |
|-----|----------|-------------|
| Port range keys in `portsAttributes` | Low | Range patterns like `"40000-55000"` are not matched. Only exact port number keys work. The official CLI also does not implement this -- it is a VS Code feature. |
| `onAutoForward` behavior | Low | All six enum values are parsed but none trigger any behavior. Rumpelpod does not auto-detect ports that containers start listening on, so `onAutoForward` is a no-op. The official CLI similarly defers this to the tool layer. |
| `protocol` attribute | Low | Parsed but unused. The official CLI does not define this field either (it is VS Code-specific). |
| `requireLocalPort` attribute | Low | Parsed but unused. Not in the official CLI's `PortAttributes` type. |
| `elevateIfNeeded` attribute | Low | Parsed but unused. Present in both the official CLI and rumpelpod type definitions but not acted on by either. |
| Image metadata merging for `forwardPorts` | Low | The official CLI merges `forwardPorts` across image metadata layers (base image, features, devcontainer.json) using set union. Rumpelpod reads only a single devcontainer.json. This is a consequence of not supporting Dev Container Features, not a port-specific gap. |
| `appPort` | None | Intentionally unsupported with a warning. Correct per deprecation. |

---

## Multi-Pod Port Remapping (Rumpelpod-Specific)

The official devcontainer CLI manages exactly one container, so port conflicts
between containers do not arise. Rumpelpod manages multiple pods for the same
repository, each potentially requesting the same forwarded ports.

### How it works

1. **Port allocation tracking:** All allocated local ports are stored in the
   `forwarded_ports` table with a unique index on `local_port`
   (`src/daemon/db.rs:159`). This prevents two pods from being assigned the
   same local port.

2. **Container creation phase** (`compute_publish_ports()` at
   `src/daemon.rs:1165`):
   - For each port in `forwardPorts`, the daemon checks whether the container
     port number is already allocated by another pod or in use on the host.
   - If available, it requests that Docker bind to the same port number
     (e.g. container 3000 -> host 3000).
   - If taken, it requests port 0, letting Docker auto-assign an available
     host port.
   - For remote Docker hosts, port 0 is always requested (the SSH forward
     manager handles local port assignment independently).

3. **Port forwarding setup phase** (`setup_port_forwarding()` at
   `src/daemon.rs:1230`):
   - After the container starts, the daemon reads the actual Docker-assigned
     host ports via container inspection.
   - For local Docker: the Docker-assigned host port IS the local port.
   - For remote Docker: the daemon allocates a local port (preferring the
     container port number if available) and sets up an SSH `-L` tunnel.
   - The final container-port-to-local-port mapping is recorded in the
     database.

4. **Conflict resolution:** The first pod to request a port gets the
   "natural" mapping (e.g. 3000->3000). Subsequent pods requesting the same
   container port get a remapped local port (e.g. 3000->10XXX). The `rumpel
   ports` command shows both the container port and the actual local port
   so the user knows where to connect.

### Example

```
$ rumpel ports pod-a
CONTAINER    LOCAL    LABEL
3000         3000     App

$ rumpel ports pod-b
CONTAINER    LOCAL    LABEL
3000         10342    App
```

Both pods forward container port 3000, but pod-b's local port was remapped to
10342 because pod-a already had 3000.

---

## Remote SSH Forwarding Behavior (Rumpelpod-Specific)

When pods run on a remote Docker host (configured via `host = "ssh://..."` in
`.rumpelpod.toml`), port forwarding involves an additional SSH tunnel layer.

### Architecture

```
User's machine                 Remote Docker host
+-----------+                  +------------------+
| localhost |  SSH -L tunnel   | Docker container |
|   :3000   | <=============> |      :3000       |
+-----------+                  +------------------+
```

### How it works

1. The daemon maintains SSH connections to remote hosts via the
   `SshForwardManager` (`src/daemon/ssh_forward.rs`). Each remote host gets
   one SSH connection with a control socket for multiplexing.

2. During container creation, `compute_publish_ports()` always requests port 0
   for remote hosts (`src/daemon.rs:1179-1180`). This lets Docker auto-assign
   host ports on the remote machine, avoiding conflicts with other services
   running there.

3. During `setup_port_forwarding()`, the daemon:
   a. Reads the Docker-assigned host port on the remote machine.
   b. Allocates a local port on the user's machine (preferring the container
      port number, falling back to the 10000-65000 range).
   c. Uses `ssh -O forward -L 127.0.0.1:LOCAL:127.0.0.1:REMOTE_DOCKER_PORT`
      to dynamically add a local forward through the existing SSH connection.

4. The SSH tunnel is transparent to the user. `rumpel ports` shows the local
   port, and traffic flows: `localhost:LOCAL -> SSH tunnel -> remote
   Docker host:DOCKER_PORT -> container:CONTAINER_PORT`.

### Re-entry behavior

When a pod is re-entered (`rumpel enter` on an existing pod), the daemon checks
whether the SSH tunnel for each forwarded port is still active. If a tunnel
has broken (e.g. the SSH connection was restarted), it re-establishes the
forward using the same local port from the database
(`src/daemon.rs:1283-1294`).

### Reconnection and resilience

The `SshForwardManager` detects broken tunnels via Docker socket pings with a
hard 5-second timeout (`src/daemon/ssh_forward.rs:36`). If a tunnel dies, it
is automatically re-established with exponential backoff (1s initial, 60s max).
