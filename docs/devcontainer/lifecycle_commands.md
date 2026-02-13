# Devcontainer Lifecycle Commands: Spec vs Rumpelpod

Comparison of the official devcontainer CLI (reference implementation) and
rumpelpod's implementation of lifecycle commands.

Source references:
- Official CLI: `src/spec-common/injectHeadless.ts`, `src/spec-node/utils.ts`,
  `src/spec-node/configContainer.ts`
- Rumpelpod: `src/devcontainer.rs` (types/parsing), `src/daemon.rs` (execution),
  `src/enter.rs` (re-entry), `src/daemon/db.rs` (idempotency tracking)

---

## Lifecycle Execution Order

### Official spec

```
initializeCommand (host) ->
onCreateCommand (container, once) ->
updateContentCommand (container, on content change) ->
postCreateCommand (container, once) ->
dotfiles installation ->
postStartCommand (container, every start) ->
postAttachCommand (container, every attach)
```

### Rumpelpod

```
[initializeCommand skipped -- intentionally unsupported] ->
onCreateCommand (container, once) ->
updateContentCommand (container, on every entry including first) ->
postCreateCommand (container, once) ->
[no dotfiles support] ->
postStartCommand (container, every start) ->
postAttachCommand (container, every attach/enter)
```

---

## Summary Table

| Command | Spec Behavior | Rumpelpod Behavior | Status |
|---------|---------------|-------------------|--------|
| initializeCommand | Runs on the HOST before container creation, on every invocation. Supports string/array/object formats. Object commands run in parallel via `Promise.all`. | Intentionally unsupported. Parsed but emits a warning and is ignored. | Intentional gap |
| onCreateCommand | Runs inside the container once after first creation. Tracked via a marker file keyed on container creation timestamp. | Runs once after first creation. Tracked via `on_create_ran` flag in SQLite database. Does not re-run on subsequent enters. | Conformant |
| updateContentCommand | Runs after onCreateCommand on first creation, and re-runs when content changes. Tracked via marker file; `rerun` flag can force re-execution during prebuilds. | Runs on EVERY entry (first creation and every subsequent `rumpel enter`), positioned after git sync. Not gated by a content-change check. | Differs (see details) |
| postCreateCommand | Runs once after updateContentCommand on first creation. Tracked via marker file keyed on container creation timestamp. | Runs once after updateContentCommand on first creation. Tracked via `post_create_ran` flag in SQLite database. | Conformant |
| dotfiles | Installed between postCreateCommand and postStartCommand. Configured via separate CLI flags (repository, installCommand, targetPath). | Not supported. No dotfiles installation step exists. | Gap |
| postStartCommand | Runs every time the container starts (but not if already running). Tracked via marker file keyed on container start timestamp. | Runs every time the container starts. On re-entry of an already-running container, it is skipped (only runs if the container `was_stopped`). | Conformant |
| postAttachCommand | Runs every time a tool attaches. Always runs (`doRun = true`). | Runs on every `rumpel enter` call. | Conformant |
| waitFor | Default: `updateContentCommand`. Commands after the waitFor target are run but the tool does not wait for them before connecting. The `skipNonBlocking` flag in the lifecycle hook controls this. | Default: `updateContentCommand`. Commands after the waitFor target are collected into a `bg_commands` vec and run via `spawn_background_lifecycle_commands` in a detached thread. Errors in background commands are logged but do not propagate. | Conformant |

---

## Detailed Analysis

### 1. initializeCommand -- Intentionally Unsupported

**Spec:** Runs on the host machine before container creation. Runs on every
invocation (not just first creation). Supports all three command formats.
Object-format commands run in parallel via `Promise.all`. Failure aborts
container creation with a `ContainerError`.

**Rumpelpod:** Parsed in `src/devcontainer.rs:157` as `Option<LifecycleCommand>`
but listed in `warn_unsupported_fields()` at line 566. When present, a warning
is printed to stderr and the field is ignored.

**Why:** The initializeCommand runs on the host, which assumes the host has the
necessary tools and environment. This does not generalize to non-local backends
such as Kubernetes or remote Docker over SSH, where the "host" concept does not
apply. The recommendation is to use a Dockerfile or onCreateCommand instead.

This is documented in `docs/devcontainer.md` under "Intentionally Unsupported"
and covered by integration tests in `tests/cli/devcontainer/unsupported.rs`.

### 2. onCreateCommand -- Conformant

**Spec:** Runs once after first container creation. The official CLI uses a
marker file (`.onCreateCommandMarker`) inside the container's user data folder,
keyed on the container's `createdAt` timestamp. If the timestamp changes (i.e.,
the container was recreated), the command runs again.

**Rumpelpod:** Uses a database flag (`on_create_ran` in the `pods` table in
SQLite, tracked in `src/daemon/db.rs`). The `run_once_lifecycle_commands`
function at `src/daemon.rs:1865` checks `db::has_on_create_run()` before
executing, and calls `db::mark_on_create_ran()` after success or failure.

**Difference in tracking mechanism:** The official CLI uses in-container marker
files; rumpelpod uses a host-side SQLite database. Both achieve the same
outcome: the command runs exactly once per container creation. The database
approach is slightly more robust against container filesystem modifications but
means the tracking state is separate from the container itself.

**Failure behavior matches:** Both implementations skip later commands
(postCreateCommand) when onCreateCommand fails. Rumpelpod explicitly marks
`post_create_ran` as well to prevent orphaned retries.

### 3. updateContentCommand -- Behavioral Difference

**Spec:** Runs after onCreateCommand on first creation. On subsequent
connections, re-runs only when content has changed. The official CLI uses a
marker file with the container's `createdAt` timestamp -- the command re-runs if
the timestamp changed (new container) or if the `rerun` flag is set (used during
prebuilds). In normal re-attach scenarios with an existing container, it does
NOT re-run.

**Rumpelpod:** Runs on EVERY entry including the first creation and every
subsequent `rumpel enter`. This is visible in two places in `src/daemon.rs`:

1. First creation path (line ~1903): `run_once_lifecycle_commands` always
   executes updateContentCommand (no database guard -- unlike onCreateCommand
   and postCreateCommand which check `_ran` flags).
2. Re-entry path (line ~2184): Unconditionally checks for and runs
   updateContentCommand after git sync completes.

**Why this differs:** Rumpelpod uses git-based sync rather than bind mounts.
Every `rumpel enter` synchronizes the repository from the host into the
container. Since content genuinely changes on every entry (git sync may pull new
commits), running updateContentCommand on every entry is a reasonable semantic
choice -- it ensures `npm install`, `pip install`, etc. stay up-to-date after
each sync. The official CLI is designed for bind mounts where content changes
are live and do not need a re-sync step.

**Impact:** Projects using updateContentCommand for expensive operations (like
a full `npm install`) will see that command run on every `rumpel enter`, not
just on first creation. This may be slower but is more correct for the
git-sync model.

### 4. postCreateCommand -- Conformant

**Spec:** Runs once after updateContentCommand on first creation. Marker-file
tracked like onCreateCommand.

**Rumpelpod:** Database-tracked via `post_create_ran`. Runs once on first
creation. Skipped on subsequent enters.

Both implementations skip postCreateCommand if updateContentCommand or
onCreateCommand failed.

### 5. postStartCommand -- Conformant

**Spec:** Runs every time the container starts. Uses a marker file keyed on
the container's `startedAt` timestamp to avoid re-running if the container
was not restarted.

**Rumpelpod:** On first creation, always runs (the container was just created
and started). On re-entry, only runs if `was_stopped` is true (the container
was stopped and restarted). This matches the spec's intent: the command runs
once per container start, not once per attach.

### 6. postAttachCommand -- Conformant

**Spec:** Runs on every tool attach. The official CLI always passes
`doRun = true` for this command.

**Rumpelpod:** Runs on every `rumpel enter` call, in both the first-creation
and re-entry code paths. This matches the spec.

### 7. waitFor -- Conformant

**Spec:** Default is `updateContentCommand`. Commands up to and including the
waitFor target run synchronously (blocking the tool from connecting). Commands
after the target run in the background. The official CLI uses `skipNonBlocking`
to short-circuit the lifecycle chain after the waitFor target.

**Rumpelpod:** Default is `updateContentCommand` (set in
`effective_wait_for()` at `src/devcontainer.rs:587`). The `WaitFor` enum
derives `Ord` in lifecycle order so that comparisons like
`wait_for >= WaitFor::PostStartCommand` work naturally. Commands up to the
target run synchronously via `run_lifecycle_command`. Commands after the target
are collected into a `Vec<(String, LifecycleCommand)>` and handed to
`spawn_background_lifecycle_commands`, which runs them sequentially in a
detached thread.

**Background failure handling:** The official CLI logs background failures.
Rumpelpod does the same: background commands that fail are logged via
`error!()` and the thread stops executing further background commands (it
`break`s out of the loop). The user's session is unaffected.

### 8. Command Format Support

**Spec formats:**
- **String:** `"echo hello"` -- run via shell (`/bin/sh -c "echo hello"`)
- **Array:** `["echo", "hello"]` -- run directly without shell
- **Object:** `{"a": "echo a", "b": ["echo", "b"]}` -- run named commands in
  parallel. The official CLI uses `Promise.allSettled` for in-container commands
  (waits for all to finish, then checks for failures) and `Promise.all` for
  initializeCommand (fails fast on first error).

**Rumpelpod formats** (defined in `src/devcontainer.rs:391`):
- **String:** `LifecycleCommand::String(String)` -- run via `sh -c`
- **Array:** `LifecycleCommand::Array(Vec<String>)` -- run directly
- **Object:** `LifecycleCommand::Object(HashMap<String, StringOrArray>)` --
  run in parallel using `std::thread::spawn` per named command, then
  `join` all handles and check for errors.

**Parallel execution comparison:**
- Official CLI: `Promise.allSettled` -- waits for ALL commands to finish, then
  reports the first failure. This means all parallel commands run to completion
  even if one fails early.
- Rumpelpod: `std::thread::spawn` + `join` -- spawns all threads, then joins
  them sequentially. All threads run concurrently and all are waited on. If
  any result is an error, it is propagated. This is semantically equivalent
  to `Promise.allSettled` -- all commands run to completion, errors are
  checked after all finish.

Both implementations are conformant for parallel execution.

---

## Gaps

Things that could be implemented to improve spec conformance.

### 1. Dotfiles Installation

**Spec:** Dotfiles are installed between postCreateCommand and postStartCommand.
The official CLI supports a `dotfilesConfiguration` with repository URL,
install command, and target path.

**Rumpelpod:** No dotfiles support. This is not part of the devcontainer.json
spec itself (it is a tool-level feature), so it is a tool gap rather than a
spec gap. Low priority since rumpelpod's primary use case is agent execution,
not interactive development.

### 2. updateContentCommand Content-Change Detection

**Spec:** updateContentCommand should ideally only re-run when content actually
changed. The official CLI uses marker files with timestamps.

**Rumpelpod:** Runs on every entry unconditionally. This is correct for the
git-sync model (content may have changed) but could be optimized by checking
whether git sync actually changed anything. If no new commits were pulled,
updateContentCommand could be skipped.

### 3. Feature Lifecycle Hooks

**Spec:** Dev Container Features can contribute their own lifecycle commands
which are merged with the devcontainer.json commands. The official CLI
maintains a `LifecycleHooksInstallMap` that maps each hook to an array of
`{command, origin}` pairs from both the config and installed features.

**Rumpelpod:** Features are intentionally unsupported, so feature lifecycle
hooks are also unsupported.

---

## Architectural Limitations

Things that rumpelpod inherently cannot or should not support due to its
design.

### 1. initializeCommand (Host Execution)

Rumpelpod is designed to work with remote Docker hosts and potentially
Kubernetes. Running commands on the "host" is ambiguous in these contexts.
The daemon runs on the user's machine, but the containers run elsewhere. This
command is intentionally unsupported.

### 2. Bind-Mount-Based Content Change Detection

The official CLI's updateContentCommand re-runs based on container creation
timestamps because bind mounts make content changes instantaneous. Rumpelpod
uses git sync, so the "content changed" signal is fundamentally different.
The current approach of running on every entry is a valid adaptation.

### 3. Session Tracking for waitFor

The official CLI's waitFor interacts with its persistent connection model: the
tool stays connected and can run commands in the background while the user
works. Rumpelpod's `enter` command is a one-shot exec that returns. Background
commands run in the daemon, not in the user's terminal. This means:
- Background command output goes to daemon logs, not to the user's terminal.
- There is no way for the user to see background command progress during
  their session.

This is an acceptable trade-off for an agent runner.

---

## Bugs

Confirmed incorrect behaviors.

### 1. No Bugs Found

The implementation matches the spec in all areas it claims to support. The
updateContentCommand behavioral difference (running on every entry) is an
intentional adaptation for the git-sync model, not a bug. The waitFor
implementation correctly separates foreground and background commands. Object
format parallel execution works correctly.

The only potential issue is that updateContentCommand is not gated by any
content-change check, which means it runs even when git sync pulled no new
changes. This is a performance issue, not a correctness bug. The command
itself is expected to be idempotent.
