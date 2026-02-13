# Variable Substitution: Spec vs Rumpelpod

Comparison of devcontainer.json `${...}` variable substitution between the
official devcontainer CLI (reference implementation) and rumpelpod.

Sources:
- Official CLI: `src/spec-common/variableSubstitution.ts`
- Rumpelpod: `src/devcontainer.rs`
- Spec: <https://containers.dev/implementors/json_reference/>


## Variable Comparison Table

| Variable pattern            | Spec | CLI | Rumpelpod | Notes |
|-----------------------------|------|-----|-----------|-------|
| `${localEnv:VAR}`          | Yes  | Yes | Yes       | Host environment variable; empty string if unset |
| `${localEnv:VAR:default}`  | Yes  | Yes | Yes*      | *Default parsing differs (see below) |
| `${env:VAR}`               | No   | Yes | No        | Undocumented CLI alias for `localEnv` |
| `${containerEnv:VAR}`      | Yes  | Yes | Yes       | Only in `remoteEnv` per spec |
| `${containerEnv:VAR:default}` | Yes | Yes | Yes*   | *Default parsing differs (see below) |
| `${localWorkspaceFolder}`  | Yes  | Yes | Yes       | Host path to workspace root |
| `${localWorkspaceFolderBasename}` | Yes | Yes | Yes | Basename of host workspace path |
| `${containerWorkspaceFolder}` | Yes | Yes | Yes    | Container workspace path |
| `${containerWorkspaceFolderBasename}` | Yes | Yes | Yes | Basename of container workspace path |
| `${devcontainerId}`        | Yes  | Yes | Yes       | Stable hash identifier; format differs (see below) |


## ${env:VAR} Alias

The CLI's `replaceWithContext` function (line 94-115 of variableSubstitution.ts)
has a `switch` that handles both `'env'` and `'localEnv'` as equivalent:

```typescript
case 'env':
case 'localEnv':
    return lookupValue(isWindows, context.env, args, match, context.configFile);
```

Rumpelpod's `resolve_variable` only checks for `localEnv:` prefix. It does
not recognize `${env:VAR}`. This means devcontainer.json files using
`${env:VAR}` (which the CLI supports) will leave the variable unresolved in
rumpelpod.

The spec does not document `${env:VAR}`, so this is an undocumented CLI
behavior rather than a spec violation.


## Default Value Parsing

The CLI splits the inner variable text on `:` and passes all segments as an
array. For `${localEnv:VAR:default:a:b:c}`, the CLI produces
`args = ["VAR", "default", "a", "b", "c"]` and uses only `args[1]`
(`"default"`) as the fallback value. Extra colon-separated segments are
silently discarded.

Rumpelpod's `split_var_default` uses `split_once(':')`, so for
`VAR:default:a:b:c` it produces `("VAR", Some("default:a:b:c"))`. The entire
remainder after the first colon becomes the default value.

**Result**: `${localEnv:UNSET:default:a:b:c}` resolves to:
- CLI: `"default"`
- Rumpelpod: `"default:a:b:c"`

This is a **behavioral difference**. Default values containing colons are rare
in practice, but the rumpelpod behavior differs from the reference
implementation. The spec is ambiguous on this point since it does not define
the escaping or parsing of the default value segment.


## Two-Phase Substitution

### CLI phases

The CLI applies substitution in three distinct calls, composed via
`addSubstitution`:

1. **Config load** (`substitute`): Resolves `localEnv`, `env`,
   `localWorkspaceFolder`, `localWorkspaceFolderBasename`,
   `containerWorkspaceFolder`, `containerWorkspaceFolderBasename`.
   Unrecognized variables pass through unchanged.

2. **Before container** (`beforeContainerSubstitute`): Resolves
   `devcontainerId` using the container's id labels. All other variables
   pass through.

3. **After container start** (`containerSubstitute`): Resolves
   `containerEnv` by reading the container's actual environment. All other
   variables pass through.

These three functions compose: the CLI chains them so each phase only handles
its own variable type and leaves others intact for subsequent phases.

### Rumpelpod phases

Rumpelpod applies substitution in two call sites:

1. **Client side** (`enter.rs`, line 138): Resolves only `localEnv`.
   All other context fields are `None`/default, so workspace and container
   variables pass through.

2. **Daemon side** (`daemon.rs`, `resolve_daemon_vars`): Resolves
   `localWorkspaceFolder`, `localWorkspaceFolderBasename`,
   `containerWorkspaceFolder`, `containerWorkspaceFolderBasename`, and
   `devcontainerId` in a single pass. The `workspace_folder` property is
   pre-resolved first since `containerWorkspaceFolder` is derived from it.

3. **At enter time** (`enter.rs`, `resolve_remote_env`): Resolves
   `containerEnv` in `remoteEnv` values only, by running
   `docker exec printenv VAR` against the running container.

### Comparison

The phasing is functionally equivalent. Both implementations use the same
strategy of leaving unresolved variables as literal text so a later phase can
handle them. The key difference is that the CLI resolves `devcontainerId` in
a separate phase (before container creation), while rumpelpod bundles it with
the workspace variable resolution on the daemon side. This does not cause
behavioral differences because `devcontainerId` does not depend on the
container being running.


## build.args Restriction

### Spec

The spec documents `build.args` as supporting `${localEnv:...}`. The
`${devcontainerId}` variable table explicitly excludes `build.args` from its
list of applicable properties. The spec example for `build.args` only shows
`${localEnv:VARIABLE_NAME}`.

### CLI

The CLI applies `substitute` (phase 1) to the entire config object
recursively, which includes `build.args`. Since phase 1 resolves `localEnv`,
`localWorkspaceFolder`, `containerWorkspaceFolder`, and folder basenames,
all of these would be substituted in `build.args`. The CLI does not have
special-case restriction logic for `build.args` -- it relies on the user
following the spec's documented variable availability.

### Rumpelpod

Rumpelpod explicitly restricts `build.args` via a restricted
`SubstitutionContext`:

```rust
let restricted = SubstitutionContext {
    resolve_local_env: ctx.resolve_local_env,
    ..Default::default()
};
```

This means only `${localEnv:...}` is resolved in `build.args`. Other
variables like `${localWorkspaceFolder}` and `${devcontainerId}` are left
as literal text.

### Comparison

Rumpelpod is stricter than the CLI. The CLI would resolve
`${localWorkspaceFolder}` inside `build.args`, while rumpelpod would not.
Rumpelpod's behavior more closely matches the spec's intent (the spec only
documents `${localEnv:...}` for `build.args`, and `${devcontainerId}`
explicitly excludes it). In practice, using workspace folder variables in
build args is unusual.


## Property Coverage

### CLI approach

The CLI uses a recursive `substitute0` function that walks all keys and
string values in the entire config object. It does not distinguish between
properties; every string in the config gets substitution.

### Rumpelpod approach

Rumpelpod uses exhaustive destructuring in `DevContainer::substitute()` and
explicitly decides which properties get substitution. Properties that do not
get substitution are passed through unchanged.

### Properties with substitution in rumpelpod

| Property | Rumpelpod | Spec says substitution | CLI |
|----------|-----------|----------------------|-----|
| `name` | Yes | Not explicitly, but `devcontainerId` table lists it | Yes (recursive) |
| `image` | **No** | Not explicitly | Yes (recursive) |
| `build.dockerfile` | **No** | Not explicitly | Yes (recursive) |
| `build.context` | **No** | Not explicitly | Yes (recursive) |
| `build.args` (values) | Yes (restricted) | Yes (`localEnv` only documented) | Yes |
| `build.options` | **No** | Not explicitly | Yes (recursive) |
| `build.target` | **No** | Not explicitly | Yes (recursive) |
| `build.cacheFrom` | **No** | Not explicitly | Yes (recursive) |
| `dockerfile` (legacy) | **No** | Not explicitly | Yes (recursive) |
| `context` (legacy) | **No** | Not explicitly | Yes (recursive) |
| `workspaceMount` | Yes | Yes | Yes |
| `workspaceFolder` | Yes | Yes | Yes |
| `runArgs` | Yes | Not explicitly, but `devcontainerId` table lists it | Yes (recursive) |
| `containerEnv` (values) | Yes | Yes | Yes |
| `remoteEnv` (values) | Yes | Yes | Yes |
| `containerUser` | Yes | Yes | Yes |
| `remoteUser` | Yes | Yes | Yes |
| `mounts` (string and object) | Yes | Yes | Yes |
| `initializeCommand` | Yes | Yes | Yes |
| `onCreateCommand` | Yes | Yes | Yes |
| `updateContentCommand` | Yes | Yes | Yes |
| `postCreateCommand` | Yes | Yes | Yes |
| `postStartCommand` | Yes | Yes | Yes |
| `postAttachCommand` | Yes | Yes | Yes |
| `forwardPorts` | No | No | Yes (recursive) |
| `portsAttributes` | No | No | Yes (recursive) |
| `otherPortsAttributes` | No | No | Yes (recursive) |
| `capAdd` | No | No | Yes (recursive) |
| `securityOpt` | No | No | Yes (recursive) |
| `features` | No | No | Yes (recursive) |
| `customizations` | No | Not explicitly, but `devcontainerId` table lists it | Yes (recursive) |
| `hostRequirements` | No | No | Yes (recursive) |

### Notable gaps in rumpelpod

- `image`: Not substituted. If a devcontainer.json uses
  `${localEnv:REGISTRY}/myimage`, it would not be resolved. The spec does
  not explicitly say `image` supports substitution, but the CLI handles it
  by virtue of its recursive approach.

- `customizations`: Not substituted. The `devcontainerId` variable table
  explicitly lists `customizations` as an applicable property. Rumpelpod
  does not process it.

- `build.options`, `build.target`, `build.cacheFrom`: Not substituted. The
  spec does not explicitly require this, but the CLI handles it.


## devcontainerId Computation

### CLI

The CLI computes `devcontainerId` from container id labels:

```typescript
function devcontainerIdForLabels(idLabels: Record<string, string>): string {
    const stringInput = JSON.stringify(idLabels, Object.keys(idLabels).sort());
    const hash = crypto.createHash('sha256').update(Buffer.from(stringInput, 'utf-8')).digest();
    return BigInt(`0x${hash.toString('hex')}`).toString(32).padStart(52, '0');
}
```

- Input: Container labels like `{"devcontainer.config_file": "/path/to/devcontainer.json", "devcontainer.local_folder": "/path/to/workspace"}`
- Hash: SHA-256
- Encoding: Base-32, zero-padded to 52 characters
- Format: `/^[0-9a-v]{52}$/`

### Rumpelpod

```rust
pub fn compute_devcontainer_id(repo_path: &Path, pod_name: &str) -> String {
    let label_json = serde_json::json!({
        "rumpelpod.name": pod_name,
        "rumpelpod.repo_path": repo_path.to_string_lossy(),
    });
    let normalized = serde_json::to_string(&label_json).expect("...");
    let hash = Sha256::digest(normalized.as_bytes());
    hex::encode(hash)
}
```

- Input: JSON with `rumpelpod.name` and `rumpelpod.repo_path`
- Hash: SHA-256
- Encoding: Hexadecimal, 64 characters
- Format: `/^[0-9a-f]{64}$/`

### Differences

| Aspect | CLI | Rumpelpod |
|--------|-----|-----------|
| Input data | Host folder path + config file path | Repo path + pod name |
| Label keys | `devcontainer.local_folder`, `devcontainer.config_file` | `rumpelpod.name`, `rumpelpod.repo_path` |
| Encoding | Base-32 (52 chars) | Hex (64 chars) |
| Uniqueness scope | Per workspace folder + config file | Per repo path + pod name |

These produce different IDs for the same workspace. This is acceptable
because the `devcontainerId` is only used within a single tool's containers
(e.g., naming volumes). Cross-tool volume sharing is not a use case, and the
spec only requires stability and uniqueness, not a specific algorithm.

Rumpelpod's inclusion of `pod_name` in the hash means that different pods in
the same repo get different IDs, which is correct for rumpelpod's multi-pod
model.


## containerEnv Resolution Mechanism

### CLI

The CLI resolves `${containerEnv:VAR}` by reading the container's environment
from its inspect data or from the process environment inside the container.
The `containerSubstitute` function receives a `containerEnv` object (built
from `container.Config.Env`), and looks up variables in that object directly
in memory.

### Rumpelpod

Rumpelpod resolves `${containerEnv:VAR}` by spawning
`docker exec <container_id> printenv <VAR>` for each variable reference. This
is done in `read_container_env_var`:

```rust
fn read_container_env_var(docker_socket: &Path, container_id: &str, var_name: &str) -> Option<String> {
    let output = std::process::Command::new("docker")
        .args(["-H", &format!("unix://{}", docker_socket.display())])
        .args(["exec", container_id, "printenv", var_name])
        .output()
        .ok()?;
    // ...
}
```

### Differences

- **Performance**: Rumpelpod spawns a `docker exec` process per variable.
  With many `${containerEnv:...}` references, this could be slow. The CLI
  reads the environment once from container inspect data.

- **Accuracy**: Rumpelpod's approach reads the live runtime environment,
  which includes variables set by shell init files or entrypoint scripts.
  The CLI reads `container.Config.Env`, which only includes variables
  declared in the image or set at container creation time.

- **Scope**: Rumpelpod only resolves `containerEnv` in `remoteEnv` values
  (via `resolve_remote_env` in enter.rs). The CLI resolves it across all
  config properties.


## Bugs and Gaps

### 1. Missing ${env:VAR} alias

**Severity**: Low.
The CLI supports `${env:VAR}` as an alias for `${localEnv:VAR}`. Rumpelpod
does not. The spec does not document this alias, so this is not a spec
violation, but devcontainer.json files written for VS Code may use it.

### 2. Default value parsing divergence

**Severity**: Low.
For `${localEnv:VAR:default:extra}`, rumpelpod uses `"default:extra"` as
the default while the CLI uses `"default"`. This only matters when defaults
contain colons, which is uncommon.

### 3. customizations not substituted

**Severity**: Low.
The spec's `devcontainerId` variable table lists `customizations` as an
applicable property. Rumpelpod does not apply substitution to `customizations`.
In practice, rumpelpod does not process `customizations` at all (they are
tool-specific settings for VS Code etc.), so this is unlikely to matter.

### 4. image property not substituted

**Severity**: Low.
The CLI substitutes all string properties including `image`. Rumpelpod does
not. If a user writes `"image": "${localEnv:REGISTRY}/myimage:latest"`, it
would work in the CLI but not in rumpelpod. The spec does not explicitly
list `image` as supporting substitution.

### 5. containerEnv scope

**Severity**: Low.
The spec says `${containerEnv:...}` is only for `remoteEnv`. Rumpelpod
correctly limits `containerEnv` resolution to `remoteEnv`. The CLI resolves
it across all properties (broader than spec).

### 6. devcontainerId format incompatibility

**Severity**: None in practice.
The CLI produces a 52-character base-32 string; rumpelpod produces a
64-character hex string. This does not matter because the IDs are only used
within each tool's own container infrastructure.

### 7. build.args allows localWorkspaceFolder in CLI but not rumpelpod

**Severity**: Low.
The CLI's recursive substitution resolves `${localWorkspaceFolder}` in
`build.args`. Rumpelpod restricts `build.args` to `localEnv` only. The spec
says "Any" for `localWorkspaceFolder`, which could include `build.args`, but
the spec's example for `build.args` only shows `localEnv`.
