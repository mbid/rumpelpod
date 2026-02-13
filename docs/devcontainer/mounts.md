# Mounts: Rumpelpod vs. Official Devcontainer CLI

This document compares rumpelpod's implementation of devcontainer.json mount
properties against the official devcontainer CLI (the reference
implementation at github.com/devcontainers/cli).

Sources examined:

- Rumpelpod: `src/devcontainer.rs` (types, parsing, variable substitution),
  `src/daemon.rs` (container creation, mount enforcement),
  `tests/cli/devcontainer/mounts.rs` (integration tests)
- Official CLI: `src/spec-configuration/containerFeaturesConfiguration.ts`
  (Mount interface, parseMount), `src/spec-node/imageMetadata.ts`
  (mergeMounts, dedup by target), `src/spec-node/singleContainer.ts`
  (container creation), `src/spec-node/dockerfileUtils.ts`
  (generateMountCommand), `src/spec-node/devContainersSpecCLI.ts`
  (CLI --mount flag regex)

---

## Feature Comparison Table

| Feature                        | Official CLI             | Rumpelpod                | Notes                              |
|--------------------------------|--------------------------|--------------------------|------------------------------------|
| String format mounts           | Yes                      | Yes                      | Both support comma-separated pairs |
| Object format mounts           | Yes                      | Yes                      | Both support `{type, source, target}` |
| Mount type: bind               | Yes                      | Yes (blocked on remote)  | See "Architectural Limitations"    |
| Mount type: volume             | Yes                      | Yes                      | Full parity                        |
| Mount type: tmpfs              | No (not in schema)       | Yes                      | Rumpelpod extension                |
| `external` property            | Yes                      | No                       | Missing from MountObject           |
| `readOnly` / `readonly`        | Not in Mount interface   | Yes                      | Rumpelpod extends spec             |
| Variable substitution          | Yes                      | Yes                      | Both substitute mounts             |
| Unresolved variable detection  | No explicit check        | Yes                      | Rumpelpod rejects leftover `${`    |
| Dedup by target (merge)        | Yes                      | No                       | Rumpelpod has no image metadata    |
| workspaceMount                 | Yes                      | Unsupported (warns)      | Rumpelpod uses Git-based sync      |
| CLI --mount flag               | Yes (strict regex)       | No CLI --mount flag      | Rumpelpod only reads JSON config   |

---

## String Format Parsing Comparison

Both implementations parse Docker `--mount`-style strings: comma-separated
`key=value` pairs. The details differ in several ways.

### Key aliases

| Key alias     | Official CLI | Rumpelpod |
|---------------|--------------|-----------|
| `type`        | Yes          | Yes       |
| `source`      | Yes          | Yes       |
| `src`         | Yes          | Yes       |
| `target`      | Yes          | Yes       |
| `destination` | Yes          | Yes       |
| `dst`         | Yes          | Yes       |
| `readonly`    | No           | Yes       |
| `ro`          | No           | Yes       |
| `external`    | No (*)       | No        |

(*) The official CLI's `parseMount()` function does not explicitly handle
`readonly`, `ro`, or `external` as key aliases; however, its generic
key=value reducer means any key present in the string will end up as a
property on the returned object. The `external` key is only validated via the
CLI's `--mount` flag regex, not through `parseMount()`.

### Parsing approach

**Official CLI** (`containerFeaturesConfiguration.ts:115-119`):

```typescript
export function parseMount(str: string): Mount {
    return str.split(',')
        .map(s => s.split('='))
        .reduce((acc, [key, value]) => ({
            ...acc,
            [(normalizedMountKeys[key] || key)]: value
        }), {}) as Mount;
}
```

The official CLI normalizes keys via a lookup table (`src` -> `source`,
`destination` -> `target`, `dst` -> `target`) and then casts the resulting
object to the Mount interface. There is no validation that required fields
are present. Unrecognized keys are silently included in the object.

**Rumpelpod** (`devcontainer.rs:345-387`):

```rust
fn parse_string(s: &str) -> Result<Self> {
    // ...
    for part in s.split(',') {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "type" => mount_type = Some(value.to_string()),
                "source" | "src" => source = Some(value.to_string()),
                "target" | "destination" | "dst" => target = Some(value.to_string()),
                "readonly" | "ro" => {
                    read_only = Some(value == "true" || value == "1");
                }
                _ => {} // Ignore unknown keys
            }
        } else if part == "readonly" || part == "ro" {
            read_only = Some(true);
        }
    }
    let target = target.ok_or_else(|| anyhow!("mount string missing 'target': {s}"))?;
    // ...
}
```

Rumpelpod uses an explicit match on known keys and validates that `target`
is present, returning an error if not. Unknown keys are silently ignored.
It also handles bare `readonly` / `ro` (without `=value`), matching Docker's
own behavior where `readonly` alone means read-only.

### Key differences in string parsing

1. **Validation**: Rumpelpod validates that `target` is present and returns
   an error if missing. The official CLI does not validate and will produce
   a Mount object with an undefined `target`.

2. **Read-only handling**: Rumpelpod supports both `readonly=true` and bare
   `readonly` (without a value). The official CLI does not handle read-only
   in its string parser at all -- the Mount interface has no `readonly`
   field.

3. **Default type**: Both default to `bind` when `type` is omitted. In
   rumpelpod this is explicit (`None => MountType::Bind`). In the official
   CLI it happens implicitly because the type field is simply absent from
   the parsed object.

---

## Mount Type Support Comparison

### Official CLI

The Mount interface defines the type as a union of two string literals:

```typescript
export interface Mount {
    type: 'bind' | 'volume';
    source?: string;
    target: string;
    external?: boolean;
}
```

The CLI's `--mount` flag regex further confirms only bind and volume:

```typescript
const mountRegex = /^type=(bind|volume),source=([^,]+),target=([^,]+)
    (?:,external=(true|false))?$/;
```

There is no `tmpfs` in the official interface or validation.

### Rumpelpod

```rust
pub enum MountType {
    Bind,
    Volume,
    Tmpfs,
}
```

Rumpelpod adds `Tmpfs` as a third mount type. This is mapped to Docker's
`MountTypeEnum::TMPFS` in `daemon.rs` when creating the container. The
tmpfs type is tested in `tests/cli/devcontainer/mounts.rs::mount_tmpfs`.

### Assessment

Rumpelpod's tmpfs support is an **extension beyond the spec**. Docker
natively supports tmpfs mounts, and many devcontainer.json files use them in
practice (for example, to provide a fast scratch directory). The official
spec schema omits tmpfs, so devcontainer.json files using tmpfs mounts would
be rejected by strict schema validators but would work in rumpelpod.

---

## Object Format Comparison

### Official CLI Mount interface

```typescript
export interface Mount {
    type: 'bind' | 'volume';
    source?: string;
    target: string;
    external?: boolean;
}
```

### Rumpelpod MountObject struct

```rust
pub struct MountObject {
    pub mount_type: MountType,   // bind | volume | tmpfs
    pub source: Option<String>,
    pub target: String,
    pub read_only: Option<bool>,
}
```

### Field-by-field comparison

| Field      | Official CLI        | Rumpelpod             | Match? |
|------------|---------------------|-----------------------|--------|
| type       | `'bind' \| 'volume'` | `Bind \| Volume \| Tmpfs` | Rumpelpod is a superset |
| source     | Optional string     | Optional string       | Yes    |
| target     | Required string     | Required string       | Yes    |
| external   | Optional boolean    | Not present           | No     |
| read_only  | Not present         | Optional boolean      | No     |

The `external` and `read_only` fields are each present in only one
implementation. See the dedicated sections below.

---

## The `external` Property

### Official CLI behavior

The `external` boolean on a mount object indicates that the volume is
externally managed and should not be created or destroyed by the tool.
In Docker Compose mode, this maps to the `external: true` property on a
top-level volume definition (`dockerCompose.ts:759`).

For single container mode, the official CLI passes mounts via
`--mount` strings to `docker run`. Docker volumes referenced in `--mount`
are created implicitly if they do not exist; the `external` flag is
relevant primarily for Compose workflows and for the CLI's volume
lifecycle management.

### Rumpelpod behavior

Rumpelpod's `MountObject` struct does not have an `external` field. The
field is not deserialized from devcontainer.json and is not used anywhere
in the codebase.

Since rumpelpod does not manage volume lifecycle (it does not create or
destroy Docker volumes), the practical impact is minimal for the current
single-container workflow. However, if rumpelpod ever adds volume cleanup
on `rumpel rm`, the `external` flag would be needed to avoid destroying
externally managed volumes.

### Impact

Low for current usage. An `external: true` property in devcontainer.json
will be silently ignored during deserialization (serde skips unknown fields
by default unless `deny_unknown_fields` is set, which it is not).

---

## Read-Only Mounts

### Official CLI behavior

The official CLI's Mount interface does not include a `readonly` or
`readOnly` field. Read-only mounts are not part of the object schema.
In string format, `readonly` would be passed through to Docker as-is
since the string is forwarded directly to `--mount`.

### Rumpelpod behavior

Rumpelpod supports read-only mounts in both formats:

- **Object format**: The `read_only` field (serialized as `readOnly` in
  JSON due to `rename_all = "camelCase"`) maps to bollard's
  `BollardMount.read_only` field.
- **String format**: Both `readonly` and `ro` are recognized, with or
  without a value (`readonly`, `readonly=true`, `ro=1`).

The read-only flag is passed through to Docker's mount API when creating
the container (`daemon.rs:1002`).

### Assessment

Rumpelpod's read-only support is an extension that aligns with Docker's
native `--mount` syntax. It is useful and unlikely to conflict with the
spec, but devcontainer.json files relying on `readOnly` in the object
format would not work with the official CLI.

---

## Variable Substitution in Mounts

### Official CLI behavior

The official CLI applies variable substitution generically to all object
properties via `substitute0()`, which recursively walks the configuration
object and replaces `${...}` patterns in all string values. This
includes mount strings and mount object fields.

Supported variables: `${localEnv:VAR}`, `${localWorkspaceFolder}`,
`${localWorkspaceFolderBasename}`, `${containerWorkspaceFolder}`,
`${containerWorkspaceFolderBasename}`, `${devcontainerId}`,
`${containerEnv:VAR}`.

### Rumpelpod behavior

Rumpelpod applies substitution to mounts explicitly in
`DevContainer::substitute()` (`devcontainer.rs:722-734`):

```rust
let mounts = mounts.map(|v| {
    v.into_iter()
        .map(|m| match m {
            Mount::String(s) => Mount::String(sub(s)),
            Mount::Object(obj) => Mount::Object(MountObject {
                source: sub_opt(obj.source),
                target: sub(obj.target),
                mount_type: obj.mount_type,
                read_only: obj.read_only,
            }),
        })
        .collect()
});
```

Both string and object formats get variable substitution applied to
source and target. Rumpelpod supports the same set of variables as the
official CLI.

### Unresolved variable detection

Rumpelpod adds an extra safety check in `resolved_mounts()`
(`devcontainer.rs:844-856`):

```rust
for m in &mounts {
    for field in [m.source.as_deref(), Some(m.target.as_str())]
        .into_iter()
        .flatten()
    {
        if field.contains("${") {
            anyhow::bail!(
                "unresolved variable in mount: '{field}'. \
                 Check for typos in variable references."
            );
        }
    }
}
```

This rejects mounts that contain unresolved `${...}` references after
substitution, providing a clear error message instead of passing a
literal `${...}` string to Docker (which would fail with a confusing
error). The official CLI does not have an equivalent check.

---

## Deduplication by Target Path

### Official CLI behavior

The official CLI deduplicates mounts by target path when merging image
metadata from multiple sources (base image, features, devcontainer.json).
The `mergeMounts()` function in `imageMetadata.ts:263-277`:

```typescript
function mergeMounts(imageMetadata: ImageMetadataEntry[]) {
    const seen = new Set<string>();
    const mounts = imageMetadata.map(entry => entry.mounts)
        .filter(Boolean)
        .flat()
        .map(mount => ({
            obj: typeof mount === 'string' ? parseMount(mount) : mount!,
            orig: mount!,
        }))
        .reverse()
        .filter(mount =>
            !seen.has(mount.obj.target) && seen.add(mount.obj.target))
        .reverse()
        .map(mount => mount.orig);
    return mounts.length ? mounts : undefined;
}
```

The last definition for a given target path wins. This is important when
features or base images define mounts that the devcontainer.json wants to
override.

### Rumpelpod behavior

Rumpelpod does not perform any deduplication of mounts. The
`resolved_mounts()` method parses all mounts from devcontainer.json and
returns them as-is. If two mounts target the same path, both are passed
to Docker, which will apply the last one.

### Assessment

This difference has low practical impact because rumpelpod does not
implement Dev Container Features (which are the primary source of
multiple mount definitions for the same target). Without features, the
only mount source is devcontainer.json itself, where duplicate targets
would be a user error. Docker's own behavior of applying the last mount
for a given target provides an implicit dedup.

If rumpelpod ever adds feature support, deduplication would need to be
implemented.

---

## Architectural Limitations: Bind Mounts on Remote Docker

### Rumpelpod's bind mount restriction

Rumpelpod blocks bind mounts when the Docker host is remote
(`daemon.rs:1994-2005`):

```rust
if docker_host.is_remote() {
    for m in &mounts {
        if m.mount_type == devcontainer::MountType::Bind {
            anyhow::bail!(
                "bind mounts are not supported with remote Docker hosts. \
                 The source path '{}' would reference the remote filesystem, \
                 not your local machine. Use volume or tmpfs mounts instead.",
                m.source.as_deref().unwrap_or("<none>")
            );
        }
    }
}
```

This is enforced after variable substitution and mount parsing, but
before container creation. The error message explains why and suggests
alternatives.

### Official CLI behavior

The official CLI does not have an equivalent restriction. It passes bind
mount source paths to Docker regardless of whether the Docker host is
local or remote. When using a remote Docker host, bind mount sources
reference the remote filesystem, which may or may not be the user's
intent.

### Rationale

Rumpelpod's restriction is a deliberate safety measure. Because rumpelpod
uses Git-based sync instead of bind-mounting the workspace, there is no
mechanism to make host files available on a remote Docker host. A bind
mount source like `/home/user/data` would reference a path on the remote
machine, which is almost certainly not what the developer intended.

Volume and tmpfs mounts work correctly on remote Docker because they do
not reference the host filesystem.

This restriction is covered by the integration test
`mount_bind_blocked_remote` in `tests/cli/devcontainer/mounts.rs`.

---

## Docker API Integration

### Official CLI

The official CLI constructs `docker run` arguments as strings, passing
mounts via `--mount` flags:

```typescript
const featureMounts = ([] as string[]).concat(
    ...[
        ...mergedConfig.mounts || [],
        ...params.additionalMounts,
    ].map(m => generateMountCommand(m))
);
```

`generateMountCommand()` converts Mount objects to `--mount` strings like
`type=volume,src=foo,dst=/bar`. String-format mounts are passed through
unchanged.

### Rumpelpod

Rumpelpod uses the bollard Docker API library, converting MountObject
structs to bollard's `Mount` type (`daemon.rs:986-1004`):

```rust
let bollard_mounts = if mounts.is_empty() {
    None
} else {
    Some(
        mounts.iter().map(|m| {
            let typ = match m.mount_type {
                MountType::Bind => MountTypeEnum::BIND,
                MountType::Volume => MountTypeEnum::VOLUME,
                MountType::Tmpfs => MountTypeEnum::TMPFS,
            };
            BollardMount {
                target: Some(m.target.clone()),
                source: m.source.clone(),
                typ: Some(typ),
                read_only: m.read_only,
                ..Default::default()
            }
        }).collect()
    )
};
```

This is a programmatic approach rather than string concatenation, which
avoids quoting and escaping issues with paths that contain special
characters.

---

## Summary of Differences

### Rumpelpod implements but the official CLI does not

- **tmpfs mount type**: Practical extension beyond the spec schema.
- **Read-only mounts**: Both object (`readOnly`) and string (`readonly`,
  `ro`) formats.
- **Unresolved variable detection**: Rejects `${...}` in mount paths
  after substitution.
- **Bind mount restriction on remote Docker**: Safety measure for
  remote backends.
- **String parsing validation**: Requires `target` to be present.

### Official CLI implements but rumpelpod does not

- **`external` property**: Indicates a volume should not be managed by
  the tool.
- **Dedup by target path**: When merging mounts from image metadata
  (base image + features + devcontainer.json), the last definition for a
  given target wins.
- **workspaceMount**: Rumpelpod warns and ignores this property because
  it uses Git-based sync instead of bind-mounting the workspace.

### Parity

- String and object mount formats
- Variable substitution in mount source and target
- Volume and bind mount types
- `source` as optional (for tmpfs-like mounts without a source)
- Key aliases in string format (`src`, `dst`, `destination`)
