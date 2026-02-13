# Devcontainer Image and Build: Rumpelpod vs Official CLI

Comparison of how rumpelpod and the official devcontainer CLI handle image
and build configuration properties from devcontainer.json.

**Source files referenced:**

- Rumpelpod: `src/devcontainer.rs` (types, parsing, path resolution),
  `src/image.rs` (docker build invocation), `src/enter.rs` (config loading)
- CLI: `src/spec-node/singleContainer.ts` (build orchestration),
  `src/spec-node/utils.ts` (context/dockerfile path helpers),
  `src/spec-configuration/configuration.ts` (types),
  `src/spec-node/imageMetadata.ts` (metadata merging),
  `src/spec-node/configContainer.ts` (JSONC parsing)


## Feature Comparison Table

| Property             | Official CLI                              | Rumpelpod                                  | Match? |
|----------------------|-------------------------------------------|--------------------------------------------|--------|
| `image`              | Pull + run                                | Pull + run                                 | Yes    |
| `build.dockerfile`   | Resolved relative to devcontainer.json    | Resolved relative to devcontainer.json     | Yes    |
| `build.context`      | Resolved relative to devcontainer.json; defaults to Dockerfile parent dir | Resolved relative to devcontainer.json; defaults to `"."` (devcontainer.json dir) | **Differs** |
| `build.args`         | Passed as `--build-arg`; only `${localEnv:...}` substitution | Passed as `--build-arg`; only `${localEnv:...}` substitution | Yes    |
| `build.options`      | Appended as raw CLI flags                 | Appended as raw CLI flags                  | Yes    |
| `build.target`       | Passed as `--target`                      | Passed as `--target`                       | Yes    |
| `build.cacheFrom`    | Passed as `--cache-from` (string or array)| Passed as `--cache-from` (string or array) | Yes    |
| `dockerfile` (legacy)| Accepted as `dockerFile` (capital F); merged into build config | Accepted as `dockerfile` (lowercase f); merged into build | **Differs** |
| `context` (legacy)   | Accepted at top level; used if `build.context` absent | Accepted at top level; used if `build.context` absent | Yes    |
| JSONC parsing        | Uses `jsonc-parser` library               | Uses `json5` crate                         | Compatible |
| Image metadata       | Reads `devcontainer.metadata` label from images and merges | Not implemented                            | **Missing** |
| BuildKit/buildx      | Full support (buildx, --platform, --push, --cache-to) | Not supported (always uses `docker build`) | **Missing** |


## Build Option Handling Details

### build.dockerfile and build.context

Both implementations resolve `build.dockerfile` relative to the directory
containing devcontainer.json, which matches the spec.

**Context default differs.** When `build.context` is not set:

- The CLI defaults to the **parent directory of the Dockerfile**. For example,
  if devcontainer.json is at `.devcontainer/devcontainer.json` and
  `build.dockerfile` is `../docker/Dockerfile`, the default context is
  `../docker/`.
- Rumpelpod defaults to `"."` (the devcontainer.json directory itself). In
  the same example, the context would be `.devcontainer/`.

In the common case where the Dockerfile lives alongside devcontainer.json
(e.g., `.devcontainer/Dockerfile`), both defaults produce the same result.
The behavior diverges only when the Dockerfile is in a different directory
and `build.context` is omitted.

**Relevant code:**

CLI (`src/spec-node/utils.ts`):
```typescript
export function getDockerContextPath(cliHost, config) {
    const context = 'dockerFile' in config ? config.context : config.build.context;
    if (context) {
        return getConfigFilePath(cliHost, config, context);
    }
    return parentURI(getDockerfilePath(cliHost, config));
}
```

Rumpelpod (`src/devcontainer.rs`):
```rust
let context = self.build.as_ref()
    .and_then(|b| b.context.clone())
    .or_else(|| self.context.take())
    .unwrap_or_else(|| ".".to_string());
```

### build.args

Both implementations correctly pass build args as `--build-arg KEY=VALUE`
flags. Both correctly restrict variable substitution in `build.args` to
only `${localEnv:...}`, per the spec.

Rumpelpod (`src/devcontainer.rs` lines 702-710):
```rust
let restricted = SubstitutionContext {
    resolve_local_env: ctx.resolve_local_env,
    ..Default::default()
};
BuildOptions {
    args: b.args.map(|m| {
        m.into_iter()
            .map(|(k, v)| (k, substitute_vars(&v, &restricted)))
            .collect()
    }),
    ...
}
```

### build.target

Both pass `--target <target>` to `docker build`. The CLI additionally has
logic to handle the target in the context of Features (injecting stages into
the Dockerfile), which rumpelpod does not do since it does not support
Features.

### build.cacheFrom

Both handle `cacheFrom` as either a single string or an array of strings,
passing each as `--cache-from <value>`.

Rumpelpod also includes `cacheFrom` values in its content-addressed image
tag hash, so changing cache sources triggers a rebuild. The CLI does not
do content-addressed image tagging.

### build.options

Both append `build.options` as raw CLI flags to the docker build command.

### Docker build invocation

The CLI supports two modes:
1. **BuildKit/buildx** -- uses `docker buildx build` with `--load`,
   `--platform`, `--push`, `--cache-to`, `BUILDKIT_INLINE_CACHE` options.
2. **Classic** -- uses `docker build`.

Rumpelpod always uses `docker build` (classic mode). It does not support
buildx, multi-platform builds, or remote push.

Rumpelpod adds `--rm` to every build. The CLI does not explicitly pass
`--rm` (Docker's default is `--rm=true` anyway).

### Image caching strategy

The CLI relies on Docker's standard layer caching and `--cache-from`.

Rumpelpod computes a SHA-256 hash over the Dockerfile content, context
path, build args, target, options, and cacheFrom values, then uses this as
the image tag (`rumpelpod-devcontainer-<hash>`). Before building, it checks
whether an image with that tag already exists via `docker image inspect`. If
so, the build is skipped entirely, avoiding the cost of sending context to
the Docker daemon. This is especially useful for remote Docker hosts.


## Legacy Property Handling

### Legacy `dockerfile` / `dockerFile`

The official CLI uses `dockerFile` (capital F) as the legacy top-level
property name. This is defined in
`src/spec-configuration/configuration.ts`:
```typescript
{
    dockerFile: string;
    context?: string;
    build?: { target?, args?, cacheFrom?, options? };
}
```

Rumpelpod uses `#[serde(rename_all = "camelCase")]` on its `DevContainer`
struct, where the Rust field is named `dockerfile`. The `camelCase`
transform converts `dockerfile` to `"dockerfile"` in JSON -- it does NOT
produce `"dockerFile"`. This means:

- A devcontainer.json with `"dockerfile": "Dockerfile"` is parsed correctly
  by rumpelpod.
- A devcontainer.json with `"dockerFile": "Dockerfile"` (capital F, as
  the official spec uses) is **silently ignored** by rumpelpod.

This is a compatibility gap. Any devcontainer.json that uses the
`"dockerFile"` spelling (which is the legacy name used by VS Code and the
official CLI) will not be recognized by rumpelpod.

### Legacy `context`

Both implementations accept a top-level `context` property and merge it
into the build configuration when `build.context` is absent. The merge
logic is functionally equivalent.


## Image Metadata

### What the CLI does

The official CLI reads a `devcontainer.metadata` label from Docker images
and containers (`src/spec-node/imageMetadata.ts`):

```typescript
export const imageMetadataLabel = 'devcontainer.metadata';

function internalGetImageMetadata0(imageDetails, output) {
    const str = (imageDetails.Config.Labels || {})[imageMetadataLabel];
    if (str) {
        const obj = JSON.parse(str);
        if (Array.isArray(obj)) return obj;
        if (obj && typeof obj === 'object') return [obj];
    }
    return [];
}
```

This metadata is an array of `ImageMetadataEntry` objects that can carry
properties like `remoteUser`, `containerEnv`, `mounts`, `customizations`,
lifecycle commands, `init`, `privileged`, `capAdd`, `securityOpt`, etc.

The CLI merges this image-embedded metadata with the devcontainer.json
configuration using `mergeConfiguration()`. This allows a base image to
ship default devcontainer settings (e.g., the Microsoft universal image
sets `remoteUser: "codespace"` and lifecycle commands via metadata labels).

When Features are applied, the CLI writes updated metadata back into the
image as a label, creating a layered configuration chain:
base image metadata -> Feature metadata -> devcontainer.json overrides.

### What rumpelpod does

Rumpelpod does **not** read `devcontainer.metadata` labels from images.
There is no code referencing this label anywhere in the codebase.

This means:
- Base images that embed devcontainer configuration via labels (common with
  Microsoft's devcontainer images) will not have those settings applied.
- Properties like `remoteUser` or `containerEnv` set in image metadata
  will be ignored.
- For image-based devcontainers (`"image": "..."`), only properties
  explicitly written in devcontainer.json take effect.

This is a significant gap for users of pre-built devcontainer images that
rely on embedded metadata.


## JSONC / JSON5 Parsing Compatibility

The official CLI uses the `jsonc-parser` npm package (from the VS Code
ecosystem) to parse devcontainer.json files. This supports:
- Single-line comments (`// ...`)
- Multi-line comments (`/* ... */`)
- Trailing commas

Rumpelpod uses the `json5` Rust crate (`json5::from_str`). JSON5 is a
superset of JSON that supports:
- Single-line comments (`// ...`)
- Multi-line comments (`/* ... */`)
- Trailing commas
- Unquoted keys
- Single-quoted strings
- Hexadecimal numbers
- Leading/trailing decimal points
- Infinity and NaN
- Multi-line strings (escaped newlines)

Since JSON5 is a strict superset of JSONC, any valid devcontainer.json that
the official CLI can parse will also be parsed correctly by rumpelpod's
`json5::from_str()`. The json5 crate additionally accepts some constructs
that JSONC would reject (like unquoted keys), but this is a non-issue in
practice since devcontainer.json files are written to be valid JSONC.

**Verdict: fully compatible.** The json5 crate is a suitable replacement for
jsonc-parser when parsing devcontainer.json.


## Summary of Gaps

1. **Legacy `dockerFile` property (capital F):** Rumpelpod deserializes the
   field as `"dockerfile"` (all lowercase). Devcontainer configs using
   `"dockerFile"` (the official legacy name) are silently ignored.

2. **Default build context when omitted:** Rumpelpod defaults to the
   devcontainer.json directory (`"."`). The CLI defaults to the Dockerfile's
   parent directory. Different results only when Dockerfile is outside the
   devcontainer.json directory and context is not explicitly set.

3. **Image metadata merging:** Rumpelpod does not read
   `devcontainer.metadata` labels from images. Pre-built images with
   embedded configuration (common with Microsoft devcontainer images) will
   not have their settings applied.

4. **BuildKit / buildx support:** Rumpelpod uses `docker build` only. No
   support for `buildx`, multi-platform builds, `--push`, or `--cache-to`.
