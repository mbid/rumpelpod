# Docker compose support

Status: implemented.

Scope: the docker engine only. Podman and Kubernetes are out of scope
for the first implementation; a section at the end records how the
design is expected to carry over to Kubernetes so that we do not paint
ourselves into a corner.

## Goals

Support devcontainer.json files that use `dockerComposeFile`,
`service`, and `runServices`. A pod then consists of the agent
container (the compose service named by `service`) plus sidecar
containers (the other services). Rumpelpod's security model is
unchanged: the agent container is untrusted, and all rumpelpod
machinery must keep working without granting the agent anything new.

## The compose model

Rumpelpod never parses compose YAML itself. The merged and
interpolated model is rendered once at pod creation with

    docker compose -f ... -f ... config --no-normalize --format json

which resolves multiple files, `extends`, profiles, and environment
interpolation with compose's own semantics. The rendered JSON is
persisted in the pod's database row, next to the stored
devcontainer.json, so that reconnect, fork, and recreate do not depend
on the host tree. It is also the engine-neutral internal model that a
future Kubernetes backend would consume.

`--no-normalize` keeps implicit network and volume names relative to
the project. Normalized output embeds the original project name in
those resources, which would make a fork share them with its source.

Rumpelpod influences the project not by editing the user's files but
by generating an additional override file passed as the last `-f`.
The override file is regenerated from persisted state whenever it is
needed; it is not a source of truth.

## Project identity, discovery, persistence

The compose project name is the existing PodId
(`rumpel-<basename>-<pod>-<hash>`), which already satisfies compose's
project name rules. One project per (repo_path, pod_name), so two pods
on the same repo get disjoint container sets, networks, and volumes.
The generated override resets explicit `container_name` values so they
cannot bypass the project namespace and collide across pods.

Compose labels every container with `com.docker.compose.project` and
`com.docker.compose.service`; container discovery goes through those
plus the existing rumpelpod labels, which the override file applies to
every service. The `dev.rumpelpod.name` label goes only on the agent
service so that per-repo listing continues to see one entry per pod;
sidecars carry only the repo path label.

Database changes: the pods table gains the agent service name and the
rendered compose config; forwarded_ports gains a service column.

Pod status is the agent container's status. Sidecars stopping is
normal compose behavior (one-shot services exist) and is not a pod
failure. Whole-project lifecycle uses compose: stop and start operate
via `docker compose -p <id>`, and delete is
`docker compose -p <id> down -v`. Removing named volumes on delete is
deliberate: pod deletion is destructive, and keeping sidecar data
around with no pod to use it would only leak. Note that recreate
therefore wipes sidecar volume contents; the dirty-patch and agent
state snapshots only cover the agent container.

## Image preparation

The two-stage build is unchanged; only the provenance of the base
image changes. For the agent service:

- `image:` in the compose file is used as the base directly.
- `build:` services use Compose's `build --with-dependencies` command
  rather than reimplementing Compose build semantics in our buildx path.
  Fidelity matters more here than our content-addressed skip; docker's
  layer cache keeps repeated builds cheap. The resulting image ID (not
  tag) is the base.

`build_prepared_image` runs on top of that base exactly as today. The
prepared tag hash additionally covers the base image ID, which is
content-addressed by docker itself, so an unchanged compose build
still hits the prepared image cache.

The override file replaces the agent service's `image:` with the
prepared image. Sidecar services with `build:` sections are built by
`docker compose build` before `up --no-build`. Their persisted build
entries are replaced with image IDs so reconnect and fork do not need
the original build contexts.

## Trust model

Sidecars fall into two kinds: those inside the agent's trust domain
(a throwaway database the agent migrates and breaks) and those that
should only expose a deliberately narrow interface to the agent (a
credential-holding proxy, an egress gateway).

Rumpelpod does not model this distinction. Docker networks have no
per-port policy, so the network is not a trust boundary rumpelpod
could enforce, and inventing rumpelpod-specific trust annotations was
considered and rejected: which services are trusted, which networks
they share, and which need a hardened runtime is the compose writer's
call, expressed with native compose constructs (per-service
`networks:`, per-service `runtime:` such as kata).

What rumpelpod owes the writer is that its own machinery never
crosses the boundaries the writer drew. Concretely: no rumpelpod
channel may route one container's traffic through a different
container. This rules out forwarding sidecar ports by proxying
through the agent container, which would let the untrusted agent read
and modify host-to-sidecar traffic.

## Getting rumpel into sidecars

Port forwarding needs `rumpel tcp-proxy` inside the target container.
rumpel is a fully static musl binary, so it runs in any Linux image,
including distroless images with no shell and no libc.

Injection is a plain `docker cp` into each non-agent container, done
after `docker compose up` and again on every reconnect. `docker cp`
is implemented daemon-side via the archive API: it needs no tar and no
shell in the image, works on created but never started containers, and
streams from the client, so remote engines over ssh work unchanged.
(This is unlike `kubectl cp`, which execs tar in the target.)

Details:

- Architecture is detected per container, because compose supports
  per-service `platform:` and emulation makes mixed-arch projects
  real even on one engine. The container inspect JSON is consulted
  first: under the containerd image store it carries
  `ImageManifestDescriptor.Platform.Architecture`, which names the
  exact variant the container was created from. Under the classic
  store that field is absent and the image is inspected by the ID
  from `.Image`; a classic-store image ID names a single-platform
  config, so this is exact. Never inspect by tag: a cross-platform
  pull retags a multi-arch tag in the classic store.
- Only amd64 and arm64 are supported; any other reported architecture
  is a hard error naming the service.
- The single matching binary is staged as
  `staged/opt/rumpelpod/bin/rumpel` with mode 755 and copied with
  `docker cp staged/. <ctr>:/`, so intermediate directories are
  created even on images without `/opt`, and later execs are
  architecture-blind. `docker cp` writes files root-owned; mode 755
  is what lets the service's configured user run the binary.
- Copies die with their container: no volume, no cleanup, and no
  shared object that one container could tamper with to poison what
  the daemon later execs in another.
- Services with `read_only: true` make `docker cp` fail. This is a
  hard error telling the writer to add a writable mount at
  `/opt/rumpelpod`; no automatic fallback.
- Container recreation outside rumpelpod (a manual
  `docker compose up` after editing the file) removes the copies, but
  it also invalidates any cached container IDs, so reconnect
  re-resolves containers via the compose labels and re-copies in the
  same pass.

The agent container is excluded: it gets rumpel baked into the
prepared image, and its copy must not be reachable from any other
container either.

## Port forwarding

Forwarding declarations stay in devcontainer.json; the compose file
declares what exists and how services see each other, while
`forwardPorts` declares what crosses out of the project to the
developer's machine.

- A number forwards a port of the agent service.
- A string `"<service>:<port>"` forwards a port of a sidecar and is
  valid only for compose pods. The service name is resolved against
  the compose model; unknown names are a hard error.
- The historical reading of `"a:b"` as a local:container port pair is
  dropped. The current code already discards the left half, the
  devcontainer spec has no such form (local port choice belongs to
  the client), and user-pinned local ports would collide across pods
  the same way published ports do. With it gone, string entries have
  exactly one meaning and there is no ambiguity with numeric service
  names.
- Invalid entries are a hard error instead of the current
  warn-and-skip.

Each forward keeps the existing mechanics: a stable loopback listener
bound by the daemon (near the container port, reclaimed from the
database on reconnect), and per connection one
`docker exec <ctr> rumpel tcp-proxy --port N` in the target service's
own container. The exec channel runs host to daemon to container, so
the agent is never in the path for sidecar traffic, sidecars need no
shared network with anything, and even loopback-only services are
forwardable. `rumpel forward-port` gains a `--service` flag.

Compose `ports:` entries (engine-level host publishing) are stripped
from every service in the override file, with a warning pointing at
`forwardPorts`. Published ports claim fixed engine-host ports, which
collide across pods and land on the wrong machine for remote engines,
and they default to binding all interfaces, which silently exposes
agent-reachable services to the engine host's network. Compose merges
`ports:` additively across files, so stripping requires the explicit
`!reset` tag in the override entry.

## overrideCommand

The spec default flips for compose: true for image and Dockerfile
devcontainers, false for compose, because compose services mean their
command (sidecars must run their workload, and compose devcontainer
files conventionally give the dev service `command: sleep infinity`
themselves). Rumpelpod follows the spec: compose pods run the agent
service's own command by default, and an explicit
`overrideCommand: true` makes the override file replace the agent
service's entrypoint and command with the keepalive. Single-container
pods keep today's behavior.

Consequence: with the false default, an agent service whose command
exits takes the pod down with it, a failure mode single-container
pods never had. The error path must say why the container is not
running (command exited, what to set) rather than reporting a generic
not-running state.

## Kubernetes outlook

There is no compose-on-Kubernetes layer to lean on: docker's stack
deploy orchestrator is discontinued and kompose is an offline, lossy
converter. The plan is that the persisted `docker compose config`
JSON acts as rumpelpod's multi-container model with per-backend
materializers: docker compose now, Kubernetes later (services map to
pods and Services, `runtime:` to RuntimeClass, and Kubernetes has the
per-port network policy docker lacks). Binary injection becomes an
init container populating an emptyDir, which needs nothing from
sidecar images at all and sidesteps kubectl cp's in-container tar
requirement. Mixed-architecture node pools are covered by the same
per-container architecture selection.

## Implementation order

1. Compose model rendering and override file generation. Pure
   functions over the rendered JSON; integration-testable without the
   daemon.
2. Launch, reconnect, stop, delete for compose pods, including the
   rumpel injection pass and database changes.
3. Port forwarding: the `"service:port"` form, direct exec into
   sidecars, `rumpel forward-port --service`.
4. forwardPorts parsing cleanup (drop the pair form, fail hard on
   invalid entries), `ports:` stripping, `overrideCommand` handling.
5. Docs: GUIDE.md deviations list, removing the three fields from the
   unsupported-warning list, flipping the warning tests into positive
   integration tests.
