# Claude subcommand testing via API proxy

## Background

The `rumpel agent` subcommand makes LLM API calls from the **host** side.
Tests cache these via `LlmCache` (see `llm-cache/README.md`): requests are
hashed and responses stored as JSON files in the repo.

The `rumpel claude` subcommand is different: it launches the Claude CLI
**inside the container**. The Claude CLI makes its own API calls. We
currently have no tests for this path.

## Feasibility (confirmed via experiment)

The Claude CLI respects `ANTHROPIC_BASE_URL`. Setting it to a local HTTP
server redirects all API traffic there. Combined with
`ANTHROPIC_API_KEY=dummy`, no real credentials are needed when serving
cached responses.

Request bodies are **byte-for-byte deterministic** across runs when the
following three CLI flags / env vars are used:

| Source of non-determinism      | Fix                                              |
|--------------------------------|--------------------------------------------------|
| Session UUID in `metadata`     | `--session-id 00000000-0000-0000-0000-000000000001` |
| Current date in system-reminder| `faketime '2025-01-15 12:00:00'`                 |
| Session persistence side effects | `--no-session-persistence`                     |

This was validated over 10 consecutive runs: all produced the identical
raw-bytes request body (same md5).

Node.js / V8 preserves object property insertion order (ES2015 spec), so
JSON.stringify output is stable. There is no hash-seed randomization.

### Request pattern

For a simple prompt, the Claude CLI makes 2-3 requests per turn:

1. `POST /v1/messages?beta=true` -- streaming SSE, main model (the LLM call)
2. `POST /v1/messages/count_tokens?beta=true` -- non-streaming JSON
3. `POST /v1/messages?beta=true` -- non-streaming or streaming, haiku model
   (auxiliary: file-path extraction from tool output, etc.)

For tool-use turns, the main model request repeats with the tool result
appended to the message list.

## Architecture

```
  Host (test process)                       Container (sandbox)
  +--------------------------+              +---------------------+
  |                          |              |                     |
  |  Test case               |              |  claude CLI         |
  |    |                     |              |    |                |
  |    +-> rumpel claude ... |              |    +-> POST /v1/... |
  |         |                |              |         |           |
  |         +-> docker exec  +---bridge---->|         |           |
  |              (screen + claude)          |         |           |
  |                          |              |         |           |
  |  Claude test proxy       |<--ANTHROPIC_BASE_URL---+           |
  |  (bound to bridge IP)    |              |                     |
  |    |                     |              +---------------------+
  |    +-> llm-cache lookup  |
  |    +-> (on miss) real API|
  |    +-> store in cache    |
  +--------------------------+
```

The proxy binds to the Docker bridge gateway IP (typically 172.17.0.1,
discovered the same way the git HTTP server does it). The container
reaches it via `ANTHROPIC_BASE_URL=http://172.17.0.1:<port>`.

## Implementation plan

### 1. Test image: install claude CLI, screen, faketime

The `build_test_image` helper in `tests/cli/common.rs` accepts
`extra_dockerfile_lines`. Claude tests will need a dedicated image with:

```dockerfile
USER root
RUN apt-get update && apt-get install -y screen faketime curl
# Install claude CLI (pinned version for reproducibility)
RUN curl -fsSL https://cli.anthropic.com/install.sh | sh
USER testuser
```

Pinning the Claude CLI version is important: upgrades can change the
system prompt, tool definitions, or request structure, which would
invalidate the entire cache. We should pin by checking the installed
version and failing loudly if it drifts. Investigate whether the install
script supports version pinning; otherwise, download a specific binary.

### 2. Claude test proxy (Rust, in-process)

Add a new test utility, conceptually similar to the git HTTP server but
for Anthropic API caching. It should live in a new test module, e.g.
`tests/cli/claude/proxy.rs`.

**Global singleton via `OnceLock`:**

```rust
use std::sync::OnceLock;

struct ClaudeTestProxy {
    port: u16,
    addr: String,  // e.g. "172.17.0.1"
}

static CLAUDE_PROXY: OnceLock<ClaudeTestProxy> = OnceLock::new();

fn claude_proxy() -> &'static ClaudeTestProxy {
    CLAUDE_PROXY.get_or_init(|| {
        // Bind to bridge gateway IP, port 0 (auto-assign)
        // Start background tokio task to serve requests
    })
}
```

A single proxy instance is shared across all claude test cases.

**Request serialization via a global Mutex:**

When two tests run in parallel and both trigger a cache miss for the same
request, we would make two real API calls and get potentially different
responses, corrupting the cache. To avoid this, all cache-miss API
forwarding is serialized behind a Mutex:

```rust
// Simplified sketch
static API_FORWARD_LOCK: Mutex<()> = Mutex::new(());

async fn handle_request(req: Request) -> Response {
    let cache_key = compute_key(&req);

    // Cache lookup is lock-free (read-only, files are immutable once written)
    if let Some(cached) = cache.get(&cache_key) {
        return cached;
    }

    // Serialize all cache-miss forwarding
    let _guard = API_FORWARD_LOCK.lock().unwrap();

    // Double-check after acquiring lock (another thread may have just populated it)
    if let Some(cached) = cache.get(&cache_key) {
        return cached;
    }

    let response = forward_to_anthropic(&req).await;
    cache.put(&cache_key, &response);
    response
}
```

This makes cache regeneration slower (one API call at a time), but keeps
things simple and avoids race conditions. Cache hits (the normal test
path) remain fully parallel.

**Streaming support:**

The main Claude CLI requests use streaming SSE. The proxy must:
- On cache miss: forward the request, collect the **full SSE event
  stream** as bytes, store it, and replay it to the client.
- On cache hit: replay the stored SSE byte stream with correct
  `Content-Type: text/event-stream` headers.

The cache stores raw response bytes (headers + body), not parsed JSON.
This avoids having to understand the SSE format for caching purposes.

**Offline mode (`RUMPELPOD_TEST_LLM_OFFLINE`):**

Same behavior as the agent cache: when `RUMPELPOD_TEST_LLM_OFFLINE=1`
(the default in tests), cache misses return an error response instead of
forwarding. The error message tells the developer to re-run with
`RUMPELPOD_TEST_LLM_OFFLINE=0` to populate the cache. This ensures CI
never silently makes real API calls.

### 3. Injecting `ANTHROPIC_BASE_URL` into the container

The `rumpel claude` command already injects `remoteEnv` variables from
devcontainer.json into the `docker exec` environment (via `merge_env`).
This is the cleanest mechanism.

Claude tests write their own devcontainer.json (like the remote_env
tests do). They include:

```json
{
    "remoteEnv": {
        "ANTHROPIC_BASE_URL": "${localEnv:ANTHROPIC_BASE_URL}",
        "ANTHROPIC_API_KEY": "${localEnv:ANTHROPIC_API_KEY}"
    }
}
```

The test harness sets `ANTHROPIC_BASE_URL=http://<bridge_ip>:<port>` and
`ANTHROPIC_API_KEY=dummy-for-test` in its own process environment before
invoking `rumpel claude`. The `${localEnv:...}` substitution forwards
these into the container's `docker exec` environment.

### 4. Cache key computation

The cache key is a SHA-256 hash of the **raw request bytes** (method +
path + body). Headers are excluded because:
- `x-api-key` varies (dummy in tests vs real when populating)
- `Host` header changes with proxy port
- Stainless metadata headers are noise

The request body alone is sufficient because it already contains the
model, messages, tools, system prompt, and all parameters.

We reuse the existing `llm-cache/` directory structure, adding a new
subdirectory:

```
llm-cache/
  anthropic/       # existing: agent API cache
  gemini/          # existing: agent API cache
  xai/             # existing: agent API cache
  claude-cli/      # new: claude subcommand proxy cache
```

### 5. Invoking claude from tests

Tests use `rumpel claude <pod> -- <claude-args>` through a PTY (similar
to the agent interactive tests). The claude CLI is run in `--print` mode
for testability:

```rust
fn run_claude_in_pod(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
) -> String {
    let proxy = claude_proxy();

    let output = pod_command(repo, daemon)
        .env("ANTHROPIC_BASE_URL", &format!("http://{}:{}", proxy.addr, proxy.port))
        .env("ANTHROPIC_API_KEY", "dummy-for-test")
        .args([
            "claude", "test-pod",
            "--no-dangerously-skip-permissions",
            "--",
            "--print", prompt,
            "--no-session-persistence",
            "--session-id", "00000000-0000-0000-0000-000000000001",
            "--model", "claude-sonnet-4-5-20250929",
        ])
        .success()
        .expect("rumpel claude failed");

    String::from_utf8_lossy(&output).to_string()
}
```

**faketime**: The test image has `faketime` installed. The `rumpel claude`
command's screen wrapper (or a test-specific wrapper) prepends
`faketime '2026-02-15 12:00:00'` to the claude invocation. This could
be done by:
- Having the test pass an extra `--` arg that wraps the claude call, or
- Setting `LD_PRELOAD` and `FAKETIME` env vars via remoteEnv (faketime
  supports this without the wrapper binary).

The `LD_PRELOAD` + `FAKETIME` env var approach is cleaner:

```json
{
    "remoteEnv": {
        "LD_PRELOAD": "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
        "FAKETIME": "2026-02-15 12:00:00"
    }
}
```

### 6. Test structure

```
tests/
  cli/
    claude/
      mod.rs          # module declaration
      proxy.rs        # ClaudeTestProxy: HTTP server + LlmCache integration
      smoke.rs        # basic smoke test: simple prompt, verify output
```

The proxy is initialized lazily on first use (OnceLock). It runs for the
lifetime of the test process.

### 7. CLAUDE.md / project context

The Claude CLI injects `CLAUDE.md` content from the working directory
into its requests. Since tests run from a test repo (not the rumpelpod
repo), the system prompt will not contain rumpelpod's own CLAUDE.md.
This is fine and actually desirable -- it makes the requests smaller and
more stable.

If a test needs specific project context, it can write a CLAUDE.md into
the test repo.

### 8. Rollout order

1. **Proxy server** (`tests/cli/claude/proxy.rs`): HTTP server with
   cache lookup, SSE replay, serialized forwarding, offline mode.
2. **Test image builder**: helper that builds a claude-capable image
   (screen + faketime + claude CLI).
3. **Test harness**: helper functions to invoke `rumpel claude` with
   correct env vars, faketime, and session pinning.
4. **Smoke test**: single simple prompt, verify the response arrives.
5. **Cache population**: run once with `RUMPELPOD_TEST_LLM_OFFLINE=0`,
   commit the cache files.
6. **CI integration**: verify tests pass in offline mode.
