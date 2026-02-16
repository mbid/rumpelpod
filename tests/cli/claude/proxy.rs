//! HTTP proxy for caching Claude CLI API requests in tests.
//!
//! Binds to the Docker bridge gateway IP so containers can reach it.
//! Caches responses to llm-cache/claude-cli/ for deterministic offline replay.
//!
//! A single proxy instance is shared across all claude tests (via OnceLock).
//! Cache hits are lock-free; cache-miss forwarding is serialized behind a
//! Mutex to prevent duplicate API calls from parallel tests.

#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::runtime::Runtime;

pub struct ClaudeTestProxy {
    pub port: u16,
    /// IP address containers should use to reach the proxy.
    pub addr: String,
    _runtime: Runtime,
}

static CLAUDE_PROXY: OnceLock<ClaudeTestProxy> = OnceLock::new();

/// Serializes cache-miss API forwarding to prevent duplicate API calls
/// when parallel tests trigger misses for the same request.
static API_FORWARD_LOCK: Mutex<()> = Mutex::new(());

/// Get or initialize the global claude test proxy.
pub fn claude_proxy() -> &'static ClaudeTestProxy {
    CLAUDE_PROXY.get_or_init(|| {
        let (bind_ip, container_ip) = if cfg!(target_os = "macos") {
            ("0.0.0.0".to_string(), "host.docker.internal".to_string())
        } else {
            let ip = get_bridge_gateway_ip();
            (ip.clone(), ip)
        };

        let addr: SocketAddr = format!("{}:0", bind_ip)
            .parse()
            .expect("parse bind address");

        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .expect("create proxy socket");
        socket
            .set_reuse_address(true)
            .expect("set SO_REUSEADDR on proxy socket");
        socket.bind(&addr.into()).expect("bind proxy socket");
        socket.listen(128).expect("listen on proxy socket");

        let std_listener: TcpListener = socket.into();
        std_listener
            .set_nonblocking(true)
            .expect("set proxy socket nonblocking");

        let port = std_listener
            .local_addr()
            .expect("get proxy local addr")
            .port();

        std::fs::create_dir_all(cache_dir()).expect("create claude-cli cache dir");

        let runtime = Runtime::new().expect("create tokio runtime for claude proxy");

        let listener = runtime.block_on(async {
            tokio::net::TcpListener::from_std(std_listener)
                .expect("convert proxy to tokio listener")
        });

        let app = Router::new().fallback(handle_request);

        runtime.spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("claude proxy server failed");
        });

        eprintln!(
            "claude proxy: listening on {}:{} (containers reach via {}:{})",
            bind_ip, port, container_ip, port
        );

        ClaudeTestProxy {
            port,
            addr: container_ip,
            _runtime: runtime,
        }
    })
}

fn get_bridge_gateway_ip() -> String {
    let output = Command::new("docker")
        .args([
            "network",
            "inspect",
            "bridge",
            "--format",
            "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
        ])
        .output()
        .expect("docker network inspect bridge failed");

    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(!ip.is_empty(), "could not determine bridge gateway IP");
    ip
}

fn cache_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("llm-cache")
        .join("claude-cli")
}

/// Normalize the request body to strip fields that vary between runs but
/// don't affect the semantics of the response (container-specific user IDs,
/// config hashes, auto-memory state).
fn normalize_body(body: &[u8]) -> Vec<u8> {
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };

    // metadata.user_id contains a per-container hash
    if let Some(meta) = json.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        meta.remove("user_id");
    }

    // system[0] is the billing header with a per-run cch hash
    if let Some(system) = json.get_mut("system") {
        if let Some(arr) = system.as_array_mut() {
            // Strip billing header entry (first element, contains cch=)
            if arr
                .first()
                .and_then(|v| v.get("text"))
                .and_then(|t| t.as_str())
                .is_some_and(|s| s.contains("x-anthropic-billing-header"))
            {
                arr.remove(0);
            }
            // Strip auto-memory section from system prompt text
            for entry in arr.iter_mut() {
                if let Some(text) = entry.get_mut("text") {
                    if let Some(s) = text.as_str() {
                        if let Some(pos) = s.find("\n# auto memory\n") {
                            // Cut auto memory up to the next top-level heading or env block
                            let after = &s[pos + 1..];
                            let end = after
                                .find("\nHere is useful information about the environment")
                                .map(|i| pos + 1 + i)
                                .unwrap_or(s.len());
                            let mut cleaned = s[..pos].to_string();
                            cleaned.push_str(&s[end..]);
                            *text = serde_json::Value::String(cleaned);
                        }
                    }
                }
            }
        }
    }

    // Deterministic serialization
    serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec())
}

fn compute_cache_key(method: &str, path_and_query: &str, body: &[u8]) -> String {
    let normalized = normalize_body(body);
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\n");
    hasher.update(path_and_query.as_bytes());
    hasher.update(b"\n");
    hasher.update(&normalized);
    hex::encode(hasher.finalize())
}

/// On-disk format for cached API responses.
#[derive(Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    content_type: String,
    /// Base64-encoded raw response body (may be SSE event stream).
    body: String,
}

impl CachedResponse {
    fn from_parts(status: u16, content_type: &str, body: &[u8]) -> Self {
        Self {
            status,
            content_type: content_type.to_string(),
            body: base64::engine::general_purpose::STANDARD.encode(body),
        }
    }

    fn body_bytes(&self) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.body)
            .expect("invalid base64 in cached response")
    }

    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK);
        let body = self.body_bytes();
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, &self.content_type)
            .body(Body::from(body))
            .unwrap()
    }
}

fn cache_get(key: &str) -> Option<CachedResponse> {
    let path = cache_dir().join(format!("{key}.json"));
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn cache_put(key: &str, response: &CachedResponse) {
    let dir = cache_dir();
    let final_path = dir.join(format!("{key}.json"));
    let data = serde_json::to_string_pretty(response).expect("serialize cached response");

    let temp = tempfile::Builder::new()
        .prefix("cache-")
        .suffix(".json")
        .tempfile_in(&dir)
        .expect("create temp file for claude cache");
    std::fs::write(temp.path(), &data).expect("write temp claude cache file");
    temp.persist(final_path).expect("persist claude cache file");
}

fn is_offline_mode() -> bool {
    std::env::var("RUMPELPOD_TEST_LLM_OFFLINE")
        .map(|s| s == "1" || s.to_lowercase() == "true")
        .unwrap_or(false)
}

async fn handle_request(req: Request<Body>) -> Response {
    let method = req.method().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    // Collect headers for forwarding (skip hop-by-hop and host)
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter(|(name, _)| {
            let n = name.as_str();
            n != "host" && n != "connection" && n != "transfer-encoding"
        })
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();

    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("claude proxy: failed to read request body: {e}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let cache_key = compute_cache_key(&method, &path_and_query, &body_bytes);

    // Lock-free cache lookup (files are immutable once written)
    if let Some(cached) = cache_get(&cache_key) {
        eprintln!("claude proxy: cache hit {method} {path_and_query}");
        return cached.into_response();
    }

    if is_offline_mode() {
        eprintln!(
            "claude proxy: cache miss in offline mode\n\
             key: {cache_key}\n\
             {method} {path_and_query}\n\
             Re-run with RUMPELPOD_TEST_LLM_OFFLINE=0 to populate the cache."
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Cache miss in offline mode. \
             Re-run with RUMPELPOD_TEST_LLM_OFFLINE=0 to populate the cache.",
        )
            .into_response();
    }

    // Forward to real API, serialized to prevent duplicate API calls
    let result = tokio::task::spawn_blocking(move || {
        let _guard = API_FORWARD_LOCK.lock().unwrap();

        // Double-check after acquiring lock (another thread may have populated it)
        if let Some(cached) = cache_get(&cache_key) {
            return cached;
        }

        let real_api_key = std::env::var("ANTHROPIC_API_KEY")
            .expect("ANTHROPIC_API_KEY must be set when RUMPELPOD_TEST_LLM_OFFLINE=0");

        let url = format!("https://api.anthropic.com{}", path_and_query);

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(180))
            .build()
            .expect("build forwarding reqwest client");

        let mut request = client.request(
            method.parse().expect("parse HTTP method for forwarding"),
            &url,
        );

        let mut has_api_key = false;
        for (name, value) in &headers {
            if name == "x-api-key" {
                request = request.header("x-api-key", &real_api_key);
                has_api_key = true;
            } else {
                request = request.header(name.as_str(), value.as_str());
            }
        }
        if !has_api_key {
            request = request.header("x-api-key", &real_api_key);
        }

        request = request.body(body_bytes.to_vec());

        eprintln!(
            "claude proxy: forwarding {} {} to Anthropic API",
            method, path_and_query
        );

        let response = request.send().expect("forward request to Anthropic API");
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let response_body = response.bytes().expect("read forwarded response body");

        let cached = CachedResponse::from_parts(status, &content_type, &response_body);
        cache_put(&cache_key, &cached);

        eprintln!("claude proxy: cached response {} {}", status, cache_key);

        cached
    })
    .await
    .expect("API forwarding task panicked");

    result.into_response()
}
