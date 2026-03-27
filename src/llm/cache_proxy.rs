//! HTTP cache proxy for LLM API requests (Claude CLI, etc.).
//!
//! Runs inside the git HTTP server (on the host) and caches API
//! responses to disk so tests can replay them deterministically.
//! The pod server inside containers forwards requests here via the
//! existing exec tunnel, so this works for local Docker, remote
//! Docker, and Kubernetes alike.
//!
//! Gated on the `RUMPELPOD_TEST_LLM_OFFLINE` environment variable:
//! present = test mode (the value controls online vs offline behavior).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::git_http_server::SharedGitServerState;

/// Shared state for the LLM cache proxy routes on the git HTTP server.
#[derive(Clone)]
pub struct LlmCacheProxyState {
    /// Git server state, used to authenticate bearer tokens.
    pub git_state: SharedGitServerState,
    /// Root cache directory (e.g. `llm-cache/claude-cli`).
    pub cache_dir: PathBuf,
}

/// Serializes cache-miss API forwarding so parallel tests that miss
/// on the same request don't all call the real API.
static API_FORWARD_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Cache key computation
// ---------------------------------------------------------------------------

/// Extract only the fields that determine API response semantics.
/// Everything else (system prompts, tools, metadata, temperature, etc.)
/// is excluded so the cache survives Claude CLI version changes.
fn extract_cache_fields(body: &[u8]) -> Vec<u8> {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };

    let mut key_fields = serde_json::Map::new();
    for field in ["model", "messages", "stream"] {
        if let Some(val) = json.get(field) {
            key_fields.insert(field.to_string(), val.clone());
        }
    }

    serde_json::to_vec(&serde_json::Value::Object(key_fields)).unwrap_or_else(|_| body.to_vec())
}

fn compute_cache_key(method: &str, path_and_query: &str, body: &[u8]) -> String {
    let cache_fields = extract_cache_fields(body);
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\n");
    hasher.update(path_and_query.as_bytes());
    hasher.update(b"\n");
    hasher.update(&cache_fields);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// On-disk cache format
// ---------------------------------------------------------------------------

/// First line of a cached response file (JSON), followed by a newline
/// and the raw response body.
#[derive(Serialize, Deserialize)]
struct ResponseMeta {
    status: u16,
    path: String,
    headers: BTreeMap<String, String>,
}

fn response_dir(cache_dir: &Path) -> PathBuf {
    cache_dir.join("response")
}

fn request_dir(cache_dir: &Path) -> PathBuf {
    cache_dir.join("request")
}

/// Read a cached response: JSON metadata line, newline, raw body.
fn cache_get(cache_dir: &Path, key: &str) -> Option<(ResponseMeta, Vec<u8>)> {
    let data = std::fs::read(response_dir(cache_dir).join(key)).ok()?;
    let nl = data.iter().position(|&b| b == b'\n')?;
    let meta: ResponseMeta = serde_json::from_slice(&data[..nl]).ok()?;
    Some((meta, data[nl + 1..].to_vec()))
}

/// Write response file (JSON metadata + newline + raw body) and
/// request file (pretty-printed JSON for debugging, gitignored).
fn cache_put(
    cache_dir: &Path,
    key: &str,
    meta: &ResponseMeta,
    response_body: &[u8],
    request_body: &[u8],
) {
    let resp_dir = response_dir(cache_dir);
    let resp_path = resp_dir.join(key);
    let mut resp_data = serde_json::to_string(meta).expect("serialize response meta");
    resp_data.push('\n');
    let resp_bytes = [resp_data.as_bytes(), response_body].concat();
    atomic_write(&resp_dir, &resp_path, &resp_bytes);

    let req_dir = request_dir(cache_dir);
    let req_path = req_dir.join(key);
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(request_body) {
        let pretty = serde_json::to_string_pretty(&json).unwrap_or_default();
        atomic_write(&req_dir, &req_path, pretty.as_bytes());
    } else {
        atomic_write(&req_dir, &req_path, request_body);
    }
}

fn atomic_write(dir: &Path, final_path: &Path, data: &[u8]) {
    let temp = tempfile::Builder::new()
        .prefix("cache-")
        .tempfile_in(dir)
        .expect("create temp file for llm cache");
    std::fs::write(temp.path(), data).expect("write temp llm cache file");
    temp.persist(final_path).expect("persist llm cache file");
}

fn build_response(meta: &ResponseMeta, body: Vec<u8>) -> Response {
    let status = StatusCode::from_u16(meta.status).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    for (name, value) in &meta.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(Body::from(body)).unwrap()
}

fn is_offline_mode() -> bool {
    std::env::var("RUMPELPOD_TEST_LLM_OFFLINE")
        .map(|s| s == "1" || s.to_lowercase() == "true")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Axum handler (runs on the git HTTP server, host side)
// ---------------------------------------------------------------------------

/// Handle an LLM cache proxy request on the git HTTP server.
///
/// Authenticates the caller via bearer token (same as git endpoints),
/// then serves from cache or forwards to the real API.
pub async fn handle_llm_cache_proxy(
    State(state): State<LlmCacheProxyState>,
    req: Request<Body>,
) -> Response {
    // Authenticate using the git server's bearer token registry.
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let token = match auth_header {
        Some(ref h) if h.starts_with("Bearer ") => &h[7..],
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if !state.git_state.has_token(token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let method = req.method().to_string();
    let full_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    // Strip the /llm-cache-proxy/anthropic prefix to get the real API path.
    let path_and_query = match full_path.find("/v1/") {
        Some(idx) => full_path[idx..].to_string(),
        None => full_path.clone(),
    };

    // Collect headers for forwarding (skip hop-by-hop, host, and auth)
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter(|(name, _)| {
            let n = name.as_str();
            n != "host" && n != "connection" && n != "transfer-encoding" && n != "authorization"
        })
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();

    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("llm-cache-proxy: failed to read request body: {e}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let cache_key = compute_cache_key(&method, &path_and_query, &body_bytes);
    let cache_dir = state.cache_dir.clone();

    eprintln!("llm-cache-proxy: {method} {path_and_query} -> key {cache_key}");

    // Lock-free cache lookup (files are immutable once written)
    if let Some((meta, body)) = cache_get(&cache_dir, &cache_key) {
        eprintln!("llm-cache-proxy: cache hit {method} {path_and_query}");
        return build_response(&meta, body);
    }

    if is_offline_mode() {
        eprintln!(
            "llm-cache-proxy: cache miss in offline mode\n\
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

    // Forward to real API, serialized to prevent duplicate calls
    tokio::task::spawn_blocking(move || {
        let _guard = API_FORWARD_LOCK.lock().unwrap();

        // Double-check after acquiring lock
        if let Some((meta, body)) = cache_get(&cache_dir, &cache_key) {
            return build_response(&meta, body);
        }

        let real_api_key = std::env::var("ANTHROPIC_API_KEY")
            .expect("ANTHROPIC_API_KEY must be set when RUMPELPOD_TEST_LLM_OFFLINE=0");

        let url = format!("https://api.anthropic.com{path_and_query}");

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

        eprintln!("llm-cache-proxy: forwarding {method} {path_and_query} to Anthropic API");

        let response = request.send().expect("forward request to Anthropic API");
        let status = response.status().as_u16();
        let mut resp_headers = BTreeMap::new();
        for (name, value) in response.headers() {
            let n = name.as_str();
            if n == "connection" || n == "transfer-encoding" {
                continue;
            }
            if let Ok(v) = value.to_str() {
                resp_headers.insert(n.to_string(), v.to_string());
            }
        }
        let response_body = response.bytes().expect("read forwarded response body");

        let meta = ResponseMeta {
            status,
            path: path_and_query.clone(),
            headers: resp_headers,
        };
        cache_put(&cache_dir, &cache_key, &meta, &response_body, &body_bytes);

        eprintln!("llm-cache-proxy: cached response {status} {cache_key}");

        build_response(&meta, response_body.to_vec())
    })
    .await
    .expect("API forwarding task panicked")
}
