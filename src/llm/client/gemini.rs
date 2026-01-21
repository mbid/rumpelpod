//! Google Gemini API client supporting both AI Studio and Vertex AI.
//!
//! AI Studio uses the REST API at `https://generativelanguage.googleapis.com/v1beta/`.
//! Vertex AI uses the REST API at `https://aiplatform.googleapis.com/v1/`.
//!
//! See https://ai.google.dev/api/generate-content for the AI Studio API reference.
//! See https://cloud.google.com/vertex-ai/docs/reference/rest for the Vertex AI API reference.
//!
//! ## Backend Selection
//!
//! The client automatically selects the backend based on available credentials:
//! 1. **Vertex AI** (preferred): Used when `GOOGLE_APPLICATION_CREDENTIALS` is set to a
//!    service account JSON key file path. Also requires `GOOGLE_CLOUD_PROJECT` (or extracted
//!    from key file) and optionally `GOOGLE_CLOUD_LOCATION` (defaults to "global").
//! 2. **AI Studio**: Used when `GEMINI_API_KEY` is set.
//!
//! Vertex AI takes precedence over AI Studio when both are configured.

use anyhow::{Context, Result};
use log::{debug, info, warn};
use rand::Rng;
use std::time::Duration;

use super::vertex_auth::{VertexAuthenticator, VertexConfig};
use crate::llm::cache::LlmCache;
use crate::llm::types::gemini::{GenerateContentRequest, GenerateContentResponse};

/// AI Studio API base URL.
const AISTUDIO_API_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta/models";

/// Vertex AI API base URL template.
/// Format: https://aiplatform.googleapis.com/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent
const VERTEX_API_BASE_URL: &str = "https://aiplatform.googleapis.com/v1";

/// Backend type for the Gemini API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    /// Google AI Studio (uses API key)
    AiStudio,
    /// Google Cloud Vertex AI (uses OAuth2 service account)
    VertexAi,
}

pub struct Client {
    /// API key for AI Studio backend
    api_key: Option<String>,
    /// Authenticator for Vertex AI backend
    vertex_auth: Option<VertexAuthenticator>,
    /// Which backend to use
    backend: Backend,
    client: reqwest::blocking::Client,
    cache: Option<LlmCache>,
    offline_test_mode: bool,
}

impl Client {
    /// Create a new client with optional caching for deterministic testing.
    ///
    /// Backend selection:
    /// 1. **Vertex AI** (preferred): Used when `GOOGLE_APPLICATION_CREDENTIALS` is set.
    /// 2. **AI Studio**: Used when `GEMINI_API_KEY` is set.
    ///
    /// If cache is provided and no credentials are set, only cached responses will work.
    ///
    /// See [`llm-cache/README.md`](../../../llm-cache/README.md) for cache documentation.
    pub fn new_with_cache(cache: Option<LlmCache>) -> Result<Self> {
        // If SANDBOX_TEST_LLM_OFFLINE is set, ignore API key/credentials to ensure strict caching in tests
        let offline_test_mode = std::env::var("SANDBOX_TEST_LLM_OFFLINE")
            .map(|s| s == "1" || s.to_lowercase() == "true")
            .unwrap_or(false);

        // Use 180s timeout as API requests with large context can take >30s to complete.
        // This includes connection, sending request body, and receiving response.
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(180))
            .build()
            .context("Failed to build HTTP client")?;

        // Try Vertex AI first (preferred backend)
        let vertex_config = if offline_test_mode {
            None
        } else {
            VertexConfig::from_env()?
        };

        if let Some(config) = vertex_config {
            info!(
                "Using Vertex AI backend (project: {}, location: {})",
                config.project_id, config.location
            );
            let vertex_auth = VertexAuthenticator::new(config, http_client.clone());
            return Ok(Self {
                api_key: None,
                vertex_auth: Some(vertex_auth),
                backend: Backend::VertexAi,
                client: http_client,
                cache,
                offline_test_mode,
            });
        }

        // Fall back to AI Studio
        let api_key = if offline_test_mode {
            None
        } else {
            std::env::var("GEMINI_API_KEY")
                .ok()
                .filter(|s| !s.is_empty())
        };

        if api_key.is_none() && cache.is_none() && !offline_test_mode {
            anyhow::bail!(
                "No Gemini credentials found. Set either:\n\
                 - GOOGLE_APPLICATION_CREDENTIALS (for Vertex AI)\n\
                 - GEMINI_API_KEY (for AI Studio)"
            );
        }

        if api_key.is_some() {
            info!("Using AI Studio backend");
        }

        Ok(Self {
            api_key,
            vertex_auth: None,
            backend: Backend::AiStudio,
            client: http_client,
            cache,
            offline_test_mode,
        })
    }

    /// Build the API URL for a specific model.
    fn build_url(&self, model: &str) -> String {
        match self.backend {
            Backend::AiStudio => {
                // API key is passed as query parameter for AI Studio
                if let Some(ref api_key) = self.api_key {
                    format!(
                        "{}/{}:generateContent?key={}",
                        AISTUDIO_API_BASE_URL, model, api_key
                    )
                } else {
                    format!("{}/{}:generateContent", AISTUDIO_API_BASE_URL, model)
                }
            }
            Backend::VertexAi => {
                // Vertex AI uses a different URL format with project/location
                let auth = self.vertex_auth.as_ref().unwrap();
                format!(
                    "{}/projects/{}/locations/{}/publishers/google/models/{}:generateContent",
                    VERTEX_API_BASE_URL,
                    auth.project_id(),
                    auth.location(),
                    model
                )
            }
        }
    }

    /// Build the cache URL (without credentials for consistent lookups).
    fn build_cache_url(&self, model: &str) -> String {
        // Use a consistent URL format for caching regardless of backend
        // This allows cache hits when switching between backends
        format!("{}/{}:generateContent", AISTUDIO_API_BASE_URL, model)
    }

    /// Build headers for the API request.
    fn build_headers(&self) -> Result<Vec<(&'static str, String)>> {
        let mut headers = vec![("content-type", "application/json".to_string())];

        // Add Authorization header for Vertex AI
        if self.backend == Backend::VertexAi {
            let auth = self.vertex_auth.as_ref().unwrap();
            let token = auth.get_access_token()?;
            headers.push(("authorization", format!("Bearer {}", token)));
        }

        Ok(headers)
    }

    /// Retry logic follows claude code's behavior: up to 10 retries, first retry instant
    /// (unless rate-limited), then 2 minute delays with jitter.
    ///
    /// For Vertex AI, 401 errors trigger a token refresh (once) before retrying.
    pub fn generate_content(
        &self,
        model: &str,
        request: GenerateContentRequest,
    ) -> Result<GenerateContentResponse> {
        const MAX_RETRIES: u32 = 10;
        const BASE_RETRY_DELAY: Duration = Duration::from_secs(120);
        const MAX_JITTER: Duration = Duration::from_secs(30);

        // Serialize request body to a string once
        let body = serde_json::to_string(&request).context("Failed to serialize request")?;

        // Build cache key using URL without credentials + body
        // Use only content-type header for cache key (not auth headers)
        let cache_url = self.build_cache_url(model);
        let cache_headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];

        // Check cache first
        if let Some(ref cache) = self.cache {
            // Include URL in cache key computation
            let cache_input = format!("{}\n{}", cache_url, body);
            let cache_key = cache.compute_key(&cache_headers, &cache_input);
            if let Some(cached_response) = cache.get(&cache_key) {
                let response = GenerateContentResponse::from_response_json(&cached_response)
                    .with_context(|| {
                        format!("Failed to parse cached response: {cached_response}")
                    })?;
                return Ok(response);
            }
        }

        // No cache hit - need credentials to make the request
        let has_credentials = match self.backend {
            Backend::AiStudio => self.api_key.is_some(),
            Backend::VertexAi => self.vertex_auth.is_some(),
        };
        if !has_credentials {
            if self.offline_test_mode {
                anyhow::bail!(
                    "LLM Cache miss in test offline mode.\n\
                     See llm-cache/README.md for details.\n\
                     To populate the cache, rerun the test with SANDBOX_TEST_LLM_OFFLINE=0 set in the environment."
                );
            }
            anyhow::bail!("Cache miss and no credentials set - cannot make API request");
        }

        let url = self.build_url(model);

        let mut attempt = 0;
        let mut did_refresh_token = false;

        loop {
            // Build headers (may fetch/refresh OAuth token for Vertex AI)
            let request_headers = if did_refresh_token {
                // After a 401, we already refreshed, so use normal headers
                self.build_headers()?
            } else {
                self.build_headers()?
            };

            debug!("Sending Gemini API request (attempt {})", attempt + 1);
            let mut req = self.client.post(&url).body(body.clone());

            for (name, value) in &request_headers {
                req = req.header(*name, value);
            }

            let response = match req.send() {
                Ok(response) => {
                    debug!("Gemini API response received");
                    response
                }
                Err(e) => {
                    warn!(
                        "Gemini API request failed: {} (timeout={})",
                        e,
                        e.is_timeout()
                    );
                    // Only retry on timeout errors, fail immediately on other errors
                    if e.is_timeout() && attempt < MAX_RETRIES {
                        attempt += 1;

                        let delay = if attempt == 1 {
                            Duration::ZERO
                        } else {
                            let jitter = rand::rng().random_range(Duration::ZERO..MAX_JITTER);
                            BASE_RETRY_DELAY + jitter
                        };

                        warn!("Retrying after {:?}", delay);
                        if !delay.is_zero() {
                            std::thread::sleep(delay);
                        }
                        continue;
                    }
                    return Err(e).context("Failed to send request to Gemini API");
                }
            };

            let status = response.status();
            debug!("Gemini API response status: {}", status);

            if status.is_success() {
                let response_text = response.text().context("Failed to read response body")?;

                if let Some(ref cache) = self.cache {
                    let cache_input = format!("{}\n{}", cache_url, body);
                    let cache_key = cache.compute_key(&cache_headers, &cache_input);
                    cache.put(&cache_key, &response_text)?;
                }

                let response = GenerateContentResponse::from_response_json(&response_text)
                    .with_context(|| {
                        format!("Failed to parse Gemini API response: {response_text}")
                    })?;

                if let Some(ref usage) = response.usage_metadata {
                    debug!(
                        "Gemini API request successful: {:?} prompt tokens, {:?} completion tokens",
                        usage.prompt_token_count, usage.candidates_token_count
                    );
                }
                return Ok(response);
            }

            // Handle 401 Unauthorized - refresh token once for Vertex AI
            if status.as_u16() == 401 && self.backend == Backend::VertexAi && !did_refresh_token {
                warn!("Received 401 Unauthorized, refreshing OAuth token and retrying");
                // Force token refresh
                if let Some(ref auth) = self.vertex_auth {
                    auth.clear_cached_token();
                    match auth.refresh_token() {
                        Ok(_) => {
                            did_refresh_token = true;
                            // Don't increment attempt counter for token refresh
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to refresh OAuth token: {}", e);
                            // Fall through to return the 401 error
                        }
                    }
                }
            }

            let is_rate_limited = status.as_u16() == 429;
            let should_retry = matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504);

            if should_retry && attempt < MAX_RETRIES {
                attempt += 1;

                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(Duration::from_secs);

                let delay = if let Some(retry_after) = retry_after {
                    retry_after
                } else if attempt == 1 && !is_rate_limited {
                    Duration::ZERO
                } else {
                    let jitter = rand::rng().random_range(Duration::ZERO..MAX_JITTER);
                    BASE_RETRY_DELAY + jitter
                };

                warn!(
                    "Gemini API error (status {}), retrying after {:?} (attempt {})",
                    status, delay, attempt
                );
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                continue;
            }

            let error_text = response.text().unwrap_or_default();
            warn!("Gemini API error (status {}): {}", status, error_text);
            anyhow::bail!("Gemini API error (status {}): {}", status, error_text);
        }
    }
}
