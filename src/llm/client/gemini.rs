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

use log::{debug, info};
use std::time::Duration;

use super::vertex_auth::{VertexAuthenticator, VertexConfig};
use crate::llm::cache::LlmCache;
use crate::llm::error::LlmError;
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
    pub fn new_with_cache(cache: Option<LlmCache>) -> Result<Self, LlmError> {
        // If RUMPELPOD_TEST_LLM_OFFLINE is set, ignore API key/credentials to ensure strict caching in tests
        let offline_test_mode = std::env::var("RUMPELPOD_TEST_LLM_OFFLINE")
            .map(|s| s == "1" || s.to_lowercase() == "true")
            .unwrap_or(false);

        // Use 180s timeout as API requests with large context can take >30s to complete.
        // This includes connection, sending request body, and receiving response.
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(180))
            .build()
            .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to build HTTP client: {}", e)))?;

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
            return Err(LlmError::Other(anyhow::anyhow!(
                "No Gemini credentials found. Set either:\n\
                 - GOOGLE_APPLICATION_CREDENTIALS (for Vertex AI)\n\
                 - GEMINI_API_KEY (for AI Studio)"
            )));
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
    fn build_headers(&self) -> anyhow::Result<Vec<(&'static str, String)>> {
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
    /// Send a generate content request to the Gemini API.
    /// Returns proper error types that distinguish between retryable and non-retryable errors.
    pub fn generate_content(
        &self,
        model: &str,
        request: GenerateContentRequest,
    ) -> Result<GenerateContentResponse, LlmError> {
        // Serialize request body to a string once
        let body = serde_json::to_string(&request)
            .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to serialize request: {}", e)))?;

        // Build cache key using URL without credentials + body
        // Use only content-type header for cache key (not auth headers)
        let cache_url = self.build_cache_url(model);
        let cache_headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];

        // Check cache first
        if let Some(ref cache) = self.cache {
            // Include URL in cache key computation
            let cache_key = cache.compute_key(&cache_url, &cache_headers, &body);
            if let Some(cached_response) = cache.get(&cache_key) {
                let response = GenerateContentResponse::from_response_json(&cached_response)
                    .map_err(|e| {
                        LlmError::Other(anyhow::anyhow!("Failed to parse cached response: {}", e))
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
                return Err(LlmError::Other(anyhow::anyhow!(
                    "LLM Cache miss in test offline mode.\n\
                     See llm-cache/README.md for details.\n\
                     To populate the cache, rerun the test with RUMPELPOD_TEST_LLM_OFFLINE=0 set in the environment."
                )));
            }
            return Err(LlmError::Other(anyhow::anyhow!(
                "Cache miss and no credentials set - cannot make API request"
            )));
        }

        let url = self.build_url(model);

        // Build headers (may fetch/refresh OAuth token for Vertex AI)
        let request_headers = self.build_headers().map_err(LlmError::Other)?;

        debug!("Sending Gemini API request");
        let mut req = self.client.post(&url).body(body.clone());

        for (name, value) in &request_headers {
            req = req.header(*name, value);
        }

        let response = req.send()?;

        let status = response.status();
        debug!("Gemini API response status: {}", status);

        // Check for rate limiting before consuming response body
        if status.as_u16() == 429 {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(Duration::from_secs);

            return Err(LlmError::RateLimited { retry_after });
        }

        // Handle 401 Unauthorized for Vertex AI - token refresh needed
        if status.as_u16() == 401 && self.backend == Backend::VertexAi {
            if let Some(ref auth) = self.vertex_auth {
                auth.clear_cached_token();
            }
            return Err(LlmError::Other(anyhow::anyhow!(
                "Unauthorized (401). OAuth token may need refresh."
            )));
        }

        // Convert retryable server errors (500, 502, 503, 504) to reqwest::Error
        // so they can be retried by the agent. Other errors (4xx, 501, etc.) will be
        // returned as non-retryable errors.
        let response = if matches!(status.as_u16(), 500 | 502 | 503 | 504) {
            // error_for_status will convert this to a reqwest::Error
            response.error_for_status()?
        } else {
            // For non-retryable errors, convert to LlmError::Other
            match response.error_for_status() {
                Ok(r) => r,
                Err(e) => return Err(LlmError::Other(anyhow::anyhow!("Gemini API error: {}", e))),
            }
        };

        let response_text = response
            .text()
            .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to read response body: {}", e)))?;

        if let Some(ref cache) = self.cache {
            let cache_key = cache.compute_key(&cache_url, &cache_headers, &body);
            cache
                .put(&cache_key, &response_text)
                .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to cache response: {}", e)))?;
        }

        let response =
            GenerateContentResponse::from_response_json(&response_text).map_err(|e| {
                LlmError::Other(anyhow::anyhow!(
                    "Failed to parse Gemini API response: {}",
                    e
                ))
            })?;

        if let Some(ref usage) = response.usage_metadata {
            debug!(
                "Gemini API request successful: {:?} prompt tokens, {:?} completion tokens",
                usage.prompt_token_count, usage.candidates_token_count
            );
        }
        Ok(response)
    }
}
