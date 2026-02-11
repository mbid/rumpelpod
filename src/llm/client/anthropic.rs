use log::debug;
use std::time::Duration;

use crate::llm::cache::LlmCache;
use crate::llm::error::LlmError;
use crate::llm::types::anthropic::{MessagesRequest, MessagesResponse};

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";

pub struct Client {
    api_key: Option<String>,
    base_url: String,
    client: reqwest::blocking::Client,
    cache: Option<LlmCache>,
    offline_test_mode: bool,
}

impl Client {
    /// Create a new client with optional caching for deterministic testing.
    /// If cache is provided and no API key is set, only cached responses will work.
    ///
    /// See [`llm-cache/README.md`](../../../llm-cache/README.md) for cache documentation.
    pub fn new_with_cache(
        cache: Option<LlmCache>,
        base_url: Option<String>,
    ) -> Result<Self, LlmError> {
        // If RUMPELPOD_TEST_LLM_OFFLINE is set, ignore API key to ensure strict caching in tests
        let offline_test_mode = std::env::var("RUMPELPOD_TEST_LLM_OFFLINE")
            .map(|s| s == "1" || s.to_lowercase() == "true")
            .unwrap_or(false);

        let api_key = if offline_test_mode {
            None
        } else {
            std::env::var("ANTHROPIC_API_KEY")
                .ok()
                .filter(|s| !s.is_empty())
        };

        if api_key.is_none() && cache.is_none() && !offline_test_mode {
            return Err(LlmError::Other(anyhow::anyhow!(
                "ANTHROPIC_API_KEY not set and no cache provided"
            )));
        }

        let base_url = base_url.unwrap_or_else(|| ANTHROPIC_API_URL.to_string());

        // Use 180s timeout as API requests with large context can take >30s to complete.
        // This includes connection, sending request body, and receiving response.
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(180))
            .build()
            .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to build HTTP client: {}", e)))?;

        Ok(Self {
            api_key,
            base_url,
            client,
            cache,
            offline_test_mode,
        })
    }

    /// Build request headers for the messages endpoint.
    /// Build headers for the API request. If `for_cache_key` is true, excludes the API key
    /// so cache lookups work regardless of whether an API key is set.
    fn build_headers(
        &self,
        for_cache_key: bool,
        enable_thinking: bool,
        enable_effort: bool,
    ) -> Vec<(&'static str, String)> {
        let mut beta_flags = Vec::new();
        if enable_thinking {
            beta_flags.push("interleaved-thinking-2025-05-14");
        }
        if enable_effort {
            beta_flags.push("effort-2025-11-24");
        }

        let mut headers = vec![
            ("anthropic-version", ANTHROPIC_VERSION.to_string()),
            ("content-type", "application/json".to_string()),
        ];
        if !beta_flags.is_empty() {
            headers.push(("anthropic-beta", beta_flags.join(",")));
        }
        if !for_cache_key {
            if let Some(ref api_key) = self.api_key {
                headers.push(("x-api-key", api_key.clone()));
            }
        }
        headers
    }

    /// Send a messages request to the Anthropic API.
    /// Returns proper error types that distinguish between retryable and non-retryable errors.
    pub fn messages(&self, request: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        let enable_thinking = request.thinking.is_some();
        let enable_effort = request.output_config.is_some();

        // Serialize request body to a string once
        let body = serde_json::to_string(&request)
            .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to serialize request: {}", e)))?;

        // Build headers for cache key computation (excludes API key for consistent cache lookups)
        let cache_headers = self.build_headers(true, enable_thinking, enable_effort);
        let cache_header_refs: Vec<(&str, &str)> = cache_headers
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();

        // Check cache first
        if let Some(ref cache) = self.cache {
            // Include base URL in cache key to ensure different URLs don't share cache entries
            let cache_key = cache.compute_key(&self.base_url, &cache_header_refs, &body);
            if let Some(cached_response) = cache.get(&cache_key) {
                let response: MessagesResponse =
                    serde_json::from_str(&cached_response).map_err(|e| {
                        LlmError::Other(anyhow::anyhow!("Failed to parse cached response: {}", e))
                    })?;
                return Ok(response);
            }
        }

        // No cache hit - need API key to make the request
        if self.api_key.is_none() {
            if self.offline_test_mode {
                return Err(LlmError::Other(anyhow::anyhow!(
                    "LLM Cache miss in test offline mode.\n\
                     See llm-cache/README.md for details.\n\
                     To populate the cache, rerun the test with RUMPELPOD_TEST_LLM_OFFLINE=0 set in the environment."
                )));
            }
            return Err(LlmError::Other(anyhow::anyhow!(
                "Cache miss and no ANTHROPIC_API_KEY set - cannot make API request"
            )));
        }

        // Build headers including API key for actual requests
        let request_headers = self.build_headers(false, enable_thinking, enable_effort);

        debug!("Sending API request");
        let mut req = self.client.post(&self.base_url).body(body.clone());

        for (name, value) in &request_headers {
            req = req.header(*name, value);
        }

        let response = req.send()?;

        let status = response.status();
        debug!("API response status: {}", status);

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

        // Convert retryable server errors (500, 502, 503, 504, 511) to reqwest::Error
        // so they can be retried by the agent. Other errors (4xx, 501, etc.) will be
        // returned as non-retryable errors.
        let response = if matches!(status.as_u16(), 500 | 502 | 503 | 504 | 511) {
            // error_for_status will convert this to a reqwest::Error
            response.error_for_status()?
        } else if !status.is_success() {
            // Read response body before converting to error for better diagnostics
            let body = response
                .text()
                .unwrap_or_else(|_| "(failed to read body)".to_string());
            return Err(LlmError::Other(anyhow::anyhow!(
                "Anthropic API error ({}): {}",
                status,
                body
            )));
        } else {
            response
        };

        let response_text = response
            .text()
            .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to read response body: {}", e)))?;

        if let Some(ref cache) = self.cache {
            // Include base URL in cache key (same as cache lookup)
            let cache_key = cache.compute_key(&self.base_url, &cache_header_refs, &body);
            cache
                .put(&cache_key, &response_text)
                .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to cache response: {}", e)))?;
        }

        let response: MessagesResponse = serde_json::from_str(&response_text).map_err(|e| {
            LlmError::Other(anyhow::anyhow!(
                "Failed to parse Anthropic API response: {}",
                e
            ))
        })?;
        debug!(
            "API request successful: {} input tokens, {} output tokens",
            response.usage.input_tokens, response.usage.output_tokens
        );
        Ok(response)
    }
}
