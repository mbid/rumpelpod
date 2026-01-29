//! xAI (Grok) API client.
//!
//! The xAI API uses the `/v1/responses` endpoint for agentic workflows.
//! See https://docs.x.ai/docs/api-reference for the full API reference.

use log::debug;
use std::time::Duration;

use crate::llm::cache::LlmCache;
use crate::llm::error::LlmError;
use crate::llm::types::xai::{ResponseRequest, ResponseResponse};

const XAI_API_URL: &str = "https://api.x.ai/v1/responses";

pub struct Client {
    api_key: Option<String>,
    client: reqwest::blocking::Client,
    cache: Option<LlmCache>,
    offline_test_mode: bool,
}

impl Client {
    /// Create a new client with optional caching for deterministic testing.
    /// If cache is provided and no API key is set, only cached responses will work.
    ///
    /// See [`llm-cache/README.md`](../../../llm-cache/README.md) for cache documentation.
    pub fn new_with_cache(cache: Option<LlmCache>) -> Result<Self, LlmError> {
        // If SANDBOX_TEST_LLM_OFFLINE is set, ignore API key to ensure strict caching in tests
        let offline_test_mode = std::env::var("SANDBOX_TEST_LLM_OFFLINE")
            .map(|s| s == "1" || s.to_lowercase() == "true")
            .unwrap_or(false);

        let api_key = if offline_test_mode {
            None
        } else {
            std::env::var("XAI_API_KEY").ok().filter(|s| !s.is_empty())
        };

        if api_key.is_none() && cache.is_none() && !offline_test_mode {
            return Err(LlmError::Other(anyhow::anyhow!(
                "XAI_API_KEY not set and no cache provided"
            )));
        }

        // Use 180s timeout as API requests with large context can take >30s to complete.
        // This includes connection, sending request body, and receiving response.
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(180))
            .build()
            .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to build HTTP client: {}", e)))?;

        Ok(Self {
            api_key,
            client,
            cache,
            offline_test_mode,
        })
    }

    /// Build headers for the API request. If `for_cache_key` is true, excludes the API key
    /// so cache lookups work regardless of whether an API key is set.
    fn build_headers(&self, for_cache_key: bool) -> Vec<(&'static str, String)> {
        let mut headers = vec![("content-type", "application/json".to_string())];
        if !for_cache_key {
            if let Some(api_key) = &self.api_key {
                headers.push(("authorization", format!("Bearer {api_key}")));
            }
        }
        headers
    }

    /// Send a response request to the xAI API.
    /// Returns proper error types that distinguish between retryable and non-retryable errors.
    pub fn create_response(&self, request: ResponseRequest) -> Result<ResponseResponse, LlmError> {
        // Serialize request body to a string once
        let body = serde_json::to_string(&request)
            .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to serialize request: {}", e)))?;
        debug!("Request body: {}", body);

        // Build headers for cache key computation (excludes API key for consistent cache lookups)
        let cache_headers = self.build_headers(true);
        let cache_header_refs: Vec<(&str, &str)> = cache_headers
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();

        // Check cache first
        if let Some(ref cache) = self.cache {
            // Include URL in cache key for consistency with other clients
            let cache_key = cache.compute_key(XAI_API_URL, &cache_header_refs, &body);
            if let Some(cached_response) = cache.get(&cache_key) {
                let response: ResponseResponse =
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
                     To populate the cache, rerun the test with SANDBOX_TEST_LLM_OFFLINE=0 set in the environment."
                )));
            }
            return Err(LlmError::Other(anyhow::anyhow!(
                "Cache miss and no XAI_API_KEY set - cannot make API request"
            )));
        }

        // Build headers including API key for actual requests
        let request_headers = self.build_headers(false);

        debug!("Sending xAI API request");
        let mut req = self.client.post(XAI_API_URL).body(body.clone());

        for (name, value) in &request_headers {
            req = req.header(*name, value);
        }

        let response = req.send()?;

        let status = response.status();
        debug!("xAI API response status: {}", status);

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
                Err(e) => return Err(LlmError::Other(anyhow::anyhow!("xAI API error: {}", e))),
            }
        };

        let response_text = response
            .text()
            .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to read response body: {}", e)))?;

        if let Some(ref cache) = self.cache {
            // Include URL in cache key (same as cache lookup)
            let cache_key = cache.compute_key(XAI_API_URL, &cache_header_refs, &body);
            cache
                .put(&cache_key, &response_text)
                .map_err(|e| LlmError::Other(anyhow::anyhow!("Failed to cache response: {}", e)))?;
        }

        println!("xAI API response body: {}", response_text);

        let response: ResponseResponse = serde_json::from_str(&response_text).map_err(|e| {
            LlmError::Other(anyhow::anyhow!("Failed to parse xAI API response: {}", e))
        })?;

        debug!("xAI API request successful");
        Ok(response)
    }
}
