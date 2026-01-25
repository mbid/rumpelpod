//! xAI (Grok) API client.
//!
//! The xAI API uses the `/v1/responses` endpoint for agentic workflows.
//! See https://docs.x.ai/docs/api-reference for the full API reference.

use anyhow::{Context, Result};
use log::{debug, warn};
use rand::Rng;
use std::time::Duration;

use crate::llm::cache::LlmCache;
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
    pub fn new_with_cache(cache: Option<LlmCache>) -> Result<Self> {
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
            anyhow::bail!("XAI_API_KEY not set and no cache provided");
        }

        // Use 180s timeout as API requests with large context can take >30s to complete.
        // This includes connection, sending request body, and receiving response.
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(180))
            .build()
            .context("Failed to build HTTP client")?;

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

    /// Retry logic follows claude code's behavior: up to 10 retries, first retry instant
    /// (unless rate-limited), then 2 minute delays with jitter.
    pub fn create_response(&self, request: ResponseRequest) -> Result<ResponseResponse> {
        const MAX_RETRIES: u32 = 10;
        const BASE_RETRY_DELAY: Duration = Duration::from_secs(120);
        const MAX_JITTER: Duration = Duration::from_secs(30);

        // Serialize request body to a string once
        let body = serde_json::to_string(&request).context("Failed to serialize request")?;
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
                let response: ResponseResponse = serde_json::from_str(&cached_response)
                    .with_context(|| {
                        format!("Failed to parse cached response: {cached_response}")
                    })?;
                return Ok(response);
            }
        }

        // No cache hit - need API key to make the request
        if self.api_key.is_none() {
            if self.offline_test_mode {
                anyhow::bail!(
                    "LLM Cache miss in test offline mode.\n                     See llm-cache/README.md for details.\n                     To populate the cache, rerun the test with SANDBOX_TEST_LLM_OFFLINE=0 set in the environment."
                );
            }
            anyhow::bail!("Cache miss and no XAI_API_KEY set - cannot make API request");
        }

        // Build headers including API key for actual requests
        let request_headers = self.build_headers(false);

        let mut attempt = 0;

        loop {
            debug!("Sending xAI API request (attempt {})", attempt + 1);
            let mut req = self.client.post(XAI_API_URL).body(body.clone());

            for (name, value) in &request_headers {
                req = req.header(*name, value);
            }

            let response = match req.send() {
                Ok(response) => {
                    debug!("xAI API response received");
                    response
                }
                Err(e) => {
                    warn!("xAI API request failed: {} (timeout={})", e, e.is_timeout());
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
                    return Err(e).context("Failed to send request to xAI API");
                }
            };

            let status = response.status();
            debug!("xAI API response status: {}", status);

            if status.is_success() {
                let response_text = response.text().context("Failed to read response body")?;

                if let Some(ref cache) = self.cache {
                    // Include URL in cache key (same as cache lookup)
                    let cache_key = cache.compute_key(XAI_API_URL, &cache_header_refs, &body);
                    cache.put(&cache_key, &response_text)?;
                }

                println!("xAI API response body: {}", response_text);

                let response: ResponseResponse = serde_json::from_str(&response_text)
                    .with_context(|| {
                        format!("Failed to parse xAI API response: {response_text}")
                    })?;

                debug!("xAI API request successful");
                return Ok(response);
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
                    "xAI API error (status {}), retrying after {:?} (attempt {})",
                    status, delay, attempt
                );
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                continue;
            }

            let error_text = response.text().unwrap_or_default();
            warn!("xAI API error (status {}): {}", status, error_text);
            anyhow::bail!("xAI API error (status {}): {}", status, error_text);
        }
    }
}
