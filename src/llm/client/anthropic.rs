use anyhow::{Context, Result};
use log::{debug, warn};
use rand::Rng;
use std::time::Duration;

use crate::llm::cache::LlmCache;
use crate::llm::types::anthropic::{MessagesRequest, MessagesResponse};

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";

pub struct Client {
    api_key: Option<String>,
    base_url: String,
    client: reqwest::blocking::Client,
    cache: Option<LlmCache>,
}

impl Client {
    /// Create a new client with optional caching for deterministic testing.
    /// If cache is provided and no API key is set, only cached responses will work.
    ///
    /// See [`llm-cache/README.md`](../../../llm-cache/README.md) for cache documentation.
    pub fn new_with_cache(cache: Option<LlmCache>, base_url: Option<String>) -> Result<Self> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .ok()
            .filter(|s| !s.is_empty());

        if api_key.is_none() && cache.is_none() {
            anyhow::bail!("ANTHROPIC_API_KEY not set and no cache provided");
        }

        let base_url = base_url.unwrap_or_else(|| ANTHROPIC_API_URL.to_string());

        // Use 180s timeout as API requests with large context can take >30s to complete.
        // This includes connection, sending request body, and receiving response.
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(180))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            api_key,
            base_url,
            client,
            cache,
        })
    }

    /// Build request headers for the messages endpoint.
    /// Build headers for the API request. If `for_cache_key` is true, excludes the API key
    /// so cache lookups work regardless of whether an API key is set.
    fn build_headers(&self, for_cache_key: bool) -> Vec<(&'static str, String)> {
        let mut headers = vec![
            ("anthropic-version", ANTHROPIC_VERSION.to_string()),
            (
                "anthropic-beta",
                "web-fetch-2025-09-10,interleaved-thinking-2025-05-14,effort-2025-11-24"
                    .to_string(),
            ),
            ("content-type", "application/json".to_string()),
        ];
        if !for_cache_key {
            if let Some(ref api_key) = self.api_key {
                headers.push(("x-api-key", api_key.clone()));
            }
        }
        headers
    }

    /// Retry logic follows claude code's behavior: up to 10 retries, first retry instant
    /// (unless rate-limited), then 2 minute delays with jitter.
    pub fn messages(&self, request: MessagesRequest) -> Result<MessagesResponse> {
        const MAX_RETRIES: u32 = 10;
        const BASE_RETRY_DELAY: Duration = Duration::from_secs(120);
        const MAX_JITTER: Duration = Duration::from_secs(30);

        // Serialize request body to a string once
        let body = serde_json::to_string(&request).context("Failed to serialize request")?;

        // Build headers for cache key computation (excludes API key for consistent cache lookups)
        let cache_headers = self.build_headers(true);
        let cache_header_refs: Vec<(&str, &str)> = cache_headers
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();

        // Check cache first
        if let Some(ref cache) = self.cache {
            let cache_key = cache.compute_key(&cache_header_refs, &body);
            if let Some(cached_response) = cache.get(&cache_key) {
                let response: MessagesResponse = serde_json::from_str(&cached_response)
                    .with_context(|| {
                        format!("Failed to parse cached response: {cached_response}")
                    })?;
                return Ok(response);
            }
        }

        // No cache hit - need API key to make the request
        if self.api_key.is_none() {
            anyhow::bail!("Cache miss and no ANTHROPIC_API_KEY set - cannot make API request");
        }

        // Build headers including API key for actual requests
        let request_headers = self.build_headers(false);

        let mut attempt = 0;

        loop {
            debug!("Sending API request (attempt {})", attempt + 1);
            let mut req = self.client.post(&self.base_url).body(body.clone());

            for (name, value) in &request_headers {
                req = req.header(*name, value);
            }

            let response = match req.send() {
                Ok(response) => {
                    debug!("API response received");
                    response
                }
                Err(e) => {
                    warn!("API request failed: {} (timeout={})", e, e.is_timeout());
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
                    return Err(e).context("Failed to send request to Anthropic API");
                }
            };

            let status = response.status();
            debug!("API response status: {}", status);

            if status.is_success() {
                let response_text = response.text().context("Failed to read response body")?;

                if let Some(ref cache) = self.cache {
                    let cache_key = cache.compute_key(&cache_header_refs, &body);
                    cache.put(&cache_key, &response_text)?;
                }

                let response: MessagesResponse = serde_json::from_str(&response_text)
                    .with_context(|| {
                        format!("Failed to parse Anthropic API response: {response_text}")
                    })?;
                debug!(
                    "API request successful: {} input tokens, {} output tokens",
                    response.usage.input_tokens, response.usage.output_tokens
                );
                return Ok(response);
            }

            let is_rate_limited = status.as_u16() == 429;
            let should_retry = matches!(status.as_u16(), 429 | 500 | 504 | 529);

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
                    "API error (status {}), retrying after {:?} (attempt {})",
                    status, delay, attempt
                );
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                continue;
            }

            let error_text = response.text().unwrap_or_default();
            warn!("API error (status {}): {}", status, error_text);
            anyhow::bail!("Anthropic API error (status {}): {}", status, error_text);
        }
    }
}
