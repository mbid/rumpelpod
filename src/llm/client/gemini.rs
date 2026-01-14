//! Google Gemini API client (AI Studio).
//!
//! Uses the REST API at `https://generativelanguage.googleapis.com/v1beta/`.
//! See https://ai.google.dev/api/generate-content for the full API reference.

use anyhow::{Context, Result};
use log::{debug, warn};
use rand::Rng;
use std::time::Duration;

use crate::llm::cache::LlmCache;
use crate::llm::types::gemini::{GenerateContentRequest, GenerateContentResponse};

const GEMINI_API_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta/models";

pub struct Client {
    api_key: Option<String>,
    client: reqwest::blocking::Client,
    cache: Option<LlmCache>,
}

impl Client {
    /// Create a new client with optional caching for deterministic testing.
    /// If cache is provided and no API key is set, only cached responses will work.
    ///
    /// See [`llm-cache/README.md`](../../../llm-cache/README.md) for cache documentation.
    pub fn new_with_cache(cache: Option<LlmCache>) -> Result<Self> {
        let api_key = std::env::var("GEMINI_API_KEY")
            .ok()
            .filter(|s| !s.is_empty());

        if api_key.is_none() && cache.is_none() {
            anyhow::bail!("GEMINI_API_KEY not set and no cache provided");
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
        })
    }

    /// Build the API URL for a specific model.
    fn build_url(&self, model: &str) -> String {
        // API key is passed as query parameter for Gemini
        if let Some(ref api_key) = self.api_key {
            format!(
                "{}/{}:generateContent?key={}",
                GEMINI_API_BASE_URL, model, api_key
            )
        } else {
            format!("{}/{}:generateContent", GEMINI_API_BASE_URL, model)
        }
    }

    /// Build the cache URL (without API key for consistent lookups).
    fn build_cache_url(&self, model: &str) -> String {
        format!("{}/{}:generateContent", GEMINI_API_BASE_URL, model)
    }

    /// Build headers for the API request.
    fn build_headers(&self) -> Vec<(&'static str, String)> {
        vec![("content-type", "application/json".to_string())]
    }

    /// Retry logic follows claude code's behavior: up to 10 retries, first retry instant
    /// (unless rate-limited), then 2 minute delays with jitter.
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

        // Build cache key using URL without API key + headers + body
        let cache_url = self.build_cache_url(model);
        let cache_headers = self.build_headers();
        let cache_header_refs: Vec<(&str, &str)> = cache_headers
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();

        // Check cache first
        if let Some(ref cache) = self.cache {
            // Include URL in cache key computation
            let cache_input = format!("{}\n{}", cache_url, body);
            let cache_key = cache.compute_key(&cache_header_refs, &cache_input);
            if let Some(cached_response) = cache.get(&cache_key) {
                let response = GenerateContentResponse::from_response_json(&cached_response)
                    .context("Failed to parse cached response")?;
                return Ok(response);
            }
        }

        // No cache hit - need API key to make the request
        if self.api_key.is_none() {
            anyhow::bail!("Cache miss and no GEMINI_API_KEY set - cannot make API request");
        }

        let url = self.build_url(model);
        let request_headers = self.build_headers();

        let mut attempt = 0;

        loop {
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
                    let cache_key = cache.compute_key(&cache_header_refs, &cache_input);
                    cache.put(&cache_key, &response_text)?;
                }

                let response = GenerateContentResponse::from_response_json(&response_text)
                    .context("Failed to parse Gemini API response")?;

                if let Some(ref usage) = response.usage_metadata {
                    debug!(
                        "Gemini API request successful: {:?} prompt tokens, {:?} completion tokens",
                        usage.prompt_token_count, usage.candidates_token_count
                    );
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::types::gemini::{
        Content, FinishReason, FunctionCallingConfig, FunctionCallingMode, FunctionDeclaration,
        GenerationConfig, GoogleSearch, Part, Role, SystemInstruction, Tool, ToolConfig,
    };
    use std::path::PathBuf;

    fn get_cache() -> LlmCache {
        let cache_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("llm-cache");
        LlmCache::new(&cache_dir, "gemini").expect("Failed to create cache")
    }

    #[test]
    fn test_hello_world() {
        let cache = get_cache();
        let client = Client::new_with_cache(Some(cache)).expect("Failed to create client");

        let request = GenerateContentRequest {
            contents: vec![Content {
                role: Role::User,
                parts: vec![Part::text("Say exactly: Hello World")],
            }],
            tools: None,
            tool_config: None,
            system_instruction: None,
            generation_config: Some(GenerationConfig {
                temperature: Some(0.0),
                max_output_tokens: Some(100),
                ..Default::default()
            }),
        };

        let response = client
            .generate_content("gemini-2.5-flash", request)
            .expect("API call failed");

        assert!(!response.candidates.is_empty());
        let candidate = &response.candidates[0];
        assert!(
            candidate.finish_reason == Some(FinishReason::Stop)
                || candidate.finish_reason.is_none()
        );

        let text = response.text().expect("Expected text response");
        assert!(
            text.to_lowercase().contains("hello world"),
            "Response should contain 'hello world', got: {}",
            text
        );
    }

    #[test]
    fn test_tool_invocation() {
        let cache = get_cache();
        let client = Client::new_with_cache(Some(cache)).expect("Failed to create client");

        // Define a simple tool
        let tool = Tool {
            function_declarations: Some(vec![FunctionDeclaration {
                name: "get_weather".to_string(),
                description: "Get the current weather in a city".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "city": {
                            "type": "string",
                            "description": "The city name"
                        }
                    },
                    "required": ["city"]
                }),
            }]),
            google_search: None,
        };

        let request = GenerateContentRequest {
            contents: vec![Content {
                role: Role::User,
                parts: vec![Part::text("What's the weather in Paris?")],
            }],
            tools: Some(vec![tool]),
            tool_config: Some(ToolConfig {
                function_calling_config: FunctionCallingConfig {
                    mode: FunctionCallingMode::Any,
                    allowed_function_names: None,
                },
            }),
            system_instruction: None,
            generation_config: Some(GenerationConfig {
                temperature: Some(0.0),
                max_output_tokens: Some(100),
                ..Default::default()
            }),
        };

        let response = client
            .generate_content("gemini-2.5-flash", request)
            .expect("API call failed");

        assert!(!response.candidates.is_empty());

        // Verify tool was called
        let function_calls = response.function_calls();
        assert_eq!(function_calls.len(), 1);
        assert_eq!(function_calls[0].name, "get_weather");

        // Verify arguments
        assert!(
            function_calls[0].args.get("city").is_some(),
            "Expected city argument, got: {}",
            function_calls[0].args
        );
    }

    #[test]
    fn test_system_instruction() {
        let cache = get_cache();
        let client = Client::new_with_cache(Some(cache)).expect("Failed to create client");

        let request = GenerateContentRequest {
            contents: vec![Content {
                role: Role::User,
                parts: vec![Part::text("What is your name?")],
            }],
            tools: None,
            tool_config: None,
            system_instruction: Some(SystemInstruction {
                parts: vec![Part::text(
                    "You are a helpful assistant named Claude. Always introduce yourself by name.",
                )],
            }),
            generation_config: Some(GenerationConfig {
                temperature: Some(0.0),
                max_output_tokens: Some(100),
                ..Default::default()
            }),
        };

        let response = client
            .generate_content("gemini-2.5-flash", request)
            .expect("API call failed");

        let text = response.text().expect("Expected text response");
        assert!(
            text.to_lowercase().contains("claude"),
            "Response should mention Claude, got: {}",
            text
        );
    }

    #[test]
    fn test_google_search() {
        let cache = get_cache();
        let client = Client::new_with_cache(Some(cache)).expect("Failed to create client");

        // Use Google Search to find recent information
        let tool = Tool {
            function_declarations: None,
            google_search: Some(GoogleSearch::default()),
        };

        let request = GenerateContentRequest {
            contents: vec![Content {
                role: Role::User,
                parts: vec![Part::text(
                    "Who won the UEFA Euro 2024 football championship?",
                )],
            }],
            tools: Some(vec![tool]),
            tool_config: None,
            system_instruction: None,
            generation_config: Some(GenerationConfig {
                temperature: Some(0.0),
                max_output_tokens: Some(200),
                ..Default::default()
            }),
        };

        let response = client
            .generate_content("gemini-2.5-flash", request)
            .expect("API call failed");

        // Check that we got grounding metadata (search was performed)
        let candidate = &response.candidates[0];
        assert!(
            candidate.grounding_metadata.is_some(),
            "Expected grounding metadata from Google Search"
        );

        let grounding = candidate.grounding_metadata.as_ref().unwrap();
        assert!(
            !grounding.web_search_queries.is_empty(),
            "Expected web search queries to be populated"
        );

        // The response should mention Spain (the winner)
        let text = response.text().expect("Expected text response");
        assert!(
            text.to_lowercase().contains("spain"),
            "Response should mention Spain as Euro 2024 winner, got: {}",
            text
        );
    }
}
