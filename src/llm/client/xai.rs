//! xAI (Grok) API client.
//!
//! The xAI API is OpenAI-compatible, using the `/v1/chat/completions` endpoint.
//! See https://docs.x.ai/docs/api-reference for the full API reference.

use anyhow::{Context, Result};
use log::{debug, warn};
use rand::Rng;
use std::time::Duration;

use crate::llm::cache::LlmCache;
use crate::llm::types::xai::{ChatCompletionRequest, ChatCompletionResponse};

const XAI_API_URL: &str = "https://api.x.ai/v1/chat/completions";

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
        let api_key = std::env::var("XAI_API_KEY").ok().filter(|s| !s.is_empty());

        if api_key.is_none() && cache.is_none() {
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
    pub fn chat_completion(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse> {
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
                let response: ChatCompletionResponse = serde_json::from_str(&cached_response)
                    .context("Failed to parse cached response")?;
                return Ok(response);
            }
        }

        // No cache hit - need API key to make the request
        if self.api_key.is_none() {
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
                    let cache_key = cache.compute_key(&cache_header_refs, &body);
                    cache.put(&cache_key, &response_text)?;
                }

                let response: ChatCompletionResponse = serde_json::from_str(&response_text)
                    .context("Failed to parse xAI API response")?;
                debug!(
                    "xAI API request successful: {} prompt tokens, {} completion tokens",
                    response.usage.prompt_tokens, response.usage.completion_tokens
                );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::types::xai::{
        FinishReason, FunctionDefinition, Message, MessageContent, Role, SearchMode,
        SearchParameters, Tool, ToolChoice, ToolChoiceMode, ToolType,
    };
    use std::path::PathBuf;

    fn get_cache() -> LlmCache {
        let cache_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("llm-cache");
        LlmCache::new(&cache_dir, "xai").expect("Failed to create cache")
    }

    #[test]
    fn test_hello_world() {
        let cache = get_cache();
        let client = Client::new_with_cache(Some(cache)).expect("Failed to create client");

        let request = ChatCompletionRequest {
            model: "grok-3-mini-fast".to_string(),
            messages: vec![Message {
                role: Role::User,
                content: Some(MessageContent::Text("Say exactly: Hello World".to_string())),
                tool_calls: None,
                tool_call_id: None,
            }],
            max_tokens: Some(100),
            temperature: Some(0.0),
            top_p: None,
            tools: None,
            tool_choice: None,
            stream: Some(false),
            search_parameters: None,
        };

        let response = client.chat_completion(request).expect("API call failed");

        assert_eq!(response.choices.len(), 1);
        let choice = &response.choices[0];
        assert_eq!(choice.message.role, Role::Assistant);
        assert!(choice.finish_reason == Some(FinishReason::Stop));

        let content = choice.message.content.as_ref().expect("Expected content");
        assert!(
            content.to_lowercase().contains("hello world"),
            "Response should contain 'hello world', got: {}",
            content
        );
    }

    #[test]
    fn test_tool_invocation() {
        let cache = get_cache();
        let client = Client::new_with_cache(Some(cache)).expect("Failed to create client");

        // Define a simple tool
        let tool = Tool {
            tool_type: ToolType::Function,
            function: FunctionDefinition {
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
            },
        };

        let request = ChatCompletionRequest {
            model: "grok-3-mini-fast".to_string(),
            messages: vec![Message {
                role: Role::User,
                content: Some(MessageContent::Text(
                    "What's the weather in Paris?".to_string(),
                )),
                tool_calls: None,
                tool_call_id: None,
            }],
            max_tokens: Some(100),
            temperature: Some(0.0),
            top_p: None,
            tools: Some(vec![tool]),
            tool_choice: Some(ToolChoice::Mode(ToolChoiceMode::Required)),
            stream: Some(false),
            search_parameters: None,
        };

        let response = client.chat_completion(request).expect("API call failed");

        assert_eq!(response.choices.len(), 1);
        let choice = &response.choices[0];
        assert_eq!(choice.message.role, Role::Assistant);
        assert!(
            choice.finish_reason == Some(FinishReason::ToolCalls),
            "Expected tool_calls finish reason, got: {:?}",
            choice.finish_reason
        );

        // Verify tool was called
        let tool_calls = choice
            .message
            .tool_calls
            .as_ref()
            .expect("Expected tool_calls");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].function.name, "get_weather");

        // Parse and verify arguments
        let args: serde_json::Value =
            serde_json::from_str(&tool_calls[0].function.arguments).expect("Invalid JSON args");
        assert!(
            args.get("city").is_some(),
            "Expected city argument, got: {}",
            args
        );
    }

    #[test]
    fn test_web_search() {
        // Test that the model can use web search to find information past its knowledge cutoff.
        // The US penny production ended in November 2025, after the model's training data.
        let cache = get_cache();
        let client = Client::new_with_cache(Some(cache)).expect("Failed to create client");

        let request = ChatCompletionRequest {
            model: "grok-3-mini-fast".to_string(),
            messages: vec![Message {
                role: Role::User,
                content: Some(MessageContent::Text(
                    "When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.".to_string(),
                )),
                tool_calls: None,
                tool_call_id: None,
            }],
            max_tokens: Some(100),
            temperature: Some(0.0),
            top_p: None,
            tools: None,
            tool_choice: None,
            stream: Some(false),
            search_parameters: Some(SearchParameters {
                mode: Some(SearchMode::On),
                ..Default::default()
            }),
        };

        let response = client.chat_completion(request).expect("API call failed");

        assert_eq!(response.choices.len(), 1);
        let choice = &response.choices[0];
        assert_eq!(choice.message.role, Role::Assistant);
        assert!(choice.finish_reason == Some(FinishReason::Stop));

        let content = choice.message.content.as_ref().expect("Expected content");
        // The last US penny was minted on November 12, 2025
        assert!(
            content.contains("2025-11-12"),
            "Response should contain the last US penny minting date '2025-11-12', got: {}",
            content
        );
    }
}
