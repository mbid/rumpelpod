//! Type definitions for the xAI (Grok) API.
//!
//! The xAI API is OpenAI-compatible, using the `/v1/chat/completions` endpoint.
//! See https://docs.x.ai/docs/api-reference for the full API reference.

use serde::{Deserialize, Serialize};

/// Role of a message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// Reason the model stopped generating.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFilter,
}

/// Text content part in a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextContent {
    #[serde(rename = "type")]
    pub content_type: TextContentType,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TextContentType {
    Text,
}

/// Image URL content part in a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUrlContent {
    #[serde(rename = "type")]
    pub content_type: ImageUrlContentType,
    pub image_url: ImageUrl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImageUrlContentType {
    ImageUrl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUrl {
    /// URL or base64-encoded image data (data:image/jpeg;base64,...)
    pub url: String,
    /// Image detail level: "low", "high", or "auto"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Content of a message - can be simple text or multimodal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// Simple text content
    Text(String),
    /// Multimodal content (text, images, etc.)
    Parts(Vec<ContentPart>),
}

/// A single part of multimodal content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text { text: String },
    ImageUrl { image_url: ImageUrl },
}

/// A tool call made by the assistant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub tool_type: ToolCallType,
    pub function: FunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolCallType {
    Function,
}

/// Function call details within a tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    /// JSON-encoded arguments
    pub arguments: String,
}

/// A message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    /// Content of the message (None for assistant messages with only tool_calls)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<MessageContent>,
    /// Tool calls made by the assistant (only present for assistant role)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// ID of the tool call this message is responding to (only for tool role)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// Tool definition for function calling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    #[serde(rename = "type")]
    pub tool_type: ToolType,
    pub function: FunctionDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolType {
    Function,
}

/// Function definition for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    pub name: String,
    pub description: String,
    /// JSON Schema for the function parameters
    pub parameters: serde_json::Value,
}

/// Tool choice configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolChoice {
    /// "none", "auto", or "required"
    Mode(ToolChoiceMode),
    /// Force a specific function
    Function(ToolChoiceFunction),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ToolChoiceMode {
    None,
    Auto,
    Required,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolChoiceFunction {
    #[serde(rename = "type")]
    pub choice_type: ToolChoiceFunctionType,
    pub function: ToolChoiceFunctionName,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolChoiceFunctionType {
    Function,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolChoiceFunctionName {
    pub name: String,
}

/// Search mode for live search functionality.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SearchMode {
    /// Disables search, uses model without accessing additional data sources.
    Off,
    /// Model automatically decides whether to perform live search.
    Auto,
    /// Enables live search.
    On,
}

/// Data source type for live search.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SearchSourceType {
    Web,
    News,
    X,
    Rss,
}

/// A search source configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchSource {
    #[serde(rename = "type")]
    pub source_type: SearchSourceType,
    /// Allowed websites (max 5, cannot be used with excluded_websites).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_websites: Option<Vec<String>>,
    /// Excluded websites (max 5, cannot be used with allowed_websites).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded_websites: Option<Vec<String>>,
}

/// Search parameters for live search in chat completions.
///
/// Enables the model to search the web, news, X, and RSS feeds for real-time data.
/// See https://docs.x.ai/docs/guides/live-search for details.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SearchParameters {
    /// Search mode: "off", "auto", or "on". Defaults to "auto" if unspecified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<SearchMode>,
    /// Maximum number of search results. Optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_search_results: Option<u32>,
    /// Whether to return citations in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_citations: Option<bool>,
    /// Start date for search data (ISO8601 format, e.g., "2025-01-01").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_date: Option<String>,
    /// End date for search data (ISO8601 format, e.g., "2025-12-31").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_date: Option<String>,
    /// Data sources to search. Defaults to web, news, and x if unspecified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<SearchSource>>,
}

/// Request body for the chat completions endpoint.
#[derive(Debug, Serialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Whether to stream the response (not supported by this client yet)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Search parameters for live search functionality.
    /// See https://docs.x.ai/docs/guides/live-search
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_parameters: Option<SearchParameters>,
}

/// Response from the chat completions endpoint.
#[derive(Debug, Deserialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Usage,
}

/// A single completion choice.
#[derive(Debug, Deserialize)]
pub struct Choice {
    pub index: u32,
    pub message: ResponseMessage,
    pub finish_reason: Option<FinishReason>,
}

/// Message in a response choice.
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseMessage {
    pub role: Role,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub tool_calls: Option<Vec<ToolCall>>,
}

/// Token usage information.
#[derive(Debug, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}
