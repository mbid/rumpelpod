//! Type definitions for the xAI (Grok) API.
//!
//! The xAI API uses the `/v1/responses` endpoint for agentic workflows.
//! See https://docs.x.ai/docs/api-reference for the full API reference.

use serde::{Deserialize, Serialize};

/// xAI models.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Model {
    /// Grok 4.1 Fast - frontier model optimized for agentic tool calling
    #[serde(rename = "grok-4-1-fast-reasoning")]
    Grok41Fast,
    /// Grok 4.1 Fast - non-reasoning variant
    #[serde(rename = "grok-4-1-fast-non-reasoning")]
    Grok41FastNonReasoning,
    /// Custom model string
    Custom(String),
}

impl std::fmt::Display for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use the serde rename as the string representation
        let s = match self {
            Model::Grok41Fast => "grok-4-1-fast-reasoning",
            Model::Grok41FastNonReasoning => "grok-4-1-fast-non-reasoning",
            Model::Custom(s) => s,
        };
        write!(f, "{}", s)
    }
}

/// Role of a message in the conversation (kept for local history display).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// Tool definition for function calling and server-side tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Tool {
    /// Function tool for custom function calling
    Function {
        name: String,
        description: String,
        /// JSON Schema for the function parameters
        parameters: serde_json::Value,
    },
    /// Server-side web search tool
    WebSearch {
        #[serde(skip_serializing_if = "Option::is_none")]
        allowed_domains: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        excluded_domains: Option<Vec<String>>,
    },
}

/// Request body for the responses endpoint.
#[derive(Debug, Serialize)]
pub struct ResponseRequest {
    pub model: String,
    pub input: ResponseInput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    // Only set store if false, default is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ResponseInput {
    Prompt(String),
    Items(Vec<ResponseInputItem>),
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseInputItem {
    FunctionCallOutput { call_id: String, output: String },
}

/// Response from the responses endpoint.
#[derive(Debug, Deserialize)]
pub struct ResponseResponse {
    pub id: String,
    pub output: Option<Vec<ResponseOutputItem>>,
    #[serde(alias = "created_at")]
    pub created: u64,
    pub model: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseOutputItem {
    /// Function call from the model requesting tool execution
    FunctionCall {
        call_id: String,
        name: String,
        arguments: String,
    },
    /// Direct text output
    Text { text: String },
    /// Message with structured content parts
    Message {
        content: Vec<MessageContentPart>,
        role: Role,
    },
    /// Server-side web search was performed (results in subsequent Message)
    WebSearchCall { id: String, status: String },
    /// Server-side X/Twitter search was performed
    XSearchCall { id: String, status: String },
    /// Reasoning/thinking output from the model
    Reasoning { id: String, status: String },
    /// Handle unknown types gracefully
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageContentPart {
    OutputText {
        text: String,
    },
    #[serde(other)]
    Unknown,
}

// Legacy types kept for local history / compatibility if needed,
// but updated to reflect they are not used for the API request anymore.

/// Content of a message - can be simple text or multimodal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// Simple text content
    Text(String),
    // We don't need Parts for now as the new API handles input as string or tool outputs
}

/// A message in the conversation (for local tracking).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    /// Content of the message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<MessageContent>,
    /// Tool calls made by the assistant
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// ID of the tool call this message is responding to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// A tool call (for local tracking).
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

/// Function call details (for local tracking).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    /// JSON-encoded arguments
    pub arguments: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_serialization() {
        // Test function tool serialization
        let function_tool = Tool::Function {
            name: "bash".to_string(),
            description: "Execute bash".to_string(),
            parameters: serde_json::json!({"type": "object"}),
        };
        let json = serde_json::to_string(&function_tool).unwrap();
        assert!(
            json.contains("\"type\":\"function\""),
            "Function tool should have type:function"
        );
        assert!(
            json.contains("\"name\":\"bash\""),
            "Function tool should have name field"
        );

        // Test web_search tool serialization - should NOT have nested web_search field
        let web_search_tool = Tool::WebSearch {
            allowed_domains: None,
            excluded_domains: None,
        };
        let json = serde_json::to_string(&web_search_tool).unwrap();
        // Should serialize to just {"type":"web_search"} without any nested objects
        assert_eq!(
            json, r#"{"type":"web_search"}"#,
            "WebSearch with no config should serialize cleanly"
        );

        // Test web_search with allowed_domains
        let web_search_with_domains = Tool::WebSearch {
            allowed_domains: Some(vec!["example.com".to_string()]),
            excluded_domains: None,
        };
        let json = serde_json::to_string(&web_search_with_domains).unwrap();
        assert!(
            json.contains("\"allowed_domains\":[\"example.com\"]"),
            "Should have allowed_domains at top level"
        );
        assert!(
            !json.contains("\"web_search\":"),
            "Should NOT have nested web_search field"
        );
    }
}
