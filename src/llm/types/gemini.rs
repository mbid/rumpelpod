//! Type definitions for the Google Gemini API (AI Studio).
//!
//! Uses the REST API at `https://generativelanguage.googleapis.com/v1beta/`.
//! See https://ai.google.dev/api/generate-content for the full API reference.

// Allow unused fields - they're part of the API response schema but we don't use all of them.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Role of a message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Model,
}

/// Reason the model stopped generating.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::enum_variant_names)]
pub enum FinishReason {
    FinishReasonUnspecified,
    Stop,
    MaxTokens,
    Safety,
    Recitation,
    Language,
    Other,
    Blocklist,
    ProhibitedContent,
    Spii,
    MalformedFunctionCall,
    ImageSafety,
    ImageProhibitedContent,
    ImageOther,
    NoImage,
    ImageRecitation,
    UnexpectedToolCall,
    TooManyToolCalls,
    MissingThoughtSignature,
}

/// Text part in a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TextPart {
    pub text: String,
}

/// Inline data part (for images, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InlineDataPart {
    pub mime_type: String,
    pub data: String,
}

/// Function call from the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub args: serde_json::Value,
}

/// Function response to send back to the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionResponse {
    pub name: String,
    pub response: serde_json::Value,
}

/// A part of content - can be text, inline data, function call, or function response.
#[derive(Debug, Clone)]
pub enum Part {
    Text(String),
    InlineData(InlineDataPart),
    FunctionCall(FunctionCall),
    FunctionResponse(FunctionResponse),
}

impl Part {
    pub fn text(text: impl Into<String>) -> Self {
        Part::Text(text.into())
    }

    pub fn function_call(name: impl Into<String>, args: serde_json::Value) -> Self {
        Part::FunctionCall(FunctionCall {
            name: name.into(),
            args,
        })
    }

    pub fn function_response(name: impl Into<String>, response: serde_json::Value) -> Self {
        Part::FunctionResponse(FunctionResponse {
            name: name.into(),
            response,
        })
    }
}

// Custom serialization for Part to match Gemini's expected format
impl serde::Serialize for Part {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        match self {
            Part::Text(text) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("text", text)?;
                map.end()
            }
            Part::InlineData(data) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("inlineData", data)?;
                map.end()
            }
            Part::FunctionCall(fc) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("functionCall", fc)?;
                map.end()
            }
            Part::FunctionResponse(fr) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("functionResponse", fr)?;
                map.end()
            }
        }
    }
}

// Custom deserialization for Part
impl<'de> serde::Deserialize<'de> for Part {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;

        struct PartVisitor;

        impl<'de> Visitor<'de> for PartVisitor {
            type Value = Part;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a Part object with text, inlineData, functionCall, or functionResponse",
                )
            }

            fn visit_map<M>(self, mut map: M) -> Result<Part, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut text: Option<String> = None;
                let mut inline_data: Option<InlineDataPart> = None;
                let mut function_call: Option<FunctionCall> = None;
                let mut function_response: Option<FunctionResponse> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "text" => text = Some(map.next_value()?),
                        "inlineData" => inline_data = Some(map.next_value()?),
                        "functionCall" => function_call = Some(map.next_value()?),
                        "functionResponse" => function_response = Some(map.next_value()?),
                        _ => {
                            // Skip unknown fields
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                if let Some(text) = text {
                    Ok(Part::Text(text))
                } else if let Some(data) = inline_data {
                    Ok(Part::InlineData(data))
                } else if let Some(fc) = function_call {
                    Ok(Part::FunctionCall(fc))
                } else if let Some(fr) = function_response {
                    Ok(Part::FunctionResponse(fr))
                } else {
                    Err(serde::de::Error::custom(
                        "Part must have text, inlineData, functionCall, or functionResponse",
                    ))
                }
            }
        }

        deserializer.deserialize_map(PartVisitor)
    }
}

/// Content in a conversation (a turn from either user or model).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Content {
    pub role: Role,
    pub parts: Vec<Part>,
}

/// Function declaration for tool calling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionDeclaration {
    pub name: String,
    pub description: String,
    /// JSON Schema for the function parameters
    pub parameters: serde_json::Value,
}

/// Google Search tool configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GoogleSearch {}

/// Tool definition - can contain function declarations or server-side tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    /// Function declarations for custom tools.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_declarations: Option<Vec<FunctionDeclaration>>,
    /// Google Search grounding tool (server-side).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_search: Option<GoogleSearch>,
}

/// Function calling mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FunctionCallingMode {
    ModeUnspecified,
    Auto,
    Any,
    None,
}

/// Function calling configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionCallingConfig {
    pub mode: FunctionCallingMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_function_names: Option<Vec<String>>,
}

/// Tool configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolConfig {
    pub function_calling_config: FunctionCallingConfig,
}

/// System instruction content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInstruction {
    pub parts: Vec<Part>,
}

/// Generation configuration options.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
}

/// Request body for the generateContent endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateContentRequest {
    pub contents: Vec<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_config: Option<ToolConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_instruction: Option<SystemInstruction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_config: Option<GenerationConfig>,
}

/// Safety rating for a piece of content.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyRating {
    pub category: String,
    pub probability: String,
    #[serde(default)]
    pub blocked: bool,
}

/// Citation source information.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CitationSource {
    #[serde(default)]
    pub start_index: Option<u32>,
    #[serde(default)]
    pub end_index: Option<u32>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
}

/// Citation metadata.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CitationMetadata {
    #[serde(default)]
    pub citation_sources: Vec<CitationSource>,
}

/// A single candidate response from the model.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub content: Content,
    #[serde(default)]
    pub finish_reason: Option<FinishReason>,
    #[serde(default)]
    pub safety_ratings: Option<Vec<SafetyRating>>,
    #[serde(default)]
    pub citation_metadata: Option<CitationMetadata>,
    #[serde(default)]
    pub grounding_metadata: Option<GroundingMetadata>,
    #[serde(default)]
    pub index: Option<u32>,
}

/// Token usage information.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageMetadata {
    pub prompt_token_count: u32,
    pub candidates_token_count: u32,
    pub total_token_count: u32,
}

/// Web source information in grounding chunks.
#[derive(Debug, Clone, Deserialize)]
pub struct WebSource {
    pub uri: String,
    pub title: String,
}

/// A grounding chunk containing a web source.
#[derive(Debug, Clone, Deserialize)]
pub struct GroundingChunk {
    pub web: Option<WebSource>,
}

/// A segment of text that is supported by grounding.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroundingSegment {
    pub start_index: Option<u32>,
    pub end_index: Option<u32>,
    pub text: Option<String>,
}

/// Support information linking text segments to grounding chunks.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroundingSupport {
    pub segment: Option<GroundingSegment>,
    pub grounding_chunk_indices: Option<Vec<u32>>,
}

/// Search entry point for displaying search suggestions.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchEntryPoint {
    pub rendered_content: Option<String>,
}

/// Metadata about grounding with Google Search.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroundingMetadata {
    /// Search queries that were executed.
    #[serde(default)]
    pub web_search_queries: Vec<String>,
    /// HTML/CSS for rendering search suggestions.
    #[serde(default)]
    pub search_entry_point: Option<SearchEntryPoint>,
    /// Web sources used for grounding.
    #[serde(default)]
    pub grounding_chunks: Vec<GroundingChunk>,
    /// Links between text segments and their sources.
    #[serde(default)]
    pub grounding_supports: Vec<GroundingSupport>,
}

/// Response from the generateContent endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateContentResponse {
    pub candidates: Vec<Candidate>,
    #[serde(default)]
    pub usage_metadata: Option<UsageMetadata>,
    #[serde(default)]
    pub model_version: Option<String>,
}

impl GenerateContentResponse {
    /// Extract text from the first candidate's response.
    pub fn text(&self) -> Option<String> {
        self.candidates.first().and_then(|c| {
            c.content.parts.iter().find_map(|p| match p {
                Part::Text(text) => Some(text.clone()),
                _ => None,
            })
        })
    }

    /// Extract function calls from the first candidate's response.
    pub fn function_calls(&self) -> Vec<&FunctionCall> {
        self.candidates
            .first()
            .map(|c| {
                c.content
                    .parts
                    .iter()
                    .filter_map(|p| match p {
                        Part::FunctionCall(fc) => Some(fc),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}
