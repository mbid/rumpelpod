//! Type definitions for the Google Gemini API (AI Studio).
//!
//! Uses the REST API at `https://generativelanguage.googleapis.com/v1beta/`.
//! See https://ai.google.dev/api/generate-content for the full API reference.

// Allow unused fields - they're part of the API response schema but we don't use all of them.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Gemini models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
pub enum Model {
    /// Gemini 2.5 Flash - fast, stable, best price-performance
    #[serde(rename = "gemini-2.5-flash")]
    #[value(name = "gemini-2.5-flash")]
    Gemini25Flash,
    /// Gemini 3 Flash - frontier model built for speed and scale
    #[serde(rename = "gemini-3-flash-preview")]
    #[value(name = "gemini-3-flash-preview")]
    Gemini3Flash,
    /// Gemini 3 Pro - most intelligent frontier model
    #[serde(rename = "gemini-3-pro-preview")]
    #[value(name = "gemini-3-pro-preview")]
    Gemini3Pro,
}

impl std::fmt::Display for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use the serde rename as the string representation
        let s = match self {
            Model::Gemini25Flash => "gemini-2.5-flash",
            Model::Gemini3Flash => "gemini-3-flash-preview",
            Model::Gemini3Pro => "gemini-3-pro-preview",
        };
        write!(f, "{}", s)
    }
}

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

/// The content type within a Part.
#[derive(Debug, Clone)]
pub enum PartContent {
    Text(String),
    InlineData(InlineDataPart),
    FunctionCall(FunctionCall),
    FunctionResponse(FunctionResponse),
}

/// A part of content - can be text, inline data, function call, or function response.
/// Gemini 3 models include thought signatures for maintaining reasoning context.
#[derive(Debug, Clone)]
pub struct Part {
    pub content: PartContent,
    /// Thought signature for Gemini 3 models. Must be preserved and returned
    /// to maintain reasoning context across API calls.
    pub thought_signature: Option<String>,
}

impl Part {
    pub fn text(text: impl Into<String>) -> Self {
        Part {
            content: PartContent::Text(text.into()),
            thought_signature: None,
        }
    }

    pub fn function_call(name: impl Into<String>, args: serde_json::Value) -> Self {
        Part {
            content: PartContent::FunctionCall(FunctionCall {
                name: name.into(),
                args,
            }),
            thought_signature: None,
        }
    }

    pub fn function_response(name: impl Into<String>, response: serde_json::Value) -> Self {
        Part {
            content: PartContent::FunctionResponse(FunctionResponse {
                name: name.into(),
                response,
            }),
            thought_signature: None,
        }
    }

    /// Check if this part is a Text variant.
    pub fn as_text(&self) -> Option<&str> {
        match &self.content {
            PartContent::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Check if this part is a FunctionCall variant.
    pub fn as_function_call(&self) -> Option<&FunctionCall> {
        match &self.content {
            PartContent::FunctionCall(fc) => Some(fc),
            _ => None,
        }
    }

    /// Check if this part is a FunctionResponse variant.
    pub fn as_function_response(&self) -> Option<&FunctionResponse> {
        match &self.content {
            PartContent::FunctionResponse(fr) => Some(fr),
            _ => None,
        }
    }
}

// Custom serialization for Part to match Gemini's expected format
impl serde::Serialize for Part {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let has_signature = self.thought_signature.is_some();
        let map_size = if has_signature { 2 } else { 1 };

        match &self.content {
            PartContent::Text(text) => {
                let mut map = serializer.serialize_map(Some(map_size))?;
                map.serialize_entry("text", text)?;
                if let Some(ref sig) = self.thought_signature {
                    map.serialize_entry("thoughtSignature", sig)?;
                }
                map.end()
            }
            PartContent::InlineData(data) => {
                let mut map = serializer.serialize_map(Some(map_size))?;
                map.serialize_entry("inlineData", data)?;
                if let Some(ref sig) = self.thought_signature {
                    map.serialize_entry("thoughtSignature", sig)?;
                }
                map.end()
            }
            PartContent::FunctionCall(fc) => {
                let mut map = serializer.serialize_map(Some(map_size))?;
                map.serialize_entry("functionCall", fc)?;
                if let Some(ref sig) = self.thought_signature {
                    map.serialize_entry("thoughtSignature", sig)?;
                }
                map.end()
            }
            PartContent::FunctionResponse(fr) => {
                let mut map = serializer.serialize_map(Some(map_size))?;
                map.serialize_entry("functionResponse", fr)?;
                if let Some(ref sig) = self.thought_signature {
                    map.serialize_entry("thoughtSignature", sig)?;
                }
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
                let mut thought_signature: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "text" => text = Some(map.next_value()?),
                        "inlineData" => inline_data = Some(map.next_value()?),
                        "functionCall" => function_call = Some(map.next_value()?),
                        "functionResponse" => function_response = Some(map.next_value()?),
                        "thoughtSignature" => thought_signature = Some(map.next_value()?),
                        _ => {
                            // Skip unknown fields
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let content = if let Some(text) = text {
                    PartContent::Text(text)
                } else if let Some(data) = inline_data {
                    PartContent::InlineData(data)
                } else if let Some(fc) = function_call {
                    PartContent::FunctionCall(fc)
                } else if let Some(fr) = function_response {
                    PartContent::FunctionResponse(fr)
                } else {
                    return Err(serde::de::Error::custom(
                        "Part must have text, inlineData, functionCall, or functionResponse",
                    ));
                };

                Ok(Part {
                    content,
                    thought_signature,
                })
            }
        }

        deserializer.deserialize_map(PartVisitor)
    }
}

/// Content in a conversation (a turn from either user or model).
/// Used for requests - role is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Content {
    pub role: Role,
    pub parts: Vec<Part>,
}

/// Content as returned in API responses.
/// The role field is optional in responses (official SDKs treat it as optional),
/// so we deserialize to this type and then convert to Content.
#[derive(Debug, Clone, Deserialize)]
pub struct ContentResponse {
    pub role: Option<Role>,
    pub parts: Option<Vec<Part>>,
}

impl ContentResponse {
    /// Convert to Content, defaulting missing role to Model.
    /// API responses are always from the model, so this is the correct default.
    pub fn into_content(self) -> Content {
        Content {
            role: self.role.unwrap_or(Role::Model),
            parts: self.parts.unwrap_or_default(),
        }
    }
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

/// A single candidate response from the model (raw API response).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CandidateResponse {
    pub content: ContentResponse,
    #[serde(default)]
    pub finish_reason: Option<FinishReason>,
    #[serde(default)]
    pub finish_message: Option<String>,
    #[serde(default)]
    pub safety_ratings: Option<Vec<SafetyRating>>,
    #[serde(default)]
    pub citation_metadata: Option<CitationMetadata>,
    #[serde(default)]
    pub grounding_metadata: Option<GroundingMetadata>,
    #[serde(default)]
    pub index: Option<u32>,
}

/// A single candidate response from the model.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub content: Content,
    pub finish_reason: Option<FinishReason>,
    pub finish_message: Option<String>,
    pub safety_ratings: Option<Vec<SafetyRating>>,
    pub citation_metadata: Option<CitationMetadata>,
    pub grounding_metadata: Option<GroundingMetadata>,
    pub index: Option<u32>,
}

impl From<CandidateResponse> for Candidate {
    fn from(
        CandidateResponse {
            content,
            finish_reason,
            finish_message,
            safety_ratings,
            citation_metadata,
            grounding_metadata,
            index,
        }: CandidateResponse,
    ) -> Self {
        Candidate {
            content: content.into_content(),
            finish_reason,
            finish_message,
            safety_ratings,
            citation_metadata,
            grounding_metadata,
            index,
        }
    }
}

/// Token usage information.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageMetadata {
    #[serde(default)]
    pub prompt_token_count: Option<u32>,
    #[serde(default)]
    pub candidates_token_count: Option<u32>,
    #[serde(default)]
    pub total_token_count: Option<u32>,
    #[serde(default)]
    pub cached_content_token_count: Option<u32>,
    #[serde(default)]
    pub thoughts_token_count: Option<u32>,
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

/// Raw response from the generateContent endpoint (for deserialization).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateContentResponseRaw {
    pub candidates: Vec<CandidateResponse>,
    #[serde(default)]
    pub usage_metadata: Option<UsageMetadata>,
    #[serde(default)]
    pub model_version: Option<String>,
}

/// Response from the generateContent endpoint.
#[derive(Debug)]
pub struct GenerateContentResponse {
    pub candidates: Vec<Candidate>,
    pub usage_metadata: Option<UsageMetadata>,
    pub model_version: Option<String>,
}

impl From<GenerateContentResponseRaw> for GenerateContentResponse {
    fn from(raw: GenerateContentResponseRaw) -> Self {
        GenerateContentResponse {
            candidates: raw.candidates.into_iter().map(Candidate::from).collect(),
            usage_metadata: raw.usage_metadata,
            model_version: raw.model_version,
        }
    }
}

impl GenerateContentResponse {
    /// Parse from JSON string, converting the raw response to the public type.
    /// This handles the optional `role` field in responses by defaulting to Model.
    pub fn from_response_json(json: &str) -> Result<Self, serde_json::Error> {
        let raw: GenerateContentResponseRaw = serde_json::from_str(json)?;
        Ok(raw.into())
    }

    /// Extract text from the first candidate's response.
    pub fn text(&self) -> Option<String> {
        self.candidates.first().and_then(|c| {
            c.content
                .parts
                .iter()
                .find_map(|p| p.as_text().map(|s| s.to_string()))
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
                    .filter_map(|p| p.as_function_call())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_malformed_function_call_response() {
        let json = r#"{
  "candidates": [
    {
      "content": {},
      "finishReason": "MALFORMED_FUNCTION_CALL",
      "index": 0,
      "finishMessage": "Malformed function call: call:default_api:edit{file_path: src/agent/anthropic.rs}"
    }
  ],
  "usageMetadata": {
    "promptTokenCount": 14265,
    "totalTokenCount": 14265
  },
  "modelVersion": "gemini-3-flash-preview"
}"#;

        let response = GenerateContentResponse::from_response_json(json).unwrap();
        assert_eq!(response.candidates.len(), 1);
        assert_eq!(
            response.candidates[0].finish_reason,
            Some(FinishReason::MalformedFunctionCall)
        );
        assert!(response.candidates[0]
            .finish_message
            .as_ref()
            .unwrap()
            .contains("Malformed function call"));
        assert!(response.candidates[0].content.parts.is_empty());
    }
}
