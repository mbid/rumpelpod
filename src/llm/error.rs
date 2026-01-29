use std::time::Duration;
use thiserror::Error;

/// Error types for LLM API calls that distinguish between retryable and non-retryable errors.
#[derive(Error, Debug)]
pub enum LlmError {
    /// A network or connection error from reqwest that may be transient.
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),

    /// API rate limit was hit. Contains optional retry-after duration if provided by the server.
    #[error("Too Many Requests")]
    RateLimited { retry_after: Option<Duration> },

    /// Any other error that should not be retried (e.g., invalid API key, bad request, logic errors).
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
