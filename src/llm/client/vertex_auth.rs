//! Google Cloud Vertex AI authentication via service account JWT.
//!
//! This module handles OAuth2 token generation from a Google Cloud service account
//! JSON key file. It creates JWTs signed with the service account's private key
//! and exchanges them for short-lived access tokens.
//!
//! Environment variables:
//! - `GOOGLE_APPLICATION_CREDENTIALS`: Path to service account JSON key file
//! - `GOOGLE_CLOUD_PROJECT`: GCP project ID (optional, extracted from key file if not set)
//! - `GOOGLE_CLOUD_LOCATION`: GCP location (defaults to "global")

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

/// Scope required for Vertex AI API access.
const VERTEX_AI_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// Google OAuth2 token endpoint.
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// JWT grant type for service account authentication.
const JWT_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Buffer time before token expiry to consider it expired (5 minutes).
const TOKEN_EXPIRY_BUFFER_SECS: u64 = 300;

/// Service account JSON key file structure.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccountKey {
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    #[serde(rename = "type")]
    pub key_type: String,
}

/// JWT claims for Google OAuth2.
#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

/// Response from Google OAuth2 token endpoint.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[allow(dead_code)]
    token_type: String,
}

/// Cached OAuth2 access token with expiry tracking.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    /// Unix timestamp when the token expires
    expires_at: u64,
}

impl CachedToken {
    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        // Consider expired if within buffer time of actual expiry
        now + TOKEN_EXPIRY_BUFFER_SECS >= self.expires_at
    }
}

/// Vertex AI configuration extracted from environment.
#[derive(Debug, Clone)]
pub struct VertexConfig {
    pub project_id: String,
    pub location: String,
    service_account_key: ServiceAccountKey,
}

impl VertexConfig {
    /// Load Vertex AI configuration from environment variables.
    ///
    /// Returns None if GOOGLE_APPLICATION_CREDENTIALS is not set.
    pub fn from_env() -> Result<Option<Self>> {
        // Check for service account credentials file
        let credentials_path = match std::env::var("GOOGLE_APPLICATION_CREDENTIALS") {
            Ok(path) if !path.is_empty() => PathBuf::from(path),
            _ => return Ok(None),
        };

        // Load and parse the service account key file
        let key_json = fs::read_to_string(&credentials_path).with_context(|| {
            format!(
                "Failed to read service account key file: {}",
                credentials_path.display()
            )
        })?;

        let service_account_key: ServiceAccountKey =
            serde_json::from_str(&key_json).with_context(|| {
                format!(
                    "Failed to parse service account key file: {}",
                    credentials_path.display()
                )
            })?;

        // Validate key type
        if service_account_key.key_type != "service_account" {
            anyhow::bail!(
                "Invalid key type '{}' in credentials file, expected 'service_account'",
                service_account_key.key_type
            );
        }

        // Get project ID from env or from the key file
        let project_id = std::env::var("GOOGLE_CLOUD_PROJECT")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| service_account_key.project_id.clone());

        // Get location from env or default to "global"
        let location = std::env::var("GOOGLE_CLOUD_LOCATION")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "global".to_string());

        Ok(Some(Self {
            project_id,
            location,
            service_account_key,
        }))
    }
}

/// Vertex AI authenticator that manages OAuth2 tokens.
pub struct VertexAuthenticator {
    config: VertexConfig,
    http_client: reqwest::blocking::Client,
    /// Cached token protected by mutex for thread safety
    cached_token: Mutex<Option<CachedToken>>,
}

impl VertexAuthenticator {
    /// Create a new authenticator from Vertex AI configuration.
    pub fn new(config: VertexConfig, http_client: reqwest::blocking::Client) -> Self {
        Self {
            config,
            http_client,
            cached_token: Mutex::new(None),
        }
    }

    /// Get a valid access token, refreshing if necessary.
    ///
    /// Returns the access token string for use in Authorization header.
    pub fn get_access_token(&self) -> Result<String> {
        // Check if we have a valid cached token
        {
            let cached = self.cached_token.lock().unwrap();
            if let Some(ref token) = *cached {
                if !token.is_expired() {
                    return Ok(token.access_token.clone());
                }
            }
        }

        // Need to refresh the token
        self.refresh_token()
    }

    /// Force refresh the access token.
    ///
    /// This is called when we get a 401 error, indicating the token may have
    /// been invalidated before its expected expiry.
    pub fn refresh_token(&self) -> Result<String> {
        let token = self.fetch_new_token()?;
        let access_token = token.access_token.clone();

        // Cache the new token
        let mut cached = self.cached_token.lock().unwrap();
        *cached = Some(token);

        Ok(access_token)
    }

    /// Clear the cached token.
    ///
    /// Called when we receive an authentication error to ensure we fetch a fresh token.
    pub fn clear_cached_token(&self) {
        let mut cached = self.cached_token.lock().unwrap();
        *cached = None;
    }

    /// Fetch a new access token from Google OAuth2.
    fn fetch_new_token(&self) -> Result<CachedToken> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time before UNIX epoch")?
            .as_secs();

        // JWT expires in 1 hour (Google's maximum)
        let exp = now + 3600;

        let claims = JwtClaims {
            iss: self.config.service_account_key.client_email.clone(),
            scope: VERTEX_AI_SCOPE.to_string(),
            aud: TOKEN_URL.to_string(),
            exp,
            iat: now,
        };

        // Create JWT header with key ID
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.config.service_account_key.private_key_id.clone());

        // Sign the JWT with the private key
        let encoding_key =
            EncodingKey::from_rsa_pem(self.config.service_account_key.private_key.as_bytes())
                .context("Failed to parse RSA private key from service account")?;

        let jwt = encode(&header, &claims, &encoding_key)
            .context("Failed to encode JWT for service account")?;

        // Exchange JWT for access token
        let response = self
            .http_client
            .post(TOKEN_URL)
            .form(&[("grant_type", JWT_GRANT_TYPE), ("assertion", &jwt)])
            .send()
            .context("Failed to send token request to Google OAuth2")?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().unwrap_or_default();
            anyhow::bail!(
                "OAuth2 token request failed (status {}): {}",
                status,
                error_text
            );
        }

        let token_response: TokenResponse = response
            .json()
            .context("Failed to parse OAuth2 token response")?;

        Ok(CachedToken {
            access_token: token_response.access_token,
            expires_at: now + token_response.expires_in,
        })
    }

    /// Get the project ID from the configuration.
    pub fn project_id(&self) -> &str {
        &self.config.project_id
    }

    /// Get the location from the configuration.
    pub fn location(&self) -> &str {
        &self.config.location
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_token_expiry() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Token that expires in 10 minutes - should not be considered expired
        let valid_token = CachedToken {
            access_token: "test".to_string(),
            expires_at: now + 600,
        };
        assert!(!valid_token.is_expired());

        // Token that expires in 4 minutes - should be considered expired (within buffer)
        let expiring_token = CachedToken {
            access_token: "test".to_string(),
            expires_at: now + 240,
        };
        assert!(expiring_token.is_expired());

        // Token that already expired - should be considered expired
        let expired_token = CachedToken {
            access_token: "test".to_string(),
            expires_at: now - 60,
        };
        assert!(expired_token.is_expired());
    }
}
