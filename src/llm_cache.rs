//! LLM response cache for deterministic testing.
//!
//! See [`llm-cache/README.md`](../../llm-cache/README.md) for usage documentation.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// LLM response cache for testing.
/// Uses sha256 hash of request (headers + body) as filename.
pub struct LlmCache {
    cache_dir: PathBuf,
    scratch_dir: PathBuf,
}

impl LlmCache {
    /// Create a new cache instance for a specific provider (e.g., "anthropic").
    /// Creates the directories if they don't exist.
    pub fn new(base_dir: &Path, provider: &str) -> Result<Self> {
        let cache_dir = base_dir.join(provider);
        let scratch_dir = base_dir.join("scratch");

        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("Failed to create cache dir: {}", cache_dir.display()))?;
        fs::create_dir_all(&scratch_dir)
            .with_context(|| format!("Failed to create scratch dir: {}", scratch_dir.display()))?;

        Ok(Self {
            cache_dir,
            scratch_dir,
        })
    }

    /// Compute the cache key from sorted headers and body.
    /// Headers should be passed as (name, value) pairs.
    pub fn compute_key(&self, headers: &[(&str, &str)], body: &str) -> String {
        let mut sorted_headers: Vec<_> = headers.to_vec();
        sorted_headers.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(b.1)));

        let mut hasher = Sha256::new();
        for (name, value) in sorted_headers {
            hasher.update(name.as_bytes());
            hasher.update(b": ");
            hasher.update(value.as_bytes());
            hasher.update(b"\n");
        }
        hasher.update(b"\n");
        hasher.update(body.as_bytes());

        hex::encode(hasher.finalize())
    }

    fn cache_path(&self, key: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", key))
    }

    /// Try to get a cached response.
    pub fn get(&self, key: &str) -> Option<String> {
        let path = self.cache_path(key);
        fs::read_to_string(&path).ok()
    }

    /// Store a response in the cache atomically.
    /// Uses write-to-temp-file-then-move for consistency.
    pub fn put(&self, key: &str, response: &str) -> Result<()> {
        let final_path = self.cache_path(key);

        // Create temp file in scratch directory, then persist (atomic move)
        let temp_file = tempfile::Builder::new()
            .prefix("cache-")
            .suffix(".json")
            .tempfile_in(&self.scratch_dir)
            .context("Failed to create temp file for cache")?;

        fs::write(temp_file.path(), response).context("Failed to write to temp cache file")?;

        temp_file
            .persist(&final_path)
            .with_context(|| format!("Failed to persist cache file to {}", final_path.display()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cache_key_deterministic() {
        let dir = tempdir().unwrap();
        let cache = LlmCache::new(dir.path(), "test").unwrap();

        let headers = vec![("x-api-key", "test"), ("content-type", "application/json")];
        let body = r#"{"model": "test"}"#;

        let key1 = cache.compute_key(&headers, body);
        let key2 = cache.compute_key(&headers, body);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_sorted_headers() {
        let dir = tempdir().unwrap();
        let cache = LlmCache::new(dir.path(), "test").unwrap();

        let headers1 = vec![("b-header", "2"), ("a-header", "1")];
        let headers2 = vec![("a-header", "1"), ("b-header", "2")];
        let body = "test";

        let key1 = cache.compute_key(&headers1, body);
        let key2 = cache.compute_key(&headers2, body);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_put_get() {
        let dir = tempdir().unwrap();
        let cache = LlmCache::new(dir.path(), "test").unwrap();

        let key = "abc123";
        let response = r#"{"result": "ok"}"#;

        assert!(cache.get(key).is_none());

        cache.put(key, response).unwrap();

        assert_eq!(cache.get(key), Some(response.to_string()));
    }
}
