# LLM Response Cache

This directory contains cached LLM API responses used by integration tests.

## Purpose

The cache enables **cheap and deterministic** LLM API calls in tests while keeping
them **realistic** (actual API responses, not hand-crafted mocks).

## How it works

1. Each LLM request is hashed (headers + body) to produce a deterministic cache key
2. On cache hit, the stored response is returned without an API call
3. On cache miss, the actual API is called and the response is stored

The cache key excludes the API key, so cached responses work regardless of whether
`ANTHROPIC_API_KEY`, `XAI_API_KEY`, or `GEMINI_API_KEY` is set.

## Workflow for tests

1. **First run (populate cache):** Run tests with `ANTHROPIC_API_KEY` set.
   Cache misses will hit the real API and store responses.

2. **Check in cache files:** Commit new/modified files in `llm-cache/` to the repo.

3. **Subsequent runs:** Tests use cached responses. No API key needed, fast & deterministic.

## Detecting problems

If **new files appear** in `llm-cache/` on every test run, something is wrong:
- Non-deterministic request content (timestamps, random IDs, etc.)
- Test logic changed but cache wasn't updated

Run `git status llm-cache/` after tests to check for unexpected new files.

## Regenerating the cache

When agent implementation changes affect LLM requests (different prompts, tools, etc.),
the cache needs to be regenerated:

1. Optionally delete affected cache files (or all of `llm-cache/anthropic/*.json`)
2. Run tests with `ANTHROPIC_API_KEY` set
3. Commit the new cache files

This happens automatically on the first test run after such changes.

## Directory structure

```
llm-cache/
├── README.md           # This file
├── anthropic/          # Cached Anthropic API responses
│   ├── .gitkeep
│   └── <sha256>.json   # Individual cached responses
├── gemini/             # Cached Google Gemini API responses
│   ├── .gitkeep
│   └── <sha256>.json   # Individual cached responses
├── xai/                # Cached xAI API responses
│   ├── .gitkeep
│   └── <sha256>.json   # Individual cached responses
└── scratch/            # Temporary files during atomic writes (not committed)
```

## Implementation

See [`src/llm_cache.rs`](../src/llm_cache.rs) for the cache implementation.
