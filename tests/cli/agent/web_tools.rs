//! Tests for web search and fetch functionality.

use crate::common::{build_test_image, write_test_sandbox_config, TestDaemon, TestRepo};

use super::common::{
    run_agent_with_prompt_model_and_args, ANTHROPIC_MODEL, GEMINI_MODEL, XAI_MODEL,
};

fn agent_web_search(model: &str, extra_args: &[&str]) {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
        model,
        extra_args,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("2025-11-12"),
        "Agent should find that the last US penny was minted on 2025-11-12.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_web_search_anthropic() {
    // Default should be enabled, so no flags needed
    agent_web_search(ANTHROPIC_MODEL, &[]);
}

#[test]
fn agent_web_search_anthropic_explicit_enable() {
    agent_web_search(ANTHROPIC_MODEL, &["--enable-anthropic-websearch"]);
}

#[test]
fn agent_web_search_xai() {
    agent_web_search(XAI_MODEL, &[]);
}

#[test]
fn agent_web_search_gemini() {
    agent_web_search(GEMINI_MODEL, &[]);
}

#[test]
fn agent_web_search_disabled_anthropic() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
        ANTHROPIC_MODEL,
        &["--disable-anthropic-websearch"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The agent should refuse or fail to find the info.
    // Based on previous failure, it says "I don't have the ability to search the web".
    assert!(
        stdout.contains("don't have the ability to search the web")
            || stdout.contains("cannot search the web")
            || !stdout.contains("2025-11-12"),
        "Agent should NOT find the date when web search is disabled.\nstdout: {}",
        stdout
    );
}

#[test]
fn agent_web_search_anthropic_config_disable_works() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    // Disable websearch in config
    let config_path = repo.path().join(".sandbox.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("Failed to read config");
    config.push_str("\n[agent]\nanthropic-websearch = false\n");
    std::fs::write(&config_path, config).expect("Failed to update config");

    let daemon = TestDaemon::start();

    // Run without CLI flag - should be disabled by config
    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
        ANTHROPIC_MODEL,
        &[],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("don't have the ability to search the web")
            || stdout.contains("cannot search the web")
            || !stdout.contains("2025-11-12"),
        "Agent should NOT find the date when web search is disabled via config.\nstdout: {}",
        stdout
    );
}

#[test]
fn agent_web_search_anthropic_config_disable_cli_enable() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    // Disable websearch in config
    let config_path = repo.path().join(".sandbox.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("Failed to read config");
    config.push_str("\n[agent]\nanthropic-websearch = false\n");
    std::fs::write(&config_path, config).expect("Failed to update config");

    let daemon = TestDaemon::start();

    // Run WITH enable CLI flag - should be enabled despite config
    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
        ANTHROPIC_MODEL,
        &["--enable-anthropic-websearch"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("2025-11-12"),
        "Agent should find the date when web search is enabled via CLI overriding config.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_web_search_anthropic_flags_conflict() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // --enable AND --disable -> should fail with conflict error
    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Test",
        ANTHROPIC_MODEL,
        &[
            "--enable-anthropic-websearch",
            "--disable-anthropic-websearch",
        ],
    );

    assert!(
        !output.status.success(),
        "Agent should fail when conflicting flags are provided"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("argument '--enable-anthropic-websearch' cannot be used with '--disable-anthropic-websearch'") ||
        stderr.contains("argument '--disable-anthropic-websearch' cannot be used with '--enable-anthropic-websearch'"),
        "Error should mention conflicting arguments.\nstderr: {}",
        stderr
    );
}

#[test]
fn agent_web_search_anthropic_config_enable_cli_disable() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    // Enable websearch in config
    let config_path = repo.path().join(".sandbox.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("Failed to read config");
    config.push_str("\n[agent]\nanthropic-websearch = true\n");
    std::fs::write(&config_path, config).expect("Failed to update config");

    let daemon = TestDaemon::start();

    // Run WITH disable CLI flag
    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
        ANTHROPIC_MODEL,
        &["--disable-anthropic-websearch"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("don't have the ability to search the web")
            || stdout.contains("cannot search the web")
            || !stdout.contains("2025-11-12"),
        "Agent should NOT find the date when web search is disabled via CLI override.\nstdout: {}",
        stdout
    );
}
