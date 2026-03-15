//! Tests for web search and fetch functionality.

use crate::common::{build_test_image, TestRepo};
use crate::executor::TestPod;

use super::common::{
    run_agent_interactive_model_and_args, ANTHROPIC_MODEL, GEMINI_MODEL, XAI_MODEL,
};

fn agent_web_search(model: &str, extra_args: &[&str], test_name: &str) {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, test_name);

    let output = run_agent_interactive_model_and_args(
        &repo,
        &pod.daemon,
        &["Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format."],
        model,
        extra_args,
    );

    assert!(
        output.stdout.contains("2025-11-12"),
        "Agent should find that the last US penny was minted on 2025-11-12.\nstdout: {}",
        output.stdout
    );
}

#[test]
fn agent_web_search_anthropic() {
    // Default should be enabled, so no flags needed
    agent_web_search(ANTHROPIC_MODEL, &[], "agent-web-anthropic");
}

#[test]
fn agent_web_search_anthropic_explicit_enable() {
    agent_web_search(
        ANTHROPIC_MODEL,
        &["--enable-anthropic-websearch"],
        "agent-web-anth-en",
    );
}

#[test]
fn agent_web_search_xai() {
    agent_web_search(XAI_MODEL, &[], "agent-web-xai");
}

#[test]
fn agent_web_search_gemini() {
    agent_web_search(GEMINI_MODEL, &[], "agent-web-gemini");
}

#[test]
fn agent_web_search_disabled_anthropic() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "agent-web-disabled");

    let output = run_agent_interactive_model_and_args(
        &repo,
        &pod.daemon,
        &["Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format."],
        ANTHROPIC_MODEL,
        &["--disable-anthropic-websearch"],
    );

    // The agent should refuse or fail to find the info.
    // Based on previous failure, it says "I don't have the ability to search the web".
    assert!(
        output
            .stdout
            .contains("don't have the ability to search the web")
            || output.stdout.contains("cannot search the web")
            || !output.stdout.contains("2025-11-12"),
        "Agent should NOT find the date when web search is disabled.\nstdout: {}",
        output.stdout
    );
}

#[test]
fn agent_web_search_anthropic_config_disable_works() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "agent-web-cfg-dis");

    // Disable websearch in config
    let config_path = repo.path().join(".rumpelpod.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("Failed to read config");
    config.push_str("\n[agent]\nanthropic-websearch = false\n");
    std::fs::write(&config_path, config).expect("Failed to update config");

    // Run without CLI flag - should be disabled by config
    let output = run_agent_interactive_model_and_args(
        &repo,
        &pod.daemon,
        &["Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format."],
        ANTHROPIC_MODEL,
        &[],
    );

    assert!(
        output
            .stdout
            .contains("don't have the ability to search the web")
            || output.stdout.contains("cannot search the web")
            || !output.stdout.contains("2025-11-12"),
        "Agent should NOT find the date when web search is disabled via config.\nstdout: {}",
        output.stdout
    );
}

#[test]
fn agent_web_search_anthropic_config_disable_cli_enable() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "agent-web-cfg-en");

    // Disable websearch in config
    let config_path = repo.path().join(".rumpelpod.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("Failed to read config");
    config.push_str("\n[agent]\nanthropic-websearch = false\n");
    std::fs::write(&config_path, config).expect("Failed to update config");

    // Run WITH enable CLI flag - should be enabled despite config
    let output = run_agent_interactive_model_and_args(
        &repo,
        &pod.daemon,
        &["Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format."],
        ANTHROPIC_MODEL,
        &["--enable-anthropic-websearch"],
    );

    assert!(
        output.stdout.contains("2025-11-12"),
        "Agent should find the date when web search is enabled via CLI overriding config.\nstdout: {}",
        output.stdout
    );
}

#[test]
fn agent_web_search_anthropic_flags_conflict() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "agent-web-conflict");

    // --enable AND --disable -> should fail with conflict error
    let output = run_agent_interactive_model_and_args(
        &repo,
        &pod.daemon,
        &["Test"],
        ANTHROPIC_MODEL,
        &[
            "--enable-anthropic-websearch",
            "--disable-anthropic-websearch",
        ],
    );

    assert!(
        !output.success,
        "Agent should fail when conflicting flags are provided"
    );

    // In PTY mode, stdout and stderr are combined
    let msg = &output.stdout;
    assert!(
        msg.contains("enable-anthropic-websearch")
            && msg.contains("disable-anthropic-websearch")
            && msg.contains("cannot be used with"),
        "Error should mention conflicting arguments.\noutput: {}",
        msg
    );
}

#[test]
fn agent_web_search_anthropic_config_enable_cli_disable() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "agent-web-en-dis");

    // Enable websearch in config
    let config_path = repo.path().join(".rumpelpod.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("Failed to read config");
    config.push_str("\n[agent]\nanthropic-websearch = true\n");
    std::fs::write(&config_path, config).expect("Failed to update config");

    // Run WITH disable CLI flag
    let output = run_agent_interactive_model_and_args(
        &repo,
        &pod.daemon,
        &["Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format."],
        ANTHROPIC_MODEL,
        &["--disable-anthropic-websearch"],
    );

    assert!(
        output
            .stdout
            .contains("don't have the ability to search the web")
            || output.stdout.contains("cannot search the web")
            || !output.stdout.contains("2025-11-12"),
        "Agent should NOT find the date when web search is disabled via CLI override.\nstdout: {}",
        output.stdout
    );
}
