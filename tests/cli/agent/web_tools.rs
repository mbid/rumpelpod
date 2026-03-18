//! Tests for web search and fetch functionality.

use std::fs;

use crate::common::{write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

use super::common::{
    run_agent_interactive_model_and_args, ANTHROPIC_MODEL, GEMINI_MODEL, XAI_MODEL,
};

fn agent_web_search(model: &str, extra_args: &[&str], test_name: &str) {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, test_name);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let output = run_agent_interactive_model_and_args(
        &repo,
        &daemon,
        &["Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format."],
        model,
        extra_args,
        home.path(),
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
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "agent-web-disabled");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let output = run_agent_interactive_model_and_args(
        &repo,
        &daemon,
        &["Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format."],
        ANTHROPIC_MODEL,
        &["--disable-anthropic-websearch"],
        home.path(),
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
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "agent-web-cfg-dis");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");

    // Disable websearch in config
    let mut config = executor.toml.clone();
    config.push_str("\n[agent]\nanthropic-websearch = false\n");
    fs::write(repo.path().join(".rumpelpod.toml"), config).unwrap();

    // Run without CLI flag - should be disabled by config
    let output = run_agent_interactive_model_and_args(
        &repo,
        &daemon,
        &["Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format."],
        ANTHROPIC_MODEL,
        &[],
        home.path(),
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
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "agent-web-cfg-en");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");

    // Disable websearch in config
    let mut config = executor.toml.clone();
    config.push_str("\n[agent]\nanthropic-websearch = false\n");
    fs::write(repo.path().join(".rumpelpod.toml"), config).unwrap();

    // Run WITH enable CLI flag - should be enabled despite config
    let output = run_agent_interactive_model_and_args(
        &repo,
        &daemon,
        &["Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format."],
        ANTHROPIC_MODEL,
        &["--enable-anthropic-websearch"],
        home.path(),
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
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "agent-web-conflict");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // --enable AND --disable -> should fail with conflict error
    let output = run_agent_interactive_model_and_args(
        &repo,
        &daemon,
        &["Test"],
        ANTHROPIC_MODEL,
        &[
            "--enable-anthropic-websearch",
            "--disable-anthropic-websearch",
        ],
        home.path(),
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
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "agent-web-en-dis");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");

    // Enable websearch in config
    let mut config = executor.toml.clone();
    config.push_str("\n[agent]\nanthropic-websearch = true\n");
    fs::write(repo.path().join(".rumpelpod.toml"), config).unwrap();

    // Run WITH disable CLI flag
    let output = run_agent_interactive_model_and_args(
        &repo,
        &daemon,
        &["Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format."],
        ANTHROPIC_MODEL,
        &["--disable-anthropic-websearch"],
        home.path(),
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
