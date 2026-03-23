This is a rust project implementing an isolated LLM agent runner (rumpelpod).

- Comments and commit messages should explain "why", not "what".
  Don't paraphrase code next to the comment.
- If you write code, you should commit your changes.
- Run ./pipeline to ensure your commit doesn't break anything.
- The full suite is expensive; run smoke tests first: `cargo xtest enter_smoke_test`, `cargo xtest enter_verifies_user_and_repo_path`, `cargo xtest claude_smoke`, `cargo xtest gateway_pod_commit_triggers_push`.
  Pick tests related to what you changed when possible.
- ./pipeline accepts test filter args, e.g. `./pipeline list_` runs only tests matching "list_".
- Preserve pipeline output: `./pipeline 2>&1 | tee /tmp/pipeline.log`.
- After committing, fetch from the `host` remote and rebase on your upstream to stay up to date.
- Unless prompted otherwise, don't try to remain backwards compatible.
  Assume all containers/files/databases were created with the current version.
- No unicode (e.g. emojis, em dashes) in comments, code, commit messages etc.
  Only if needed to test unicode support etc.
- Most features should have tests.
  Prefer integration tests/ over unit tests.
- Readers should not require a lot of context to understand tests.
  Some fixtures are OK, but bias towards some duplication across test cases over introducing new helpers.
- Use `cargo xtest` instead of `cargo test`.
  It builds cross-architecture binaries and sets up the test environment.
- Never fall through to a "default" when matching known variants.
  Be explicit about every case and fail hard on unknown values rather than silently continuing in a potentially invalid state.
- You should almost never ignore errors:
  Prefer failing over continuing in degraded state in most cases.
  When an error is expected in normal operation, be as specific about the error as possible.
  E.g. when reading a file that is not expected to exist, ignore only not found errors but not others.
  When there's no choice but to continue after an error has occurred (e.g. in Drop, or while cleaning up after a previous error), log to stderr.
- Multiline strings: Use indoc, formatdoc, printdoc etc.
- Format strings: Prefer the format!("{var}") variant over format!("{}", v).
  Introduce variables if necessary, e.g. let var = var.display(); for paths.
- Prefer explicit control flow over anyhow macros like bail! and ensure!.
- For changes that require testing on macos, log onto a macbook via `ssh macos` and clone your checkout to /tmp/<your-hostname>/rumpelpod.
  If you can't log on but your change should be tested on macos, report to the user.
