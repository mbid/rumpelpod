This is a rust project implementing an isolated LLM agent runner (rumpelpod).

- Don't run commands in interactive mode (e.g. git rebase, git rebase --continue):
  You can't operate the UI, only run commands.
- Comments and commit messages should explain "why", not "what".
  Don't paraphrase code next to the comment.
- If you write code, you should commit your changes.
  DON'T STOP BEFORE YOU'RE DONE!
- Run ./pipeline to ensure your commit doesn't break anything.
- After committing, fetch and rebase on host/master to stay up to date.
- Unless prompted otherwise, don't try to remain backwards compatible.
  Assume all containers/files/databases were created with the current version.
- No unicode (e.g. emojis, em dashes) in comments, code, commit messages etc.
  Only if needed to test unicode support etc.
- Most features should have tests.
  Prefer integration tests/ over unit tests.
- Use `cargo xtest` instead of `cargo test`.
  It builds cross-architecture binaries and sets up the test environment.
- Never fall through to a "default" when matching known variants.
  Be explicit about every case and fail hard on unknown values rather
  than silently continuing in a potentially invalid state.
- For changes that require testing on macos, log onto a macbook via `ssh macos` and clone your checkout to /tmp/<your-hostname>/rumpelpod.
  If you can't log on but your change should be tested on macos, report to the user.
