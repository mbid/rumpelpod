This is a rust project implementing a sandboxed LLM agent.

- Be resourceful about commands with long output.
  Use head, tail, grep etc. and check file sizes before checking their full contents.
- Comments and commit messages should explain "why", not "what".
  Don't paraphrase code next to the comment.
- Format, run tests before committing.
- Always run tests with a timeout, e.g. 60 seconds, to prevent getting stuck.
- Don't run commands in interactive mode (e.g. git rebase, git rebase --continue):
  You can't operate the UI, only run commands.
- Don't use --test-threads unless you are debugging a concurrency issue.
- Run ./pipeline before finishing your work to ensure everything is properly formatted, builds without warnings, and passes clippy.
- After committing, fetch and rebase on host/master to stay up to date.
