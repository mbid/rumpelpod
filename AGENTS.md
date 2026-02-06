This is a rust project implementing a sandboxed LLM agent.

- Be resourceful about commands with long output.
  Use head, tail, grep etc. and check file sizes before checking their full contents.
  If you need to run multiple commands, try invoke all commands at once or put all of them in a single bash invocation.
- Don't run commands in interactive mode (e.g. git rebase, git rebase --continue):
  You can't operate the UI, only run commands.
- Comments and commit messages should explain "why", not "what".
  Don't paraphrase code next to the comment.
- If you write code, you should commit your changes.
  DON'T STOP BEFORE YOU'RE DONE!
- Run ./pipeline to ensure your commit doesn't break anything.
- After committing, fetch and rebase on host/master to stay up to date.
