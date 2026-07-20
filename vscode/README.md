# Rumpelpod for VS Code

This workspace extension keeps each rumpelpod agent in a persistent VS Code
terminal, rendered by VS Code's xterm.js terminal frontend, and opens that
pod's review in the adjacent editor group. It is built for desktop VS Code and
browser-hosted VS Code servers whose extension host runs on the same machine as
the `rumpel` command.

Open the Rumpelpod activity bar view, select a pod, or use the `+` action to
choose an agent and create one. Selecting a pod shows its agent terminal on the
left and the first changed file on the right. Expand a pod to choose another
changed file. The selected agent is saved in workspace state; use `Change
Agent` from a pod's context menu to replace it.

## Development

The Rust type generator owns `src/generated/`. The repository tool regenerates
those bindings, packages the extension, rebuilds the development daemon,
installs both, and restarts the browser workspace:

```sh
cargo vscode
```

The devcontainer starts that workspace at port 3000 and forwards it as
`Rumpelpod VS Code`. Its per-container password is available with
`cat ~/.config/rumpelpod/vscode-password`. Use `npm run watch` for
TypeScript-only iteration, and run `cargo vscode` again when the daemon,
generated contracts, or installed VSIX must change. `cargo vscode --check`
performs the extension checks used by the Rust pipeline without updating
either live service.

The browser integration test launches an isolated code-server instance and a
real rumpelpod daemon, then drives the packaged extension with Playwright. Run
it through the normal test pipeline:

```sh
cargo pipeline vscode_browser_opens_pod_change_as_diff
```
