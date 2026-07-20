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

The Rust type generator owns `src/generated/`. Generate those files before the
first build, then run:

```sh
npm install
npm run check
npm run build
```

Use `npm run watch` while developing. Package a VSIX with `npm run package`.
The integration suite is run with `npm run test:integration` once the browser
server and Playwright browser dependencies are installed.
