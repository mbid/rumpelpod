# Pod Git credential review

Reviewed against `e532cd32`. This branch records findings only; the
implementation and tests are unchanged from that revision.

## Findings

1. **The injected bearer header applies to unrelated HTTP remotes.**
   `http.extraHeader` is set without a URL scope in main repository setup,
   submodule setup, submodule refresh, and the initial submodule update
   command. Git can therefore send the pod token to unrelated HTTP(S)
   destinations before an authentication challenge. A read-only
   `git config --get-urlmatch` check in the current pod confirmed that the
   bearer header also matches an unrelated HTTPS URL. No token values were
   printed or transmitted for that check.
   See `rumpelpod/src/pod/git_setup.rs:376`, `:680`, `:730`, and `:806`.

   Scope the header to the repository URL shared by the `host` and
   `rumpelpod` remotes, including the corresponding submodule URLs. Remove
   obsolete scopes when tunnel ports change. Git applies HTTP URL matching
   to the initial URL, so redirects also need consideration.
   [Git HTTP configuration documentation](https://github.com/git/git/blob/master/Documentation/config/http.adoc)

2. **Git errors can disclose the token.**
   Credential writes and initial submodule updates pass bearer values to
   Git. `CommandExt::success` includes the full command in an error on
   failure. Git trace output can also contain those values. Error handling
   should omit sensitive command arguments and redact tokens in stderr.
   See `rumpelpod/src/command_ext.rs:94` and the setup call sites above.

3. **The token grants capabilities beyond Git.**
   The same token authenticates the host SSH-agent relay and the pod API,
   including command execution and file access. A leaked Git token grants
   those capabilities if the corresponding endpoints are reachable.
   Separate Git, agent-relay, and pod-control credentials would reduce the
   impact of accidental disclosure.
   See `rumpelpod/src/git_http_server.rs:855` and
   `rumpelpod/src/pod/server.rs:203`.

4. **The host token database does not enforce private permissions.**
   SQLite creates the database with its default file mode, `0644` before
   the process umask is applied. The code does not restrict it to `0600`,
   and creates its parent directory without an explicit private mode.
   Other local users could read tokens if the parent directories permit
   traversal. Enforce private directory and database permissions.
   See `rumpelpod/src/daemon/db.rs:180` and `:269`.

5. **Stopping a pod does not revoke its host gateway token.**
   Token lookup checks for a matching database record without checking
   status or expiry. Credentials remain valid while that record exists;
   stopping a pod or restarting the daemon does not rotate them. Consider
   explicit revocation or rotation for leaked credentials.
   See `rumpelpod/src/daemon/db.rs:452`.

## Why the SSH-agent relay uses authentication

The endpoints are Unix sockets, but the forwarding path is:

```text
Pod SSH client
  -> pod SSH_AUTH_SOCK (Unix socket)
  -> WebSocket /ssh-agent with Authorization: Bearer ...
  -> pod loopback TCP listener
  -> per-pod exec stdin/stdout tunnel
  -> shared host loopback HTTP gateway
  -> selected host SSH-agent Unix socket
```

The pod's Unix socket does not require bearer authentication. The relay
adds the token when opening the WebSocket. The host gateway uses it to
identify the pod and select its agent. The exec tunnel forwards bytes to
an ordinary TCP connection; pod identity is not attached to that
connection. Host loopback TCP is also reachable by other local processes.

Authentication is therefore a consequence of the shared HTTP gateway
architecture. A dedicated connection tied to one pod and its agent could
instead derive authorization from that connection, without this separate
bearer token. Removing the token check from the current shared endpoint
would not provide that isolation.

By default, each pod uses an isolated agent with no keys. Keys are added
through `rumpel ssh-add` or `sshAgent.keys`. Forwarding the invoking shell's
agent requires `sshAgent.ambient: true`. The relay supports outbound SSH;
normal `host`/`rumpelpod` Git synchronization uses HTTP and does not need it.
See `GUIDE.md:357`, `rumpelpod/src/pod/server.rs:2323`,
`rumpelpod/src/tunnel.rs:356`, and `rumpelpod/src/git_http_server.rs:855`.

The host gateway binds to loopback, and Git pushes are restricted by the
host hook to the authenticated pod's namespace. A leaked token alone does
not make the gateway reachable from the public Internet.
