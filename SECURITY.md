# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/xzchick/envy-tunnel/security/advisories/new)
rather than a public issue. You'll get an acknowledgement, and a fix or an explanation, as
soon as practical.

## Design notes

- The VPN itself is unmodified WireGuard. ENVY only generates configuration and runs the
  official tools; there is no custom cryptography or protocol.
- Device private keys are generated locally (X25519 via `cryptography`, clamped like
  `wg genkey`) and never transmitted. The server key is generated on the server by `wg genkey`.
- Every value placed into a server script is validated against a strict pattern and
  shell-quoted; the device list is written through a quoted heredoc so nothing in it is expanded.
- Server scripts are sent on ssh's stdin (never as command-line arguments, which other users
  on the server could see in the process list). They contain preshared keys, so `--print` warns.
- Local state is written atomically with owner-only permissions. Exports never overwrite.
- SSH runs with `BatchMode=yes` by default (no password prompts) and
  `StrictHostKeyChecking=accept-new` (first connection is trusted and remembered; a changed
  host key is refused).
