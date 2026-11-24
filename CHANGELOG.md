# Changelog

## 0.1.0 — 2026-11-24

First release.

- Set up standard WireGuard on your own Linux VPS over `ssh` (apt, dnf, yum, pacman, zypper,
  apk), with NAT, IP forwarding, IPv6, ufw/firewalld rules and systemd. Idempotent; refuses to
  touch a WireGuard interface it didn't create; can print its script instead of running it.
- Devices: keys and preshared keys made locally, lowest-free address allocation, live sync
  (`wg syncconf`) on add/revoke, QR codes for the phone apps, `.conf` export (never overwrites).
- Connect this computer through NetworkManager or `wg-quick` (Linux), `wg-quick` (macOS) or the
  WireGuard for Windows tunnel service.
- Server status: last handshake and traffic per device.
- Native PyQt6 window and a full command line.
- Standalone bundles for macOS, Windows and Linux; Sigstore-signed checksums and a CycloneDX SBOM.
- CI runs a real WireGuard server-and-client end-to-end test on Linux.
