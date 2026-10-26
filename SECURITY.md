# Security Policy

RootreX is a **defensive-education** tool. It demonstrates Layer-2 (ARP) manipulation and the limits of on-path traffic observation so operators and defenders understand them first-hand. It is designed to be run **only** on networks you own or are explicitly authorized to test, against devices whose owners have consented.

## Responsible use

- **Authorized, consented, lab use only.** Do not run RootreX on networks or against devices you are not authorized to test. Doing so is illegal in most jurisdictions, and the responsibility is entirely the operator's.
- RootreX enforces this in software, not just on paper:
  - a **consent gate** on launch (nothing transmits until you confirm authorization),
  - an explicit **target allowlist** (no "select everyone and cut"),
  - **bulletproof ARP restore** on exit, crash, unhandled exception, signal, and the STOP control,
  - a **loopback-only** control plane (binds `127.0.0.1`), and
  - a hard rule that it records **metadata, never content**.
- Capabilities that only make sense against people who never agreed — **deauthentication frame injection, evil-twin impersonation of networks you don't own, and TLS/HTTPS content decryption** — are **documented but never implemented**.

## Reporting a vulnerability

If you find a way to **bypass the safety rails** (consent gate, allowlist, restore, loopback binding, or the "metadata-not-content" boundary), please report it privately:

- Use **GitHub's private vulnerability reporting** on this repository: the **Security → Report a vulnerability** tab. (Enable it under *Settings → Code security and analysis* if it isn't already.)
- Please **do not** open a public issue for a safety-rail bypass before it's fixed.

Include clear steps to reproduce and the impact. There is no bug bounty — this is an educational project — but fixes that harden the safety model are the top priority.

## Supported versions

Only the latest release is maintained.
