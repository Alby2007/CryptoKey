# CryptoKey documentation

CryptoKey turns a USB flash drive into a physical security key: pull the
drive and the PC locks behind a private desktop or a fullscreen overlay;
insert it (or type your recovery phrase) to unlock.

These docs describe how the pieces fit together. For the user-facing guide
(install, usage, warnings) see the [root README](../README.md).

| Doc | What it covers |
|---|---|
| [architecture.md](architecture.md) | Process roles, component map, threading model, data stores |
| [security-model.md](security-model.md) | Threat model, key material & crypto, unlock policies, lock surfaces, IPC security, known limits |
| [lifecycle.md](lifecycle.md) | Guard state machine, secure-desktop engage/disengage, secret ratchet, unlock decision flow, backoff |
| [recovery.md](recovery.md) | Every failure mode and the mechanism that survives it |
| [reference.md](reference.md) | CLI verbs, IPC protocol, `config.json` fields, file paths, startup modes, log format |
| [macos.md](macos.md) | The macOS port — `CryptoKey.Mac` host, platform mapping, LaunchAgent install, permissions, limits |

## Thirty-second tour

One executable plays several roles depending on `argv`: the **daemon**
(`guard`), the **dashboard** (`open`/bare launch), the **CLI** (one-shot
verbs over a named pipe), the **startup helper** (`--set-startup`), and
the **lock watchdog** (`--lock-watchdog`). A single `GuardService` state
machine polls the drive's hardware serial, verifies a DPAPI-wrapped keyfile
on it, and drives an `ILockSurface` — either the classic per-monitor overlay
or a private Windows desktop the session is switched onto. A rolling-secret
ratchet burns the keyfile secret after every verified session so a cloned
drive ages out; everything else is documented from there.

On macOS the same Core runs inside `CryptoKey.Mac` — capture+tap lock,
Keychain-wrapped keyfiles, unix-socket IPC, LaunchAgent autostart; see
[macos.md](macos.md).
