# Security model

## Threat model

CryptoKey is a **convenience lock**, not a security boundary. It defends
against the honest-attacker scenarios — someone walking up to an unlocked
desk, a borrowed laptop, "who touched my machine" — with durable tripwires
for the rest.

| Defends against | Mechanism |
|---|---|
| Opportunistic access when you step away | Lock on removal (or failure to verify) + input containment |
| Focus-stealing / covering the lock UI | Secure mode: private desktop — nothing else exists there |
| Keyfile copied to another drive or another user | Hardware serial check + DPAPI binding (user+machine) |
| Long-lived key cloning | Secret ratchet — a stale clone is flagged and burns out |
| `config.json` tampering | Keyfile attestation MAC — tripwire, not gate |
| Passphrase brute force | PBKDF2 + exponential input freeze enforced in the hook |
| Single-process kill of the guard | Persistent watchdog — heartbeats the control pipe (~2 s dead-detection), fail-closed `LockWorkStation` + respawn if the guard died locked, respawn if unlocked. The guard respawns the watchdog the same way |
| Casual discovery of the kill path | Lock policies — while locked, HKCU `DisableTaskMgr`/`NoLogoff`/`NoClose` hide Task Manager, Sign out/Switch user, and Start-menu power buttons. In overlay mode this closes the CAD → Task Manager → end-process kill path outright; in secure mode it's a garnish on top of desktop isolation. Priors (any registry kind) backed up verbatim to `lockpolicies.json`, restored on unlock |
| "Walked away with the key still in" | `GetLastInputInfo` idle lock — fires only from Unlocked (Paused suppresses it like all auto-lock) |
| Wiping the whole `%APPDATA%\CryptoKey` folder | Registry backup — `HKCU\Software\CryptoKey\Config` holds the same JSON, a third copy on a different kill surface. Load chain: primary → `.bak` → registry (registry restores re-create both files and log as tamper); the watchdog's respawn gate accepts any copy |
| Silent tamper | Webcam stills (opt-in, `captures/` trimmed to 50) + remote alerts via ntfy.sh/any webhook — tripwires become forensics and a pager |
| `SwitchDesktop`-away attack | Flap monitor — while the secure desktop is engaged it polls `OpenInputDesktop` every ~300ms inside `_engageSync`; a foreign input desktop gets re-switched instantly, ≥3 in 10s escalates to `LockWorkStation` + alert + snap (the attacker lands on real OS auth). Legit paths — `Winlogon` by name, or an `OpenInputDesktop` failure (the SAS ACL-deny tell) — are skipped, not counted |

| Does **not** defend against | Why |
|---|---|
| `taskkill`/`Stop-Process`/Process Explorer | Lock policies hide the Task Manager GUI affordance only — the kill capability itself is untouched |
| CAD "Switch user" | `HideFastUserSwitching` is an HKLM-only policy — outside user-mode scope. The session stays locked in the background and another user can't reach our processes anyway |
| Ctrl+Alt+Del power button | No user-mode policy can remove it — `NoClose` covers Start only |
| Hardened images that deny user writes to `HKCU\...\Policies` | Policies apply partially or not at all (logged `N/3`) — run the guard elevated for full coverage |
| GPO-owned policy values | A domain refresh owns these keys — ours flicker off until the next lock; cosmetic failure for a cosmetic feature |
| Name-based mass kill (`taskkill /f /im cryptokey.exe`) | Both processes die in one call — the user-mode ceiling. The per-engage lock-watchdog still restores your desktop on a locked kill |
| Wiping `config.json` + `.bak` + the registry backup + killing the pair | Nothing to respawn into — three copies live on three surfaces now, but an attacker who knows all three still wins |
| A same-user attacker who knows the registry key | `HKCU\Software\CryptoKey\Config` is readable/writable by the user — the backup is honest about that; it only ever feeds a Load that the keyfile's attestation then verifies |
| Sub-tick desktop access | Each flap grants ~300ms of flicker, never usable access — the re-switch always wins, and a storm drops the attacker at OS auth. One accepted race: a storm colliding with a legit unlock can escalate to `LockWorkStation` post-unlock — fail-safe direction, vanishingly rare |
| Ctrl+Alt+Del / On-Screen Keyboard | SAS and UIAccess can't be hooked from user mode (OSK bypasses the keyboard hook entirely) |
| Firmware-level serial spoofing | WMI serials are what the drive reports; cheap drives report junk |
| An attacker who can enroll their own drive | Enrolling requires interactive access to the app — an unlocked session is already lost |

## Key material

| Item | Where | Form |
|---|---|---|
| Device secret | `.cryptokey` on the drive | 64 random bytes, generated at enroll; never stored locally in plaintext |
| `SecretSalt` / `SecretHash` | `config.json` | Verifier: `SHA-256(salt ‖ secret)` — 64 B of entropy, single salted SHA-256 suffices |
| `PrevSecretHash` | `config.json` | Prior generation — the interrupted-rotation heal window |
| `PassphraseHash` | `config.json` | PBKDF2-HMAC-SHA256, per-config iteration count (600 000 new, legacy 100 000 verifies), salted — the failsafe factor |
| Attestation | inside the keyfile envelope | `HMAC-SHA256(secret, "CKY-ATTEST" ‖ serial ‖ PassphraseHash)` |

## Keyfile envelope (v2)

```text
.cryptokey on disk:

  "CKY2" (4B magic) ‖ ProtectedData.Protect( plaintext , CurrentUser )

  plaintext = secret (64B) ‖ attestation (32B)
```

- **DPAPI under `CurrentUser`** binds the file to this Windows user on this
  machine — a copied `.cryptokey` unwraps to garbage anywhere else.
- **Attestation MAC** covers the serial and passphrase hash, so swapping
  `config.json` values (e.g. a known passphrase hash) makes the keyfile's
  attestation disagree with the live config → tamper flag. It's a
  **tripwire, not a gate**: the secret itself still verifies and the next
  rotation re-binds the envelope to the live config.
- **Legacy 64-byte files** (pre-v2 raw secret) verify as `AttestState.Missing`
  — "pre-attestation" — and self-upgrade on the next rotation. They log
  once; they don't raise the clone alarm.
- Envelope parsing is strict: bad magic, DPAPI unwrap failure, short
  plaintext, or a fixed-time attestation mismatch all classify cleanly —
  unwrap failures are treated as "not ours" and fail closed.

## Secret ratchet

Every verified key session burns the secret. Config moves first — atomic
`config.json` save — then every mounted letter's keyfile is rewritten
(tmp+move+read-back). The drive can lag one generation safely: a `Previous`
match still verifies but is flagged.

```mermaid
flowchart LR
    subgraph before["gen N"]
        C1["config: cur=N · prev=N−1"]
        D1["drive: N"]
    end
    before --> rotate["verify → edge rotation"]
    subgraph after["gen N+1"]
        C2["config: cur=N+1 · prev=N"]
        D2["drive: N+1"]
    end
    rotate --> after
```

Failure semantics:

- **Crash after config save, before write** → drive holds `prev` → stale
  verify → heals on next pass (`keepPrev` pins the chain so a failed write
  can never orphan the drive two generations back).
- **Keyfile deleted from every letter** → nothing verifies, so no rotation
  edge ever fires — the drive stays dead until the explicit **Repair
  keyfile** action (Security tab; unlocked + drive present). Auto-heal is
  deliberately avoided: writing a fresh keyfile on a failed check would
  arm any drive spoofing the serial.
- **Previous-generation match** → unlocks (non-strict) but logs
  "possible clone", sets the tamper badge, and re-poisons itself.
- Clone lifetime is bounded: every guard restart burns a generation.

## Unlock policies

`Guard.UnlockPolicy` — `KeyOrPassphrase` (default), `KeyAndPassphrase`,
`KeyOnly` — plus `StrictTamper`:

| Policy | Key insert | Passphrase | Stale keyfile |
|---|---|---|---|
| `KeyOrPassphrase` | unlocks | unlocks | unlocks (flagged) — strict: no |
| `KeyAndPassphrase` | **arms the factor** — stays locked until passphrase | completes unlock only while armed | strict: doesn't arm |
| `KeyOnly` | unlocks | rejected — "insert the key" | strict: no auto-unlock |

- Under `KeyAndPassphrase` the armed factor is **volatile**: removing the
  key while locked disarms it — a correct passphrase alone won't unlock
  ("insert your key first").
- **Break-glass**: strict + stale keyfile + correct passphrase → unlocks,
  logged loudly as a break-glass event with the tamper alarm. An absent key
  under 2FA is *not* break-glass — the passphrase alone never suffices.
- `StrictTamper` says a replayed previous-generation secret never counts as
  the key factor — under any policy. The rotation still heals the file to
  current, at which point normal rules apply.

## Lock surfaces

| | `secure` (default) | `overlay` (`--classic`, or `LockMode:"overlay"`) |
|---|---|---|
| Mechanism | Private desktop `CryptoKeyLock` + `SwitchDesktop` | Per-monitor borderless topmost forms + `ClipCursor` |
| What attacker sees | Empty desktop + the lock card — no taskbar, no windows | Your wallpaper behind a dark overlay |
| Input containment | Structural + LL hooks on the lock thread | LL hooks swallow everything |
| Reachable by Task Manager UI | No (lock UI lives on another desktop) | Yes (it's a window) |
| Failure rescue | Lock-watchdog + supervisor + `--release-desktop` + panic | Supervisor only — no desktop to rescue |
| Cost | Lock thread + watchdog process per engage | One-shot hooks + forms |

Engage failures in secure mode **auto-fall-back to the overlay** — the lock
must always land. The overlay is also the SAS-safe path: locking while the
Ctrl+Alt+Del screen is up deliberately skips the desktop switch.

## IPC & pipe security

`\\.\pipe\cryptokey-ctl` accepts one line per connection from the local
machine:

- **DACL**: `GA` to the owning user's SID only — another user's session
  can't `pause`/`lock`/`quit` you.
- **SACL**: medium-integrity label so a normal medium-IL CLI can command an
  elevated guard, while low-IL (sandboxed) processes stay out. Applied only
  when `SE_SECURITY_PRIVILEGE` is available; startup logs which branch
  landed.
- Per-connection read timeout (~5 s) — a connect-but-silent client can't
  starve the pipe.
- `quit` is refused while locked (quitting would be a silent unlock);
  `pause` requires unlocked/paused.

## Passphrase backoff

Failures 1–2 are free. From failure 3: `15 << min(fails−3, 5)` seconds,
capped at 300 — 15 s → 30 s → 60 s → 120 s → 240 s → 300 s. Enforced
**inside the low-level hook** before any buffering or Enter handling, so
input during a freeze is eaten without counting. The lock screen paints a
live countdown. The counter is in-memory — it clears on unlock, re-lock,
config reload, or restart (documented trade-off).

## Known limits

Carried from the [root README](../README.md#warnings--known-limits):
self-lockout is real (test in `--dev`); Ctrl+Alt+Del/OSK can't be blocked
from user mode; serials can be spoofed at firmware level; DPAPI makes the
keyfile single-user/single-machine (one enrolled user per drive); a running
guard rewrites `config.json` on every rotation (`cryptokey quit` before
hand-editing).
