# Recovery & failure modes

Every failure the design anticipates, and the mechanism that survives it.
The rule throughout: **fail closed** — an ambiguous state locks rather than
exposes, and every lock mode keeps an escape path that doesn't depend on
the lock working.

## Lock-surface failures

| Failure | What happens | Rescue |
|---|---|---|
| `taskkill` / crash while secure-locked | Windows does **not** return the input desktop on owner death | Watchdog process (spawned before every `SwitchDesktop`) sees the parent die and `SwitchDesktop("Default")` itself |
| Lock-thread pump dies unexpectedly | `finally` → `ReleaseInput` — clears `_engaged`, retries the switch-back (×4), unhooks, reaps watchdog | Same watchdog if the guard also dies |
| `SwitchDesktop` *back* fails | Teardown aborts: form, hooks, and watchdog stay alive; `Disengage` returns `false`; `GuardService` **stays Locked** | Next unlock retries the switch; process exit still lets the watchdog fire |
| Secure `Engage` fails at any step | Logged reason → automatic fallback to the classic overlay | The lock must always land |
| Overlay hooks fail to install | Screen-only lock + visible `WARNING: input hooks failed` status | While locked the policies have already applied — Ctrl+Alt+Del → **Switch user** or the **power button** → reboot (Task Manager is disabled by design while locked) |
| Session stranded on the lock desktop anyway | — | `cryptokey --release-desktop` from **another logged-in session** (CAD → Switch user) or Win+R after a reboot — Task Manager's "Run new task" is policy-blocked while locked — or the dev panic combo |

## Key / keyfile failures

| Failure | What happens | Rescue |
|---|---|---|
| Keyfile wiped from the drive | Drive can't verify → `None` forever — no verify edge, so rotation never runs | Security tab → **Repair keyfile** (explicit, user-gated: unlocked session + drive present — the enrollment trust bar). Deliberately not automatic — auto-healing a failed check would hand a working keyfile to any serial-spoofing drive |
| Rotation interrupted (crash mid-write) | Config is a generation ahead; drive holds `prev` | Stale verify → `keepPrev` rotation heals — a failed write can never orphan the drive two gens back |
| Read-only / write-protected drive | Write fails every time | Drive stays `prev`-valid, flagged each poll, retry every 5 s — no lockout |
| `.cryptokey` copied to another drive / user | Serial check rejects other drives; DPAPI unwrap fails for other users/machines | Re-enroll, or the passphrase under `KeyOrPassphrase` |
| Clone of the keyfile in play | Presents `prev` after rotation | "possible clone" log + tamper badge; the ratchet burns it out — clone lifetime ≤ 1 session |
| Attestation mismatch (config tampered) | Tripwire: tamper note + log, secret still verifies | Next rotation re-binds the envelope to the live config |
| Corrupt/malformed keyfile | Unwrap/parse failure → `SecretMatch.None` → fail closed | Re-enroll; under `KeyOrPassphrase` the passphrase still works |

## Config failures

| Failure | What happens | Rescue |
|---|---|---|
| `config.json` corrupt | Quarantined to `config.json.bad`; `config.json.bak` (last-good mirror, written on every save) loads instead | Modal warning on boot (autostart hides the console — a silent fail-open would mean "no protection, no sign") |
| `config.json` **and** `.bak` corrupt | `.bak` quarantined to `.bak.bad`; `HKCU\Software\CryptoKey\Config` restores both files and flags `LastRestoreFromRegistry` | Distinct "folder was wiped" modal + guard-log tamper line + remote alert; only if **all three** copies are dead does the app refuse to run → re-enroll |
| Whole `%APPDATA%\CryptoKey` folder wiped | Both files re-created from the registry copy on next launch; watchdog respawns via `ConfigStore.Resumable` | Same tamper modal — deleting the folder alone can't disarm CryptoKey; a real reset also deletes `HKCU\Software\CryptoKey` |
| Hand-edited config overwritten | A running guard saves in-memory state on every rotation | `cryptokey quit` before hand-editing — documented |
| Re-enroll while guard runs | `reenrolled` IPC → in-place `ReloadConfig` — serial, hashes, guard settings all refresh | Old passphrase dies immediately; if the new key isn't inserted the fail-closed check locks |
| `.tmp` orphans from crashed writes | Atomic tmp+move — the real file is never torn | Next write overwrites the orphan |

## Input failures

| Failure | What happens | Rescue |
|---|---|---|
| Forgotten passphrase | — | The key itself under `KeyOrPassphrase`/`KeyOnly`… otherwise a true lockout (the settings warning is honest about this) |
| Lost key under `KeyOnly` / 2FA | No passphrase path by design | Re-enroll a new drive; panic combo in `--dev`; CAD → Switch user and kill from that session → watchdog restores input |
| Frozen input during backoff | Cooldown gate in the hook | Amber countdown; panic combo works through the freeze (checked first) |
| Hook callback stalls | `LowLevelHooksTimeout` → input leaks | By design everything slow runs off the hook thread: WMI polling, PBKDF2, USB rotation writes |

## Process / IPC failures

| Failure | What happens | Rescue |
|---|---|---|
| Second instance launched | Mutex held → pipes `open` to the running guard | `--takeover` waits ~30 s on the mutex for elevated handoff |
| Elevated guard vs medium-IL CLI | SACL grants medium-IL write | If the label can't be applied it's logged at startup — DACL-only still works same-integrity |
| Pipe client connects but never writes | 5 s read timeout drops it | Sequential accept loop can't starve |
| Guard wedged mid-command | CLI read times out (1.5 s) → "guard is not running" | `taskkill` + relaunch |
| Watchdog can't spawn | `Engage` fails *before* the switch | Falls back to the overlay — no watchdog, no switch, no strand |
| Startup entry stale (exe moved) | `GetMode` validates content — task XML + exe existence, Run-value path alive | Re-toggle in Settings to re-register |

## The escape hatches, ranked

1. **Passphrase** — normal failsafe (unless `KeyOnly`, by design).
2. **Panic combo** `Ctrl+Alt+Shift+F12` — `--dev` only; disengages first, then exits.
3. **Watchdog** — automatic on guard death while secure-locked.
4. **`cryptokey --release-desktop`** — manual desktop rescue, independent of IPC/hooks; also restores lock policies. Reachable while locked only from another logged-in session (Switch user) — after a reboot, Win+R works.
5. **`--classic`** — skips the desktop machinery entirely on next launch.
6. **Ctrl+Alt+Del → Switch user or the power button** — the last resort while locked. Task Manager and Sign out are *policy-disabled by design* while locked (that's what closes the kill path), so don't plan on them. A reboot always clears a stranded private desktop — desktop objects die with the session — and persisted policies restore when the guard next starts.
