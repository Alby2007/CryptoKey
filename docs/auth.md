# CryptoKey Accounts

A cloud identity layer (Supabase Auth, email + password) that gates the
**app surface** — the dashboard, the tray's mutating items, and the CLI's
sensitive verbs — with an offline grace path for when the network is gone.

It is deliberately **not** a workstation lock factor. The USB key and the
recovery phrase remain the only things that unlock a locked session, and
the guard engages and holds a lock with no account, no session, and no
network. This document is the contract for what the account does and
doesn't cover.

## What the account gates

| Surface | Gated | Open |
|---|---|---|
| Dashboard window | opens only after auth | — |
| Tray | pause / resume / quit | lock now |
| IPC verbs | `pause`, `resume`, `quit`, `reenrolled`, `vault <mutator>`, `update apply` | `status`, `lock`, `vault status`, `update status/check`, `auth status`, `open`, `deeplink` |
| CLI | same verbs via `cryptokey <verb>` (masked password prompt on `AUTH_REQUIRED`) | `status`, `lock`, `enroll` without a bound account |

`lock` is intentionally ungated — it only makes the machine safer. Read
verbs stay open; they expose no secrets.

### The IPC auth trailer

Mutating verbs accept `|auth <base64 password>` — base64 so passwords can
contain anything (`|` can't appear in a normalized argument). The CLI
reads the password masked (`*` echo, Backspace edits, Esc abandons) and
appends the trailer for that one send; it's never written to argv, logs,
or disk. A correct password also arms the process's authorization for the
rest of the session.

## Identity & session lifecycle

- **Sign up** (`/auth/v1/signup`) — with email confirmation on, the window
  tells you to confirm before signing in; with it off, the returned
  session establishes the account immediately.
- **Sign in** (`/token?grant_type=password`) — success stores the bearer
  pair in `session.dat` (DPAPI on Windows, the Keychain wrap on macOS,
  entropy-tagged so a session blob can't be swapped for a keyfile blob)
  and rewrites the **local verifier**: a PBKDF2-SHA256(password, salt,
  600,000) record inside `config.json` — never the password itself.
  An `email_not_confirmed` rejection is the one failure still treated as
  success: GoTrue checks the password before the confirm gate, so that
  response proves the credentials — the session then runs verifier-only
  (offline-equivalent) until the first confirmed sign-in lands tokens.
- **Refresh** (`/token?grant_type=refresh_token`) — the engine's slow tick
  renews tokens inside 10 minutes of expiry; a rejected refresh ends the
  session, a network failure keeps it (grace).
- **Sign out** (`/logout` best-effort) — clears `session.dat` and drops
  this run's authorization regardless of whether the server heard.
- **Recovery** — `cryptokey://recover?token_hash=…&type=recovery` deep
  links (email → browser → app) land on the reset face: `verify` →
  `PUT /user` → new verifier.

## Offline grace

The verifier exists so a network outage can't lock you out of your own
dashboard: after one successful online sign-in, the same password unlocks
the app offline (`TryUnlockOffline`), and `SignIn` falls back to it
automatically when the server is unreachable. Boundaries:

- Only the **linked email** is accepted offline — one account per install.
- Online sign-in is single-tenant too: a successful sign-in as a
  *different* account is refused rather than silently rebinding the
  verifier — binding a new account is the key-fenced **Relink** flow.
- The verifier authorizes the **app**, not the workstation. It is never a
  lock factor.
- A password **reset on another device** leaves this install's verifier
  stale — the old password keeps working locally until the next online
  sign-in rewrites it. To revoke offline immediately, sign out (the
  verifier survives sign-out — it's the identity, not the session) or
  delete the account section in `config.json` and relink.
- An in-memory throttle (5 failures → 30 s cooldown, doubling to 15 min)
  rate-limits local attempts; it resets on success and is not durable —
  the verifier record is the hard bound, not the throttle.

## Integrity: the verifier is attestation-bound

`config.json`'s `Account` section is inside the keyfile's attestation MAC
(`|accounthash=<verifierHash>` in the guard canonical). Two consequences:

- **Graft detection**: an attacker who edits `config.json` to insert
  *their* verifier trips `AttestState.Mismatch` on the next key verify —
  and the engine refuses the password path entirely while the attestation
  is dirty (`SetAttestationClean(false)`), so a forged record can't
  authorize anything. Strict rule: once an account is bound, the
  account-free historical canon forms are no longer accepted.
- **Re-attestation**: signing in, changing the password, or relinking
  rewrites the verifier, which dirties the MAC — so those flows require
  the enrolled key present (the next verify re-wraps the envelope
  quietly). This is why the reset/relink faces say "insert your key".

Deleting the `Account` section is the documented escape: it surfaces as a
tamper announce on the next verify and heals the envelope to the
account-free canon. While `session.dat` or `account.pending.json` still
marks the install as enrolled, the gate stays closed — sign in (or use
**Relink** on the Account page / sign-in face, which needs the enrolled
key) to bind a fresh record. Sign out *first*, and a delete removes the
account entirely — the gate lifts; the install is simply unenrolled.

## Setup (Supabase)

`supabase.json` beside the executable (or `CRYPTOKEY_SUPABASE_JSON`
points elsewhere):

```json
{ "projectUrl": "https://xyz.supabase.co", "anonKey": "eyJ…" }
```

The anon key is designed to ship inside clients — GoTrue treats it as
public; Supabase RLS is what protects table data, and CryptoKey creates
**no tables** (auth only). Email confirmation, redirect URLs, and
password policy are project settings in the Supabase dashboard — set the
`cryptokey://recover` redirect under Auth → URL Configuration.

A missing/invalid `supabase.json` is a visible banner on the auth window,
never a crash: online flows report "Supabase isn't configured", offline
grace keeps working for a linked account, and an install that never
enrolled an account runs exactly like before — the guard is never gated.

## Failure & tamper behavior

| State | Behavior |
|---|---|
| `session.dat` corrupt/foreign | treated as no session — sign in again |
| `account.pending.json` (pre-enroll staging) | folds into `KeyConfig.Account` on first commit; relaunch resumes at sign-in |
| `config.json` account section deleted | tamper announce → heal to account-free canon → relink required for the gate |
| Verifier hash tampered | `AttestState.Mismatch` → password path refused, relink only |
| Server unreachable | online flows report cleanly; offline grace unlocks with the same password |

## Explicitly out of scope

Settings sync, multi-device management, licensing, and any role for the
account in workstation locking. The threat model for the lock itself —
private desktop, intruder sentinel, watchdog, USB key, recovery phrase —
lives in `security-model.md`; the account layer adds an app-side identity
gate and nothing else.
