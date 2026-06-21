# esylla-auth — design

An authentication module for the esylla framework. JSON/headless only (no
server-rendered forms). Plugs into a host with `.module(Auth::new())`.

Feature scope is modeled on django-allauth, built in phases.

## Phase 1 (current)

- Email/password: signup → email verification → login → logout
- Sessions: opaque tokens, stored behind a `SessionStore` trait
- Password: reset (forgot → email link/code → set) and change (authenticated)
- OAuth: Google + GitHub (authorization-code + PKCE), connect/disconnect

Later phases: multiple emails, more providers, MFA (TOTP + recovery codes),
reauthentication, login-by-code, WebAuthn/passkeys, JWT token strategy, active
session management.

## Architecture

`Auth` implements `esylla::Module<S>`. It contributes routes, migrations, and an
`on_init` hook. The host satisfies the module's needs via `FromRef`:

- a `DatabaseConnection` (sea-orm) — user/account persistence
- a `SessionStore` — session storage (Redis / Postgres impls)
- a `Mailer` — verification / reset emails
- an `AuthConfig` — TTLs, cookie policy, OAuth client creds

Override seams (each a trait, defaults provided):

- `UserStore` — user lookup/creation (default impl over the bundled `users` entity)
- `SessionStore` — session storage
- `Mailer` — email delivery
- `AccountAdapter` — behavior hooks (`is_open_for_signup`, `generate_handle`,
  `on_user_created`, `clean_email`, …), allauth-adapter style

## Security baseline (non-negotiable)

Grounded in OWASP cheat sheets and RFC 9700 (OAuth BCP, 2025); see Sources.

- **Passwords**: Argon2id, `m=19456 KiB (19 MiB), t=2, p=1` (OWASP minimum),
  per-password random salt, timing-safe verify. Reject inputs over 4096 bytes
  (Argon2 DoS guard). Min length enforced at the validation layer.
- **Tokens** (email-verify / password-reset / oauth-state): CSPRNG, ≥256-bit,
  single-use, time-limited, and **stored as a SHA-256 hash at rest** — the raw
  token is only ever in the email/URL, never in the DB/store.
- **Sessions**: opaque id, 256-bit CSPRNG (OWASP needs ≥64-bit); stored hashed at
  rest; **new id issued on login** (no fixation); idle (sliding) + absolute
  expiry. Cookie: `__Host-` prefix (Secure, `Path=/`, no Domain) by default —
  `__Secure-` when a cross-subdomain Domain is configured; HttpOnly; SameSite=Lax
  (needed for the OAuth redirect-back; Strict optional via config).
- **Enumeration prevention**: identical message *and* timing for unknown-account
  vs wrong-password on login; forgot-password always returns success.
- **Password reset / change**: invalidates the user's other sessions; never
  auto-logs-in after a reset.
- **OAuth**: Authorization-Code + PKCE `S256` (mandatory), one-time `state` bound
  to the flow, `nonce` + full `id_token` validation (JWKS signature, `iss`,
  `aud`, `exp`) for OIDC providers (Google); exact `redirect_uri` matching.
- **Rate-limit hooks** on login / signup / reset / verification (host supplies the
  limiter). Never log credentials or tokens.

### Sources

- OWASP Password Storage Cheat Sheet — Argon2id `m=19456,t=2,p=1`
- OWASP Session Management Cheat Sheet — ≥64-bit session id, `__Host-` cookie
- OWASP Forgot Password Cheat Sheet — single-use, hashed-at-rest, enumeration
- RFC 9700 (OAuth 2.0 Security BCP, 2025) — PKCE S256, state/nonce, exact redirect
