# esylla-auth

Authentication for [esylla] — email/password, sessions, and OAuth.

[![Crates.io](https://img.shields.io/crates/v/esylla-auth)](https://crates.io/crates/esylla-auth)
[![Documentation](https://docs.rs/esylla-auth/badge.svg)](https://docs.rs/esylla-auth)

A drop-in `esylla::Module` providing signup with email verification, login/logout,
opaque sessions, password reset/change, and OAuth. Mount it with one `.module(...)`
call; everything behind it — stores, mailer, session strategy, per-route choice — is
swappable.

## Features

- **Email/password** — signup is held as a pending registration; the account is
  created only after the email is verified, so an unverified address never reserves
  an account.
- **Sessions** — opaque, server-side tokens (256-bit, stored hashed, sliding idle +
  absolute expiry, fresh token per login). Or stateless **JWT** (`jwt` feature).
- **Password reset & change** — both invalidate the user's other sessions; reset
  never auto-logs-in.
- **OAuth** (`oauth` feature) — authorization-code + PKCE for Google and Microsoft
  (OpenID Connect, ID-token + nonce validated) and GitHub. Add your own provider by
  implementing `OAuthProvider`.
- **Overridable** — swap `UserStore` / `SessionStore` / `Mailer` / `SessionStrategy`,
  hook signup/login with an `AccountAdapter`, or replace any built-in route and call
  the public `AuthServices` from your own handler.
- **Security by default** — Argon2id, single-use hashed tokens, account-enumeration
  and timing defenses, `__Host-`/`__Secure-` cookies.

## Example

```rust
use std::sync::Arc;
use axum::extract::FromRef;
use esylla::Esylla;
use esylla_auth::{Auth, AuthConfig, AuthServices};

#[derive(Clone)]
struct AppState {
    auth: AuthServices,
}

// Auth handlers extract `AuthServices` from your state via `FromRef`.
impl FromRef<AppState> for AuthServices {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

// `mailer` is any `Mailer` — e.g. `SmtpMailer` (smtp feature) or your own impl.
let auth = AuthServices::new(db, Arc::new(mailer), AuthConfig::default());

let app = Esylla::new(AppState { auth })
    .module(Auth::new()) // routes + migrations + OpenAPI, in one line
    .into_router();
```

The module contributes its migrations to the framework's runner and its endpoints to
the merged OpenAPI document.

## Feature flags

| Flag    | Adds                                                                       |
|---------|----------------------------------------------------------------------------|
| `oauth` | Google/Microsoft/GitHub OAuth (`oauth2`, `openidconnect`, `reqwest`)       |
| `smtp`  | `SmtpMailer` over SMTP with overridable templates (`lettre`, `minijinja`)  |
| `jwt`   | `JwtSessions`, a stateless session strategy (`jsonwebtoken`)               |
| `redis` | `RedisSessionStore`, an opaque session store over a shared Redis (`redis`) |

The default build is email/password + opaque sessions, backed by the database the
host already provides — no extra services required.

## Status

Early development, APIs may change before 1.0.

## MSRV

Rust 1.96.

## License

MIT, see [LICENSE](LICENSE).

[esylla]: https://github.com/esylla/esylla
