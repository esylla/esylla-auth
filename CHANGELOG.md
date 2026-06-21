# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-21

Initial release.

### Added

- Email/password signup with mandatory verification: the account is created only
  when the verification token is confirmed (held as a pending registration until
  then), so an unverified address never reserves an account.
- Login, logout, and opaque server-side sessions — 256-bit tokens stored hashed,
  with a sliding idle window and a hard absolute cap, and a fresh token per login.
- Password reset (forgot → reset) and authenticated change, both invalidating the
  user's other sessions; reset never logs the user in.
- `SessionStrategy` abstraction with two implementations: `OpaqueSessions`
  (default) and, behind the `jwt` feature, stateless HS256 `JwtSessions` (issuer/
  audience-bound, 256-bit-minimum secret).
- OAuth authorization-code + PKCE behind the `oauth` feature: Google and Microsoft
  (OpenID Connect, ID-token + nonce validated, HTTPS issuer required) and GitHub,
  with `state` bound to the initiating browser and a registry for host-supplied
  `OAuthProvider`s.
- `SmtpMailer` behind the `smtp` feature (lettre + minijinja) with overridable
  templates and subjects.
- `RedisSessionStore` behind the `redis` feature — an opaque session store over a
  host-owned, shared Redis connection.
- Extensibility seams: swappable `UserStore` / `SessionStore` / `Mailer` /
  `SessionStrategy`, an `AccountAdapter` (signup/login hooks and email
  normalization), and per-route selection on the module.
- Security baseline: Argon2id password hashing, single-use hashed tokens claimed
  atomically, account-enumeration and timing defenses, and `__Host-`/`__Secure-`
  cookies.

[0.1.0]: https://github.com/esylla/esylla-auth/releases/tag/v0.1.0
