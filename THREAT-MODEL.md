# Threat Model — ws-barbican

Status: **v1.0** · Method: STRIDE over the public API surface
(`BarbicanValidator`, `BarbicanTokenExtractor`, `MultiTokenValidator`,
`AuthenticatedWs`, `OptionalAuthenticatedWs`, `ApiKeyStore`,
`build_ws_auth_cookie`).

Trust boundaries: (1) the HTTP upgrade request (headers, cookies,
query string — attacker-controlled), (2) the token issuers (barbican
JWTs and API keys), (3) the Axum extraction layer where auth decisions
become typed request state, (4) browser clients (cookies).

This crate is the authentication choke point for WebSocket upgrades:
a mistake here authenticates a socket for its entire lifetime, so the
model privileges *fail-closed* behavior and explicit extraction order.

## Assets

| ID | Asset | Example |
|----|-------|---------|
| A1 | WebSocket upgrade authenticity | An unauthenticated or expired client completing an upgrade |
| A2 | Token material on the wire | JWTs leaking into URLs/logs via query-string handling |
| A3 | Revocation semantics | A revoked API key or JWT validating mid-handshake |
| A4 | Cookie scoping | Auth cookie emitted with wrong name/path scope, or read from a wrong cookie |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Verifying test |
|---|--------|----------|---------|------------|----------------|
| T1 | Upgrade without a token | Spoofing | `BarbicanTokenExtractor` | Missing tokens yield `None`/401 *before* upgrade; extraction order is explicit and pinned: header → query → cookie | `extract_missing_returns_none`, `handler_401_before_upgrade_missing_token`, `extract_order_header_over_query_over_cookie`, `inner_extractor_sources` |
| T2 | Expired or invalid JWT upgraded | Spoofing | `BarbicanValidator::validate_sync` | Claims validated (exp, signature via tokenkit/barbican) synchronously at extraction; invalid → typed failure → 401 before upgrade | `validator_expired`, `expired_claims`, `validator_valid`, `valid_claims`, `handler_401_before_upgrade_invalid_token` |
| T3 | Revoked API key still accepted | Elevation | `ApiKeyStore` path | Store lookups return revocation state; revocation maps to invalid, not to a fallback-accept | `validator_revoked_maps_to_invalid`, `with_api_key_store`, `with_api_key_fn` |
| T4 | Token leakage via query strings (referrer/history/logs) | Information Disclosure | query extraction | Query extraction is opt-in via `with_query_keys`/`query_keys` with a constrained key list; header/cookie are preferred in the documented order; URL-decoded values are handled explicitly | `extract_custom_query_keys`, `default_keys_and_cookie`, `extract_query_url_decode`, `extract_query_access_token`, `extract_query_token` |
| T5 | Cookie confusion / wrong cookie name | Spoofing | cookie extraction, `build_ws_auth_cookie` | Cookie name is configurable (`with_cookie_name`, `cookie_name`) and the cookie builder delegates to tokenkit's canonical construction | `extract_cookie`, `extract_cookie_disabled`, `build_ws_auth_cookie_delegates`, `extractor_cookie` |
| T6 | Optional auth silently escalating | Elevation | `OptionalAuthenticatedWs` | The optional extractor never 401s — it yields `None` on failure; handlers must branch on the value, and the behavior is pinned by test so it cannot regress to hard-deny or silent-accept | `handler_optional_never_401` |
| T7 | Multi-token validator confusion (JWT vs API key) | Spoofing | `MultiTokenValidator` | Each candidate token class is validated by its own validator; JWT validation failures do not fall through to API-key acceptance except by explicit multi-token design | `validator_multi_token_jwt_and_api_key`, `validate_sync_paths` |

## OPEN RISKS (missing mitigations — not fabricated)

- **OPEN-1 — query-string tokens are a documented, opt-in necessity.**
  Browsers cannot set headers on WebSocket handshakes; deployments that
  disable query extraction must rely on cookies. Access-token-bearing
  URLs can leak via logs/referrers — operators should prefer cookies.
- **OPEN-2 — no per-connection re-validation.** Auth is enforced at
  upgrade time; long-lived sockets are not re-validated midstream.
  Callers needing session revocation mid-socket must layer it above.

## Out of Scope

- Token issuance/rotation internals (owned by barbican/tokenkit).
- Post-upgrade message-level authorization.
- TLS termination and origin checks (deployment concern).

## Residual Risks

- Cookie-based auth inherits browser CSRF posture for the *handshake*
  request; WebSocket origins should be validated at the server layer
  (Axum configuration) — the crate does not enforce same-origin.
