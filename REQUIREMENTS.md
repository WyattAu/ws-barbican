# Requirements — ws-barbican

Numbered, testable requirements. Every requirement maps to at least one named
test; every security-relevant test cites at least one requirement. Threat
IDs reference `THREAT-MODEL.md`.

Scope note: `ws-barbican` is the WebSocket authentication bridge —
barbican + ws-kit + tokenkit integration for Axum. It extracts tokens
(header → query → cookie), validates them (JWT claims, API keys with
revocation), and exposes `AuthenticatedWs` / `OptionalAuthenticatedWs`
extractors that fail closed before the upgrade.

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WB-001 | `BarbicanTokenExtractor` extracts tokens in priority order: Authorization header, then configured query keys, then the auth cookie | MUST |
| REQ-WB-002 | Query extraction is opt-in and constrained to configured key names; values are URL-decoded | MUST |
| REQ-WB-003 | `BarbicanValidator::validate_sync` accepts valid claims, rejects expired/invalid ones, and maps revoked API keys to invalid | MUST |
| REQ-WB-004 | `AuthenticatedWs` rejects unauthenticated requests with 401 *before* the upgrade; `OptionalAuthenticatedWs` never 401s and yields `None` instead | MUST |
| REQ-WB-005 | `MultiTokenValidator` validates JWT and API-key tokens through their respective validators | MUST |
| REQ-WB-006 | Cookie name is configurable; `build_ws_auth_cookie` delegates to tokenkit's canonical cookie construction | SHOULD |
| REQ-WB-007 | `ApiKeyStore` (async trait) supports store-backed and closure-backed key lookup | SHOULD |

## Security

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WB-100 | Fail-closed upgrade path: missing or invalid tokens produce 401 before the socket exists (T1, T2) | MUST |
| REQ-WB-101 | Expired JWT claims are rejected synchronously at extraction time (T2) | MUST |
| REQ-WB-102 | Revocation is honored: revoked keys map to invalid, never to fallback-accept (T3) | MUST |
| REQ-WB-103 | Optional authentication cannot escalate: the optional extractor's `None` outcome is pinned by test (T6) | MUST |
| REQ-WB-104 | Extraction order is deterministic and pinned: header over query over cookie (T1, T4) | MUST |
| REQ-WB-105 | Validator classes are disjoint: a JWT failure is not silently retried as an API key except via the explicit multi-token validator (T7) | MUST |

## Robustness

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WB-200 | URL-encoded query values decode before validation | MUST |
| REQ-WB-201 | Defaults exist for query keys and cookie name; all are overridable | SHOULD |

## Traceability Matrix

| Requirement | Test (fn, file) | Property class |
|-------------|-----------------|----------------|
| REQ-WB-001 | `extract_order_header_over_query_over_cookie`, `inner_extractor_sources`, `extract_header_preferred_via_tokenkit_helper`, `extractor_header`, `extractor_query_access_token`, `extractor_query_token`, `extractor_cookie`, `extractor_missing` (`src/`, `tests/`) | unit/integration |
| REQ-WB-002 | `extract_custom_query_keys`, `default_keys_and_cookie`, `query_keys`, `extract_query_url_decode` | unit |
| REQ-WB-003 | `validator_valid`, `validator_expired`, `validator_revoked_maps_to_invalid`, `validate_sync_paths`, `valid_claims`, `expired_claims` | unit |
| REQ-WB-004 | `handler_401_before_upgrade_missing_token`, `handler_401_before_upgrade_invalid_token`, `handler_optional_never_401`, `handler_success_before_upgrade`, `extract_missing_returns_none` | integration |
| REQ-WB-005 | `validator_multi_token_jwt_and_api_key`, `validate_sync_paths` | unit |
| REQ-WB-006 | `extract_cookie`, `extract_cookie_disabled`, `with_cookie_name`, `build_ws_auth_cookie_delegates` | unit |
| REQ-WB-007 | `with_api_key_store`, `with_api_key_fn` | unit |
| REQ-WB-100 | `handler_401_before_upgrade_missing_token`, `handler_401_before_upgrade_invalid_token` | integration |
| REQ-WB-101 | `validator_expired`, `expired_claims` | unit |
| REQ-WB-102 | `validator_revoked_maps_to_invalid` | unit |
| REQ-WB-103 | `handler_optional_never_401` | integration |
| REQ-WB-104 | `extract_order_header_over_query_over_cookie`, `inner_extractor_sources` | unit |
| REQ-WB-105 | `validator_multi_token_jwt_and_api_key`, `validate_sync_paths` | unit |
| REQ-WB-200 | `extract_query_url_decode` | unit |
| REQ-WB-201 | `default_keys_and_cookie`, `extract_custom_query_keys` | unit |

## Test Count

- 21 `#[test]` functions across unit and router-integration suites.
- All-features suite passes with 0 failures; no-default-features suite passes.
