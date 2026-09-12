
## [0.1.2] - 2026-09-12

### Added
- `tests/config_matrix.rs` (4 tests): behavior-observable coverage for every
  builder knob — `with_query_keys` (replaces defaults), `with_cookie_name`
  (rename + disable), `with_api_key_store` (trait-object fallback), and
  `with_api_key_fn` (closure fallback, JWT-preferred). Dead-knob sweep found
  zero dead knobs; all extraction already delegates to ws-kit's
  `TokenExtractor`.

## [0.1.1] - 2026-09-05

### Changed
- Dependency reqs: ws-kit 0.3 (allowed_origins), barbican 0.2 (segment-boundary paths), registry-only tokenkit 0.1
