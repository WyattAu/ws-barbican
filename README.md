# ws-barbican

[![docs.rs](https://docs.rs/ws-barbican/badge.svg)](https://docs.rs/ws-barbican)
[![crates.io](https://img.shields.io/crates/v/ws-barbican.svg)](https://crates.io/crates/ws-barbican)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

WebSocket authentication bridge — `barbican` + `ws-kit` + `tokenkit` integration for Axum.

## Features

- `BarbicanValidator` — validates JWTs via `tokenkit::JwtService`
- `MultiTokenValidator` — accepts either JWT or API-key tokens
- `BarbicanTokenExtractor` — extracts bearer tokens from `Authorization: Bearer`, query `?token=` / `?access_token=`, or `Cookie: session=`
- `AuthenticatedWs<C>` — Axum extractor that authenticates WebSocket upgrades before `on_upgrade` (401 before upgrade)
- `build_ws_auth_cookie` — delegates to `tokenkit::build_auth_cookie`

## Quick start

```rust
use std::sync::Arc;
use axum::{Router, routing::get};
use tokenkit::service::{JwtConfig, JwtService};
use ws_barbican::handler::AuthenticatedWs;
use tokenkit::claims::StandardClaims;
use axum::extract::ws::WebSocketUpgrade;
use axum::response::IntoResponse;

async fn ws_handler(
    AuthenticatedWs(claims): AuthenticatedWs<StandardClaims>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |_socket| async move {
        tracing::info!(sub = ?claims.sub, "ws connected");
    })
}

let config = JwtConfig { secret: "secret".to_string(), ..Default::default() };
let service = Arc::new(JwtService::new(config));
let app = Router::new().route("/ws", get(ws_handler)).with_state(service);
```

## Extractor

```rust
use ws_barbican::extractor::BarbicanTokenExtractor;
use http::{Request, HeaderMap};

let ex = BarbicanTokenExtractor::default(); // Bearer, ?token=, ?access_token=, Cookie session
```

## Validator

```rust
use ws_barbican::validator::{BarbicanValidator, WsAuthValidator};

let v = BarbicanValidator::new(service);
let claims = v.validate("jwt_token").await.unwrap();
```

## Handler

```rust
use ws_barbican::handler::{barbican_ws_handler, build_ws_auth_cookie};

let cookie = build_ws_auth_cookie("session", "jwt", 3600, true);
```

## License

MIT OR Apache-2.0
