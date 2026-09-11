#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # ws-barbican
//!
//! WebSocket authentication bridge combining `ws-kit`, `barbican`, and `tokenkit`.
//!
//! - [`validator::BarbicanValidator`] — validates JWTs via [`tokenkit::service::JwtService`].
//! - [`validator::MultiTokenValidator`] — validates either JWT or API-key tokens.
//! - [`extractor::BarbicanTokenExtractor`] — extracts bearer tokens from `Authorization` header, query string, or `Cookie`.
//! - [`handler::AuthenticatedWs`] — Axum extractor that authenticates WebSocket upgrades before `on_upgrade`.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokenkit::service::{JwtConfig, JwtService};
//! use ws_barbican::handler::AuthenticatedWs;
//! use tokenkit::claims::StandardClaims;
//! use axum::extract::ws::WebSocketUpgrade;
//! use axum::response::IntoResponse;
//!
//! async fn ws_handler(
//!     AuthenticatedWs(claims): AuthenticatedWs<StandardClaims>,
//!     ws: WebSocketUpgrade,
//! ) -> impl IntoResponse {
//!     ws.on_upgrade(move |_socket| async move {
//!         // `claims` is the validated `StandardClaims`; handle the socket here.
//!         let _ = claims.sub.clone();
//!     })
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let config = JwtConfig { secret: "secret".to_string(), ..Default::default() };
//! let service = Arc::new(JwtService::new(config));
//! let _ = service;
//! # });
//! ```

/// Token extraction for WebSocket upgrades.
pub mod extractor;
/// Axum extractors and helpers for authenticated WebSocket upgrades.
pub mod handler;
/// JWT and multi-token validators.
pub mod validator;

// Re-exports from barbican and tokenkit for ergonomic use.
pub use barbican::{AuthRejection, BearerToken, Claims, OptionalAuth};
/// Standard JWT claims re-exported from `tokenkit`.
pub use tokenkit::claims::StandardClaims;
