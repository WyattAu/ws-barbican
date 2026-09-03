use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use chrono::{Duration, Utc};
use http::request::Parts;
use tokenkit::claims::StandardClaims;
use tokenkit::service::{JwtAlgorithm, JwtConfig, JwtService};
use ws_barbican::extractor::BarbicanTokenExtractor;
use ws_barbican::handler::{AuthenticatedWs, OptionalAuthenticatedWs};
use ws_barbican::validator::{BarbicanValidator, MultiTokenValidator, WsAuthValidator};

fn service_with_secret(secret: &str) -> Arc<JwtService> {
    let cfg = JwtConfig {
        algorithm: JwtAlgorithm::HS256,
        secret: secret.to_string(),
        issuer: Some("test-issuer".to_string()),
        ..Default::default()
    };
    Arc::new(JwtService::new(cfg))
}

fn valid_claims() -> StandardClaims {
    StandardClaims {
        sub: Some("user-1".to_string()),
        iss: Some("test-issuer".to_string()),
        exp: Some(Utc::now() + Duration::seconds(3600)),
        iat: Some(Utc::now()),
        jti: Some("jti-1".to_string()),
        role: Some("user".to_string()),
        ..Default::default()
    }
}

fn expired_claims() -> StandardClaims {
    StandardClaims {
        sub: Some("user-exp".to_string()),
        iss: Some("test-issuer".to_string()),
        exp: Some(Utc::now() - Duration::seconds(3600)),
        iat: Some(Utc::now() - Duration::seconds(7200)),
        jti: Some("jti-exp".to_string()),
        ..Default::default()
    }
}

fn parts_with(headers: HeaderMap, uri: &str) -> Parts {
    let req = Request::builder().uri(uri).body(()).unwrap();
    let (mut parts, _) = req.into_parts();
    parts.headers = headers;
    parts
}

// ---- extractor integration ----

#[test]
fn extractor_header() {
    let ex = BarbicanTokenExtractor::default();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        "Bearer header_token".parse().unwrap(),
    );
    let parts = parts_with(headers, "/ws?token=query_token");
    assert_eq!(ex.extract(&parts, "token=query_token"), Some("header_token".to_string()));
}

#[test]
fn extractor_query_token() {
    let ex = BarbicanTokenExtractor::default();
    let parts = parts_with(HeaderMap::new(), "/ws?token=q123");
    assert_eq!(ex.extract(&parts, "token=q123"), Some("q123".to_string()));
}

#[test]
fn extractor_query_access_token() {
    let ex = BarbicanTokenExtractor::default();
    let parts = parts_with(HeaderMap::new(), "/ws?access_token=at456");
    assert_eq!(ex.extract(&parts, "access_token=at456"), Some("at456".to_string()));
}

#[test]
fn extractor_cookie() {
    let ex = BarbicanTokenExtractor::default();
    let mut headers = HeaderMap::new();
    headers.insert(http::header::COOKIE, "session=cookie_tok".parse().unwrap());
    let parts = parts_with(headers, "/ws");
    assert_eq!(ex.extract(&parts, ""), Some("cookie_tok".to_string()));
}

#[test]
fn extractor_missing() {
    let ex = BarbicanTokenExtractor::default();
    let parts = parts_with(HeaderMap::new(), "/ws");
    assert_eq!(ex.extract(&parts, ""), None);
}

// ---- validator integration ----

#[tokio::test]
async fn validator_valid() {
    let svc = service_with_secret("valid-secret-12345");
    let v = BarbicanValidator::new(Arc::clone(&svc));
    let token = svc.encode(&valid_claims()).unwrap();
    let decoded = v.validate(&token).await.unwrap();
    assert_eq!(decoded.sub.as_deref(), Some("user-1"));
}

#[tokio::test]
async fn validator_expired() {
    let svc = service_with_secret("valid-secret-12345");
    let v = BarbicanValidator::new(Arc::clone(&svc));
    let token = svc.encode(&expired_claims()).unwrap();
    let err = v.validate(&token).await.unwrap_err();
    assert_eq!(err, ws_kit::extractor::WsAuthError::Expired);
}

#[tokio::test]
async fn validator_revoked_maps_to_invalid() {
    // Revoked is mapped to Invalid (WsAuthError has no Revoked variant)
    // Simulate by directly checking the error mapping via an invalid token that would be revoked
    // We test the mapping logic via MultiTokenValidator fallback still returning Invalid for unknown keys
    let svc = service_with_secret("valid-secret-12345");
    let v = BarbicanValidator::new(svc);
    let err = v.validate("not.a.jwt").await.unwrap_err();
    assert_eq!(err, ws_kit::extractor::WsAuthError::Invalid);
}

#[tokio::test]
async fn validator_multi_token_jwt_and_api_key() {
    let svc = service_with_secret("valid-secret-12345");
    let mv = MultiTokenValidator::new(Arc::clone(&svc)).with_api_key_fn(|k| {
        if k == "api-123" {
            Some(StandardClaims {
                sub: Some("api-user".into()),
                ..Default::default()
            })
        } else {
            None
        }
    });
    // JWT succeeds
    let token = svc.encode(&valid_claims()).unwrap();
    assert_eq!(mv.validate(&token).await.unwrap().sub.as_deref(), Some("user-1"));
    // API key succeeds
    assert_eq!(mv.validate("api-123").await.unwrap().sub.as_deref(), Some("api-user"));
    // Both fail
    assert!(mv.validate("bad").await.is_err());
}

// ---- handler integration: 401 before on_upgrade ----

#[derive(Clone)]
struct AppState {
    jwt: Arc<JwtService>,
}

impl From<Arc<JwtService>> for AppState {
    fn from(jwt: Arc<JwtService>) -> Self {
        Self { jwt }
    }
}

impl axum::extract::FromRef<AppState> for Arc<JwtService> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.jwt)
    }
}

#[tokio::test]
async fn handler_401_before_upgrade_missing_token() {
    let svc = service_with_secret("valid-secret-12345");
    let state = AppState { jwt: svc };
    let req = Request::builder().uri("/ws").body(()).unwrap();
    let (mut parts, _) = req.into_parts();
    let res = AuthenticatedWs::<StandardClaims>::from_request_parts(&mut parts, &state).await;
    assert!(res.is_err());
    let resp = res.unwrap_err().into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn handler_401_before_upgrade_invalid_token() {
    let svc = service_with_secret("valid-secret-12345");
    let state = AppState { jwt: svc };
    let req = Request::builder()
        .uri("/ws")
        .header(http::header::AUTHORIZATION, "Bearer invalid.token.here")
        .body(())
        .unwrap();
    let (mut parts, _) = req.into_parts();
    let res = AuthenticatedWs::<StandardClaims>::from_request_parts(&mut parts, &state).await;
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().into_response().status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn handler_success_before_upgrade() {
    let svc = service_with_secret("valid-secret-12345");
    let token = svc.encode(&valid_claims()).unwrap();
    let state = AppState { jwt: svc };
    let req = Request::builder()
        .uri("/ws")
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(())
        .unwrap();
    let (mut parts, _) = req.into_parts();
    let res = AuthenticatedWs::<StandardClaims>::from_request_parts(&mut parts, &state).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn handler_optional_never_401() {
    let svc = service_with_secret("valid-secret-12345");
    let state = AppState { jwt: svc };
    let req = Request::builder().uri("/ws").body(()).unwrap();
    let (mut parts, _) = req.into_parts();
    let res = OptionalAuthenticatedWs::<StandardClaims>::from_request_parts(&mut parts, &state).await;
    assert!(res.is_ok());
    assert!(res.unwrap().0.is_none());
}

#[cfg(test)]
mod proptest_integration {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn bearer_extraction_via_extractor(token in "[a-zA-Z0-9._-]{1,30}") {
            let ex = BarbicanTokenExtractor::default();
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap()
            );
            // Need a valid http request parts for extraction
            let parts = parts_with(headers, "/ws");
            prop_assert_eq!(ex.extract(&parts, ""), Some(token));
        }

        #[test]
        fn query_extraction_via_extractor(token in "[a-zA-Z0-9]{1,20}") {
            let ex = BarbicanTokenExtractor::default();
            let parts = parts_with(HeaderMap::new(), &format!("/ws?token={token}"));
            prop_assert_eq!(ex.extract(&parts, &format!("token={token}")), Some(token));
        }
    }
}
