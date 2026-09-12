// Config-knob behavior matrix: every builder knob on `BarbicanTokenExtractor`
// and `MultiTokenValidator` must observably change extraction/validation
// behavior — default vs configured must differ.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use http::{HeaderMap, Request};
use tokenkit::claims::StandardClaims;
use tokenkit::service::{JwtAlgorithm, JwtConfig, JwtService};
use ws_barbican::extractor::BarbicanTokenExtractor;
use ws_barbican::validator::{ApiKeyStore, MultiTokenValidator};

fn parts_with(headers: HeaderMap, uri: &str) -> http::request::Parts {
    let req = Request::builder().uri(uri).body(()).unwrap();
    let (mut parts, _) = req.into_parts();
    parts.headers = headers;
    parts
}

fn service_with_secret(secret: &str) -> Arc<JwtService> {
    let cfg = JwtConfig {
        algorithm: JwtAlgorithm::HS256,
        secret: secret.to_string(),
        issuer: Some("config-matrix-issuer".to_string()),
        ..Default::default()
    };
    Arc::new(JwtService::new(cfg))
}

fn valid_token(svc: &JwtService) -> String {
    use chrono::{Duration, Utc};
    let claims = StandardClaims {
        sub: Some("user-1".to_string()),
        iss: Some("config-matrix-issuer".to_string()),
        exp: Some(Utc::now() + Duration::seconds(3600)),
        iat: Some(Utc::now()),
        jti: Some("jti-1".to_string()),
        ..Default::default()
    };
    svc.encode(&claims).unwrap()
}

// ---------------------------------------------------------------------------
// BarbicanTokenExtractor::with_query_keys — replaces the default
// ["token", "access_token"] list; the new keys must extract and the old
// defaults must STOP working.
// ---------------------------------------------------------------------------
#[test]
fn with_query_keys_replaces_default_keys_observably() {
    let ex = BarbicanTokenExtractor::default().with_query_keys(vec!["auth".to_string()]);

    // Configured key extracts.
    let parts = parts_with(HeaderMap::new(), "/ws?auth=custom_tok");
    assert_eq!(
        ex.extract(&parts, "auth=custom_tok"),
        Some("custom_tok".into())
    );

    // Default keys no longer match.
    let parts = parts_with(HeaderMap::new(), "/ws?token=default_tok");
    assert_eq!(
        ex.extract(&parts, "token=default_tok"),
        None,
        "replacing query keys must disable the defaults"
    );

    // Default extractor: the mirror-image behavior.
    let default_ex = BarbicanTokenExtractor::default();
    let parts = parts_with(HeaderMap::new(), "/ws?token=default_tok");
    assert_eq!(
        default_ex.extract(&parts, "token=default_tok"),
        Some("default_tok".into())
    );
}

// ---------------------------------------------------------------------------
// BarbicanTokenExtractor::with_cookie_name — Some(name) extracts from that
// cookie only; None disables cookie extraction entirely.
// ---------------------------------------------------------------------------
fn cookie_headers_session() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        http::header::COOKIE,
        "session=from_session".parse().unwrap(),
    );
    h
}

#[test]
fn with_cookie_name_controls_cookie_extraction() {
    // Renaming the cookie: new name extracts, old name is ignored.
    let renamed = BarbicanTokenExtractor::default().with_cookie_name(Some("sid".to_string()));
    let mut both = HeaderMap::new();
    both.insert(
        http::header::COOKIE,
        "session=from_session; sid=from_sid".parse().unwrap(),
    );
    let parts = parts_with(both, "/ws");
    assert_eq!(renamed.extract(&parts, ""), Some("from_sid".into()));

    let parts = parts_with(cookie_headers_session(), "/ws");
    assert_eq!(
        renamed.extract(&parts, ""),
        None,
        "the previous cookie name must stop extracting"
    );

    // None disables cookie extraction (default would have extracted).
    let no_cookie = BarbicanTokenExtractor::default().with_cookie_name(None);
    let parts = parts_with(cookie_headers_session(), "/ws");
    assert_eq!(no_cookie.extract(&parts, ""), None);
    assert_eq!(no_cookie.cookie_name(), None);
}

// ---------------------------------------------------------------------------
// MultiTokenValidator::with_api_key_store — attaching a store lets an
// API key authenticate where JWT validation fails; without the knob the
// same token is rejected.
// ---------------------------------------------------------------------------
#[test]
fn with_api_key_store_enables_fallback() {
    struct FixedStore;
    impl ApiKeyStore for FixedStore {
        fn validate(&self, key: &str) -> Option<StandardClaims> {
            (key == "store-key").then(|| StandardClaims {
                sub: Some("store-user".to_string()),
                ..Default::default()
            })
        }
    }

    let svc = service_with_secret("config-matrix-secret");
    let without = MultiTokenValidator::new(Arc::clone(&svc));
    let with = MultiTokenValidator::new(Arc::clone(&svc)).with_api_key_store(Arc::new(FixedStore));

    // JWT path identical for both.
    let token = valid_token(&svc);
    assert!(with.validate_sync(&token).is_ok());
    assert!(without.validate_sync(&token).is_ok());

    // API-key path: knob on -> accepted; knob off -> rejected.
    let ok = with.validate_sync("store-key").unwrap();
    assert_eq!(ok.sub.as_deref(), Some("store-user"));
    assert!(without.validate_sync("store-key").is_err());
}

// ---------------------------------------------------------------------------
// MultiTokenValidator::with_api_key_fn — closure variant of the same knob;
// JWT still wins when both would accept.
// ---------------------------------------------------------------------------
#[test]
fn with_api_key_fn_enables_fallback_jwt_preferred() {
    let svc = service_with_secret("config-matrix-secret");
    let mv = MultiTokenValidator::new(Arc::clone(&svc)).with_api_key_fn(|k| {
        (k == "fn-key").then(|| StandardClaims {
            sub: Some("fn-user".to_string()),
            ..Default::default()
        })
    });

    let ok = mv.validate_sync("fn-key").unwrap();
    assert_eq!(ok.sub.as_deref(), Some("fn-user"));

    // JWT preferred over the synthetic API-key claims.
    let token = valid_token(&svc);
    let claims = mv.validate_sync(&token).unwrap();
    assert_eq!(claims.sub.as_deref(), Some("user-1"));

    // A validator without the knob rejects the same API key.
    let bare = MultiTokenValidator::new(Arc::clone(&svc));
    assert!(bare.validate_sync("fn-key").is_err());
}
