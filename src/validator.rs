//! JWT and multi-token validators for WebSocket authentication.

use std::sync::Arc;

use tokenkit::claims::StandardClaims;
use tokenkit::error::JwtError;
use tokenkit::service::JwtService;
use ws_kit::extractor::WsAuthError;

/// Trait for WebSocket authentication validators.
///
/// Validates a raw bearer token string and returns decoded claims on success.
///
/// If `ws-kit` ever exposes its own `WsAuthValidator`, this trait is intended
/// to be compatible. Otherwise this crate defines the canonical trait.
pub trait WsAuthValidator: Send + Sync {
    /// Validate `token` and return decoded [`StandardClaims`].
    ///
    /// Declared with RPITIT (rather than `async fn`) so implementors get
    /// explicit control over auto-trait bounds, as recommended by the
    /// `async_fn_in_trait` lint.
    fn validate(
        &self,
        token: &str,
    ) -> impl std::future::Future<Output = Result<StandardClaims, WsAuthError>> + Send;
}

/// Validates JWTs using a shared [`JwtService`].
#[derive(Clone)]
pub struct BarbicanValidator {
    service: Arc<JwtService>,
}

impl std::fmt::Debug for BarbicanValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BarbicanValidator")
            .field("service", &"JwtService")
            .finish()
    }
}

impl BarbicanValidator {
    /// Create a new validator from an [`Arc<JwtService>`].
    pub fn new(service: Arc<JwtService>) -> Self {
        Self { service }
    }

    /// Create from a raw [`JwtService`] (wrapped in `Arc` internally).
    pub fn from_service(service: JwtService) -> Self {
        Self {
            service: Arc::new(service),
        }
    }

    /// Borrow the inner service.
    pub fn service(&self) -> &Arc<JwtService> {
        &self.service
    }

    /// Synchronous validation helper (non-trait) for contexts without async.
    pub fn validate_sync(&self, token: &str) -> Result<StandardClaims, WsAuthError> {
        self.service
            .decode::<StandardClaims>(token)
            .map_err(map_jwt_error)
    }
}

impl WsAuthValidator for BarbicanValidator {
    async fn validate(&self, token: &str) -> Result<StandardClaims, WsAuthError> {
        // `JwtService::decode` is synchronous; keep async signature for
        // compatibility with future revocation checks that may require await.
        self.validate_sync(token)
    }
}

/// Map [`JwtError`] to [`WsAuthError`].
fn map_jwt_error(err: JwtError) -> WsAuthError {
    match err {
        JwtError::Expired => WsAuthError::Expired,
        JwtError::Revoked => WsAuthError::Invalid,
        JwtError::InvalidSignature => WsAuthError::Invalid,
        JwtError::DecodingFailed(msg) => {
            let lower = msg.to_ascii_lowercase();
            if lower.contains("expired") {
                WsAuthError::Expired
            } else {
                WsAuthError::Invalid
            }
        }
        _ => WsAuthError::Invalid,
    }
}

/// Abstraction for API-key validation.
///
/// Implement this trait to provide custom API-key stores (e.g. DB, HashMap).
/// A blanket impl is provided for closures `Fn(&str) -> Option<StandardClaims>`.
pub trait ApiKeyStore: Send + Sync {
    /// Validate `key` and return synthetic claims if valid.
    fn validate(&self, key: &str) -> Option<StandardClaims>;
}

impl<F> ApiKeyStore for F
where
    F: Fn(&str) -> Option<StandardClaims> + Send + Sync,
{
    fn validate(&self, key: &str) -> Option<StandardClaims> {
        self(key)
    }
}

/// Validator that accepts either a JWT or an API key.
///
/// Tries JWT validation first; on failure falls back to API-key lookup if
/// a store is configured.
pub struct MultiTokenValidator {
    jwt: BarbicanValidator,
    api_key_store: Option<Arc<dyn ApiKeyStore>>,
}

impl std::fmt::Debug for MultiTokenValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiTokenValidator")
            .field("has_api_key_store", &self.api_key_store.is_some())
            .finish()
    }
}

impl MultiTokenValidator {
    /// Create a validator with only JWT support.
    pub fn new(service: Arc<JwtService>) -> Self {
        Self {
            jwt: BarbicanValidator::new(service),
            api_key_store: None,
        }
    }

    /// Attach an API-key store.
    pub fn with_api_key_store(mut self, store: Arc<dyn ApiKeyStore>) -> Self {
        self.api_key_store = Some(store);
        self
    }

    /// Attach a closure-based API-key validator.
    pub fn with_api_key_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Option<StandardClaims> + Send + Sync + 'static,
    {
        self.api_key_store = Some(Arc::new(f));
        self
    }

    /// Borrow the JWT validator.
    pub fn jwt_validator(&self) -> &BarbicanValidator {
        &self.jwt
    }

    /// Synchronous validation: tries JWT then API key.
    pub fn validate_sync(&self, token: &str) -> Result<StandardClaims, WsAuthError> {
        match self.jwt.validate_sync(token) {
            Ok(claims) => Ok(claims),
            Err(jwt_err) => {
                if let Some(store) = &self.api_key_store {
                    if let Some(claims) = store.validate(token) {
                        return Ok(claims);
                    }
                }
                Err(jwt_err)
            }
        }
    }
}

impl WsAuthValidator for MultiTokenValidator {
    async fn validate(&self, token: &str) -> Result<StandardClaims, WsAuthError> {
        // Delegate to sync version; async slot reserved for future IO (e.g. DB lookups).
        self.validate_sync(token)
    }
}

#[cfg(test)]
// Test code: unwrap/unwrap_err are the idiomatic way to assert outcomes.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tokenkit::service::{JwtAlgorithm, JwtConfig};

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
            aud: None,
            exp: Some(Utc::now() + Duration::seconds(3600)),
            iat: Some(Utc::now()),
            jti: Some("jti-1".to_string()),
            role: Some("user".to_string()),
            permissions: vec![],
            extra: Default::default(),
        }
    }

    fn expired_claims() -> StandardClaims {
        StandardClaims {
            sub: Some("user-2".to_string()),
            iss: Some("test-issuer".to_string()),
            exp: Some(Utc::now() - Duration::seconds(3600)),
            iat: Some(Utc::now() - Duration::seconds(7200)),
            jti: Some("jti-exp".to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn barbican_validator_valid() {
        let svc = service_with_secret("valid-secret-key-123");
        let v = BarbicanValidator::new(svc.clone());
        let claims = valid_claims();
        let token = svc.encode(&claims).unwrap();
        let decoded = v.validate(&token).await.unwrap();
        assert_eq!(decoded.sub.as_deref(), Some("user-1"));
    }

    #[tokio::test]
    async fn barbican_validator_expired_maps_to_expired() {
        let svc = service_with_secret("valid-secret-key-123");
        let v = BarbicanValidator::new(svc.clone());
        let claims = expired_claims();
        let token = svc.encode(&claims).unwrap();
        let err = v.validate(&token).await.unwrap_err();
        // jsonwebtoken returns DecodingFailed with "ExpiredSignature", mapped to Expired
        assert_eq!(err, WsAuthError::Expired);
    }

    #[tokio::test]
    async fn barbican_validator_invalid_signature() {
        let svc1 = service_with_secret("secret-one-123456");
        let svc2 = service_with_secret("secret-two-654321");
        let v = BarbicanValidator::new(svc2);
        let claims = valid_claims();
        let token = svc1.encode(&claims).unwrap();
        let err = v.validate(&token).await.unwrap_err();
        assert_eq!(err, WsAuthError::Invalid);
    }

    #[tokio::test]
    async fn barbican_validator_malformed() {
        let svc = service_with_secret("valid-secret-key-123");
        let v = BarbicanValidator::new(svc);
        let err = v.validate("not.a.jwt").await.unwrap_err();
        assert_eq!(err, WsAuthError::Invalid);
    }

    #[tokio::test]
    async fn multi_validator_jwt_success() {
        let svc = service_with_secret("valid-secret-key-123");
        let mv = MultiTokenValidator::new(svc.clone());
        let claims = valid_claims();
        let token = svc.encode(&claims).unwrap();
        let decoded = mv.validate(&token).await.unwrap();
        assert_eq!(decoded.sub.as_deref(), Some("user-1"));
    }

    #[tokio::test]
    async fn multi_validator_api_key_fallback() {
        let svc = service_with_secret("valid-secret-key-123");
        // JWT will fail; api key should succeed
        let mv = MultiTokenValidator::new(svc).with_api_key_fn(|k| {
            if k == "api-key-123" {
                Some(StandardClaims {
                    sub: Some("api-user".to_string()),
                    ..Default::default()
                })
            } else {
                None
            }
        });
        let decoded = mv.validate("api-key-123").await.unwrap();
        assert_eq!(decoded.sub.as_deref(), Some("api-user"));
    }

    #[tokio::test]
    async fn multi_validator_api_key_invalid() {
        let svc = service_with_secret("valid-secret-key-123");
        let mv = MultiTokenValidator::new(svc).with_api_key_fn(|k| {
            if k == "good" {
                Some(StandardClaims {
                    sub: Some("x".into()),
                    ..Default::default()
                })
            } else {
                None
            }
        });
        let err = mv.validate("bad-key").await.unwrap_err();
        assert_eq!(err, WsAuthError::Invalid);
    }

    #[tokio::test]
    async fn multi_validator_jwt_preferred_over_api_key() {
        let svc = service_with_secret("valid-secret-key-123");
        let mv = MultiTokenValidator::new(svc.clone()).with_api_key_fn(|_| {
            Some(StandardClaims {
                sub: Some("api-user".into()),
                ..Default::default()
            })
        });
        // valid JWT should be returned, not api-key synthetic claims
        let claims = valid_claims();
        let token = svc.encode(&claims).unwrap();
        let decoded = mv.validate(&token).await.unwrap();
        assert_eq!(decoded.sub.as_deref(), Some("user-1"));
    }

    #[test]
    fn validate_sync_paths() {
        let svc = service_with_secret("valid-secret-key-123");
        let v = BarbicanValidator::new(svc.clone());
        let claims = valid_claims();
        let token = svc.encode(&claims).unwrap();
        assert!(v.validate_sync(&token).is_ok());
        assert!(v.validate_sync("bad").is_err());
    }
}
