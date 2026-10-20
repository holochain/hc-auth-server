//! `POST /api/confirm-email`: a rate-limited yes/no check that an agent key
//! is bound to an email address.
//!
//! The route is gated by `CONFIRM_TOKENS`, a token list of its own, so the
//! caller (the voucher worker) never holds a token that can approve or
//! block agents. It reads `data.verified.email`, which only the admin route
//! `PUT /api/verified/{key}` writes. The caller-supplied `data.payload` is
//! never consulted. The stored email is never returned.

use axum::{
    Json, Router,
    extract::State as AxumState,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;

use crate::routes_api::{bearer_token, check_token};
use crate::routes_client::validate_pubkey;
use crate::state::AppState;
use crate::storage::State;
use crate::utils::sha256_hex;

/// Length of a rate-limit window in seconds.
const WINDOW_SECS: u64 = 60;

/// Returns the router for the confirm route, with its full path.
pub fn router() -> Router<AppState> {
    Router::new().route("/api/confirm-email", post(confirm_email))
}

/// Middleware that admits only a bearer token from `CONFIRM_TOKENS`.
pub async fn confirm_auth(
    AxumState(state): AxumState<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !check_token(request.headers(), &state.config.confirm_tokens) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

/// Body of `POST /api/confirm-email`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmRequest {
    /// Base64url encoded raw 32-byte Ed25519 public key.
    pub pub_key: String,
    /// The address to compare against the verified email.
    pub email: String,
}

/// Normalizes an email the way the voucher worker does: trim, then
/// ASCII `A`-`Z` to lower case, nothing else.
fn normalize(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// The decision: true only when the key is authorized and its verified
/// email equals `email` after both are normalized.
pub(crate) fn email_matches(
    state: State,
    data: &serde_json::Value,
    email: &str,
) -> bool {
    if state != State::Authorized {
        return false;
    }
    match data["verified"]["email"].as_str() {
        Some(stored) => normalize(stored) == normalize(email),
        None => false,
    }
}

/// POST /api/confirm-email - Replies `true` or `false` as JSON.
///
/// `400` for a malformed key, `429` when the per-token or per-key limit is
/// hit, `500` on a storage error. An unknown key is `false`, not `404`, so
/// the reply does not reveal which keys exist.
pub async fn confirm_email(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConfirmRequest>,
) -> Response {
    if validate_pubkey(&req.pub_key).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid pubKey").into_response();
    }

    // The token passed confirm_auth, so it is present. It is hashed so the
    // counter key does not hold the secret.
    let token = bearer_token(&headers).unwrap_or_default();
    let limits = [
        (
            format!("confirm:tok:{}", sha256_hex(token)),
            state.config.confirm_rate_per_token,
        ),
        (
            format!("confirm:key:{}", req.pub_key),
            state.config.confirm_rate_per_key,
        ),
    ];
    for (key, limit) in limits {
        match state.storage.count_in_window(&key, WINDOW_SECS).await {
            Ok(n) if n > limit => {
                return StatusCode::TOO_MANY_REQUESTS.into_response();
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!("confirm-email rate limit error: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    match state.storage.get_request(&req.pub_key).await {
        Ok(Some((st, data))) => {
            Json(email_matches(st, &data, &req.email)).into_response()
        }
        Ok(None) => Json(false).into_response(),
        Err(e) => {
            tracing::error!("confirm-email storage error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::email_matches;
    use crate::storage::State;
    use serde_json::json;

    fn data() -> serde_json::Value {
        json!({
            "verified": { "email": " Ada@Example.com " },
            "payload": { "email": "attacker@x.y" }
        })
    }

    #[test]
    fn matches_an_authorized_verified_email_after_normalization() {
        assert!(email_matches(State::Authorized, &data(), "ada@example.com"));
        assert!(email_matches(State::Authorized, &data(), "ADA@EXAMPLE.COM"));
        assert!(email_matches(
            State::Authorized,
            &data(),
            " ada@example.com "
        ));
    }

    #[test]
    fn refuses_a_key_that_is_not_authorized() {
        assert!(!email_matches(State::Pending, &data(), "ada@example.com"));
        assert!(!email_matches(State::Blocked, &data(), "ada@example.com"));
    }

    #[test]
    fn refuses_a_different_email() {
        assert!(!email_matches(State::Authorized, &data(), "attacker@x.y"));
        assert!(!email_matches(State::Authorized, &data(), "ada@example.co"));
    }

    #[test]
    fn a_payload_email_alone_never_confirms() {
        let data = json!({ "payload": { "email": "ada@example.com" } });
        assert!(!email_matches(State::Authorized, &data, "ada@example.com"));
    }

    #[test]
    fn refuses_a_verified_email_that_is_not_a_string() {
        let data = json!({ "verified": { "email": 5 } });
        assert!(!email_matches(State::Authorized, &data, "5"));
        let data = json!({ "verified": "ada@example.com" });
        assert!(!email_matches(State::Authorized, &data, "ada@example.com"));
    }

    #[test]
    fn confirm_router_merges_beside_the_api_nest() {
        // Axum panics at build time on overlapping paths. Nothing here
        // needs state, so the router is built without it.
        let _ = axum::Router::<crate::state::AppState>::new()
            .nest("/api", crate::routes_api::router())
            .merge(super::router());
    }

    #[test]
    fn non_ascii_letters_are_left_alone() {
        let data = json!({ "verified": { "email": "Émile@x.y" } });
        assert!(email_matches(State::Authorized, &data, "Émile@x.y"));
        assert!(!email_matches(State::Authorized, &data, "émile@x.y"));
    }
}
