use crate::now;
use crate::state::AppState as SharedState;
use crate::storage::StorageErr;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::get,
};

/// Returns the router for client-facing endpoints.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/now", get(now_handler))
        .route("/request-auth/{key}", axum::routing::put(request_auth))
        .route("/authenticate", axum::routing::put(authenticate))
}
use base64::prelude::*;
use ed25519_dalek::{Signature, VerifyingKey};

/// GET /now - Returns the current server time and a random nonce, base64url encoded.
///
/// Used by clients to construct a signed payload for authentication.
pub async fn now_handler() -> impl IntoResponse {
    use rand::prelude::*;

    // Current time as f64 seconds since epoch
    let now = now();

    let mut buf = [0u8; 32];

    // First 8 bytes: timestamp (f64 LE)
    buf[..8].copy_from_slice(&now.to_le_bytes());

    // Remaining 24 bytes: random
    // this is a nonce to add security to the signatures
    // while not strictly needed, it can't hurt
    rand::rng().fill_bytes(&mut buf[8..]);

    BASE64_URL_SAFE_NO_PAD.encode(buf).into_response()
}

/// PUT /request-auth/{key} - Registers a new pending authentication request.
///
/// `key` should be the base64url encoded public key. The request body should be a JSON object with metadata.
pub async fn request_auth(
    State(state): State<SharedState>,
    Path(key): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    if validate_pubkey(&key).is_err() {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    let payload = serde_json::json!({
        "createdAt": now(),
        "lastAccess": now(),
        "payload": payload,
    });

    match state.storage.add_pending_request(&key, &payload).await {
        Err(StorageErr::TooManyPendingRequests) => {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "Pending request limit reached",
            )
                .into_response();
        }
        Err(err) => {
            tracing::error!("Failed to set auth data: {}", err);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to store data",
            )
                .into_response();
        }
        Ok(_) => (),
    }

    (axum::http::StatusCode::OK, "OK").into_response()
}

/// PUT /authenticate - Validates a signed authentication request and returns a token.
///
/// Requires `Content-Type: application/octet-stream`. The body should be a JSON string.
/// If successful and approved, returns an `authToken`.
pub async fn authenticate(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Check Content-Type
    if let Some(ct) = headers.get("content-type") {
        if ct != "application/octet-stream" {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
    } else {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    // Parse bytes as UTF-8
    let body_str = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(_) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };

    // Parse as JSON
    let json_val: serde_json::Value = match serde_json::from_str(&body_str) {
        Ok(j) => j,
        Err(_) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };

    let signature = json_val.get("signature").and_then(|v| v.as_str());
    let payload = json_val.get("payload").and_then(|v| v.as_str());

    // Check pubKey
    if let Some(pub_key) = json_val.get("pubKey").and_then(|v| v.as_str()) {
        if validate_pubkey(pub_key).is_err() {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
        if let (Some(sig), Some(pay)) = (signature, payload) {
            if validate_signature(state.config.drift_secs, pub_key, sig, pay)
                .is_err()
            {
                return axum::http::StatusCode::UNAUTHORIZED.into_response();
            }
        } else {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
        match state.storage.authenticate_key(pub_key).await {
            Ok(crate::storage::AuthResult::Authorized(token)) => {
                let resp = serde_json::json!({ "authToken": token });
                (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    Json(resp),
                )
                    .into_response()
            }
            Ok(crate::storage::AuthResult::Pending) => {
                axum::http::StatusCode::ACCEPTED.into_response()
            }
            Ok(_) => axum::http::StatusCode::UNAUTHORIZED.into_response(),
            Err(e) => {
                tracing::error!("Auth error: {}", e);
                axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        axum::http::StatusCode::UNAUTHORIZED.into_response()
    }
}

/// Validates that a string is a valid base64url encoded 32-byte public key.
fn validate_pubkey(pk: &str) -> Result<(), ()> {
    let pk = BASE64_URL_SAFE_NO_PAD.decode(pk).map_err(|_| ())?;
    if pk.len() != 32 {
        return Err(());
    }
    Ok(())
}

/// Verifies an Ed25519 signature over a payload.
///
/// Ensures the payload timestamp is within the allowed `drift_secs`.
fn validate_signature(
    drift_secs: f64,
    base64_url_encoded_pubkey: &str,
    base64_url_encoded_signature: &str,
    base64_url_encoded_payload: &str,
) -> Result<(), ()> {
    // Decode inputs
    let pubkey_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(base64_url_encoded_pubkey)
        .map_err(|_| ())?;

    let sig_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(base64_url_encoded_signature)
        .map_err(|_| ())?;

    let payload_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(base64_url_encoded_payload)
        .map_err(|_| ())?;

    if payload_bytes.len() != 32 {
        return Err(());
    }

    // Extract timestamp
    let ts_bytes: [u8; 8] = payload_bytes[..8].try_into().map_err(|_| ())?;
    let timestamp = f64::from_le_bytes(ts_bytes);

    let now = now();

    if timestamp > now + drift_secs {
        return Err(());
    }

    if timestamp < now - drift_secs {
        return Err(());
    }

    // Parse key and signature
    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_bytes.try_into().map_err(|_| ())?)
            .map_err(|_| ())?;

    let signature =
        Signature::from_bytes(&sig_bytes.try_into().map_err(|_| ())?);

    // Verify
    verifying_key
        .verify_strict(&payload_bytes, &signature)
        .map_err(|_| ())?;

    Ok(())
}
