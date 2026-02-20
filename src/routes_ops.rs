use askama::Template;
use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Redirect},
};
use oauth2::{
    AuthUrl, AuthorizationCode, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl, basic::BasicClient,
};
use serde::Deserialize;
use std::collections::HashMap;
use tower_cookies::{Cookie, Cookies};

use crate::github::GitHubClient;
use crate::state::AppState as SharedState;

#[derive(Template)]
#[template(path = "home.html")]
pub struct HomeTemplate {
    pub logged_in: bool,
    pub username: Option<String>,
}

#[derive(Template)]
#[template(path = "protected.html")]
pub struct ProtectedTemplate {
    pub username: String,
    pub authorized_keys: Vec<String>,
    pub unauthorized_keys: Vec<String>,
    pub view_key: Option<String>,
    pub current_value: Option<String>,
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct ApproveRequest {
    pub key: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub code: String,
    pub state: String,
}

pub async fn ops_home(
    cookies: Cookies,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let key = tower_cookies::Key::from(&state.config.session_secret);
    let signed_cookies = cookies.signed(&key);
    let user_session = signed_cookies.get("user_session");

    let (logged_in, username) = match user_session {
        Some(cookie) => (true, Some(cookie.value().to_string())),
        None => (false, None),
    };

    let template = HomeTemplate {
        logged_in,
        username,
    };

    template.render().map(Html).map_err(|e| {
        tracing::error!("Template render error: {}", e);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })
}

pub async fn ops_auth(
    cookies: Cookies,
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let key = tower_cookies::Key::from(&state.config.session_secret);
    let signed_cookies = cookies.signed(&key);

    if let Some(cookie) = signed_cookies.get("user_session") {
        let username = cookie.value().to_string();

        // Handle CSRF token for the session
        let csrf_token = {
            let mut csrf_tokens = state.csrf_tokens.lock().unwrap();
            let entry =
                csrf_tokens.entry(username.clone()).or_insert_with(|| {
                    crate::state::CsrfTokenEntry {
                        token: rand::random::<u64>().to_string(),
                        created_at: std::time::Instant::now(),
                    }
                });
            // Update timestamp on access
            entry.created_at = std::time::Instant::now();
            entry.token.clone()
        };

        let authorized_map = state
            .storage
            .get_authorized_requests()
            .await
            .unwrap_or_default();
        let pending_map = state
            .storage
            .get_pending_requests()
            .await
            .unwrap_or_default();

        let mut authorized_keys: Vec<String> =
            authorized_map.keys().cloned().collect();
        let mut unauthorized_keys: Vec<String> =
            pending_map.keys().cloned().collect();

        authorized_keys.sort();
        unauthorized_keys.sort();

        let view_key = params.get("view_key").cloned();

        let mut current_value = None;
        if let Some(k) = &view_key {
            // Check auth first, then pending
            if let Some(val) = authorized_map.get(k) {
                current_value = Some(
                    serde_json::to_string_pretty(val)
                        .unwrap_or_else(|_| val.to_string()),
                );
            } else if let Some(val) = pending_map.get(k) {
                current_value = Some(
                    serde_json::to_string_pretty(val)
                        .unwrap_or_else(|_| val.to_string()),
                );
            }
        }

        let template = ProtectedTemplate {
            username: cookie.value().to_string(),
            authorized_keys,
            unauthorized_keys,
            view_key,
            current_value,
            csrf_token,
        };
        template
            .render()
            .map(Html)
            .map_err(|e| {
                tracing::error!("Template render error: {}", e);
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            })
            .into_response()
    } else {
        Redirect::to("/").into_response()
    }
}

pub async fn ops_approve(
    State(state): State<SharedState>,
    cookies: Cookies,
    Form(form): Form<ApproveRequest>,
) -> impl IntoResponse {
    let key = tower_cookies::Key::from(&state.config.session_secret);
    let signed_cookies = cookies.signed(&key);

    if let Some(cookie) = signed_cookies.get("user_session") {
        let username = cookie.value().to_string();
        let expected_token = {
            let csrf_tokens = state.csrf_tokens.lock().unwrap();
            csrf_tokens.get(&username).map(|e| e.token.clone())
        };

        if expected_token.is_none()
            || expected_token.unwrap() != form.csrf_token
        {
            tracing::warn!(
                "CSRF token mismatch on approve for user: {}",
                username
            );
            return Redirect::to("/ops-auth?error=invalid_csrf")
                .into_response();
        }
    } else {
        return Redirect::to("/").into_response();
    }

    if let Err(e) = state.storage.approve_request(&form.key).await {
        tracing::error!("Failed to approve request: {}", e);
    }

    Redirect::to("/ops-auth").into_response()
}

pub async fn ops_reject(
    State(state): State<SharedState>,
    cookies: Cookies,
    Form(form): Form<ApproveRequest>,
) -> impl IntoResponse {
    let key = tower_cookies::Key::from(&state.config.session_secret);
    let signed_cookies = cookies.signed(&key);

    if let Some(cookie) = signed_cookies.get("user_session") {
        let username = cookie.value().to_string();
        let expected_token = {
            let csrf_tokens = state.csrf_tokens.lock().unwrap();
            csrf_tokens.get(&username).map(|e| e.token.clone())
        };

        if expected_token.is_none()
            || expected_token.unwrap() != form.csrf_token
        {
            tracing::warn!(
                "CSRF token mismatch on reject for user: {}",
                username
            );
            return Redirect::to("/ops-auth?error=invalid_csrf")
                .into_response();
        }
    } else {
        return Redirect::to("/").into_response();
    }

    if let Err(e) = state.storage.delete_request(&form.key).await {
        tracing::error!("Failed to reject request: {}", e);
    }

    Redirect::to("/ops-auth").into_response()
}

pub async fn ops_logout(
    cookies: Cookies,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let key = tower_cookies::Key::from(&state.config.session_secret);
    let signed_cookies = cookies.signed(&key);
    // To remove, we generally just remove the cooking or overwrite with max-age 0
    let mut cookie = tower_cookies::Cookie::new("user_session", "");
    cookie.set_path("/");
    if state.config.production {
        cookie.set_secure(true);
    }
    signed_cookies.remove(cookie);

    Redirect::to("/")
}

pub async fn ops_oauth_login(
    cookies: Cookies,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let client_id = state.config.github_client_id.clone();
    let client_secret = state.config.github_client_secret.clone();
    let auth_url =
        AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
            .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new(
        "https://github.com/login/oauth/access_token".to_string(),
    )
    .expect("Invalid token endpoint URL");

    let client = BasicClient::new(
        client_id,
        Some(client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(
        RedirectUrl::new(format!(
            "{}://{}:{}/ops-oauth-callback",
            if state.config.production {
                "https"
            } else {
                "http"
            },
            state.config.host,
            state.config.port
        ))
        .expect("Invalid redirect URL"),
    );

    // Proper PKCE setup: generate both the challenge and verifier at once
    let (pkce_challenge, pkce_verifier) =
        PkceCodeChallenge::new_random_sha256();
    let csrf_token = CsrfToken::new_random();

    let (auth_url, csrf_token) = client
        .authorize_url(|| csrf_token)
        .set_pkce_challenge(pkce_challenge)
        .add_scope(Scope::new("read:org".to_string()))
        .url();

    // Store the state and verifier in AppState
    let csrf_id = rand::random::<u64>().to_string();
    {
        let mut pending = state.pending_auth.lock().unwrap();
        pending.insert(
            csrf_id.clone(),
            crate::state::PendingAuth {
                state: csrf_token,
                pkce_verifier,
                created_at: std::time::Instant::now(),
            },
        );
    }

    // Set csrf_id cookie
    let mut cookie = Cookie::new("csrf_id", csrf_id.clone());
    cookie.set_path("/");
    cookie.set_http_only(true);
    if state.config.production {
        cookie.set_secure(true);
    }
    let key = tower_cookies::Key::from(&state.config.session_secret);
    cookies.signed(&key).add(cookie);

    Redirect::to(auth_url.as_str())
}

pub async fn ops_oauth_callback(
    State(state): State<SharedState>,
    cookies: Cookies,
    Query(query): Query<AuthRequest>,
) -> impl IntoResponse {
    let client_id = state.config.github_client_id.clone();
    let client_secret = state.config.github_client_secret.clone();
    let auth_url =
        AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
            .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new(
        "https://github.com/login/oauth/access_token".to_string(),
    )
    .expect("Invalid token endpoint URL");

    let client = BasicClient::new(
        client_id,
        Some(client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(
        RedirectUrl::new(format!(
            "{}://{}:{}/ops-oauth-callback",
            if state.config.production {
                "https"
            } else {
                "http"
            },
            state.config.host,
            state.config.port
        ))
        .expect("Invalid redirect URL"),
    );

    // Verify CSRF state and PKCE verifier
    let key = tower_cookies::Key::from(&state.config.session_secret);
    let signed_cookies = cookies.signed(&key);
    let csrf_id = match signed_cookies.get("csrf_id") {
        Some(c) => c.value().to_string(),
        None => {
            tracing::warn!("Missing csrf_id cookie");
            return Redirect::to("/?error=missing_csrf").into_response();
        }
    };

    let pending_auth = {
        let mut pending = state.pending_auth.lock().unwrap();
        pending.remove(&csrf_id)
    };

    let pending_auth = match pending_auth {
        Some(p) => p,
        None => {
            tracing::warn!("No pending auth found for csrf_id");
            return Redirect::to("/?error=invalid_csrf").into_response();
        }
    };

    if pending_auth.state.secret() != &query.state {
        tracing::warn!("CSRF state mismatch");
        return Redirect::to("/?error=state_mismatch").into_response();
    }

    // Exchange the code with a token.
    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .set_pkce_verifier(pending_auth.pkce_verifier)
        .request_async(oauth2::reqwest::async_http_client)
        .await;

    match token_result {
        Ok(token) => {
            let access_token = token.access_token().secret();

            let gh_client = GitHubClient::new(
                state.http_client.clone(),
                access_token.clone(),
            );

            // Check team membership
            match gh_client
                .is_team_member(
                    &state.config.github_org,
                    &state.config.github_team,
                )
                .await
            {
                Ok(true) => {
                    // Valid member!
                    if let Ok(user) = gh_client.get_user().await {
                        let mut cookie =
                            Cookie::new("user_session", user.login);
                        cookie.set_path("/");
                        cookie.set_http_only(true);
                        if state.config.production {
                            cookie.set_secure(true);
                        }

                        let key = tower_cookies::Key::from(
                            &state.config.session_secret,
                        );
                        cookies.signed(&key).add(cookie);
                        tracing::info!(
                            "User authenticated and verified in team."
                        );
                    }
                    Redirect::to("/").into_response()
                }
                Ok(false) => {
                    tracing::warn!(
                        "User authenticated but NOT a member of the required team."
                    );

                    // DEBUGGING: List user's teams to help troubleshoot
                    if let Ok(teams) = gh_client.list_user_teams().await {
                        tracing::debug!("DEBUG: User's teams: {:?}", teams);
                        // Filter teams that belong to the configured org
                        let org_teams: Vec<_> = teams
                            .iter()
                            .filter(|t| {
                                t.organization.login == state.config.github_org
                            })
                            .collect();
                        tracing::debug!(
                            "DEBUG: Teams found in org '{}': {:?}",
                            state.config.github_org,
                            org_teams
                        );
                    } else {
                        tracing::debug!("DEBUG: Failed to list user teams.");
                    }

                    Redirect::to("/?error=access_denied").into_response()
                }
                Err(e) => {
                    tracing::error!("Failed to verify team membership: {}", e);
                    Redirect::to("/?error=verification_failed").into_response()
                }
            }
        }
        Err(e) => {
            tracing::error!("Token exchange failed: {}", e);
            Redirect::to("/").into_response()
        }
    }
}
