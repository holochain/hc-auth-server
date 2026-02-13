use askama::Template;
use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Redirect},
};
use oauth2::{
    AuthUrl, AuthorizationCode, CsrfToken, RedirectUrl, Scope, TokenResponse,
    TokenUrl, basic::BasicClient,
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
}

#[derive(Deserialize)]
pub struct ApproveRequest {
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub code: String,
}

pub async fn ops_home(
    cookies: Cookies,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let key = tower_cookies::Key::from(&state.session_secret);
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
    let key = tower_cookies::Key::from(&state.session_secret);
    let signed_cookies = cookies.signed(&key);

    if let Some(cookie) = signed_cookies.get("user_session") {
        let authorized_map =
            state.storage.get_authorized_requests().unwrap_or_default();
        let pending_map =
            state.storage.get_pending_requests().unwrap_or_default();

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
    let key = tower_cookies::Key::from(&state.session_secret);
    let signed_cookies = cookies.signed(&key);

    if signed_cookies.get("user_session").is_none() {
        return Redirect::to("/").into_response();
    }

    if let Err(e) = state.storage.approve_request(&form.key) {
        tracing::error!("Failed to approve request: {}", e);
    }

    Redirect::to("/ops-auth").into_response()
}

pub async fn ops_reject(
    State(state): State<SharedState>,
    cookies: Cookies,
    Form(form): Form<ApproveRequest>,
) -> impl IntoResponse {
    let key = tower_cookies::Key::from(&state.session_secret);
    let signed_cookies = cookies.signed(&key);

    if signed_cookies.get("user_session").is_none() {
        return Redirect::to("/").into_response();
    }

    if let Err(e) = state.storage.delete_request(&form.key) {
        tracing::error!("Failed to reject request: {}", e);
    }

    Redirect::to("/ops-auth").into_response()
}

pub async fn ops_logout(
    cookies: Cookies,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let key = tower_cookies::Key::from(&state.session_secret);
    let signed_cookies = cookies.signed(&key);
    // To remove, we generally just remove the cooking or overwrite with max-age 0
    let mut cookie = tower_cookies::Cookie::new("user_session", "");
    cookie.set_path("/");
    signed_cookies.remove(cookie);

    Redirect::to("/")
}

pub async fn ops_oauth_login(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let client_id = state.github_client_id.clone();
    let client_secret = state.github_client_secret.clone();
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
            "http://{}:{}/ops-oauth-callback",
            state.host, state.port
        ))
        .expect("Invalid redirect URL"),
    );

    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read:org".to_string())) // Need read:org to check team membership
        .url();

    Redirect::to(auth_url.as_str())
}

pub async fn ops_oauth_callback(
    State(state): State<SharedState>,
    cookies: Cookies,
    Query(query): Query<AuthRequest>,
) -> impl IntoResponse {
    let client_id = state.github_client_id.clone();
    let client_secret = state.github_client_secret.clone();
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
            "http://{}:{}/ops-oauth-callback",
            state.host, state.port
        ))
        .expect("Invalid redirect URL"),
    );

    // Exchange the code with a token.
    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
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
                .is_team_member(&state.github_org, &state.github_team)
                .await
            {
                Ok(true) => {
                    // Valid member!
                    if let Ok(user) = gh_client.get_user().await {
                        let mut cookie =
                            Cookie::new("user_session", user.login);
                        cookie.set_path("/");
                        cookie.set_http_only(true);

                        let key =
                            tower_cookies::Key::from(&state.session_secret);
                        cookies.signed(&key).add(cookie);
                        tracing::info!(
                            "User authenticated and verified in team."
                        );
                    }
                    Redirect::to("/")
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
                                t.organization.login == state.github_org
                            })
                            .collect();
                        tracing::debug!(
                            "DEBUG: Teams found in org '{}': {:?}",
                            state.github_org,
                            org_teams
                        );
                    } else {
                        tracing::debug!("DEBUG: Failed to list user teams.");
                    }

                    Redirect::to("/?error=access_denied")
                }
                Err(e) => {
                    tracing::error!("Failed to verify team membership: {}", e);
                    Redirect::to("/?error=verification_failed")
                }
            }
        }
        Err(e) => {
            tracing::error!("Token exchange failed: {}", e);
            Redirect::to("/")
        }
    }
}
