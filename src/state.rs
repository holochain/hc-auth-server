use crate::config::Config;
use crate::storage::Storage;
use oauth2::{CsrfToken, PkceCodeVerifier};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Stores pending authentication request data for the OAuth flow.
pub struct PendingAuth {
    /// OAuth CSRF token.
    pub state: CsrfToken,
    /// PKCE verifier for secure token exchange.
    pub pkce_verifier: PkceCodeVerifier,
    /// When the request was initiated.
    pub created_at: Instant,
}

/// Stores a CSRF token for защищенных (protected) forms.
pub struct CsrfTokenEntry {
    /// The CSRF token string.
    pub token: String,
    /// When the token was created.
    pub created_at: Instant,
}

/// Global shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Server configuration.
    pub config: Arc<Config>,
    /// Redis storage interface.
    pub storage: Arc<Storage>,
    /// Shared HTTP client.
    pub http_client: reqwest::Client,
    /// In-memory map of pending OAuth requests.
    pub pending_auth: Arc<Mutex<HashMap<String, PendingAuth>>>,
    /// In-memory map of active CSRF tokens for the web UI.
    pub csrf_tokens: Arc<Mutex<HashMap<String, CsrfTokenEntry>>>,
}
