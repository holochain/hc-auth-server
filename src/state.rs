use crate::config::Config;
use crate::storage::Storage;
use oauth2::{CsrfToken, PkceCodeVerifier};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct PendingAuth {
    pub state: CsrfToken,
    pub pkce_verifier: PkceCodeVerifier,
    pub created_at: Instant,
}

pub struct CsrfTokenEntry {
    pub token: String,
    pub created_at: Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub storage: Arc<Storage>,
    pub http_client: reqwest::Client,
    pub pending_auth: Arc<Mutex<HashMap<String, PendingAuth>>>,
    pub csrf_tokens: Arc<Mutex<HashMap<String, CsrfTokenEntry>>>,
}
