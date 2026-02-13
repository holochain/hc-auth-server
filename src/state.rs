use crate::config::Config;
use crate::storage::Storage;
use std::ops::Deref;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub storage: Arc<Storage>,
    pub http_client: reqwest::Client,
}

impl Deref for AppState {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}
