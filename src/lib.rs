pub mod config;
pub mod github;
pub mod routes_api;
pub mod routes_client;
pub mod routes_ops;
pub mod state;
pub mod storage;
pub mod tls;

pub use config::Config;
pub use state::AppState;
pub use storage::Storage;
pub use tls::TlsConfig;

/// Returns the current unix timestamp in seconds.
pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs_f64()
}
