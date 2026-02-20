use axum::Router;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_cookies::CookieManagerLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod github;
mod routes_api;
mod routes_client;
mod routes_ops;
mod state;
mod storage;

use config::Config;
use state::AppState;
use storage::Storage;

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs_f64()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                "info,hc_auth_server=debug,tower_http=debug".into()
            }),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");
    let port = config.port;
    let host = config.host.clone();
    let production = config.production;

    // Initialize Storage
    let storage = Storage::new(&config)
        .await
        .expect("Failed to initialize storage");

    let http_client = reqwest::Client::new();

    let state = AppState {
        config: Arc::new(config),
        storage: Arc::new(storage),
        http_client,
        pending_auth: Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        csrf_tokens: Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
    };

    // Spawn background cleanup task
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            let now = std::time::Instant::now();
            let ttl = std::time::Duration::from_secs(900); // 15 minutes

            {
                let mut pending = cleanup_state.pending_auth.lock().unwrap();
                pending.retain(|_, v| now.duration_since(v.created_at) < ttl);
            }
            {
                let mut csrf = cleanup_state.csrf_tokens.lock().unwrap();
                csrf.retain(|_, v| now.duration_since(v.created_at) < ttl);
            }
            tracing::debug!("Cleaned up expired CSRF and OAuth tokens");
        }
    });

    // Build our application with a route
    let app = Router::new()
        .merge(routes_client::router())
        .merge(routes_ops::router())
        .nest(
            "/api",
            routes_api::router().layer(axum::middleware::from_fn_with_state(
                state.clone(),
                routes_api::api_auth,
            )),
        )
        // Finally some middleware to handle cookies, and the shared state.
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr).await?;
    let protocol = if production { "https" } else { "http" };
    tracing::info!("listening on {}://{}", protocol, addr);

    axum::serve(listener, app).await?;

    Ok(())
}
