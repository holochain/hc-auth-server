use axum::Router;
use axum_server::tls_rustls::RustlsAcceptor;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_cookies::CookieManagerLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use hc_auth_server::{
    AppState, Config, Storage, routes_api, routes_client, routes_ops,
};

/// Main entry point for the authentication server.
///
/// Initializes configuration, storage, tracing, and starts the Axum web server.
/// Also spawns a background thread for cleaning up expired tokens.
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

    // Install the default rustls crypto provider. This must happen before any
    // TLS connections are established (including Redis/Valkey with `rediss://`).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to configure default TLS provider");

    // Load configuration
    let mut config = Config::from_env().expect("Failed to load configuration");
    let port = config.port;
    let host = config.host.clone();
    let tls_config = config.tls_config.take();

    // If TLS is enabled, ensure production mode is set so handlers use
    // secure cookies and the https scheme.
    if tls_config.is_some() && !config.production {
        tracing::warn!(
            "TLS is enabled but PRODUCTION is not set to true, forcing production mode. Please set PRODUCTION=true in your configuration."
        );
        config.production = true;
    }

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
    let protocol = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };
    tracing::info!("listening on {}://{}", protocol, addr);

    if let Some(tls_config) = tls_config {
        let rustls_config = tls_config
            .create_tls_config()
            .await
            .expect("Failed to create TLS config");

        tokio::spawn(tls_config.reload_task(rustls_config.clone()));

        let acceptor = RustlsAcceptor::new(rustls_config);
        axum_server::Server::from_tcp(listener.into_std()?)
            .acceptor(acceptor)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        axum::serve(listener, app).await?;
    }

    Ok(())
}
