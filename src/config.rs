use dotenvy::dotenv;
use oauth2::{ClientId, ClientSecret, RedirectUrl};
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;

use crate::tls::TlsConfig;

/// Configuration for the authentication server.
#[derive(Clone)]
pub struct Config {
    /// GitHub OAuth client ID.
    pub github_client_id: ClientId,
    /// GitHub OAuth client secret.
    pub github_client_secret: ClientSecret,
    /// GitHub organization allowed to access the admin interface.
    pub github_org: String,
    /// GitHub team within the organization allowed to access the admin interface.
    pub github_team: String,
    /// Secret key used for session cookie encryption.
    pub session_secret: Vec<u8>,
    /// The URI to redirect users to after successful authentication (e.g., admin interface).
    ///
    /// If not set, the application will attempt to construct the redirect URI based on the host and port configuration.
    /// The default is unlikely to work if the server is deployed behind a proxy and is using a different external URL!
    pub redirect_uri: Option<String>,
    /// Host address to bind the server to.
    pub host: String,
    /// Port number to bind the server to.
    pub port: u16,
    /// Redis connection URL.
    pub redis_url: Option<String>,
    /// Maximum number of pending authentication requests allowed in Redis.
    pub max_pending_requests: usize,
    /// Set of valid API tokens for system administration.
    pub api_tokens: HashSet<String>,
    /// Set of tokens that may call `/api/confirm-email` and nothing else.
    pub confirm_tokens: HashSet<String>,
    /// How many `/api/confirm-email` calls one token may make per minute.
    pub confirm_rate_per_token: u64,
    /// How many `/api/confirm-email` calls may ask about one key per minute.
    pub confirm_rate_per_key: u64,

    /// Number of seconds to allow for clock skew between the server and the client.
    pub drift_secs: f64,

    /// Whether the server is running in production mode (enables HTTPS/Secure cookies).
    pub production: bool,

    /// Optional TLS configuration for serving over HTTPS.
    pub tls_config: Option<TlsConfig>,
}

impl Config {
    /// Loads configuration from environment variables.
    ///
    /// Reads from `.env` file if present, then environment variables.
    /// Returns an error if any required variable is missing or invalid.
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenv().ok();

        let redirect_uri = match env::var("REDIRECT_URI")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            Some(uri) => {
                RedirectUrl::new(uri.clone())
                    .map_err(|e| format!("Invalid REDIRECT_URI: {e}"))?;
                Some(uri)
            }
            None => None,
        };

        Ok(Self {
            github_client_id: ClientId::new(env::var("GITHUB_CLIENT_ID")?),
            github_client_secret: ClientSecret::new(env::var(
                "GITHUB_CLIENT_SECRET",
            )?),
            github_org: env::var("GITHUB_ORG")?,
            github_team: env::var("GITHUB_TEAM")?,
            session_secret: env::var("SESSION_SECRET")?.into_bytes(),
            redirect_uri,
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()?,
            redis_url: env::var("REDIS_URL").ok(),
            max_pending_requests: env::var("MAX_PENDING_REQUESTS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()?,
            api_tokens: parse_tokens("API_TOKENS"),
            confirm_tokens: parse_tokens("CONFIRM_TOKENS"),
            confirm_rate_per_token: env::var("CONFIRM_RATE_PER_TOKEN")
                .unwrap_or_else(|_| "600".to_string())
                .parse()?,
            confirm_rate_per_key: env::var("CONFIRM_RATE_PER_KEY")
                .unwrap_or_else(|_| "30".to_string())
                .parse()?,
            drift_secs: env::var("DRIFT_SECS")
                .unwrap_or_else(|_| "300.0".to_string()) // 5 minutes
                .parse()?,
            production: match env::var("PRODUCTION") {
                Ok(v) => v.parse()?,
                Err(_) => false,
            },
            tls_config: match (
                env::var("TLS_CERT").ok().map(PathBuf::from),
                env::var("TLS_KEY").ok().map(PathBuf::from),
            ) {
                (Some(cert), Some(key)) => Some(TlsConfig::new(cert, key)),
                (None, None) => None,
                _ => {
                    return Err(
                        "Both TLS_CERT and TLS_KEY must be set, or neither"
                            .into(),
                    );
                }
            },
        })
    }
}

/// Reads a comma separated token list from the named environment variable.
///
/// Tokens are trimmed and empty entries are dropped, so a trailing comma
/// is harmless. A missing variable yields an empty set.
fn parse_tokens(var: &str) -> HashSet<String> {
    env::var(var)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    struct EnvGuard<'a> {
        _guard: std::sync::MutexGuard<'a, ()>,
    }

    impl<'a> Drop for EnvGuard<'a> {
        fn drop(&mut self) {
            unsafe {
                env::remove_var("API_TOKENS");
                env::remove_var("CONFIRM_TOKENS");
                env::remove_var("CONFIRM_RATE_PER_TOKEN");
                env::remove_var("CONFIRM_RATE_PER_KEY");
                env::remove_var("GITHUB_CLIENT_ID");
                env::remove_var("GITHUB_CLIENT_SECRET");
                env::remove_var("GITHUB_ORG");
                env::remove_var("GITHUB_TEAM");
                env::remove_var("SESSION_SECRET");
                env::remove_var("PRODUCTION");
            };
        }
    }

    impl<'a> EnvGuard<'a> {
        fn new() -> Self {
            let this = Self {
                _guard: ENV_MUTEX.lock().unwrap(),
            };
            unsafe {
                env::set_var("GITHUB_CLIENT_ID", "test-client-id");
                env::set_var("GITHUB_CLIENT_SECRET", "test-client-secret");
                env::set_var("GITHUB_ORG", "test-org");
                env::set_var("GITHUB_TEAM", "test-team");
                env::set_var("SESSION_SECRET", "test-session-secret");
            }

            this
        }
    }

    #[test]
    fn test_parse_api_tokens() {
        let _guard = EnvGuard::new();
        unsafe { env::set_var("API_TOKENS", "token1, token2 ,token3,,") };
        let config = Config::from_env().unwrap();
        assert_eq!(config.api_tokens.len(), 3);
        assert!(config.api_tokens.contains("token1"));
        assert!(config.api_tokens.contains("token2"));
        assert!(config.api_tokens.contains("token3"));
        unsafe { env::remove_var("API_TOKENS") };
    }

    #[test]
    fn test_parse_confirm_tokens() {
        let _guard = EnvGuard::new();
        unsafe { env::set_var("CONFIRM_TOKENS", " c1, c2 ,,") };
        let config = Config::from_env().unwrap();
        assert_eq!(config.confirm_tokens.len(), 2);
        assert!(config.confirm_tokens.contains("c1"));
        assert!(config.confirm_tokens.contains("c2"));
        assert!(config.api_tokens.is_empty());
    }

    #[test]
    fn test_confirm_rate_defaults() {
        let _guard = EnvGuard::new();
        let config = Config::from_env().unwrap();
        assert_eq!(config.confirm_rate_per_token, 600);
        assert_eq!(config.confirm_rate_per_key, 30);
    }

    #[test]
    fn test_confirm_rate_overrides() {
        let _guard = EnvGuard::new();
        unsafe {
            env::set_var("CONFIRM_RATE_PER_TOKEN", "10");
            env::set_var("CONFIRM_RATE_PER_KEY", "2");
        }
        let config = Config::from_env().unwrap();
        assert_eq!(config.confirm_rate_per_token, 10);
        assert_eq!(config.confirm_rate_per_key, 2);
    }

    #[test]
    fn test_empty_api_tokens() {
        let _guard = EnvGuard::new();
        unsafe { env::set_var("API_TOKENS", "") };
        let config = Config::from_env().unwrap();
        assert!(config.api_tokens.is_empty());
        unsafe { env::remove_var("API_TOKENS") };
    }

    #[test]
    fn test_production_flag() {
        let _guard = EnvGuard::new();

        unsafe { env::set_var("PRODUCTION", "true") };
        let config = Config::from_env().unwrap();
        assert!(config.production);

        unsafe { env::set_var("PRODUCTION", "false") };
        let config = Config::from_env().unwrap();
        assert!(!config.production);

        unsafe { env::remove_var("PRODUCTION") };
        let config = Config::from_env().unwrap();
        assert!(!config.production);
    }
}
