use dotenvy::dotenv;
use oauth2::{ClientId, ClientSecret};
use std::collections::HashSet;
use std::env;

#[derive(Clone)]
pub struct Config {
    pub github_client_id: ClientId,
    pub github_client_secret: ClientSecret,
    pub github_org: String,
    pub github_team: String,
    pub session_secret: Vec<u8>,
    pub host: String,
    pub port: u16,
    pub redis_url: Option<String>,
    pub max_pending_requests: usize,
    pub api_tokens: HashSet<String>,

    /// Number of seconds to allow for clock skew between the server and the client
    pub drift_secs: f64,

    pub production: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenv().ok();

        Ok(Self {
            github_client_id: ClientId::new(env::var("GITHUB_CLIENT_ID")?),
            github_client_secret: ClientSecret::new(env::var(
                "GITHUB_CLIENT_SECRET",
            )?),
            github_org: env::var("GITHUB_ORG")?,
            github_team: env::var("GITHUB_TEAM")?,
            session_secret: env::var("SESSION_SECRET")?.into_bytes(),
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()?,
            redis_url: env::var("REDIS_URL").ok(),
            max_pending_requests: env::var("MAX_PENDING_REQUESTS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()?,
            api_tokens: env::var("API_TOKENS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            drift_secs: env::var("DRIFT_SECS")
                .unwrap_or_else(|_| "300.0".to_string()) // 5 minutes
                .parse()?,
            production: env::var("PRODUCTION")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_parse_api_tokens() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { env::set_var("API_TOKENS", "token1, token2 ,token3,,") };
        let config = Config::from_env().unwrap();
        assert_eq!(config.api_tokens.len(), 3);
        assert!(config.api_tokens.contains("token1"));
        assert!(config.api_tokens.contains("token2"));
        assert!(config.api_tokens.contains("token3"));
        unsafe { env::remove_var("API_TOKENS") };
    }

    #[test]
    fn test_empty_api_tokens() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { env::set_var("API_TOKENS", "") };
        let config = Config::from_env().unwrap();
        assert!(config.api_tokens.is_empty());
        unsafe { env::remove_var("API_TOKENS") };
    }

    #[test]
    fn test_production_flag() {
        let _guard = ENV_MUTEX.lock().unwrap();

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
