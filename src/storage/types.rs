use redis::aio::ConnectionManager;

pub const STATE_PENDING: &str = "pending";
pub const STATE_AUTHORIZED: &str = "authorized";
pub const STATE_BLOCKED: &str = "blocked";

/// Storage error type.
#[derive(Debug, thiserror::Error)]
pub enum StorageErr {
    /// Too many pending requests.
    #[error("Too many pending requests")]
    TooManyPendingRequests,

    /// Redis error.
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    /// Other error.
    #[error("Other error: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl StorageErr {
    /// Wraps an arbitrary error into a `StorageErr::Other`.
    pub fn other<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        e: E,
    ) -> Self {
        Self::Other(e.into())
    }
}

/// Authorization Key State
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Pending,
    Authorized,
    Blocked,
}

impl State {
    /// Parses a string into a `State`.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            STATE_PENDING => Some(Self::Pending),
            STATE_AUTHORIZED => Some(Self::Authorized),
            STATE_BLOCKED => Some(Self::Blocked),
            _ => None,
        }
    }

    /// Returns the string representation of the `State`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => STATE_PENDING,
            Self::Authorized => STATE_AUTHORIZED,
            Self::Blocked => STATE_BLOCKED,
        }
    }
}

/// Result of an authentication attempt.
pub enum AuthResult {
    /// Key is authorized and a token is returned.
    Authorized(String),
    /// Key is still in pending status.
    Pending,
    /// Key is blocked.
    Blocked,
    /// Key not found.
    NotFound,
}

#[derive(Debug)]
pub(crate) struct ObjectRecord {
    pub(crate) state: State,
    pub(crate) json: String,
}

pub struct Storage {
    pub(crate) connection_manager: ConnectionManager,
    pub(crate) max_pending_requests: usize,
}
