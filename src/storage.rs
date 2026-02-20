use crate::config::Config;
use crate::now;
use base64::prelude::*;
use rand::RngCore;
use redis::aio::ConnectionManager;
use redis::{RedisResult, Script};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

// BEGIN NEW REDIS API

const STATE_PENDING: &str = "pending";
const STATE_AUTHORIZED: &str = "authorized";
const STATE_BLOCKED: &str = "blocked";

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
    Other(#[from] Box<dyn std::error::Error>),
}

impl StorageErr {
    /// Wraps an arbitrary error into a `StorageErr::Other`.
    pub fn other<E: Into<Box<dyn std::error::Error>>>(e: E) -> Self {
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

/// Loads and caches the Lua script for adding a pending request.
fn lua_add_pending() -> &'static Script {
    static ADD_PENDING: OnceLock<Script> = OnceLock::new();
    ADD_PENDING.get_or_init(|| Script::new(include_str!("add_pending.lua")))
}

/// Loads and caches the Lua script for transitioning a request between states.
fn lua_transition() -> &'static Script {
    static TRANSITION: OnceLock<Script> = OnceLock::new();
    TRANSITION.get_or_init(|| Script::new(include_str!("transition.lua")))
}

/// Loads and caches the Lua script for deleting a request.
fn lua_delete() -> &'static Script {
    static DELETE: OnceLock<Script> = OnceLock::new();
    DELETE.get_or_init(|| Script::new(include_str!("delete.lua")))
}

/// Formats the Redis key for an authentication record.
fn auth_key(id: &str) -> String {
    format!("auth:{id}")
}

/// Formats the Redis key for a set of IDs in a given state.
fn state_key(state: State) -> String {
    format!("state:{}", state.as_str())
}

/// Returns the current time in seconds as a string.
fn now_secs() -> String {
    (now() as u64).to_string()
}

/// Internal helper to execute the `add_pending` Lua script.
async fn redis_add_pending(
    con: &mut impl redis::aio::ConnectionLike,
    key: &str,
    state: State,
    json: &str,
    max_pending: usize,
) -> RedisResult<()> {
    lua_add_pending()
        .key(auth_key(key))
        .key(state_key(state))
        .arg(key)
        .arg(json)
        .arg(now_secs())
        .arg(max_pending)
        .invoke_async(con)
        .await
}

/// Internal helper to execute the `transition` Lua script.
async fn redis_transition(
    con: &mut impl redis::aio::ConnectionLike,
    key: &str,
    from_state: State,
    to_state: State,
) -> RedisResult<()> {
    lua_transition()
        .key(auth_key(key))
        .key(state_key(from_state))
        .key(state_key(to_state))
        .arg(key)
        .arg(from_state.as_str())
        .arg(to_state.as_str())
        .arg(now_secs())
        .invoke_async(con)
        .await
}

/// Internal helper to execute the `delete` Lua script.
async fn redis_delete(
    con: &mut impl redis::aio::ConnectionLike,
    key: &str,
) -> RedisResult<()> {
    lua_delete()
        .key(auth_key(key))
        .arg(key)
        .invoke_async(con)
        .await
}

// END NEW REDIS API

#[derive(Debug)]
pub struct ObjectRecord {
    pub state: State,
    pub json: String,
}

/// Fetches the state and JSON data for a specific authentication key.
pub async fn redis_get_object(
    con: &mut impl redis::aio::ConnectionLike,
    key: &str,
) -> redis::RedisResult<Option<ObjectRecord>> {
    let key = auth_key(key);

    let (state, json): (Option<String>, Option<String>) = redis::cmd("HMGET")
        .arg(&key)
        .arg("state")
        .arg("json")
        .query_async(con)
        .await?;

    match (state.and_then(|s| State::from_str(&s)), json) {
        (Some(state), Some(json)) => Ok(Some(ObjectRecord { state, json })),
        _ => Ok(None), // not found or partially deleted (shouldn't happen, but safe)
    }
}

/*
pub fn redis_list_all_keys(
    con: &mut dyn redis::ConnectionLike,
) -> RedisResult<HashMap<State, Vec<String>>> {
    let mut result: HashMap<State, Vec<String>> = HashMap::new();

    for state in [State::Pending, State::Authorized, State::Blocked] {
        let members: Vec<String> = redis::cmd("SMEMBERS")
            .arg(state_key(state))
            .query(con)?;

        result.insert(state, members);
    }

    Ok(result)
}
*/

pub struct Storage {
    connection_manager: ConnectionManager,
    max_pending_requests: usize,
}

impl Storage {
    /// Creates a new Storage instance using the provided configuration.
    ///
    /// Initializes a Redis connection manager. Returns an error if Redis is not configured or reachable.
    pub async fn new(
        config: &Config,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let max_pending_requests = config.max_pending_requests;
        if let Some(url) = &config.redis_url {
            let client = redis::Client::open(url.as_str())?;
            let connection_manager = ConnectionManager::new(client).await?;
            Ok(Self {
                connection_manager,
                max_pending_requests,
            })
        } else {
            Err("Redis configuration missing (REDIS_URL)".into())
        }
    }

    /// Helper to execute an async closure with a cloned connection manager.
    async fn with_connection<F, Fut, T>(
        &self,
        mut f: F,
    ) -> Result<T, StorageErr>
    where
        F: FnMut(ConnectionManager) -> Fut,
        Fut: std::future::Future<Output = Result<T, StorageErr>>,
    {
        f(self.connection_manager.clone()).await
    }

    /// Adds a new authentication request to the pending set.
    ///
    /// The `key` is typically the public key. `data` is the associated metadata.
    /// Returns an error if the maximum number of pending requests has been reached.
    pub async fn add_pending_request(
        &self,
        key: &str,
        data: &Value,
    ) -> Result<(), StorageErr> {
        let json_str =
            serde_json::to_string(data).map_err(StorageErr::other)?;

        self.with_connection(|mut con| {
            let json_str = json_str.clone();
            async move {
                redis_add_pending(
                    &mut con,
                    key,
                    State::Pending,
                    &json_str,
                    self.max_pending_requests,
                )
                .await
                .map_err(|e| {
                    if e.to_string().contains("limit_reached") {
                        StorageErr::TooManyPendingRequests
                    } else {
                        e.into()
                    }
                })?;
                Ok(())
            }
        })
        .await
    }

    /// Transitions a pending request to the authorized state.
    pub async fn approve_request(
        &self,
        key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection(|mut con| async move {
            redis_transition(&mut con, key, State::Pending, State::Authorized)
                .await?;
            Ok(())
        })
        .await
        .map_err(Into::into)
    }

    /// Deletes an authentication request from storage.
    pub async fn delete_request(
        &self,
        key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection(|mut con| async move {
            redis_delete(&mut con, key).await?;
            Ok(())
        })
        .await
        .map_err(Into::into)
    }

    /// Returns a map of all currently pending authentication requests.
    pub async fn get_pending_requests(
        &self,
    ) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
        self.get_all_by_state(State::Pending).await
    }

    /// Returns a map of all currently authorized authentication keys.
    pub async fn get_authorized_requests(
        &self,
    ) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
        self.get_all_by_state(State::Authorized).await
    }

    /// Internal helper to fetch all records in a specific state.
    async fn get_all_by_state(
        &self,
        state: State,
    ) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
        self.with_connection(|mut con| async move {
            let keys: Vec<String> = redis::cmd("SMEMBERS")
                .arg(state_key(state))
                .query_async(&mut con)
                .await?;

            let mut result = HashMap::new();
            for key in keys {
                if let Some(record) = redis_get_object(&mut con, &key).await? {
                    let val: Value = serde_json::from_str(&record.json)
                        .unwrap_or(Value::String(record.json));
                    result.insert(key, val);
                }
            }
            Ok(result)
        })
        .await
        .map_err(Into::into)
    }

    /// Validates an authorized key and returns an authentication token.
    ///
    /// If successful, updates the `lastAccess` timestamp and generates a new `authToken` if one doesn't exist.
    pub async fn authenticate_key(
        &self,
        key: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        self.with_connection(|mut con| async move {
            if let Some(record) = redis_get_object(&mut con, key).await? {
                if record.state != State::Authorized {
                    return Ok(None);
                }

                let mut json_val: Value = serde_json::from_str(&record.json)
                    .map_err(|e| {
                        redis::RedisError::from((
                            redis::ErrorKind::TypeError,
                            "Failed to parse JSON",
                            e.to_string(),
                        ))
                    })?;

                let now = now_secs();
                if let Some(obj) = json_val.as_object_mut() {
                    obj.insert(
                        "lastAccess".to_string(),
                        serde_json::Value::String(now.clone()),
                    );

                    let token = if let Some(t) =
                        obj.get("authToken").and_then(|v| v.as_str())
                    {
                        t.to_string()
                    } else {
                        let mut token_bytes = [0u8; 32];
                        rand::rng().fill_bytes(&mut token_bytes);
                        let new_token =
                            BASE64_URL_SAFE_NO_PAD.encode(token_bytes);
                        obj.insert(
                            "authToken".to_string(),
                            serde_json::Value::String(new_token.clone()),
                        );
                        new_token
                    };

                    let new_json_str =
                        serde_json::to_string(&json_val).unwrap();

                    // Update the object hash directly
                    let _: () = redis::cmd("HSET")
                        .arg(auth_key(key))
                        .arg("json")
                        .arg(new_json_str)
                        .arg("updated")
                        .arg(now)
                        .query_async(&mut con)
                        .await?;

                    Ok(Some(token))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
        .await
        .map_err(Into::into)
    }
}
