use crate::config::Config;
use base64::prelude::*;
use rand::RngCore;
use redis::aio::ConnectionManager;
use serde_json::Value;
use std::collections::HashMap;

mod lua;
mod types;

use types::ObjectRecord;
pub use types::{AuthResult, State, Storage, StorageErr};

/// Helper to parse a JSON string into a `Value`, falling back to a string value if parsing fails.
fn parse_value(json: &str) -> Value {
    serde_json::from_str(json).unwrap_or(Value::String(json.to_string()))
}

/// Formats the Redis key for an authentication record.
pub(crate) fn auth_key(id: &str) -> String {
    format!("auth:{id}")
}

/// Formats the Redis key for a set of IDs in a given state.
pub(crate) fn state_key(state: State) -> String {
    format!("state:{}", state.as_str())
}

/// Returns the current time in seconds as a string.
pub(crate) fn now_secs() -> String {
    (crate::now() as u64).to_string()
}

/// Fetches the state and JSON data for a specific authentication key.
async fn redis_get_object(
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
        _ => Ok(None),
    }
}

impl Storage {
    /// Creates a new Storage instance using the provided configuration.
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

    /// Returns a list of all authentication requests across all states.
    pub async fn get_all_requests(
        &self,
    ) -> Result<Vec<(String, State)>, Box<dyn std::error::Error>> {
        self.with_connection::<_, _, Vec<(String, State)>>(
            |mut con| async move {
                let mut result = Vec::new();
                for state in [State::Pending, State::Authorized, State::Blocked]
                {
                    let keys: Vec<String> = redis::cmd("SMEMBERS")
                        .arg(state_key(state))
                        .query_async(&mut con)
                        .await?;
                    for key in keys {
                        result.push((key, state));
                    }
                }
                Ok(result)
            },
        )
        .await
        .map_err(Into::into)
    }

    /// Fetches a specific authentication request's state and data.
    pub async fn get_request(
        &self,
        key: &str,
    ) -> Result<Option<(State, Value)>, Box<dyn std::error::Error>> {
        self.with_connection::<_, _, Option<(State, Value)>>(
            |mut con| async move {
                if let Some(record) = redis_get_object(&mut con, key).await? {
                    Ok(Some((record.state, parse_value(&record.json))))
                } else {
                    Ok(None)
                }
            },
        )
        .await
        .map_err(Into::into)
    }

    /// Transitions a request between arbitrary states.
    pub async fn transition_request(
        &self,
        key: &str,
        from_state: State,
        to_state: State,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection::<_, _, ()>(|mut con| async move {
            lua::transition(&mut con, key, from_state, to_state).await?;
            Ok(())
        })
        .await
        .map_err(Into::into)
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
                lua::add_pending(
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

    /// Transitions a request to the authorized state.
    pub async fn approve_request(
        &self,
        key: &str,
        from_state: State,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.transition_request(key, from_state, State::Authorized)
            .await
    }

    /// Transitions a request to the blocked state.
    pub async fn block_request(
        &self,
        key: &str,
        from_state: State,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.transition_request(key, from_state, State::Blocked)
            .await
    }

    /// Deletes an authentication request from storage.
    pub async fn delete_request(
        &self,
        key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection(|mut con| async move {
            lua::delete(&mut con, key).await?;
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

    /// Returns a map of all currently blocked authentication keys.
    pub async fn get_blocked_requests(
        &self,
    ) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
        self.get_all_by_state(State::Blocked).await
    }

    /// Internal helper to fetch all records in a specific state.
    async fn get_all_by_state(
        &self,
        state: State,
    ) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
        self.with_connection(|mut con| async move {
            let res: Vec<String> =
                lua::get_all_by_state(&mut con, state).await?;

            let mut result = HashMap::new();
            for chunk in res.chunks_exact(2) {
                let key = chunk[0].clone();
                let json = &chunk[1];
                result.insert(key, parse_value(json));
            }
            Ok(result)
        })
        .await
        .map_err(Into::into)
    }

    /// Validates an authorized key and returns an authentication token.
    pub async fn authenticate_key(
        &self,
        key: &str,
    ) -> Result<AuthResult, Box<dyn std::error::Error>> {
        self.with_connection(|mut con| async move {
            if let Some(record) = redis_get_object(&mut con, key).await? {
                match record.state {
                    State::Pending => return Ok(AuthResult::Pending),
                    State::Blocked => return Ok(AuthResult::Blocked),
                    State::Authorized => (),
                }

                let mut json_val: Value = parse_value(&record.json);
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

                    let _: () = redis::cmd("HSET")
                        .arg(auth_key(key))
                        .arg("json")
                        .arg(new_json_str)
                        .arg("updated")
                        .arg(now)
                        .query_async(&mut con)
                        .await?;

                    Ok(AuthResult::Authorized(token))
                } else {
                    Ok(AuthResult::NotFound)
                }
            } else {
                Ok(AuthResult::NotFound)
            }
        })
        .await
        .map_err(Into::into)
    }
}
