use crate::config::Config;
use base64::prelude::*;
use rand::RngCore;
use redis::cluster::ClusterClient;
use redis::{Client, RedisResult, Script};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;
use crate::now;

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
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            STATE_PENDING => Some(Self::Pending),
            STATE_AUTHORIZED => Some(Self::Authorized),
            STATE_BLOCKED => Some(Self::Blocked),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => STATE_PENDING,
            Self::Authorized => STATE_AUTHORIZED,
            Self::Blocked => STATE_BLOCKED,
        }
    }
}

fn lua_add_pending() -> &'static Script {
    static ADD_PENDING: OnceLock<Script> = OnceLock::new();
    ADD_PENDING.get_or_init(|| Script::new(include_str!("add_pending.lua")))
}

fn lua_transition() -> &'static Script {
    static TRANSITION: OnceLock<Script> = OnceLock::new();
    TRANSITION.get_or_init(|| Script::new(include_str!("transition.lua")))
}

fn lua_delete() -> &'static Script {
    static DELETE: OnceLock<Script> = OnceLock::new();
    DELETE.get_or_init(|| Script::new(include_str!("delete.lua")))
}

fn auth_key(id: &str) -> String {
    format!("auth:{id}")
}

fn state_key(state: State) -> String {
    format!("state:{}", state.as_str())
}

fn now_secs() -> String {
    (now() as u64).to_string()
}

fn redis_add_pending(
    con: &mut dyn redis::ConnectionLike,
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
        .invoke(con)
}

fn redis_transition(
    con: &mut dyn redis::ConnectionLike,
    key: &str,
    from_state: State,
    to_state: State
) -> RedisResult<()> {
    lua_transition()
        .key(auth_key(key))
        .key(state_key(from_state))
        .key(state_key(to_state))
        .arg(key)
        .arg(from_state.as_str())
        .arg(to_state.as_str())
        .arg(now_secs())
        .invoke(con)
}

fn redis_delete(
    con: &mut dyn redis::ConnectionLike,
    key: &str,
) -> RedisResult<()> {
    lua_delete()
        .key(auth_key(key))
        .arg(key)
        .invoke(con)
}

// END NEW REDIS API

#[derive(Debug)]
pub struct ObjectRecord {
    pub state: State,
    pub json: String,
}

pub fn redis_get_object(
    con: &mut dyn redis::ConnectionLike,
    key: &str,
) -> redis::RedisResult<Option<ObjectRecord>> {
    let key = auth_key(key);

    let (state, json): (Option<String>, Option<String>) = redis::cmd("HMGET")
        .arg(&key)
        .arg("state")
        .arg("json")
        .query(con)?;

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

pub enum RedisClient {
    Standalone(Client),
    Cluster(ClusterClient),
}

pub struct Storage {
    client: RedisClient,
    max_pending_requests: usize,
}

impl Storage {
    pub fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let max_pending_requests = config.max_pending_requests;
        if let Some(nodes) = &config.redis_cluster_nodes {
            let nodes: Vec<&str> = nodes.split(',').collect();
            let client = ClusterClient::new(nodes)?;
            Ok(Self {
                client: RedisClient::Cluster(client),
                max_pending_requests,
            })
        } else if let Some(url) = &config.redis_url {
            let client = Client::open(url.as_str())?;
            Ok(Self {
                client: RedisClient::Standalone(client),
                max_pending_requests,
            })
        } else {
            Err("Redis configuration missing (REDIS_URL or REDIS_CLUSTER_NODES)".into())
        }
    }

    fn with_connection<F, T>(
        &self,
        mut f: F,
    ) -> Result<T, StorageErr>
    where
        F: FnMut(&mut dyn redis::ConnectionLike) -> Result<T, StorageErr>,
    {
        match &self.client {
            RedisClient::Standalone(client) => {
                let mut con = client.get_connection()?;
                f(&mut con)
            }
            RedisClient::Cluster(client) => {
                let mut con = client.get_connection()?;
                f(&mut con)
            }
        }
    }

    pub fn add_pending_request(
        &self,
        key: &str,
        data: &Value,
    ) -> Result<(), StorageErr> {
        let json_str = serde_json::to_string(data).map_err(StorageErr::other)?;

        self.with_connection(|con| {
            redis_add_pending(con, key, State::Pending, &json_str, self.max_pending_requests)
                .map_err(|e| {
                    if e.to_string().contains("limit_reached") {
                        StorageErr::TooManyPendingRequests
                    } else {
                        e.into()
                    }
                })?;
            Ok(())
        })
    }

    pub fn approve_request(
        &self,
        key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection(|con| {
            redis_transition(con, key, State::Pending, State::Authorized)?;
            Ok(())
        })
        .map_err(Into::into)
    }

    pub fn delete_request(
        &self,
        key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.with_connection(|con| {
            redis_delete(con, key)?;
            Ok(())
        })
        .map_err(Into::into)
    }

    pub fn get_pending_requests(
        &self,
    ) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
        self.get_all_by_state(State::Pending)
    }

    pub fn get_authorized_requests(
        &self,
    ) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
        self.get_all_by_state(State::Authorized)
    }

    fn get_all_by_state(
        &self,
        state: State,
    ) -> Result<HashMap<String, Value>, Box<dyn std::error::Error>> {
        self.with_connection(|con| {
            let keys: Vec<String> = redis::cmd("SMEMBERS")
                .arg(state_key(state))
                .query(con)?;

            let mut result = HashMap::new();
            for key in keys {
                if let Some(record) = redis_get_object(con, &key)? {
                    let val: Value = serde_json::from_str(&record.json)
                        .unwrap_or(Value::String(record.json));
                    result.insert(key, val);
                }
            }
            Ok(result)
        })
        .map_err(Into::into)
    }

    pub fn authenticate_key(
        &self,
        key: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        self.with_connection(|con| {
            if let Some(record) = redis_get_object(con, key)? {
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
                        .query(con)?;

                    Ok(Some(token))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        })
        .map_err(Into::into)
    }
}