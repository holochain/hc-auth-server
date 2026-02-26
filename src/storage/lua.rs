use redis::{RedisResult, Script};
use std::sync::OnceLock;
use super::types::State;

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
    (crate::now() as u64).to_string()
}

/// Adds a new pending authentication request.
pub(crate) async fn add_pending(
    con: &mut impl redis::aio::ConnectionLike,
    key: &str,
    state: State,
    json: &str,
    max_pending: usize,
) -> RedisResult<()> {
    static SCRIPT: OnceLock<Script> = OnceLock::new();
    let script = SCRIPT.get_or_init(|| Script::new(include_str!("add_pending.lua")));
    script
        .key(auth_key(key))
        .key(state_key(state))
        .arg(key)
        .arg(json)
        .arg(now_secs())
        .arg(max_pending)
        .invoke_async(con)
        .await
}

/// Transitions a request between states.
pub(crate) async fn transition(
    con: &mut impl redis::aio::ConnectionLike,
    key: &str,
    from_state: State,
    to_state: State,
) -> RedisResult<()> {
    static SCRIPT: OnceLock<Script> = OnceLock::new();
    let script = SCRIPT.get_or_init(|| Script::new(include_str!("transition.lua")));
    script
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

/// Deletes an authentication request.
pub(crate) async fn delete(
    con: &mut impl redis::aio::ConnectionLike,
    key: &str,
) -> RedisResult<()> {
    static SCRIPT: OnceLock<Script> = OnceLock::new();
    let script = SCRIPT.get_or_init(|| Script::new(include_str!("delete.lua")));
    script
        .key(auth_key(key))
        .arg(key)
        .invoke_async(con)
        .await
}

/// Fetches all records in a specific state.
pub(crate) async fn get_all_by_state(
    con: &mut impl redis::aio::ConnectionLike,
    state: State,
) -> RedisResult<Vec<String>> {
    static SCRIPT: OnceLock<Script> = OnceLock::new();
    let script = SCRIPT.get_or_init(|| Script::new(include_str!("get_all_by_state.lua")));
    script
        .key(state_key(state))
        .invoke_async(con)
        .await
}
