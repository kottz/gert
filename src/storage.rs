use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{config, twitch::LiveChannel};

const TOKEN_FILE: &str = "token_public.json";
const CACHE_FILE: &str = "gert_cache.json";
const CACHE_TTL_SECONDS: f64 = 60.0;

// Token storage

#[derive(Debug, Default, Serialize, Deserialize)]
struct TokenData {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    timestamp: Option<f64>,
}

pub fn load_token() -> Option<String> {
    load_token_data().access_token
}

pub fn save_token(token: &str) -> Result<()> {
    let mut data = load_token_data();
    let token_changed = data.access_token.as_deref() != Some(token);

    data.access_token = Some(token.to_string());
    data.timestamp = Some(current_timestamp());

    if token_changed {
        data.user_id = None;
    }

    write_token_data(&data)
}

pub fn delete_token() -> Result<()> {
    let path = token_file_path()?;
    if path.exists() {
        std::fs::remove_file(&path).ok();
    }
    Ok(())
}

pub fn load_user_id() -> Option<String> {
    load_token_data().user_id
}

pub fn save_user_id(user_id: &str) -> Result<()> {
    let mut data = load_token_data();
    data.user_id = Some(user_id.to_string());
    write_token_data(&data)
}

fn load_token_data() -> TokenData {
    let Ok(path) = token_file_path() else {
        return TokenData::default();
    };

    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_token_data(data: &TokenData) -> Result<()> {
    let path = token_file_path()?;
    let json = serde_json::to_string(data).context("failed to serialize token data")?;
    std::fs::write(&path, json)
        .with_context(|| format!("failed to write token file at {}", path.display()))
}

fn token_file_path() -> Result<PathBuf> {
    Ok(state_dir()?.join(TOKEN_FILE))
}

// Cache storage

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CachePayload {
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub timestamp: Option<f64>,
    #[serde(default)]
    pub channels: Vec<LiveChannel>,
}

pub fn load_cache() -> Option<CachePayload> {
    let path = cache_file_path().ok()?;
    let contents = std::fs::read_to_string(&path).ok()?;
    let payload: CachePayload = serde_json::from_str(&contents).ok()?;

    let age = current_timestamp() - payload.timestamp?;
    if age > CACHE_TTL_SECONDS {
        return None;
    }

    Some(payload)
}

pub fn save_cache(user_id: &str, channels: &[LiveChannel]) -> Result<()> {
    let payload = CachePayload {
        user_id: Some(user_id.to_string()),
        timestamp: Some(current_timestamp()),
        channels: channels.to_vec(),
    };

    let path = cache_file_path()?;
    let json = serde_json::to_string(&payload).context("failed to serialize cache")?;
    std::fs::write(&path, json)
        .with_context(|| format!("failed to write cache file at {}", path.display()))
}

fn cache_file_path() -> Result<PathBuf> {
    Ok(cache_dir()?.join(CACHE_FILE))
}

// Directory helpers

fn state_dir() -> Result<PathBuf> {
    let proj_dirs = config::project_dirs().context("could not determine project directories")?;
    let dir = proj_dirs.data_local_dir();
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create state directory at {}", dir.display()))?;
    Ok(dir.to_path_buf())
}

fn cache_dir() -> Result<PathBuf> {
    let proj_dirs = config::project_dirs().context("could not determine project directories")?;
    let dir = proj_dirs.cache_dir();
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create cache directory at {}", dir.display()))?;
    Ok(dir.to_path_buf())
}

fn current_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
