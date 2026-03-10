use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use ureq::Agent;

use crate::{config::Config, oauth, storage};

const BASE_URL: &str = "https://api.twitch.tv/helix";

pub struct Api {
    client: Agent,
    client_id: String,
    token: String,
}

impl Api {
    pub fn new(config: &Config) -> Result<Self> {
        let token = get_or_request_token(&config.client_id)?;
        let client = build_client()?;

        Ok(Self {
            client,
            client_id: config.client_id.clone(),
            token,
        })
    }

    pub fn refresh_auth(&mut self) -> Result<()> {
        storage::delete_token()?;
        self.token = get_or_request_token(&self.client_id)?;
        self.client = build_client()?;
        Ok(())
    }

    pub fn get_user_id(&self) -> Result<String> {
        let response = self
            .authorized_get(&format!("{BASE_URL}/users"))
            .call()
            .map_err(|err| {
                anyhow::Error::new(err).context("failed to call Twitch users endpoint")
            })?;

        let payload: UsersResponse = response
            .into_json()
            .context("failed to parse Twitch user response")?;

        payload
            .data
            .into_iter()
            .next()
            .map(|u| u.id)
            .context("Twitch API returned no user data")
    }

    pub fn get_live_followed_channels(&self, user_id: &str) -> Result<Vec<LiveChannel>> {
        let mut channels = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let mut request = self.authorized_get(&format!("{BASE_URL}/streams/followed"));
            request = request.query("user_id", user_id);

            if let Some(ref c) = cursor {
                request = request.query("after", c);
            }

            let response = request.call().map_err(|err| {
                anyhow::Error::new(err).context("failed to call Twitch streams endpoint")
            })?;

            let payload: StreamsResponse = response
                .into_json()
                .context("failed to parse Twitch streams response")?;
            channels.extend(payload.data);

            cursor = payload.pagination.and_then(|p| p.cursor);
            if cursor.is_none() {
                break;
            }
        }

        Ok(channels)
    }

    fn authorized_get(&self, url: &str) -> ureq::Request {
        self.client
            .get(url)
            .set("Client-Id", &self.client_id)
            .set("Authorization", &format!("Bearer {}", self.token))
    }
}

fn get_or_request_token(client_id: &str) -> Result<String> {
    if let Some(token) = storage::load_token() {
        return Ok(token);
    }

    println!("Opening browser for Twitch login...");
    let token = oauth::authenticate(client_id)?;
    storage::save_token(&token)?;

    Ok(token)
}

fn build_client() -> Result<Agent> {
    Ok(ureq::AgentBuilder::new().user_agent("gert").build())
}

pub fn is_unauthorized(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<ureq::Error>())
        .any(|e| matches!(e, ureq::Error::Status(401, _)))
}

// API response types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveChannel {
    pub user_name: String,
    pub title: String,
    #[serde(default)]
    pub game_name: Option<String>,
    pub viewer_count: u64,
    #[serde(default)]
    pub started_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UsersResponse {
    data: Vec<TwitchUser>,
}

#[derive(Debug, Deserialize)]
struct TwitchUser {
    id: String,
}

#[derive(Debug, Deserialize)]
struct StreamsResponse {
    data: Vec<LiveChannel>,
    #[serde(default)]
    pagination: Option<Pagination>,
}

#[derive(Debug, Deserialize)]
struct Pagination {
    cursor: Option<String>,
}
