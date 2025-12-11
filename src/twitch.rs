use anyhow::{Context, Result};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION},
    Client, StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::{config::Config, oauth, storage};

const BASE_URL: &str = "https://api.twitch.tv/helix";

pub struct Api {
    client: Client,
    client_id: String,
}

impl Api {
    pub async fn new(config: &Config) -> Result<Self> {
        let token = get_or_request_token(&config.client_id).await?;
        let client = build_client(&token, &config.client_id)?;

        Ok(Self {
            client,
            client_id: config.client_id.clone(),
        })
    }

    pub async fn refresh_auth(&mut self) -> Result<()> {
        storage::delete_token().await?;
        let token = get_or_request_token(&self.client_id).await?;
        self.client = build_client(&token, &self.client_id)?;
        Ok(())
    }

    pub async fn get_user_id(&self) -> Result<String> {
        let response = self
            .client
            .get(format!("{BASE_URL}/users"))
            .send()
            .await
            .context("failed to call Twitch users endpoint")?;

        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(response.error_for_status().unwrap_err().into());
        }

        let payload: UsersResponse = response
            .error_for_status()
            .context("Twitch users endpoint returned error")?
            .json()
            .await
            .context("failed to parse Twitch user response")?;

        payload
            .data
            .into_iter()
            .next()
            .map(|u| u.id)
            .context("Twitch API returned no user data")
    }

    pub async fn get_live_followed_channels(&self, user_id: &str) -> Result<Vec<LiveChannel>> {
        let mut channels = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let mut request = self
                .client
                .get(format!("{BASE_URL}/streams/followed"))
                .query(&[("user_id", user_id)]);

            if let Some(ref c) = cursor {
                request = request.query(&[("after", c)]);
            }

            let response = request
                .send()
                .await
                .context("failed to call Twitch streams endpoint")?;

            if response.status() == StatusCode::UNAUTHORIZED {
                return Err(response.error_for_status().unwrap_err().into());
            }

            let payload: StreamsResponse = response
                .error_for_status()
                .context("Twitch streams endpoint returned error")?
                .json()
                .await
                .context("failed to parse Twitch streams response")?;
            println!("{:?}", payload.data);
            channels.extend(payload.data);

            cursor = payload.pagination.and_then(|p| p.cursor);
            if cursor.is_none() {
                break;
            }
        }

        Ok(channels)
    }
}

async fn get_or_request_token(client_id: &str) -> Result<String> {
    if let Some(token) = storage::load_token().await {
        return Ok(token);
    }

    println!("Opening browser for Twitch login...");
    let token = oauth::authenticate(client_id).await?;
    storage::save_token(&token).await?;

    Ok(token)
}

fn build_client(token: &str, client_id: &str) -> Result<Client> {
    let mut headers = HeaderMap::new();

    headers.insert(
        "Client-Id",
        HeaderValue::from_str(client_id).context("invalid client id header")?,
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid authorization header")?,
    );

    Client::builder()
        .default_headers(headers)
        .build()
        .context("failed to build HTTP client")
}

pub fn is_unauthorized(err: &anyhow::Error) -> bool {
    err.downcast_ref::<reqwest::Error>()
        .and_then(|e| e.status())
        .is_some_and(|s| s == StatusCode::UNAUTHORIZED)
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
