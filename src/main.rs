use std::{
    io,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use directories::ProjectDirs;
use reqwest::{
    Client,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time as tokio_time,
};
use url::form_urlencoded;

const REDIRECT_URI: &str = "http://localhost:3000";
const TOKEN_FILE_NAME: &str = "token_public.json";
const CACHE_FILE_NAME: &str = "gert_cache.json";
const CACHE_TTL_SECONDS: f64 = 60.0;
const AUTH_BASE_URL: &str = "https://id.twitch.tv/oauth2/authorize";
const BASE_URL: &str = "https://api.twitch.tv/helix";
const SCOPES: &[&str] = &["user:read:follows"];
const TOKEN_CAPTURE_HTML: &str = r"<html><body>
<script>
const params = new URLSearchParams(window.location.hash.substring(1));
const token = params.get('access_token');
if (token) {
    fetch('/token?access_token=' + token)
        .then(() => document.body.innerHTML = '<h2>Authorization complete. You can close this window.</h2>')
        .catch(() => document.body.innerHTML = '<h2>Failed to send token.</h2>');
} else {
    document.body.innerHTML = '<h2>No token found in URL.</h2>';
}
</script>
</body></html>";

#[derive(Debug, Default, Serialize, Deserialize)]
struct TokenData {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    timestamp: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CachePayload {
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    timestamp: Option<f64>,
    #[serde(default)]
    channels: Vec<LiveChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LiveChannel {
    user_name: String,
    title: String,
    #[serde(default)]
    game_name: Option<String>,
    viewer_count: u64,
    #[serde(default)]
    started_at: Option<String>,
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

#[derive(Serialize)]
struct StreamsParams<'a> {
    user_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<&'a str>,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let config = AppConfig::from_env()?;

    let stored_user_id = load_user_id().await;
    let cached_payload = load_cache_payload().await;
    let (cached_channels, cached_user_id) = match cached_payload {
        Some(payload) => (Some(payload.channels), payload.user_id),
        None => (None, None),
    };

    if let Some(channels) = cached_channels {
        let mismatch = stored_user_id
            .as_ref()
            .and_then(|stored| cached_user_id.as_ref().map(|cached| stored != cached))
            .unwrap_or(false);
        if !mismatch {
            if stored_user_id.is_none()
                && let Some(user_id) = cached_user_id.clone()
            {
                save_user_id(&user_id).await?;
            }
            println!("Using cached live channel results (polled < 60s ago).");
            display_channels(&channels);
            return Ok(());
        }
    }

    let token = get_token(&config.client_id).await?;
    let client = build_client(&token, &config.client_id)?;

    let user_id = if let Some(ref id) = stored_user_id {
        id.clone()
    } else {
        let id = get_user_id(&client).await?;
        save_user_id(&id).await?;
        id
    };

    let channels = get_live_followed_channels(&client, &user_id).await?;
    save_cached_channels(&user_id, &channels).await?;
    display_channels(&channels);

    Ok(())
}

#[derive(Deserialize)]
struct AppConfig {
    client_id: String,
}

impl AppConfig {
    fn from_env() -> Result<Self> {
        let mut client_id = None;

        if let Ok(env_id) = std::env::var("GERT_CLIENT_ID") {
            if !env_id.trim().is_empty() {
                println!("Using client id from GERT_CLIENT_ID env var");
                client_id = Some(env_id);
            }
        }

        if client_id.is_none() {
            if let Ok(proj_dirs) = get_project_dirs() {
                let config_dir = proj_dirs.config_dir();

                let env_path = config_dir.join(".env");
                let conf_path = config_dir.join("gert.conf");

                if let Some(id) = read_client_id_from_file(&env_path) {
                    client_id = Some(id);
                } else if let Some(id) = read_client_id_from_file(&conf_path) {
                    client_id = Some(id);
                }
            }
        }

        if let Some(client_id) = client_id {
            Ok(Self { client_id })
        } else {
            let path_hint = if let Ok(proj_dirs) = get_project_dirs() {
                proj_dirs.config_dir().display().to_string()
            } else {
                "configuration directory".to_string()
            };

            Err(anyhow!(
                "missing client id; set GERT_CLIENT_ID or add client_id=... to a gert.conf inside {}",
                path_hint
            ))
        }
    }
}

/// Provides platform-appropriate directories for this application.
fn get_project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("", "", "gert").context("could not determine home directory or project paths")
}

fn state_dir() -> Result<PathBuf> {
    let proj_dirs = get_project_dirs()?;
    let dir = proj_dirs.data_local_dir();

    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create state directory at {}", dir.display()))?;

    Ok(dir.to_path_buf())
}

fn cache_dir() -> Result<PathBuf> {
    let proj_dirs = get_project_dirs()?;
    let dir = proj_dirs.cache_dir();

    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create cache directory at {}", dir.display()))?;

    Ok(dir.to_path_buf())
}

fn token_file_path() -> Result<PathBuf> {
    Ok(state_dir()?.join(TOKEN_FILE_NAME))
}

fn cache_file_path() -> Result<PathBuf> {
    Ok(cache_dir()?.join(CACHE_FILE_NAME))
}

fn read_client_id_from_file<P: AsRef<std::path::Path>>(path: P) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if key.eq_ignore_ascii_case("client_id") || key == "GERT_CLIENT_ID" {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
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

async fn load_token_data() -> TokenData {
    let path = match token_file_path() {
        Ok(p) => p,
        Err(err) => {
            eprintln!("Token directory unavailable: {err}");
            return TokenData::default();
        }
    };

    fs::read_to_string(&path)
        .await
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

async fn write_token_data(data: &TokenData) -> Result<()> {
    let serialized = serde_json::to_string(data).context("unable to serialize token file")?;
    let path = token_file_path()?;
    fs::write(&path, serialized)
        .await
        .with_context(|| format!("unable to persist token file at {}", path.display()))
}

async fn save_token(token: &str) -> Result<()> {
    let mut data = load_token_data().await;
    let existing = data.access_token.clone();
    data.access_token = Some(token.to_string());
    data.timestamp = Some(current_timestamp());
    if existing.as_deref() != Some(token) {
        data.user_id = None;
    }
    write_token_data(&data).await
}

async fn load_token() -> Option<String> {
    load_token_data().await.access_token
}

async fn save_user_id(user_id: &str) -> Result<()> {
    let mut data = load_token_data().await;
    data.user_id = Some(user_id.to_string());
    write_token_data(&data).await
}

async fn load_user_id() -> Option<String> {
    load_token_data().await.user_id
}

async fn load_cache_payload() -> Option<CachePayload> {
    let path = cache_file_path().ok()?;
    let contents = fs::read_to_string(&path).await.ok()?;
    let payload: CachePayload = serde_json::from_str(&contents).ok()?;
    let timestamp = payload.timestamp?;
    if current_timestamp() - timestamp > CACHE_TTL_SECONDS {
        return None;
    }
    Some(payload)
}

async fn save_cached_channels(user_id: &str, channels: &[LiveChannel]) -> Result<()> {
    let payload = CachePayload {
        user_id: Some(user_id.to_string()),
        timestamp: Some(current_timestamp()),
        channels: channels.to_vec(),
    };
    let serialized =
        serde_json::to_string(&payload).context("unable to serialize cache payload")?;
    let path = cache_file_path()?;
    fs::write(&path, serialized)
        .await
        .with_context(|| format!("unable to write cache file at {}", path.display()))
}

fn current_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

async fn get_token(client_id: &str) -> Result<String> {
    if let Some(token) = load_token().await {
        return Ok(token);
    }

    println!("Opening browser for Twitch login...");
    let auth_url = build_auth_url(client_id);
    let (tx, rx) = oneshot::channel();
    let server = start_oauth_server(tx).await?;
    webbrowser::open(&auth_url).context("failed to open system browser")?;
    println!("Waiting for token...");
    let token = rx
        .await
        .context("did not receive access token from browser flow")?;
    server
        .await
        .map_err(|_| anyhow!("OAuth callback server task panicked"))?;
    save_token(&token).await?;
    Ok(token)
}

fn build_auth_url(client_id: &str) -> String {
    format!(
        "{AUTH_BASE_URL}?client_id={client_id}&redirect_uri={REDIRECT_URI}&response_type=token&scope={}",
        SCOPES.join("%20")
    )
}

async fn start_oauth_server(tx: oneshot::Sender<String>) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(("127.0.0.1", 3000))
        .await
        .context("failed to bind local OAuth callback server on port 3000")?;
    let handle = tokio::spawn(async move {
        if let Err(err) = run_oauth_server(listener, tx).await {
            eprintln!("OAuth callback server error: {err:?}");
        }
    });
    Ok(handle)
}

async fn run_oauth_server(listener: TcpListener, tx: oneshot::Sender<String>) -> Result<()> {
    let mut tx = Some(tx);
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("Incoming connection failed: {err:?}");
                continue;
            }
        };

        if let Some(token) = handle_http_request(&mut stream).await? {
            if let Some(sender) = tx.take() {
                let _ = sender.send(token);
            }
            break;
        }
    }
    Ok(())
}

async fn handle_http_request(stream: &mut TcpStream) -> Result<Option<String>> {
    let request =
        match tokio_time::timeout(Duration::from_secs(30), read_http_request(stream)).await {
            Ok(result) => result?,
            Err(_) => return Ok(None),
        };

    let mut parts = request.lines();
    let request_line = parts.next().unwrap_or("").trim();
    if request_line.is_empty() {
        return Ok(None);
    }

    let mut tokens = request_line.split_whitespace();
    let method = tokens.next().unwrap_or("");
    let path = tokens.next().unwrap_or("/");
    if method != "GET" {
        send_response(
            stream,
            "405 Method Not Allowed",
            "Method not allowed.",
            "text/plain",
        )
        .await?;
        return Ok(None);
    }

    if path.starts_with("/token") {
        let token = path
            .split_once('?')
            .and_then(|(_, query)| extract_access_token(query));
        if let Some(token) = token {
            send_response(
                stream,
                "200 OK",
                "Access token received! You can close this tab.",
                "text/plain",
            )
            .await?;
            return Ok(Some(token));
        } else {
            send_response(
                stream,
                "400 Bad Request",
                "Access token not found.",
                "text/plain",
            )
            .await?;
            return Ok(None);
        }
    }

    send_response(stream, "200 OK", TOKEN_CAPTURE_HTML, "text/html").await?;
    Ok(None)
}

async fn read_http_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() >= 64 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

async fn send_response(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
    content_type: &str,
) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

fn extract_access_token(query: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "access_token")
        .map(|(_, value)| value.into_owned())
}

fn display_channels(channels: &[LiveChannel]) {
    if channels.is_empty() {
        println!("No followed channels are live right now.");
        return;
    }

    println!("\nLIVE channels you follow:");
    for channel in channels {
        let game = channel.game_name.as_deref().unwrap_or("Unknown game");
        let live_for = format_live_duration(channel.started_at.as_deref());
        println!(
            "{} — {} — {} — live for {} ({} viewers)",
            channel.user_name, channel.title, game, live_for, channel.viewer_count
        );
    }
}

fn format_live_duration(started_at: Option<&str>) -> String {
    let started_at = match started_at {
        Some(value) => value,
        None => return "live time unknown".to_string(),
    };

    let start = match OffsetDateTime::parse(started_at, &Rfc3339) {
        Ok(parsed) => parsed,
        Err(_) => return "live time unknown".to_string(),
    };

    let elapsed = OffsetDateTime::now_utc() - start;
    if elapsed.is_negative() {
        return "live just now".to_string();
    }

    human_readable_duration(elapsed)
}

fn human_readable_duration(duration: TimeDuration) -> String {
    let total_seconds = duration.whole_seconds();
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;

    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

async fn get_user_id(client: &Client) -> Result<String> {
    let response = client
        .get(format!("{BASE_URL}/users"))
        .send()
        .await
        .context("failed to call Twitch users endpoint")?
        .error_for_status()
        .context("Twitch users endpoint returned an error status")?;

    let payload: UsersResponse = response
        .json()
        .await
        .context("failed to parse Twitch user response")?;
    payload
        .data
        .into_iter()
        .next()
        .map(|user| user.id)
        .context("Twitch API returned no user data")
}

async fn get_live_followed_channels(client: &Client, user_id: &str) -> Result<Vec<LiveChannel>> {
    let mut channels = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let params = StreamsParams {
            user_id,
            after: cursor.as_deref(),
        };

        let response = client
            .get(format!("{BASE_URL}/streams/followed"))
            .query(&params)
            .send()
            .await
            .context("failed to call Twitch streams endpoint")?
            .error_for_status()
            .context("Twitch streams endpoint returned an error status")?;

        let payload: StreamsResponse = response
            .json()
            .await
            .context("failed to parse Twitch streams response")?;
        channels.extend(payload.data);
        cursor = payload.pagination.and_then(|p| p.cursor);
        if cursor.is_none() {
            break;
        }
    }

    Ok(channels)
}
