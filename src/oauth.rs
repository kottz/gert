use std::{io, time::Duration};

use anyhow::{anyhow, Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use url::form_urlencoded;

const PORT: u16 = 44764;
const REDIRECT_URI: &str = "http://localhost:44764";
const AUTH_BASE_URL: &str = "https://id.twitch.tv/oauth2/authorize";
const SCOPES: &[&str] = &["user:read:follows"];
const LOGIN_TIMEOUT: Duration = Duration::from_secs(120);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const TOKEN_CAPTURE_PAGE: &str = r#"<html><body>
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
</body></html>"#;

/// Opens browser for Twitch OAuth and waits for the callback with the access token.
pub async fn authenticate(client_id: &str) -> Result<String> {
    let auth_url = build_auth_url(client_id);
    let (tx, rx) = oneshot::channel();

    // Start callback server before opening browser
    let listener = TcpListener::bind(("127.0.0.1", PORT))
        .await
        .context(format!(
            "failed to bind OAuth callback server on port {PORT}"
        ))?;

    let server_handle = tokio::spawn(run_callback_server(listener, tx));

    webbrowser::open(&auth_url).context("failed to open browser")?;
    println!("Waiting for login (timeout in 2 minutes)...");

    let token = match timeout(LOGIN_TIMEOUT, rx).await {
        Ok(Ok(token)) => token,
        Ok(Err(_)) => return Err(anyhow!("OAuth channel closed unexpectedly")),
        Err(_) => return Err(anyhow!("Timed out waiting for login")),
    };

    // Let server finish gracefully
    let _ = server_handle.await;

    Ok(token)
}

fn build_auth_url(client_id: &str) -> String {
    let scope = SCOPES.join("%20");
    format!("{AUTH_BASE_URL}?client_id={client_id}&redirect_uri={REDIRECT_URI}&response_type=token&scope={scope}")
}

async fn run_callback_server(listener: TcpListener, tx: oneshot::Sender<String>) -> Result<()> {
    let mut tx = Some(tx);

    loop {
        let (mut stream, _) = listener.accept().await?;

        if let Some(token) = handle_request(&mut stream).await? {
            if let Some(sender) = tx.take() {
                let _ = sender.send(token);
            }
            break;
        }
    }

    Ok(())
}

async fn handle_request(stream: &mut TcpStream) -> Result<Option<String>> {
    let request = match timeout(REQUEST_TIMEOUT, read_request(stream)).await {
        Ok(Ok(req)) => req,
        _ => return Ok(None),
    };

    let request_line = request.lines().next().unwrap_or("").trim();
    if request_line.is_empty() {
        return Ok(None);
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    if method != "GET" {
        send_response(
            stream,
            "405 Method Not Allowed",
            "Method not allowed",
            "text/plain",
        )
        .await?;
        return Ok(None);
    }

    // Token callback endpoint
    if let Some(query) = path.strip_prefix("/token?") {
        if let Some(token) = extract_token(query) {
            send_response(
                stream,
                "200 OK",
                "Token received. You can close this tab.",
                "text/plain",
            )
            .await?;
            return Ok(Some(token));
        }
        send_response(
            stream,
            "400 Bad Request",
            "Missing access token",
            "text/plain",
        )
        .await?;
        return Ok(None);
    }

    // Serve the token capture page for the initial redirect
    send_response(stream, "200 OK", TOKEN_CAPTURE_PAGE, "text/html").await?;
    Ok(None)
}

async fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];

    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }

        buffer.extend_from_slice(&chunk[..n]);

        // Check for end of HTTP headers
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        // Prevent unbounded reads
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
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

fn extract_token(query: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == "access_token")
        .map(|(_, v)| v.into_owned())
}
