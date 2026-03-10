use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};

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
pub fn authenticate(client_id: &str) -> Result<String> {
    let auth_url = build_auth_url(client_id);
    let (tx, rx) = mpsc::channel();

    // Start callback server before opening browser
    let listener = TcpListener::bind(("127.0.0.1", PORT)).context(format!(
        "failed to bind OAuth callback server on port {PORT}"
    ))?;

    let server_handle = std::thread::spawn(move || run_callback_server(listener, tx));

    println!("Open this URL in your browser to authenticate:");
    println!("{auth_url}");
    println!("Waiting for login (timeout in 2 minutes)...");

    let token = match rx.recv_timeout(LOGIN_TIMEOUT) {
        Ok(token) => token,
        Err(mpsc::RecvTimeoutError::Timeout) => return Err(anyhow!("Timed out waiting for login")),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(anyhow!("OAuth channel closed unexpectedly"));
        }
    };

    // Let server finish gracefully
    let _ = server_handle.join();

    Ok(token)
}

fn build_auth_url(client_id: &str) -> String {
    let scope = SCOPES.join("%20");
    format!("{AUTH_BASE_URL}?client_id={client_id}&redirect_uri={REDIRECT_URI}&response_type=token&scope={scope}")
}

fn run_callback_server(listener: TcpListener, tx: mpsc::Sender<String>) -> Result<()> {
    let mut tx = Some(tx);

    loop {
        let (mut stream, _) = listener.accept()?;

        if let Some(token) = handle_request(&mut stream)? {
            if let Some(sender) = tx.take() {
                let _ = sender.send(token);
            }
            break;
        }
    }

    Ok(())
}

fn handle_request(stream: &mut TcpStream) -> Result<Option<String>> {
    stream.set_read_timeout(Some(REQUEST_TIMEOUT)).ok();

    let request = match read_request(stream) {
        Ok(req) => req,
        Err(_) => return Ok(None),
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
        )?;
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
            )?;
            return Ok(Some(token));
        }
        send_response(
            stream,
            "400 Bad Request",
            "Missing access token",
            "text/plain",
        )?;
        return Ok(None);
    }

    // Serve the token capture page for the initial redirect
    send_response(stream, "200 OK", TOKEN_CAPTURE_PAGE, "text/html")?;
    Ok(None)
}

fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];

    loop {
        let n = stream.read(&mut chunk)?;
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

fn send_response(
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
    stream.write_all(response.as_bytes())
}

fn extract_token(query: &str) -> Option<String> {
    query.split('&').find_map(|part| {
        let (raw_key, raw_value) = part.split_once('=')?;
        if percent_decode(raw_key) == "access_token" {
            Some(percent_decode(raw_value))
        } else {
            None
        }
    })
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                    out.push((h * 16 + l) as char);
                    i += 3;
                    continue;
                }
                out.push('%');
                i += 1;
            }
            b => {
                out.push(b as char);
                i += 1;
            }
        }
    }

    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
