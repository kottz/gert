import requests
import webbrowser
import threading
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import os
from dotenv import load_dotenv

load_dotenv()
CLIENT_ID = os.getenv("GERT_CLIENT_ID")
REDIRECT_URI = "http://localhost:3000"
TOKEN_FILE = "token_public.json"
SCOPES = ["user:read:follows"]

AUTH_URL = (
    "https://id.twitch.tv/oauth2/authorize"
    f"?client_id={CLIENT_ID}"
    f"&redirect_uri={REDIRECT_URI}"
    f"&response_type=token"
    f"&scope={'%20'.join(SCOPES)}"
)

BASE_URL = "https://api.twitch.tv/helix"


def save_token(token):
    with open(TOKEN_FILE, "w") as f:
        json.dump({"access_token": token, "timestamp": time.time()}, f)


def load_token():
    try:
        with open(TOKEN_FILE, "r") as f:
            return json.load(f)["access_token"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        return None


class OAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        if path.startswith("/token"):
            qs = parse_qs(urlparse(path).query)
            if "access_token" in qs:
                self.server.access_token = qs["access_token"][0]
                save_token(self.server.access_token)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Access token received! You can close this tab.")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Access token not found.")
        else:
            html = f"""
            <html><body>
            <script>
            const params = new URLSearchParams(window.location.hash.substring(1));
            const token = params.get('access_token');
            if (token) {{
                fetch('/token?access_token=' + token)
                    .then(() => document.body.innerHTML = '<h2>Authorization complete. You can close this window.</h2>')
                    .catch(() => document.body.innerHTML = '<h2>Failed to send token.</h2>');
            }} else {{
                document.body.innerHTML = '<h2>No token found in URL.</h2>';
            }}
            </script>
            </body></html>
            """
            self.send_response(200)
            self.end_headers()
            self.wfile.write(html.encode())

    def log_message(self, format, *args):
        return  # silence logs


def get_token():
    token = load_token()
    if token:
        return token

    print("Opening browser for Twitch login...")
    server = HTTPServer(("localhost", 3000), OAuthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    webbrowser.open(AUTH_URL)

    print("Waiting for token...")
    while not hasattr(server, "access_token"):
        time.sleep(0.1)

    token = server.access_token
    server.shutdown()
    return token


def get_user_id(headers):
    resp = requests.get(f"{BASE_URL}/users", headers=headers)
    resp.raise_for_status()
    return resp.json()["data"][0]["id"]


def get_live_followed_channels(headers, user_id):
    live_channels = []
    cursor = None
    while True:
        params = {"user_id": user_id}
        if cursor:
            params["after"] = cursor
        resp = requests.get(
            f"{BASE_URL}/streams/followed", headers=headers, params=params
        )
        resp.raise_for_status()
        data = resp.json()
        live_channels.extend(data["data"])
        cursor = data.get("pagination", {}).get("cursor")
        if not cursor:
            break
    return live_channels


def main():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Client-Id": CLIENT_ID}
    user_id = get_user_id(headers)
    channels = get_live_followed_channels(headers, user_id)
    if channels:
        print("\nLIVE channels you follow:")
        for c in channels:
            print(f"{c['user_name']} — {c['title']} ({c['viewer_count']} viewers)")
    else:
        print("No followed channels are live right now.")


if __name__ == "__main__":
    main()
