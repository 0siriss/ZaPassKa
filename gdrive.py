"""
gdrive.py — Google Drive backup of vault snapshots.

Uses the OAuth 2.0 loopback flow for installed apps: the app opens the user's
browser, the user signs in to their own Google account there, and Google
redirects back to a short-lived local HTTP server with an authorization code.
The app never sees the Google password.

Only the `drive.appdata` scope is requested. That scope reaches a hidden
per-application folder and nothing else — no access to the user's documents,
and no other app can read what ZaPassKa writes.

Implemented on the standard library alone (urllib + http.server), so builds do
not drag in the Google client libraries.
"""
import base64
import hashlib
import json
import os
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import build_config
import database

AUTH_URI   = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URI  = "https://oauth2.googleapis.com/token"
REVOKE_URI = "https://oauth2.googleapis.com/revoke"
API_FILES  = "https://www.googleapis.com/drive/v3/files"
UPLOAD_URI = "https://www.googleapis.com/upload/drive/v3/files"
SCOPE      = "https://www.googleapis.com/auth/drive.appdata"

TOKEN_FILE  = "google_token.json"
CLIENT_FILE = "google_client.json"

HTTP_TIMEOUT   = 20
AUTH_TIMEOUT   = 300     # how long the browser consent may take


class DriveError(Exception):
    """Any failure talking to Drive or to the OAuth endpoints."""


class NotConfigured(DriveError):
    """No OAuth client available — the user has to supply one."""


class NotConnected(DriveError):
    """No stored Google authorization for this machine."""


# ── OAuth client configuration ────────────────────────────────────

def _client_file() -> Path:
    return database.get_app_dir() / CLIENT_FILE


def client_config() -> tuple[str, str]:
    """
    Resolve the OAuth client: environment first, then the build-time values,
    then whatever the user saved locally. Returns (client_id, client_secret);
    the secret is empty for clients that rely on PKCE alone.
    """
    env_id = os.environ.get("ZAPASSKA_GOOGLE_CLIENT_ID", "").strip()
    if env_id:
        return env_id, os.environ.get("ZAPASSKA_GOOGLE_CLIENT_SECRET", "").strip()

    if build_config.GOOGLE_CLIENT_ID:
        return build_config.GOOGLE_CLIENT_ID, build_config.GOOGLE_CLIENT_SECRET

    path = _client_file()
    if path.exists():
        data = json.loads(path.read_text("utf-8"))
        # Accept Google's own client_secrets.json as well as a flat pair.
        data = data.get("installed") or data.get("web") or data
        client_id = (data.get("client_id") or "").strip()
        if client_id:
            return client_id, (data.get("client_secret") or "").strip()

    raise NotConfigured(
        "No Google OAuth client configured. Create a Desktop app client in "
        "Google Cloud Console and add it in Google Drive settings."
    )


def has_client_config() -> bool:
    try:
        client_config()
        return True
    except NotConfigured:
        return False


def save_client_config(client_id: str, client_secret: str):
    path = _client_file()
    path.write_text(json.dumps({
        "installed": {"client_id": client_id.strip(),
                      "client_secret": client_secret.strip()}
    }, indent=2), "utf-8")
    _restrict(path)


# ── Token storage ─────────────────────────────────────────────────

def _token_file() -> Path:
    return database.get_app_dir() / TOKEN_FILE


def _restrict(path: Path):
    """Owner-only permissions where the platform has them."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _load_token() -> dict | None:
    path = _token_file()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return None


def _save_token(token: dict):
    path = _token_file()
    path.write_text(json.dumps(token, indent=2), "utf-8")
    _restrict(path)


def is_connected() -> bool:
    token = _load_token()
    return bool(token and token.get("refresh_token"))


def account_email() -> str:
    token = _load_token() or {}
    return token.get("email", "")


def disconnect():
    """Revoke the refresh token with Google and forget it locally."""
    token = _load_token()
    if token and token.get("refresh_token"):
        try:
            _post_form(REVOKE_URI, {"token": token["refresh_token"]})
        except DriveError:
            pass          # already revoked or offline — drop it locally anyway
    _token_file().unlink(missing_ok=True)


# ── HTTP helpers ──────────────────────────────────────────────────

def _request(url: str, method: str = "GET", data: bytes | None = None,
             headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise DriveError(f"Google returned {exc.code}: {detail}") from exc
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        raise DriveError(f"Google Drive unreachable: {exc}") from exc


def _post_form(url: str, fields: dict) -> dict:
    body = urllib.parse.urlencode(fields).encode()
    raw  = _request(url, "POST", body,
                    {"Content-Type": "application/x-www-form-urlencoded"})
    return json.loads(raw) if raw else {}


# ── Authorization ─────────────────────────────────────────────────

class _RedirectHandler(BaseHTTPRequestHandler):
    """Catches Google's redirect back to 127.0.0.1 and shows a closing page."""

    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code  = params.get("code", [None])[0]
        error = params.get("error", [None])[0]

        # Browsers also ask this server for a favicon; only a request that
        # actually carries the redirect may touch the result.
        if code or error:
            self.server.auth_code  = code
            self.server.auth_error = error
            self.server.auth_state = params.get("state", [None])[0]

        ok = code is not None
        body = (
            "<html><head><meta charset='utf-8'><title>ZaPassKa</title></head>"
            "<body style='font-family:Segoe UI,sans-serif;background:#0d1117;"
            "color:#e6edf3;display:flex;height:100vh;align-items:center;"
            "justify-content:center'><div style='text-align:center'>"
            f"<h2>{'ZaPassKa is connected' if ok else 'Authorization failed'}</h2>"
            "<p>You can close this tab and go back to the app.</p>"
            "</div></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass          # keep the console quiet


def _pkce_pair() -> tuple[str, str]:
    verifier  = base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")
    digest    = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def authorize(open_browser=webbrowser.open) -> str:
    """
    Run the browser consent flow and store the resulting refresh token.
    Returns the authorized account's e-mail when Google discloses it.
    Blocks until the user finishes or AUTH_TIMEOUT passes — call it off the UI
    thread.
    """
    client_id, client_secret = client_config()
    verifier, challenge      = _pkce_pair()
    state                    = secrets.token_urlsafe(24)

    server = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
    server.auth_code = server.auth_error = server.auth_state = None
    redirect_uri = f"http://127.0.0.1:{server.server_port}"

    params = {
        "client_id":             client_id,
        "redirect_uri":          redirect_uri,
        "response_type":         "code",
        "scope":                 SCOPE,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
        "state":                 state,
        "access_type":           "offline",
        "prompt":                "consent",
    }
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        open_browser(f"{AUTH_URI}?{urllib.parse.urlencode(params)}")

        deadline = time.monotonic() + AUTH_TIMEOUT
        while server.auth_code is None and server.auth_error is None:
            if time.monotonic() > deadline:
                raise DriveError("Authorization timed out.")
            time.sleep(0.2)

        if server.auth_error:
            raise DriveError(f"Authorization refused: {server.auth_error}")
        if server.auth_state != state:
            raise DriveError("Authorization state mismatch — request discarded.")
        code = server.auth_code
    finally:
        server.shutdown()
        server.server_close()

    fields = {
        "code":          code,
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "grant_type":    "authorization_code",
        "code_verifier": verifier,
    }
    if client_secret:
        fields["client_secret"] = client_secret

    payload = _post_form(TOKEN_URI, fields)
    if "refresh_token" not in payload:
        raise DriveError("Google did not return a refresh token — try again.")

    token = {
        "refresh_token": payload["refresh_token"],
        "access_token":  payload.get("access_token", ""),
        "expires_at":    time.time() + int(payload.get("expires_in", 0)) - 60,
        "email":         _email_from_id_token(payload.get("id_token", "")),
    }
    _save_token(token)
    return token["email"]


def _email_from_id_token(id_token: str) -> str:
    """Read the e-mail claim without verifying — display only, never trusted."""
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("email", "")
    except (IndexError, ValueError):
        return ""


def _access_token() -> str:
    token = _load_token()
    if not token or not token.get("refresh_token"):
        raise NotConnected("Google Drive is not connected.")

    if token.get("access_token") and time.time() < token.get("expires_at", 0):
        return token["access_token"]

    client_id, client_secret = client_config()
    fields = {
        "client_id":     client_id,
        "refresh_token": token["refresh_token"],
        "grant_type":    "refresh_token",
    }
    if client_secret:
        fields["client_secret"] = client_secret

    payload = _post_form(TOKEN_URI, fields)
    if "access_token" not in payload:
        raise NotConnected("Google refused to refresh the token — reconnect.")

    token["access_token"] = payload["access_token"]
    token["expires_at"]   = time.time() + int(payload.get("expires_in", 0)) - 60
    _save_token(token)
    return token["access_token"]


# ── Drive files (appDataFolder) ───────────────────────────────────

def _auth_header() -> dict:
    return {"Authorization": f"Bearer {_access_token()}"}


def list_snapshots() -> list[dict]:
    """Every snapshot file this app has stored, as {id, name, modifiedTime}."""
    query = urllib.parse.urlencode({
        "spaces":   "appDataFolder",
        "fields":   "files(id,name,modifiedTime)",
        "pageSize": "100",
        "q":        "name contains 'zapasska-' and trashed = false",
    })
    payload = json.loads(_request(f"{API_FILES}?{query}", headers=_auth_header()))
    return payload.get("files", [])


def find_file(name: str) -> dict | None:
    escaped = name.replace("'", "\\'")
    query = urllib.parse.urlencode({
        "spaces": "appDataFolder",
        "fields": "files(id,name,modifiedTime)",
        "q":      f"name = '{escaped}' and trashed = false",
    })
    payload = json.loads(_request(f"{API_FILES}?{query}", headers=_auth_header()))
    files = payload.get("files", [])
    return files[0] if files else None


def download(file_id: str) -> bytes:
    return _request(f"{API_FILES}/{file_id}?alt=media", headers=_auth_header())


def upload(name: str, content: bytes, file_id: str | None = None) -> str:
    """Create or replace a snapshot file. Returns the Drive file id."""
    if file_id:
        url, method, body, headers = (
            f"{UPLOAD_URI}/{file_id}?uploadType=media", "PATCH", content,
            {**_auth_header(), "Content-Type": "application/json"}
        )
    else:
        boundary = "zpk" + secrets.token_hex(16)
        metadata = json.dumps({"name": name, "parents": ["appDataFolder"]})
        body = (
            f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
            f"{metadata}\r\n--{boundary}\r\nContent-Type: application/json\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
        url, method, headers = (
            f"{UPLOAD_URI}?uploadType=multipart", "POST",
            {**_auth_header(),
             "Content-Type": f"multipart/related; boundary={boundary}"}
        )

    payload = json.loads(_request(url, method, body,
                                  {**headers, "Content-Length": str(len(body))}))
    return payload["id"]
