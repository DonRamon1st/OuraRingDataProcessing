# --------------------------------------------------
# Load Libraries
# --------------------------------------------------
import os
import time
import json
import hmac
import hashlib
import secrets
import sqlite3
import requests
import urllib.parse
from flask import Flask, request, redirect, jsonify

# --------------------------------------------------
# Flask setup
# --------------------------------------------------
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# --------------------------------------------------
# Configuration (MOVE SECRETS TO ENV IN PROD)
# --------------------------------------------------
CLIENT_ID = "3ff70d92-7b94-4091-990f-9ecc8c8676e3"
CLIENT_SECRET = "s7O_FUNHmuHRnZpu4VpEuixMD0OnwMgl9kCIBz9Pj10"

REDIRECT_URI = "https://doughtily-indifferent-kamilah.ngrok-free.dev/callback"
WEBHOOK_CALLBACK_URL = "https://doughtily-indifferent-kamilah.ngrok-free.dev/webhook"

AUTH_URL = "https://cloud.ouraring.com/oauth/authorize"
TOKEN_URL = "https://api.ouraring.com/oauth/token"
WEBHOOK_REG_URL = "https://api.ouraring.com/v2/webhook/subscription"

WEBHOOK_SECRET = os.environ.get(
    "OURA_WEBHOOK_SECRET",
    secrets.token_hex(32)
)

# --------------------------------------------------
# Database
# --------------------------------------------------
DB_PATH = "oura.db"
USER_ID = "default_user"  # single-user app for now

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # OAuth tokens
    cur.execute("""
        CREATE TABLE IF NOT EXISTS oauth_tokens (
            user_id TEXT PRIMARY KEY,
            access_token TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)

    # Webhook events (signals)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            data_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            raw_payload TEXT NOT NULL
        )
    """)

    # Real session data (fetched from Oura API)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS session_data (
            session_id TEXT PRIMARY KEY,
            start_time TEXT,
            end_time TEXT,
            type TEXT,
            score REAL,
            raw_json TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

init_db()

# --------------------------------------------------
# OAuth Token Helpers
# --------------------------------------------------
def save_token(token_data):
    expires_at = int(time.time()) + token_data["expires_in"]

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        INSERT OR REPLACE INTO oauth_tokens
        (user_id, access_token, refresh_token, expires_at)
        VALUES (?, ?, ?, ?)
    """, (
        USER_ID,
        token_data["access_token"],
        token_data["refresh_token"],
        expires_at
    ))

    conn.commit()
    conn.close()


def refresh_access_token(refresh_token):
    res = requests.post(TOKEN_URL, data={
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    })

    res.raise_for_status()
    token_data = res.json()
    save_token(token_data)
    return token_data["access_token"]


def get_access_token():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT access_token, refresh_token, expires_at
        FROM oauth_tokens
        WHERE user_id = ?
    """, (USER_ID,))

    row = cur.fetchone()
    conn.close()

    if not row:
        raise Exception("User not authenticated")

    access_token, refresh_token, expires_at = row

    if time.time() >= expires_at:
        return refresh_access_token(refresh_token)

    return access_token

# --------------------------------------------------
# Webhook + Data Helpers
# --------------------------------------------------
# Save webhook event to DB data extracted from payload/json
def save_webhook_event(data):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO webhook_events
        (received_at, event_type, data_type, object_id, raw_payload)
        VALUES (?, ?, ?, ?, ?)
    """, (
        int(time.time()),
        data.get("event_type"),
        data.get("data_type"),
        data.get("object_id"),
        json.dumps(data)
    ))

    conn.commit()
    conn.close()

# Fetch session data from Oura API Single Call using session_id and saved access token
def fetch_session_data(session_id):
    headers = {
        "Authorization": f"Bearer {get_access_token()}"
    }

    res = requests.get(
        f"https://api.ouraring.com/v2/usercollection/session/{session_id}",
        headers=headers
    )

    res.raise_for_status()
    return res.json()

# Save session data of the real data to DB
def save_session_data(session):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        INSERT OR REPLACE INTO session_data
        (session_id, start_time, end_time, type, score, raw_json)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        session.get("id"),
        session.get("start_time"),
        session.get("end_time"),
        session.get("type"),
        session.get("score"),
        json.dumps(session)
    ))

    conn.commit()
    conn.close()

# --------------------------------------------------
# OAuth Flow
# --------------------------------------------------
@app.route('/')
def login():
    scopes = ["personal", "daily", "heartrate", "workout", "tag", "session"]

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(scopes),
        "state": secrets.token_hex(8)
    }

    return redirect(f"{AUTH_URL}?{urllib.parse.urlencode(params)}")


@app.route('/callback')
def callback():
    code = request.args.get('code')

    res = requests.post(TOKEN_URL, data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    })

    res.raise_for_status()
    token_data = res.json()
    save_token(token_data)

    return redirect("/list")

# --------------------------------------------------
# Webhook Registration
# --------------------------------------------------
@app.route('/create_webhook')
def create_webhook():
    headers = {
        "Authorization": f"Bearer {get_access_token()}",
        "x-client-id": CLIENT_ID,
        "x-client-secret": CLIENT_SECRET,
        "Content-Type": "application/json"
    }

    payload = {
        "callback_url": WEBHOOK_CALLBACK_URL,
        "verification_token": WEBHOOK_SECRET,
        "event_type": "create",
        "data_type": "daily_stress"
    }

    res = requests.post(WEBHOOK_REG_URL, headers=headers, json=payload)

    return jsonify(res.json()), res.status_code

# --------------------------------------------------
# Webhook Listener
# --------------------------------------------------
@app.route('/webhook', methods=['GET', 'POST'])
def webhook_handler():
    # Handshake
    if request.method == 'GET':
        return jsonify({"challenge": request.args.get("challenge")})

    # Verify signature
    payload_bytes = request.get_data()
    signature = request.headers.get("x-oura-signature")

    expected_sig = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        return "Invalid signature", 401

    data = request.json
    print("WEBHOOK RECEIVED:", json.dumps(data, indent=2))

    # 1) Store webhook event
    save_webhook_event(data)

    # 2) Fetch & store real session data
    if data["data_type"] == "session" and data["event_type"] in ("create", "update"):
        try:
            session = fetch_session_data(data["object_id"])
            save_session_data(session)
            print(f"Session {data['object_id']} stored successfully")
        except Exception as e:
            print("Failed to fetch/store session:", e)

    return "OK", 200

# --------------------------------------------------
# List ALL Webhooks
# --------------------------------------------------
@app.route('/list')
def list_webhooks():
    headers = {
        "x-client-id": CLIENT_ID,
        "x-client-secret": CLIENT_SECRET
    }

    res = requests.get(
        "https://api.ouraring.com/v2/webhook/subscription",
        headers=headers
    )

    return jsonify(res.json()), res.status_code

# --------------------------------------------------
# App Entry Point
# --------------------------------------------------
if __name__ == '__main__':
    app.run(port=5000)
