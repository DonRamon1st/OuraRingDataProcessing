import os
import secrets
import hashlib
import hmac
import requests
from flask import Flask, request, redirect, session, jsonify, make_response
import urllib.parse

app = Flask(__name__)
app.secret_key = secrets.token_hex(16) # For session security

# --- CONFIGURATION (Get these from the Oura Developer Console) ---
CLIENT_ID = "3ff70d92-7b94-4091-990f-9ecc8c8676e3"
CLIENT_SECRET = "s7O_FUNHmuHRnZpu4VpEuixMD0OnwMgl9kCIBz9Pj10"
# Must match exactly what you entered in the Oura Dev Portal
REDIRECT_URI = "https://doughtily-indifferent-kamilah.ngrok-free.dev/callback"
WEBHOOK_CALLBACK_URL = "https://doughtily-indifferent-kamilah.ngrok-free.dev/webhook"

# Oura Endpoints
AUTH_URL = "https://cloud.ouraring.com/oauth/authorize"
TOKEN_URL = "https://api.ouraring.com/oauth/token"
WEBHOOK_REG_URL = "https://api.ouraring.com/v2/webhook/subscription"

# --- 1. THE OAUTH FLOW ---

@app.route('/login')
def login():
    # 1. EXACTLY as it appears in Oura Developer Console
    # Make sure this matches your CURRENT Ngrok URL
    #redirect_uri = "https://your-ngrok-id.ngrok-free.app/callback"
    
    # 2. Standard Oura V2 Scopes 
    # (Removed 'daily_readiness' - v2 uses 'daily' for all summaries)
    scopes = ["personal", "daily", "heartrate", "workout", "tag", "session"]
    
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(scopes), # Space-separated list
        "state": secrets.token_hex(8)
    }
    
    # Build and URL-encode the parameters
    url_params = urllib.parse.urlencode(params)
    target_url = f"{AUTH_URL}?{url_params}"
    
    print(f"DEBUG: Redirecting to -> {target_url}")
    return redirect(target_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    token_response = requests.post(TOKEN_URL, data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    })
    
    token_data = token_response.json()
    access_token = token_data.get('access_token')

    # --- UPDATED WEBHOOK REGISTRATION ---
    webhook_payload = {
        "callback_url": WEBHOOK_CALLBACK_URL,
        "data_type": "heartrate",
        "event_type": "create"
    }
    
    # Oura V2 Webhooks require Client ID and Secret in the headers
    registration_headers = {
        "Authorization": f"Bearer {access_token}",
        "x-client-id": CLIENT_ID,
        "x-client-secret": CLIENT_SECRET,
        "Content-Type": "application/json"
    }
    
    reg_response = requests.post(
        WEBHOOK_REG_URL, 
        json=webhook_payload, 
        headers=registration_headers
    )
    
    return jsonify({
        "oauth_status": "Successful",
        "webhook_registration": reg_response.json()
    })

# --- 2. THE WEBHOOK LISTENER ---

@app.route('/webhook', methods=['GET', 'POST'])
def webhook_handler():
    # HANDSHAKE: Oura verifies this URL when we call the registration script
    if request.method == 'GET':
        challenge = request.args.get('challenge')
        return make_response(challenge, 200)

    # DATA PAYLOAD: Oura sends data updates here
    if request.method == 'POST':
        # Verify Security Signature
        oura_signature = request.headers.get('x-oura-signature')
        payload_bytes = request.get_data()
        
        expected_sig = hmac.new(
            CLIENT_SECRET.encode('utf-8'),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(oura_signature, expected_sig):
            return "Invalid signature", 401

        # LOG THE DATA
        data = request.json
        print(f"WEBHOOK RECEIVED: {data}")
        return "OK", 200

@app.route('/list_webhooks')
def list_webhooks():
    headers = {
        "x-client-id": CLIENT_ID,
        "x-client-secret": CLIENT_SECRET,
        # You'll need a valid access_token here
    }
    # This assumes you saved your access_token somewhere or are using a hardcoded one for testing
    res = requests.get("https://api.ouraring.com/v2/webhook/subscription", headers=headers)
    return res.json()


if __name__ == '__main__':
    # Running on port 5000 to match Ngrok
    app.run(port=5000)