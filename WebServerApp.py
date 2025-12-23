import os
import secrets
import hashlib
import hmac
import requests
from flask import Flask, request, redirect, session, jsonify, make_response

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
    """Step 1: Redirect user to Oura's authorization page."""
    scopes = "personal daily_readiness daily_sleep daily_activity heartrate"
    auth_params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": scopes,
        "state": secrets.token_hex(8)
    }
    # Build the URL
    target_url = f"{AUTH_URL}?{'&'.join([f'{k}={v}' for k, v in auth_params.items()])}"
    return redirect(target_url)

@app.route('/callback')
def callback():
    """Step 2: Handle redirect from Oura and exchange code for token."""
    code = request.args.get('code')
    
    # Exchange authorization code for an access token
    token_response = requests.post(TOKEN_URL, data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    })
    
    token_data = token_response.json()
    access_token = token_data.get('access_token')

    # --- STEP 3: AUTOMATIC WEBHOOK REGISTRATION ---
    # Now that we have a token, we tell Oura to start sending data to /webhook
    webhook_payload = {
        "callback_url": WEBHOOK_CALLBACK_URL,
        "data_type": "heart_rate",
        "event_type": "create"
    }
    
    reg_response = requests.post(
        WEBHOOK_REG_URL, 
        json=webhook_payload, 
        headers={"Authorization": f"Bearer {access_token}"}
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

if __name__ == '__main__':
    # Running on port 5000 to match Ngrok
    app.run(port=5000)