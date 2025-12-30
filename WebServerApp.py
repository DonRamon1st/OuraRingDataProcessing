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

#Webhook List URL
Webhook_List_URL = "https://doughtily-indifferent-kamilah.ngrok-free.dev/list"

# --- 1. THE OAUTH FLOW & CALL BACK ---

@app.route('/')
def login():
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
    
    #Prints the target URL created and encoded based on the parameters above
    print(f"DEBUG: Redirecting to -> {target_url}")
    
    #Login function redirects user to Oura's OAuth authorization page
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
    
    #Stiore the access token in variable for later use
    global access_token 
    access_token = token_data.get('access_token')
    print("The access token received is:", access_token) 
    #return access_token
    return redirect(Webhook_List_URL)


# --- 2. THE WEBHOOK CALL API - Create Webhook ---
@app.route('/create_webhook')
def create_webhook():
    
    #Webhook header payload - Oura V2 Webhooks require Client ID and Secret in the headers
    registration_headers = {
        "Authorization": f"Bearer {access_token}",
        "x-client-id": CLIENT_ID,
        "x-client-secret": CLIENT_SECRET,
        "Content-Type": "application/json"
    }
    
    #Webhook registration payload
    webhook_payload = {
        "callback_url": WEBHOOK_CALLBACK_URL,
        "verification_token": access_token,
        "event_type": "create", #Event_Type can be 'create', 'update', or 'delete'
        "data_type": "daily_activity" #Data Type can be as described in Oura's documentation https://cloud.ouraring.com/v2/docs#operation/create_webhook_subscription_v2_webhook_subscription_post
    }

    #Build the POST request to register the webhook
    reg_response = requests.post(
        WEBHOOK_REG_URL, 
        headers=registration_headers,
        json=webhook_payload       
    )
    

    ##Calls jsonify to return the status of the webhook registration and its response
    return jsonify({
        "response_status": "tbc",
        "webhook_registration_responseHeaders": dict(reg_response.headers),
        "webhook_registration_responseText": reg_response.text,
        "webhook_registration_responseJSON": reg_response.json(),
        "webhook_response_status_code": reg_response.status_code
    })
    
           
# --- 3. THE WEBHOOK LISTENER ---
@app.route('/webhook', methods=['GET', 'POST'])
def webhook_handler():
    # HANDSHAKE
    if request.method == 'GET':
        challenge = request.args.get('challenge')
        return jsonify({"challenge": challenge}), 200

    # DATA PAYLOAD
    if request.method == 'POST':
        oura_signature = request.headers.get('x-oura-signature')
        payload_bytes = request.get_data()

        expected_sig = hmac.new(
            CLIENT_SECRET.encode('utf-8'),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(oura_signature, expected_sig):
            return "Invalid signature", 401

        data = request.json
        print(f"WEBHOOK RECEIVED: {data}")
        return "OK", 200

@app.route('/GetWebhook-SleepData')
def GetWebhook_SleepData():
    headers = {
        "x-client-id": CLIENT_ID,
        "x-client-secret": CLIENT_SECRET,
        # You'll need a valid access_token here
    }
    id = "1034914d-34b1-423c-97fc-ecf181de972b"
    #Create the GET request to list this Webhook with the id prvided
    res = requests.get(f"https://api.ouraring.com/v2/webhook/subscription/{id}", headers=headers)
    
    return jsonify({
        "response_status": "Listing Sleep webhook",
        "webhook_response_status_code": res.status_code,
        "webhook_registration_responseHeaders": dict(res.headers),
        "webhook_registration_responseText": res.text,
        "webhook_registration_responseJSON": res.json()
    })

@app.route('/list')
def list_webhooks():
    headers = {
        "x-client-id": CLIENT_ID,
        "x-client-secret": CLIENT_SECRET,
        # You'll need a valid access_token here
    }
    # This assumes you saved your access_token somewhere or are using a hardcoded one for testing
    res = requests.get("https://api.ouraring.com/v2/webhook/subscription", headers=headers)
    
    return jsonify({
        "response_status": "Listing all webhooks",
        "webhook_response_status_code": res.status_code,
        "webhook_registration_responseHeaders": dict(res.headers),
        "webhook_registration_responseText": res.text,
        "webhook_registration_responseJSON": res.json()
    })


if __name__ == '__main__':
    # Running on port 5000 to match Ngrok
    app.run(port=5000)