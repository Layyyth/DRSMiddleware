import os
import json
from flask import Flask, request, jsonify, redirect
import requests
from firebase_admin import credentials, initialize_app, firestore
from google.auth.transport.requests import Request
from google.oauth2.id_token import verify_oauth2_token

app = Flask(__name__)

# Load Firebase credentials from a local file for testing
firebase_credentials_path = "/Users/layth/Documents/Developer/Backend + middleware/Nutriwise Firebase Admin SDK.json"  # Replace with your local file path
if not os.path.exists(firebase_credentials_path):
    raise FileNotFoundError(f"Firebase credentials file not found at {firebase_credentials_path}")

# Initialize Firebase Admin SDK
with open(firebase_credentials_path) as f:
    firebase_credentials_dict = json.load(f)

cred = credentials.Certificate(firebase_credentials_dict)
initialize_app(cred)

# Initialize Firestore
db = firestore.client()

# Google OAuth details for local testing
GOOGLE_CLIENT_ID = "15533879398-8pj96ktlsrh1m893b6khen4t11e6cv4e.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
REDIRECT_URI = "http://127.0.0.1:5001/auth/google-callback"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Route to initiate Google OAuth flow
@app.route("/auth/google", methods=["GET"])
def google_auth():
    # Generate URL for Google's OAuth authorization endpoint
    auth_url = (
        f"{GOOGLE_AUTH_URL}?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_type=code&"
        f"scope=email profile"
    )
    return redirect(auth_url)

# Route to handle the callback from Google
@app.route("/auth/google-callback", methods=["GET"])
def google_callback():
    # Extract the authorization code from the request
    auth_code = request.args.get("code")
    if not auth_code:
        return jsonify({"error": "Authorization code not found."}), 400

    try:
        # Exchange the authorization code for tokens
        token_data = {
            "code": auth_code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
        token_response.raise_for_status()
        tokens = token_response.json()
        id_token = tokens.get("id_token")
        access_token = tokens.get("access_token")

        if not id_token:
            return jsonify({"error": "ID Token not received."}), 400

        # Verify the ID Token
        decoded_token = verify_oauth2_token(id_token, Request())
        user_id = decoded_token.get("sub")
        user_email = decoded_token.get("email")
        user_name = decoded_token.get("name")
        user_picture = decoded_token.get("picture")

        # Log the decoded token for debugging
        print("Decoded Token:", decoded_token)

        # Store user in Firestore (or update if exists)
        user_data = {
            "uid": user_id,
            "email": user_email,
            "displayName": user_name,
            "photoURL": user_picture,
        }
        db.collection("accounts").document(user_id).set(user_data, merge=True)

        # Return user info to the frontend
        return jsonify({"message": "User signed in successfully", "user": user_data}), 200

    except Exception as e:
        # Log the error for debugging
        print("Error during Google callback:", e)
        return jsonify({"error": "Failed to authenticate with Google", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5001)

