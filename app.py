import os
import json
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
import requests
from firebase_admin import credentials, initialize_app, firestore
from google.auth.transport.requests import Request
from google.oauth2.id_token import verify_oauth2_token

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "https://nutri-wise.vercel.app/"}})


# Load Firebase credentials from an environment variable
firebase_credentials_json = os.getenv("FIREBASE_CREDENTIALS")
if firebase_credentials_json is None:
    raise ValueError("FIREBASE_CREDENTIALS environment variable not set.")

# Parse the Firebase credentials JSON string to a Python dictionary
firebase_credentials_dict = json.loads(firebase_credentials_json)

# Initialize Firebase Admin SDK
cred = credentials.Certificate(firebase_credentials_dict)
initialize_app(cred)

# Initialize Firestore
db = firestore.client()

# Google OAuth details (retrieved from environment variables)
GOOGLE_CLIENT_ID = os.getenv("Google_ID")
GOOGLE_CLIENT_SECRET = os.getenv("Google_secret")
REDIRECT_URI = os.getenv("REDIRECT_URI")
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise ValueError("GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET environment variable not set.")

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
        # Log the error for debugging in production
        print("Error during Google callback:", e)
        return jsonify({"error": "Failed to authenticate with Google", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.getenv("PORT", 5001)))

