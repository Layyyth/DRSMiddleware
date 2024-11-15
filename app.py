import os
import json
from flask import Flask, request, jsonify
import requests
import firebase_admin
from firebase_admin import firestore, credentials
from google.auth.transport.requests import Request
from google.oauth2.id_token import verify_oauth2_token
from flask_cors import CORS  # Import CORS

app = Flask(__name__)

# Specify the allowed origins for CORS
origins = [
    'https://nutri-wise.vercel.app',
    'https://nutri-wise-lq7zew6rf-layyyths-projects.vercel.app',
    'https://whippet-just-endlessly.ngrok-free.app'  # Include the ngrok URL
]

# Configure CORS for the /auth/google-signin endpoint and any other required routes
CORS(app, resources={r"/auth/google-signin": {"origins": origins, "methods": ["POST", "OPTIONS"]}})
CORS(app, resources={r"/user/*": {"origins": origins, "methods": ["GET", "PUT", "OPTIONS"]}})

# Handle OPTIONS requests for specific routes
@app.route('/auth/google-signin', methods=['OPTIONS'])
def handle_options_google_signin():
    response = jsonify({"message": "OK"})
    response.headers.add('Access-Control-Allow-Origin', ', '.join(origins))
    response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    return response

@app.route('/user/<user_id>', methods=['OPTIONS'])
def handle_options_user(user_id):
    response = jsonify({"message": "OK"})
    response.headers.add('Access-Control-Allow-Origin', ', '.join(origins))
    response.headers.add('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    return response

# Load Firebase credentials from the FIREBASE_CREDENTIALS environment variable
firebase_credentials_json = os.getenv("FIREBASE_CREDENTIALS")
if firebase_credentials_json is None:
    raise ValueError("FIREBASE_CREDENTIALS environment variable not set.")

# Parse the JSON string to a Python dictionary
firebase_credentials_dict = json.loads(firebase_credentials_json)

# Initialize Firebase with the credentials dictionary
cred = credentials.Certificate(firebase_credentials_dict)
firebase_admin.initialize_app(cred)

# Initialize Firestore
db = firestore.client()

# Middleware to verify the ID token using Google's public certificates
def verify_oauth_middleware(func):
    def wrapper(*args, **kwargs):
        # Extract the idToken from the request JSON
        id_token = request.json.get("idToken")
        if not id_token:
            return jsonify({"error": "No idToken provided"}), 400

        try:
            # Fetch Google's public certificates
            GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
            response = requests.get(GOOGLE_CERTS_URL)
            response.raise_for_status()
            google_certs = response.json()

            # Verify the idToken using the fetched certificates
            decoded_token = verify_oauth2_token(id_token, Request(), certs=google_certs)

            # Attach user info to the request for further processing
            request.user_info = decoded_token

        except Exception as e:
            print("Error verifying ID token:", e)
            return jsonify({"error": "Authentication failed"}), 401

        return func(*args, **kwargs)  # Continue with the request

    return wrapper

@app.route("/auth/google-signin", methods=["POST"])
@verify_oauth_middleware  # Apply the middleware here
def google_signin():
    user_info = request.user_info  # This comes from the middleware
    user_id = user_info["sub"]
    
    # Create a user info dictionary to store in Firestore
    user_data = {
        "uid": user_id,
        "email": user_info.get("email"),
        "display_name": user_info.get("name"),
        "photo_url": user_info.get("picture"),
    }

    # Store user in Firestore (or update if exists)
    db.collection("users").document(user_id).set(user_data, merge=True)

    return jsonify({"message": "User signed in successfully", "user": user_data}), 200

@app.route("/user/<user_id>", methods=["GET"])
def get_user(user_id):
    try:
        user_doc = db.collection("users").document(user_id).get()
        if user_doc.exists:
            return jsonify(user_doc.to_dict()), 200
        else:
            return jsonify({"error": "User not found!"}), 404
    except Exception as e:
        print("Error retrieving user:", e)
        return jsonify({"error": "Failed to retrieve user"}), 500

@app.route("/user/<user_id>", methods=["PUT"])
def update_user(user_id):
    updated_data = request.json
    try:
        db.collection("users").document(user_id).update(updated_data)
        return jsonify({"message": "User updated successfully"}), 200
    except Exception as e:
        print("Error updating user info:", e)
        return jsonify({"error": "Failed to update user"}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))

