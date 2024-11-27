from logging import exception
import os
import json
import uuid
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
import requests
from firebase_admin import credentials, initialize_app, firestore, auth
from google.auth.transport.requests import Request
from google.oauth2.id_token import verify_oauth2_token

app = Flask(__name__)

# Temporary: Allow all origins
CORS(app, resources={r"/*": {"origins": "*"}})

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
    raise ValueError("GOOGLE_CLIENT_ID or GOOGLE_SECRET environment variable not set.")

# Utility function to generate a session key
def generate_session_key():
    return str(uuid.uuid4())

# Route to initiate Google OAuth flow
@app.route("/auth/google", methods=["GET"])
def google_auth():
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
    auth_code = request.args.get("code")
    if not auth_code:
        return jsonify({"error": "Authorization code not found."}), 400

    try:
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

        if not id_token:
            return jsonify({"error": "ID Token not received."}), 400

        decoded_token = verify_oauth2_token(id_token, Request())
        user_id = decoded_token.get("sub")
        user_email = decoded_token.get("email")
        user_name = decoded_token.get("name")
        user_picture = decoded_token.get("picture")

        session_key = generate_session_key()

        # Fetch user data from Firestore
        user_ref = db.collection("accounts").document(user_id)
        user_doc = user_ref.get()
        if user_doc.exists():
            # If user exists, update session key
            user_data = user_doc.to_dict()
            user_ref.update({"sessionKey": session_key})
        else:
            # Create new user if not exists
            user_data = {
                "uid": user_id,
                "email": user_email,
                "displayName": user_name,
                "photoURL": user_picture,
                "sessionKey": session_key,
            }
            user_ref.set(user_data)

        # Generate the redirect URL
        redirect_url = f"https://whippet-just-endlessly.ngrok-free.app/?key={session_key}"

        # Return the redirection
        return redirect(redirect_url)

    except Exception as e:
        print("Error during Google callback:", e)
        return jsonify({"error": "Failed to authenticate with Google", "message": str(e)}), 500

@app.route("/auth/create-user", methods=["POST"])
def create_account():
    try:
        data = request.json
        name = data.get("displayName")
        email = data.get("email")
        password = data.get("password")
        photo_url = data.get("photoURL")

        if not name or not email or not password:
            return jsonify({"error": "Name, email, and password are required"}), 400

        # Check if the user already exists in Firebase Authentication
        try:
            existing_user = auth.get_user_by_email(email)
            # Fetch the user's document
            user_ref = db.collection("accounts").document(existing_user.uid)
            user_doc = user_ref.get()

            if user_doc.exists:
                # Redirect based on NutriInfo availability
                user_data = user_doc.to_dict()
                session_key = generate_session_key()
                user_ref.update({"sessionKey": session_key})  # Update session key
                return jsonify({
                    "message": "User already exists",
                    "user": user_data,
                    "sessionKey": session_key
                }), 200

        except auth.UserNotFoundError:
            pass  # Continue to create the account if the user is not found

        # Generate a session key
        session_key = generate_session_key()

        # Create user in Firebase Authentication
        firebase_user = auth.create_user(
            email=email,
            password=password,
        )

        # Create document in Firestore
        user_data = {
            "uid": firebase_user.uid,
            "email": email,
            "displayName": name,
            "photoURL": photo_url,
            "sessionKey": session_key,  # Save session key to Firestore
        }

        db.collection("accounts").document(firebase_user.uid).set(user_data)

        # Return sessionKey and user data to the frontend
        return jsonify({
            "message": "Account created successfully",
            "user": user_data,
            "sessionKey": session_key
        }), 201

    except Exception as e:
        print("Error Creating Account", e)
        return jsonify({"error": "Failed to create account", "message": str(e)}), 500

@app.route("/update-nutri-info", methods=["POST"])
def update_nutri_info():
    try:
        data = request.json
        session_key = data.get("sessionKey")  
        nutri_info = data.get("NutriInfo")   

        if not session_key:
            return jsonify({"error": "Session key is required"}), 400

        if not nutri_info:
            return jsonify({"error": "NutriInfo data is required"}), 400

        # Query Firestore for the user with the given session key
        users_ref = db.collection("accounts")
        query = users_ref.where("sessionKey", "==", session_key).stream()

        user_doc = None
        for doc in query:
            user_doc = doc
            break

        if not user_doc:
            return jsonify({"error": "Invalid session key"}), 401

        # Update the NutriInfo field in Firestore
        user_ref = users_ref.document(user_doc.id)
        user_ref.update({
            "NutriInfo": nutri_info,
            "infoGatheredInit": True,
            "infoGathered": True,
        })

        # Fetch updated user data
        updated_user_data = user_ref.get().to_dict()

        return jsonify({
            "message": "NutriInfo updated successfully",
            "user": updated_user_data,
        }), 200

    except Exception as e:
        print("Error updating NutriInfo:", e)
        return jsonify({"error": "Failed to update NutriInfo", "message": str(e)}), 500


@app.route("/auth/login-with-pass", methods=["POST"])
def login_user():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        # Firebase REST API Endpoint for password authentication
        FIREBASE_AUTH_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key="

        # Firebase Web API Key (retrieved from your Firebase project settings)
        FIREBASE_WEB_API_KEY = os.getenv("FIREBASE_WEB_API_KEY")
        if not FIREBASE_WEB_API_KEY:
            return jsonify({"error": "Firebase Web API Key is not configured"}), 500

        # Make a POST request to Firebase Authentication REST API
        auth_payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }

        response = requests.post(FIREBASE_AUTH_URL + FIREBASE_WEB_API_KEY, json=auth_payload)

        if response.status_code != 200:
            # If Firebase REST API returns an error, pass it to the frontend
            error_message = response.json().get("error", {}).get("message", "Authentication failed")
            return jsonify({"error": "Invalid email or password", "details": error_message}), 401

        # Parse the Firebase response
        auth_response = response.json()
        user_id = auth_response["localId"]
        id_token = auth_response["idToken"]

        # Generate a session key
        session_key = generate_session_key()

        # Update Firestore with the new session key
        user_ref = db.collection("accounts").document(user_id)
        user_ref.update({"sessionKey": session_key})

        # Fetch updated user data
        updated_user_data = user_ref.get().to_dict()

        # Return the session key and user info to the frontend
        return jsonify({
            "message": "Login successful",
            "user": updated_user_data,
            "sessionKey": session_key,
            "idToken": id_token  # Optionally return the ID token
        }), 200

    except Exception as e:
        print("Error during login:", e)
        return jsonify({"error": "Failed to log in", "message": str(e)}), 500


@app.route("/info-gathered-false", methods=["POST"])
def info_gathered_false():
    try:
        data = request.json
        session_key = data.get("sessionKey")  # Expect the session key in the request body

        if not session_key:
            return jsonify({"error": "Session key is required"}), 400

        # Query Firestore for the user with the given session key
        users_ref = db.collection("accounts")
        query = users_ref.where("sessionKey", "==", session_key).stream()

        user_doc = None
        for doc in query:
            user_doc = doc
            break

        if not user_doc:
            return jsonify({"error": "Invalid session key"}), 401

        # Update the infoGathered field in Firestore
        user_ref = users_ref.document(user_doc.id)
        user_ref.update({
            "infoGathered": False
        })

        # Fetch updated user data
        updated_user_data = user_ref.get().to_dict()

        return jsonify({
            "message": "infoGathered set to false successfully",
            "user": updated_user_data
        }), 200

    except Exception as e:
        print("Error updating infoGathered:", e)
        return jsonify({"error": "Failed to update infoGathered", "message": str(e)}), 500



@app.route("/auth/fetch-user", methods=["POST"])
def fetch_user_data():
    try:
        session_key = request.json.get("sessionKey")  # Expect the session key in the request body
        if not session_key:
            return jsonify({"error": "Session key is required"}), 400

        # Query Firestore for the user with the given session key
        users_ref = db.collection("accounts")
        query = users_ref.where("sessionKey", "==", session_key).stream()

        user_data = None
        for doc in query:
            user_data = doc.to_dict()
            break

        if not user_data:
            return jsonify({"error": "Invalid session key"}), 401

        # Return user data to the frontend
        return jsonify({"user": user_data}), 200

    except Exception as e:
        print("Error fetching user data:", e)
        return jsonify({"error": "Failed to fetch user data", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.getenv("PORT", 5001)))

