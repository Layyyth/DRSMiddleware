import os
import json
from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import auth, firestore, credentials
from flask_cors import CORS  # Import CORS

app = Flask(__name__)

# Specify the allowed origins for CORS
origins = [
    'https://nutri-wise.vercel.app',
    'https://nutri-wise-lq7zew6rf-layyyths-projects.vercel.app',
    'https://whippet-just-endlessly.ngrok-free.app'  # Include the ngrok URL
]

# Configure CORS for the /predict endpoint
CORS(app, resources={r"/predict": {"origins": origins, "methods": ["GET", "POST", "OPTIONS"]}})

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

@app.route("/auth/google-signin", methods=["POST"])
def google_signin():
    id_token = request.json.get("idToken")

    try:
        # Verifying the token
        decoded_token = auth.verify_id_token(id_token)
        user_id = decoded_token["uid"]

        user_info = {
            "uid": user_id,
            "email": decoded_token.get("email"),
            "display_name": decoded_token.get("name"),
            "photo_url": decoded_token.get("picture"),
        }

        # Store user in Firestore
        db.collection("users").document(user_id).set(user_info, merge=True)
        return jsonify({"message": "User signed in successfully", "user": user_info}), 200

    except Exception as e:
        print("Error verifying ID token:", e)
        return jsonify({"error": "Authentication failed"}), 401

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

