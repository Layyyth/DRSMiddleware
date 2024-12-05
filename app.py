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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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

@app.route("/auth/google-callback", methods=["GET"])
def google_callback():
    auth_code = request.args.get("code")
    if not auth_code:
        return jsonify({"error": "Authorization code not found."}), 400

    try:
        print("Received auth code:", auth_code)
        
        token_data = {
            "code": auth_code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        print("Token data:", token_data)

        token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
        token_response.raise_for_status()
        tokens = token_response.json()
        print("Token response:", tokens)

        id_token = tokens.get("id_token")
        if not id_token:
            print("No ID Token in response")
            return jsonify({"error": "ID Token not received."}), 400

        decoded_token = verify_oauth2_token(id_token, Request())
        print("Decoded token:", decoded_token)

        user_id = decoded_token.get("sub")
        user_email = decoded_token.get("email")
        user_name = decoded_token.get("name")
        user_picture = decoded_token.get("picture")
        print(f"User info: {user_id}, {user_email}, {user_name}, {user_picture}")

        session_key = generate_session_key()
        print("Generated session key:", session_key)

        user_data = {
            "uid": user_id,
            "email": user_email,
            "displayName": user_name,
            "photoURL": user_picture,
            "sessionKey": session_key,
        }
        db.collection("accounts").document(user_id).set(user_data, merge=True)
        print("User data saved to Firestore")

        redirect_url = f"https://whippet-just-endlessly.ngrok-free.app/?key={session_key}"
        print("Redirecting to:", redirect_url)
        return redirect(redirect_url)

    except Exception as e:
        print("Error during Google callback:", e)
        return jsonify({"error": "Failed to authenticate with Google", "message": str(e)}), 500


def send_verification_email(email, verification_link, name):
    try:
        # Gmail SMTP server setup
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "justgradproject25@gmail.com"  # Replace with your Gmail

        # Fetch the app password from environment variables
        sender_password = os.getenv("APP_PASSWORD")
        if not sender_password:
            raise ValueError("APP_PASSWORD environment variable not set.")

        # Create the email content
        message = MIMEMultipart("alternative")
        message["Subject"] = "Verify Your Email"
        message["From"] = sender_email
        message["To"] = email

        # Email body
        html_content = f"""
        <html>
        <body>
            <p>Hi {name},</p>
            <p>Thank you for signing up! Please verify your email by clicking the link below:</p>
            <a href="{verification_link}">Verify Email</a>
            <p>If you didn't sign up, please ignore this email.</p>
        </body>
        </html>
        """
        message.attach(MIMEText(html_content, "html"))

        # Connect to the Gmail SMTP server and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, message.as_string())
        print(f"Verification email sent to {email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

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

        # Generate email verification link
        verification_link = auth.generate_email_verification_link(email)

        # Send email using Gmail SMTP
        send_verification_email(email, verification_link, name)

        # Create document in Firestore
        user_data = {
            "uid": firebase_user.uid,
            "email": email,
            "displayName": name,
            "photoURL": photo_url,
            "sessionKey": session_key,
            "emailVerified": False,
            "verificationLinkSent": True,
            "verificationLinkTimestamp": firestore.SERVER_TIMESTAMP
        }
        db.collection("accounts").document(firebase_user.uid).set(user_data)

        return jsonify({
            "message": "Account created successfully. Please check your email to verify your account.",
            "sessionKey": session_key,
            "requiresEmailVerification": True
        }), 201

    except Exception as e:
        print("Error Creating Account:", e)
        return jsonify({"error": "Failed to create account", "message": str(e)}), 500


@app.route("/auth/verify-email", methods=["POST"])
def verify_email():
    try:
        # Get the action code from the request body
        data = request.json
        action_code = data.get("actionCode")

        if not action_code:
            return jsonify({"error": "Action code is required"}), 400

        # Apply the action code to verify the email
        try:
            # Firebase Admin SDK does not directly handle action codes; use the Firebase REST API
            FIREBASE_WEB_API_KEY = os.getenv("FIREBASE_WEB_API_KEY")
            if not FIREBASE_WEB_API_KEY:
                raise ValueError("FIREBASE_WEB_API_KEY environment variable not set.")

            verify_email_url = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={FIREBASE_WEB_API_KEY}"
            payload = {
                "oobCode": action_code
            }

            response = requests.post(verify_email_url, json=payload)
            response_data = response.json()

            if response.status_code != 200:
                return jsonify({
                    "error": "Email verification failed",
                    "message": response_data.get("error", {}).get("message", "Unknown error")
                }), 400

            # Get the user's email from the response
            email = response_data.get("email")

            if not email:
                return jsonify({"error": "Email not found in verification response"}), 400

            # Update Firestore and mark email as verified
            user = auth.get_user_by_email(email)
            auth.update_user(user.uid, email_verified=True)

            user_ref = db.collection("accounts").document(user.uid)
            user_ref.update({
                "emailVerified": True,
                "verificationCompletedTimestamp": firestore.SERVER_TIMESTAMP
            })

            return jsonify({
                "message": "Email successfully verified",
                "email": email,
                "emailVerified": True
            }), 200

        except Exception as e:
            print(f"Error applying action code: {e}")
            return jsonify({"error": "Failed to process email verification", "message": str(e)}), 500

    except Exception as e:
        print(f"Error in email verification process: {e}")
        return jsonify({"error": "Failed to process email verification", "message": str(e)}), 500




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


@app.route("/auth/reset-password", methods=["POST"])
def reset_password():
    """
    Endpoint to send a password reset email to the user.
    """
    try:
        # Get the email from the request body
        data = request.json
        email = data.get("email")

        if not email:
            return jsonify({"error": "Email is required"}), 400

        # Check if the email exists in Firebase Authentication
        try:
            auth.get_user_by_email(email)
        except auth.UserNotFoundError:
            return jsonify({"message": "Email does not exist"}), 200

        # Firebase REST API Endpoint for sending password reset emails
        FIREBASE_PASSWORD_RESET_URL = "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key="

        # Firebase Web API Key (retrieved from your Firebase project settings)
        FIREBASE_WEB_API_KEY = os.getenv("FIREBASE_WEB_API_KEY")
        if not FIREBASE_WEB_API_KEY:
            return jsonify({"error": "Firebase Web API Key is not configured"}), 500

        # Make a POST request to Firebase to send the password reset email
        payload = {
            "requestType": "PASSWORD_RESET",
            "email": email
        }
        response = requests.post(FIREBASE_PASSWORD_RESET_URL + FIREBASE_WEB_API_KEY, json=payload)

        # Check the response status
        if response.status_code == 200:
            return jsonify({"message": "Password reset email sent successfully"}), 200
        else:
            error_message = response.json().get("error", {}).get("message", "Failed to send password reset email")
            return jsonify({"error": "Failed to send password reset email", "details": error_message}), 400

    except Exception as e:
        print("Error during password reset:", e)
        return jsonify({"error": "Failed to process password reset request", "message": str(e)}), 500


@app.route("/info-gathered-toggle", methods=["POST"])
def info_gathered_toggle():
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

        # Fetch current user data
        user_ref = users_ref.document(user_doc.id)
        user_data = user_doc.to_dict()

        # Toggle the `infoGathered` field
        current_status = user_data.get("infoGathered", False)
        new_status = not current_status

        # Update the `infoGathered` field in Firestore
        user_ref.update({
            "infoGathered": new_status
        })

        # Fetch updated user data
        updated_user_data = user_ref.get().to_dict()

        return jsonify({
            "message": "infoGathered toggled successfully",
            "infoGathered": new_status,
            "user": updated_user_data
        }), 200

    except Exception as e:
        print("Error toggling infoGathered:", e)
        return jsonify({"error": "Failed to toggle infoGathered", "message": str(e)}), 500



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

        if not user_data.get("emailVerified", False):
            # Instead of returning 403, inform the frontend that the user is unverified
            return jsonify({
                "message": "User email is not verified. Please verify your email.",
                "emailVerified": False,
            }), 200

        # Return user data to the frontend if verified
        return jsonify({
            "user": user_data,
            "emailVerified": True
        }), 200

    except Exception as e:
        print("Error fetching user data:", e)
        return jsonify({"error": "Failed to fetch user data", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.getenv("PORT", 5001)))

