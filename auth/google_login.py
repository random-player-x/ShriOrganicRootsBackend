import azure.functions as func
import logging
import json
import jwt
import bcrypt
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
import os
import certifi
import html
import requests  # To verify the Google ID token

if os.path.exists('.env'):
    from dotenv import load_dotenv
    load_dotenv()

google_login_bp = func.Blueprint()

# Load environment variables
MONGO_URI = os.environ.get('MONGO_URI')
JWT_SECRET = os.environ.get('JWT_SECRET')
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')  # Add this in your environment variables

if not MONGO_URI or not JWT_SECRET or not GOOGLE_CLIENT_ID:
    raise ValueError("MONGO_URI, JWT_SECRET, and GOOGLE_CLIENT_ID must be set in environment variables.")

DB_NAME = "organic"
COLLECTION_NAME = "users" 

# Connect to MongoDB
mongo_client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = mongo_client[DB_NAME]
users_collection = db[COLLECTION_NAME]

@google_login_bp.route(route="google-login", auth_level=func.AuthLevel.ANONYMOUS)
def google_login(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing Google login.')

    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse('Invalid JSON input', status_code=400)

    google_token = req_body.get('token')
    if not google_token:
        return func.HttpResponse('Google token is required', status_code=400)

    try:
        # Step 1: Verify the Google token with Google's API
        google_verify_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={google_token}"
        response = requests.get(google_verify_url)
        
        if response.status_code != 200:
            return func.HttpResponse('Invalid Google token.', status_code=401)
        
        google_data = response.json()

        # Step 2: Check if the token's audience matches your client ID
        if google_data['aud'] != GOOGLE_CLIENT_ID:
            return func.HttpResponse('Invalid Google client ID.', status_code=401)

        # Step 3: Retrieve user information from Google token
        google_email = google_data.get('email')
        google_name = google_data.get('name')
        
        if not google_email:
            return func.HttpResponse('Google token does not contain email.', status_code=400)

        # Step 4: Check if user exists in your database
        user = users_collection.find_one({'email': google_email})
        
        if user:
            # User exists, generate JWT token
            token = jwt.encode({
                'userId': str(user['_id']),
                'email': google_email,
                'exp': datetime.now(timezone.utc) + timedelta(days=2)
            }, JWT_SECRET, algorithm='HS512')

            # Prepare the user response data
            user_data = {
                'id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'isEmailVerified': user['isEmailVerified'],
                'isAdmin': user.get('isAdmin', False)
            }

        else:
            # Step 5: If user doesn't exist, create a new user (optional)
            new_user = {
                'email': google_email,
                'username': google_name,  # You can also let the user edit their username later
                'password': None,  # No password because they're using Google to log in
                'isEmailVerified': True,  # Since this is Google, the email is verified
                'isAdmin': False,  # Default to non-admin unless you have other criteria
                'createdAt': datetime.now()
            }
            result = users_collection.insert_one(new_user)
            new_user_id = result.inserted_id

            # Generate JWT for the new user
            token = jwt.encode({
                'userId': str(new_user_id),
                'email': google_email,
                'exp': datetime.now(timezone.utc) + timedelta(days=2)
            }, JWT_SECRET, algorithm='HS512')

            user_data = {
                'id': str(new_user_id),
                'username': google_name,
                'email': google_email,
                'isEmailVerified': True,
                'isAdmin': False
            }

        # Step 6: Return the JWT token and user data
        response_data = {
            'message': 'Google login successful',
            'token': token,
            'user': user_data
        }
        return func.HttpResponse(json.dumps(response_data), mimetype="application/json", status_code=200)
    
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
