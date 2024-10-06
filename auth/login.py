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

if os.path.exists('.env'):
    from dotenv import load_dotenv
    load_dotenv()

login_bp = func.Blueprint()

# Load environment variables
MONGO_URI = os.environ.get('MONGO_URI')
JWT_SECRET = os.environ.get('JWT_SECRET')

if not MONGO_URI or not JWT_SECRET:
    raise ValueError("MONGO_URI and JWT_SECRET must be set in environment variables.")

DB_NAME = "organic"
COLLECTION_NAME = "users" 

# Connect to MongoDB
mongo_client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = mongo_client[DB_NAME]
users_collection = db[COLLECTION_NAME]

@login_bp.route(route="login", auth_level=func.AuthLevel.ANONYMOUS)
def login(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse('Invalid JSON input', status_code=400)

    email = html.escape(req_body.get('email', '').strip())
    password = req_body.get('password', '').strip()

    # Validation checks for email and password
    if not email or not password:
        return func.HttpResponse('Please provide an email and password.', status_code=400)

    try:
        # Check if user exists using parameterized query
        user = users_collection.find_one({'email': email})
        if not user:
            return func.HttpResponse('User not found.', status_code=401)

        # Compare password with hashed password in the database
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return func.HttpResponse('Invalid credentials.', status_code=401)

        # Generate JWT for the authenticated user
        token = jwt.encode({
            'userId': str(user['_id']),
            'email': email,
            'exp': datetime.now(timezone.utc) + timedelta(days=2)
        }, JWT_SECRET, algorithm='HS512')

        # Prepare the user response data
        # Include isAdmin in the response, defaulting to False if it doesn't exist in the document
        user_data = {
            'id': str(user['_id']),
            'username': user['username'],
            'email': user['email'],
            'isEmailVerified': user['isEmailVerified'],
            'isAdmin': user.get('isAdmin', False)  # Set default to False
        }

        # Return the token and user information
        response_data = {
            'message': 'Login successful',
            'token': token,
            'user': user_data
        }
        return func.HttpResponse(json.dumps(response_data), mimetype="application/json", status_code=200)
    
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
