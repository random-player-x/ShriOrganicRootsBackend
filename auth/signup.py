import azure.functions as func
import logging
import json
import bcrypt
import jwt
from pymongo import MongoClient
from email_validator import validate_email, EmailNotValidError
from datetime import datetime, timedelta, timezone
import os
import certifi
import html

if os.path.exists('.env'):
    from dotenv import load_dotenv
    load_dotenv()

signup_bp = func.Blueprint()

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

def is_strong_password(password):
    # Check password strength requirements
    if (len(password) >= 8 and 
        any(c.islower() for c in password) and 
        any(c.isupper() for c in password) and 
        any(c.isdigit() for c in password) and 
        any(c in "!@#$%^&*()-_+=" for c in password)):
        return True
    return False

def create_jwt(user_id, email):
    token = jwt.encode(
        {'userId': user_id, 'email': email, 'exp': datetime.now(timezone.utc) + timedelta(days=2)}, 
        JWT_SECRET, 
        algorithm='HS512'
    )
    return token

def authenticate_admin_token(token):
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=["HS512"])
        user_email = decoded_token['email']
        user = users_collection.find_one({'email': user_email})
        if user and user.get('isAdmin', False):
            return user
        return None
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@signup_bp.route(route="signup", auth_level=func.AuthLevel.ANONYMOUS)
def signup(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse('Invalid JSON input.', status_code=400)

    email = html.escape(req_body.get('email', '').strip())
    username = html.escape(req_body.get('username', '').strip())
    password = req_body.get('password', '').strip() 

    # Validation checks
    if not email or not username or not password:
        return func.HttpResponse('Please provide an email, username, and password.', status_code=400)

    try:
        validate_email(email)
    except EmailNotValidError:
        return func.HttpResponse('Invalid email format.', status_code=400)

    if not is_strong_password(password):
        return func.HttpResponse('Password does not meet the strength requirements.', status_code=400)

    try:
        # Check if user with this email or username already exists
        user_exists = users_collection.find_one({'$or': [{'email': email}, {'username': username}]})
        if user_exists:
            if user_exists['email'] == email:
                return func.HttpResponse('User with this email already exists.', status_code=400)
                
            if user_exists['username'] == username:
                return func.HttpResponse('User with this username already exists.', status_code=400)

        # Hash the password and insert the new user
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_data = {
            'email': email,
            'username': username,
            'password': hashed_password.decode('utf-8'),
            'isEmailVerified': False,  # Default to false
            'isAdmin': False,  # Default to false
        }
        result = users_collection.insert_one(user_data)
        inserted_id = str(result.inserted_id)

        # Create JWT for the new user
        token = create_jwt(inserted_id, email)

        # Prepare the user response data
        response_data = {
            'token': token,
            'user': {
                'id': inserted_id,
                'username': username,
                'email': email,
                'isEmailVerified': False,
                'isAdmin': user_data.get('isAdmin', False)  # Default to false if not set
            }
        }
     
        return func.HttpResponse(json.dumps(response_data), mimetype="application/json", status_code=200)
    
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
