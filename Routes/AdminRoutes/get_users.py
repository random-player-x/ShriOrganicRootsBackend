import azure.functions as func
import logging
import json
from bson import ObjectId
from pymongo import MongoClient
import jwt
import os
import certifi
from datetime import datetime, timezone

get_users_bp = func.Blueprint()

# Assuming the MongoDB connection and JWT secret are already set
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

# JWT Authentication for Admin
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

# Helper function to serialize MongoDB documents (convert ObjectId, datetime)
def serialize_user(user):
    if '_id' in user:
        user['_id'] = str(user['_id'])  # Convert ObjectId to string
    if 'createdAt' in user and isinstance(user['createdAt'], datetime):
        user['createdAt'] = user['createdAt'].isoformat()  # Convert datetime to ISO 8601 string
    if 'updatedAt' in user and isinstance(user['updatedAt'], datetime):
        user['updatedAt'] = user['updatedAt'].isoformat()  # Convert datetime to ISO 8601 string
    return user

@get_users_bp.route(route="all-users", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def admin_users_get(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Admin request to get all users.')

    # Check for authorization header and validate JWT
    token = req.headers.get('Authorization')
    if not token:
        return func.HttpResponse('Authorization token missing.', status_code=401)

    token = token.replace("Bearer ", "")  # Strip 'Bearer ' prefix if present

    # Authenticate admin
    admin_user = authenticate_admin_token(token)
    if not admin_user:
        return func.HttpResponse('Unauthorized or not an admin.', status_code=403)

    try:
        # Get list of all users, excluding the password field
        users = users_collection.find({}, {'password': 0})  # Exclude password field
        users_list = []

        # Serialize each user
        for user in users:
            serialized_user = serialize_user(user)
            users_list.append(serialized_user)

        # Return the serialized list of users as JSON
        return func.HttpResponse(json.dumps(users_list), mimetype="application/json", status_code=200)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
