import azure.functions as func
import logging
import json
from bson import ObjectId
from pymongo import MongoClient
import jwt
import os
import certifi
from datetime import datetime, timezone

get_myorder_bp = func.Blueprint()

# Load environment variables
MONGO_URI = os.environ.get('MONGO_URI')
JWT_SECRET = os.environ.get('JWT_SECRET')

if not MONGO_URI or not JWT_SECRET:
    raise ValueError("MONGO_URI and JWT_SECRET must be set in environment variables.")

DB_NAME = "organic"
COLLECTION_NAME = "users"
ORDERS_COLLECTION_NAME = "user_order"

# Connect to MongoDB
mongo_client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = mongo_client[DB_NAME]
users_collection = db[COLLECTION_NAME]
orders_collection = db[ORDERS_COLLECTION_NAME]

@get_myorder_bp.route(route="my_orders", methods=['GET'], auth_level=func.AuthLevel.ANONYMOUS)
def get_my_orders(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a get my orders request.')

    # Extract JWT from Authorization header
    token = req.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return func.HttpResponse('Authorization token missing.', status_code=401)

    try:
        # Decode JWT and get user info
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=['HS512'])
        user_id = decoded_token.get('userId')
        if not user_id:
            return func.HttpResponse('Invalid token.', status_code=401)
    except jwt.ExpiredSignatureError:
        return func.HttpResponse('Token has expired.', status_code=401)
    except jwt.InvalidTokenError:
        return func.HttpResponse('Invalid token.', status_code=401)

    try:
        # Query the database for all orders placed by the user
        user_orders = list(orders_collection.find({'userId': ObjectId(user_id)}))

        # If no orders found
        if not user_orders:
            return func.HttpResponse('No orders found for this user.', status_code=404)

        # Convert MongoDB ObjectId to string for JSON serialization
        for order in user_orders:
            order['_id'] = str(order['_id'])
            order['userId'] = str(order['userId'])
            order['placedAt'] = order['placedAt'].isoformat()

        return func.HttpResponse(json.dumps(user_orders), mimetype="application/json", status_code=200)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
