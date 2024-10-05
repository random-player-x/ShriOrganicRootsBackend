import azure.functions as func
import logging
import json
from bson import ObjectId
from pymongo import MongoClient
import jwt
import os
import certifi
from datetime import datetime, timezone

order_bp = func.Blueprint()

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

@order_bp.route(route="user_order", methods=['POST'], auth_level=func.AuthLevel.ANONYMOUS)
def place_order(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a place order request.')

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

    # Parse request body to get the order items and user details
    try:
        req_body = req.get_json()
        order_items = req_body.get('orderItems', [])
        name = req_body.get('name', '').strip()
        address = req_body.get('address', '').strip()
        city = req_body.get('city', '').strip()
        pincode = req_body.get('pincode', '').strip()

        # Validate user details
        if not all([name, address, city, pincode]):
            return func.HttpResponse('Name, address, city, and pincode are required.', status_code=400)

        if not order_items:
            return func.HttpResponse('No order items provided.', status_code=400)
    except ValueError:
        return func.HttpResponse('Invalid JSON input.', status_code=400)

    # Validate and process each order item
    for item in order_items:
        if 'productId' not in item or 'quantity' not in item or 'productName' not in item or 'productPrice' not in item:
            return func.HttpResponse('Each order item must contain productId, productName, and quantity.', status_code=400)
        
        # Assign a default status for each item if not already provided
        item['status'] = item.get('status', 'Pending')

    # Prepare the order data with individual item statuses
    order_data = {
        'userId': ObjectId(user_id),
        'orderItems': order_items,  # Each item now has productId, productName, quantity, and status
        'placedAt': datetime.now(timezone.utc),
        'shippingDetails': {  # Add user details here
            'name': name,
            'address': address,
            'city': city,
            'pincode': pincode
        }
    }

    try:
        # Insert the order into the database
        result = orders_collection.insert_one(order_data)

        # Respond with a success message, including the userId and orderId
        response_data = {
            'message': 'Order placed successfully',
            'userId': str(user_id),
            'orderId': str(result.inserted_id),
            'orderItems': order_items,  # Echo back the order items with their statuses
            'shippingDetails': {  # Echo back the shipping details
                'name': name,
                'address': address,
                'city': city,
                'pincode': pincode
            }
        }
        return func.HttpResponse(json.dumps(response_data), mimetype="application/json", status_code=201)
    
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
