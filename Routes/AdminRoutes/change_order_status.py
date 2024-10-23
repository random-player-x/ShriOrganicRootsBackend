import azure.functions as func
import logging
import json
from bson import ObjectId
from pymongo import MongoClient
import jwt
import os
import certifi
from datetime import datetime, timezone
from pymongo.errors import PyMongoError

change_order_status_bp = func.Blueprint()

# Load environment variables for MongoDB and JWT
MONGO_URI = os.environ.get('MONGO_URI')
JWT_SECRET = os.environ.get('JWT_SECRET')

if not MONGO_URI or not JWT_SECRET:
    raise ValueError("MONGO_URI and JWT_SECRET must be set in environment variables.")

DB_NAME = "organic"
COLLECTION_NAME = "users"
ORDERS_COLLECTION_NAME = "user_order"

# MongoDB Connection
mongo_client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = mongo_client[DB_NAME]
users_collection = db[COLLECTION_NAME]
orders_collection = db[ORDERS_COLLECTION_NAME]

# JWT Authentication for Admin
def authenticate_admin_token(token):
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=["HS512"])
        user_email = decoded_token.get('email')
        if not user_email:
            raise jwt.InvalidTokenError
        user = users_collection.find_one({'email': user_email})
        if user and user.get('isAdmin', False):
            return user
        return None
    except jwt.ExpiredSignatureError:
        logging.warning('Token expired.')
        return None
    except jwt.InvalidTokenError:
        logging.warning('Invalid token provided.')
        return None

# Route to update order status
@change_order_status_bp.route(route="order_status", methods=["PUT"], auth_level=func.AuthLevel.ANONYMOUS)
def admin_update_order_status(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Admin is attempting to update an order item status.')

    try:
        # Extract JWT token
        token = req.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return func.HttpResponse('Authorization token missing.', status_code=401)

        # Authenticate admin
        admin_user = authenticate_admin_token(token)
        if not admin_user:
            return func.HttpResponse('Unauthorized. Admin privileges required.', status_code=403)

        # Parse request body
        req_body = req.get_json()
        user_id = req_body.get('userId', '').strip()
        product_id = req_body.get('productId')
        new_status = req_body.get('status', '').strip().lower()

        # Input validation
        if not user_id or product_id is None or not new_status:
            return func.HttpResponse('Please provide userId, productId, and status.', status_code=400)

        # Ensure productId is an integer
        try:
            product_id = int(product_id)
        except ValueError:
            return func.HttpResponse('Invalid productId. It should be an integer.', status_code=400)

        # Validate status
        valid_statuses = ['pending', 'confirmed', 'cancelled']
        if new_status not in valid_statuses:
            return func.HttpResponse(f'Invalid status. Choose from {", ".join(valid_statuses)}.', status_code=400)

        # Validate and convert userId to ObjectId
        try:
            user_object_id = ObjectId(user_id)
        except Exception:
            return func.HttpResponse('Invalid userId format.', status_code=400)

        # Directly update the status of the specific product in the order
        result = orders_collection.update_one(
            {'userId': user_object_id, 'orderItems.productId': product_id},
            {'$set': {'orderItems.$.status': new_status}}
        )

        # If no order was modified, it means the order or product was not found
        if result.matched_count == 0:
            return func.HttpResponse('Order or product not found for this user.', status_code=404)

        # Success response
        return func.HttpResponse(f'Order item status updated to {new_status}.', status_code=200)

    except PyMongoError as e:
        logging.error(f"A MongoDB error occurred: {e}")
        return func.HttpResponse(f"A database error occurred: {e}", status_code=500)

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
