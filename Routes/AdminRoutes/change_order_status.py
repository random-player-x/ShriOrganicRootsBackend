import azure.functions as func
import logging
import json
from bson import ObjectId
from pymongo import MongoClient
import jwt
import os
import certifi
from datetime import datetime, timezone

change_order_status_bp = func.Blueprint()

# Assuming the MongoDB connection and JWT secret are already set
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
@change_order_status_bp.route(route="order_status", methods=["PUT"], auth_level=func.AuthLevel.ANONYMOUS)
def admin_update_order_status(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Admin is updating the status of an individual order item.')

    try:
        # Extract JWT token from headers
        token = req.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return func.HttpResponse('Authorization token missing.', status_code=401)

        # Authenticate admin user
        admin_user = authenticate_admin_token(token)
        if not admin_user:
            return func.HttpResponse('Unauthorized. Admin privileges required.', status_code=403)

        # Parse request body to get userId, productId (as an integer), and the new status
        req_body = req.get_json()
        user_id = req_body.get('userId', '').strip()
        product_id = req_body.get('productId')  # No need to strip since this should be an integer
        new_status = req_body.get('status', '').strip().lower()

        # Validate input
        if not user_id or product_id is None or not new_status:
            return func.HttpResponse('Please provide userId, productId (integer), and status.', status_code=400)

        # Ensure productId is an integer
        try:
            product_id = int(product_id)
        except ValueError:
            return func.HttpResponse('Invalid productId. It should be an integer.', status_code=400)

        # Validate status
        if new_status not in ['pending', 'confirmed', 'cancelled']:
            return func.HttpResponse('Invalid status. Choose from pending, confirmed, or cancelled.', status_code=400)

        # Validate and convert userId to ObjectId
        try:
            user_object_id = ObjectId(user_id)
        except Exception:
            return func.HttpResponse('Invalid userId format.', status_code=400)

        # Find the order for the specific user that contains the product
        order = orders_collection.find_one({
            'userId': user_object_id,
            'orderItems.productId': product_id
        })

        if not order:
            return func.HttpResponse('Order or product not found for this user.', status_code=404)

        # Update the status of the specific product in the order
        order_items = order.get('orderItems', [])
        item_found = False

        for item in order_items:
            if item['productId'] == product_id:
                item['status'] = new_status  # Update the item's status
                item_found = True
                break

        if not item_found:
            return func.HttpResponse('Order item not found.', status_code=404)

        # Update the order in the database
        orders_collection.update_one(
            {'_id': order['_id']},
            {'$set': {'orderItems': order_items}}
        )

        # Return a success response
        return func.HttpResponse(f'Order item status updated to {new_status}.', status_code=200)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
