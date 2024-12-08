import azure.functions as func
import logging
import json
from bson import ObjectId
from pymongo import MongoClient
import jwt
import os
import certifi

delete_product_bp = func.Blueprint()

# Load MongoDB URIs and JWT secret from environment variables
MONGO_URI = os.environ.get('MONGO_URI')
MONGO_URI_2 = os.environ.get('MONGO_URI_2')
JWT_SECRET = os.environ.get('JWT_SECRET')

if not MONGO_URI or not MONGO_URI_2 or not JWT_SECRET:
    raise ValueError("MONGO_URI, MONGO_URI_2, and JWT_SECRET must be set in environment variables.")

DB_NAME = "organic"
DB_NAME_2 = "organic_products"
COLLECTION_NAME = "users"
PRODUCTS_COLLECTION_NAME = "products"

# Connect to MongoDB
mongo_client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
mongo_client_2 = MongoClient(MONGO_URI_2, tlsCAFile=certifi.where())
db = mongo_client[DB_NAME]
db_2 = mongo_client_2[DB_NAME_2]
users_collection = db[COLLECTION_NAME]
products_collection = db_2[PRODUCTS_COLLECTION_NAME]

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
        return {"error": "Token has expired."}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token."}

@delete_product_bp.route(route="delete_product", methods=["DELETE"], auth_level=func.AuthLevel.ANONYMOUS)
def delete_product(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Admin is deleting a product.')

    try:
        # Extract JWT token from headers
        token = req.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return func.HttpResponse(
                json.dumps({"message": "Authorization token missing."}),
                status_code=401,
                mimetype="application/json"
            )

        # Authenticate admin user
        admin_user = authenticate_admin_token(token)
        if isinstance(admin_user, dict) and "error" in admin_user:
            return func.HttpResponse(
                json.dumps({"message": admin_user["error"]}),
                status_code=401,
                mimetype="application/json"
            )
        if not admin_user:
            return func.HttpResponse(
                json.dumps({"message": "Unauthorized. Admin privileges required."}),
                status_code=403,
                mimetype="application/json"
            )

        # Parse the request body to get the productId
        req_body = req.get_json()
        product_id = req_body.get('productId')

        # Validate productId
        if not product_id:
            return func.HttpResponse(
                json.dumps({"message": "Missing required field: productId"}),
                status_code=400,
                mimetype="application/json"
            )
        # Check if the product exists
        product = products_collection.find_one({'productId': product_id})
        if not product:
            return func.HttpResponse(
                json.dumps({"message": "Product not found."}),
                status_code=404,
                mimetype="application/json"
            )

        # Delete the product
        products_collection.delete_one({'productId': product_id})

        # Return a success response
        return func.HttpResponse(
            json.dumps({"message": "Product deleted successfully"}),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(
            json.dumps({"message": f"An error occurred: {e}"}),
            status_code=500,
            mimetype="application/json"
        )
