import azure.functions as func
import logging
import json
from bson import ObjectId
from pymongo import MongoClient
import jwt
import os
import certifi
from datetime import datetime, timezone

create_product_bp = func.Blueprint()

# Assuming the MongoDB connection and JWT secret are already set
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

@create_product_bp.route(route="create_product", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def create_product(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Admin is creating a new product.')

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

        # Parse the request body
        req_body = req.get_json()

        # Validate required fields
        required_fields = [
            "productName", "category", "brand", "unitPrice",
            "bulkPrice", "totalCost", "availableQty",
            "minOrderQty", "warehousePincode", 
            "rating", "numReviews", 'imageUrl',
            "description"
        ]
        for field in required_fields:
            if field not in req_body:
                return func.HttpResponse(
                    json.dumps({"message": f"Missing required field: {field}"}),
                    status_code=400,
                    mimetype="application/json"
                )

        # Generate a unique product ID
        product_id = str(ObjectId())

        # Create a new product object from request data
        new_product = {
            "productId": product_id,
            "productName": req_body["productName"],
            "category": req_body["category"],
            "brand": req_body["brand"],
            "unitPrice": float(req_body["unitPrice"]),
            "bulkPrice": float(req_body["bulkPrice"]),
            "totalCost": float(req_body["totalCost"]),
            "availableQty": int(req_body["availableQty"]),
            "minOrderQty": int(req_body["minOrderQty"]),
            "warehousePincode": req_body["warehousePincode"],
            "rating": float(req_body["rating"]),
            "numReviews": int(req_body["numReviews"]),
            "imageUrl": req_body["imageUrl"],
            "description": req_body["description"],
            "createdAt": datetime.now(timezone.utc),
            "createdBy": admin_user["email"]  # Track the admin who created the product
        }

        # Insert the new product into the MongoDB collection
        products_collection.insert_one(new_product)

        # Response data
        response_data = {
            "message": "Product created successfully",
            "productDetails": {
                "productId": product_id,
                "productName": new_product["productName"],
                "category": new_product["category"],
                "brand": new_product["brand"],
                "unitPrice": new_product["unitPrice"],
                "bulkPrice": new_product["bulkPrice"],
                "totalCost": new_product["totalCost"],
                "availableQty": new_product["availableQty"],
                "minOrderQty": new_product["minOrderQty"],
                "warehousePincode": new_product["warehousePincode"],
                "rating": new_product["rating"],
                "numReviews": new_product["numReviews"],
                "imageUrl": new_product["imageUrl"],    
                "description": new_product["description"],
                "createdAt": new_product["createdAt"].isoformat(),
                "createdBy": new_product["createdBy"]  # Admin email
            }
        }

        # Return a success response with product details
        return func.HttpResponse(
            json.dumps(response_data),
            status_code=201,
            mimetype="application/json"
        )

    except ValueError:
        logging.error("Invalid JSON input.")
        return func.HttpResponse(
            json.dumps({"message": "Invalid JSON input."}),
            status_code=400,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(
            json.dumps({"message": f"An error occurred: {e}"}),
            status_code=500,
            mimetype="application/json"
        )
