import azure.functions as func
import logging
import json
from bson import ObjectId
from pymongo import MongoClient
import jwt
import os
import certifi
from datetime import datetime, timezone

update_product_bp = func.Blueprint()

# MongoDB and JWT configuration
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

# JWT Authentication for Admin (same as create_product.py)
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

@update_product_bp.route(route="update_product/{product_id}", methods=["PUT"], auth_level=func.AuthLevel.ANONYMOUS)
def update_product(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Admin is updating a product.')

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

        # Get product ID from route parameters
        product_id = req.route_params.get('product_id')
        if not product_id:
            return func.HttpResponse(
                json.dumps({"message": "Product ID is required."}),
                status_code=400,
                mimetype="application/json"
            )

        # Check if product exists
        existing_product = products_collection.find_one({"productId": product_id})
        if not existing_product:
            return func.HttpResponse(
                json.dumps({"message": "Product not found."}),
                status_code=404,
                mimetype="application/json"
            )

        # Parse the request body
        req_body = req.get_json()

        # Create update document with only provided fields
        update_fields = {}
        allowed_fields = [
            "productName", "category", "brand", "unitPrice",
            "bulkPrice", "totalCost", "availableQty",
            "minOrderQty", "warehousePincode", 
            "rating", "numReviews", "imageUrl"
        ]

        for field in allowed_fields:
            if field in req_body:
                # Convert numeric fields to appropriate types
                if field in ["unitPrice", "bulkPrice", "totalCost", "rating"]:
                    update_fields[field] = float(req_body[field])
                elif field in ["availableQty", "minOrderQty", "numReviews"]:
                    update_fields[field] = int(req_body[field])
                else:
                    update_fields[field] = req_body[field]

        if not update_fields:
            return func.HttpResponse(
                json.dumps({"message": "No valid fields to update."}),
                status_code=400,
                mimetype="application/json"
            )

        # Add update metadata
        update_fields["updatedAt"] = datetime.now(timezone.utc)
        update_fields["updatedBy"] = admin_user["email"]

        # Update the product
        products_collection.update_one(
            {"productId": product_id},
            {"$set": update_fields}
        )

        # Get updated product
        updated_product = products_collection.find_one({"productId": product_id})

        # Prepare response
        response_data = {
            "message": "Product updated successfully",
            "productDetails": {
                "productId": product_id,
                "productName": updated_product["productName"],
                "category": updated_product["category"],
                "brand": updated_product["brand"],
                "unitPrice": updated_product["unitPrice"],
                "bulkPrice": updated_product["bulkPrice"],
                "totalCost": updated_product["totalCost"],
                "availableQty": updated_product["availableQty"],
                "minOrderQty": updated_product["minOrderQty"],
                "warehousePincode": updated_product["warehousePincode"],
                "rating": updated_product["rating"],
                "numReviews": updated_product["numReviews"],
                "imageUrl": updated_product["imageUrl"],
                "updatedAt": update_fields["updatedAt"].isoformat(),
                "updatedBy": update_fields["updatedBy"]
            }
        }

        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json"
        )

    except ValueError:
        logging.error("Invalid input data.")
        return func.HttpResponse(
            json.dumps({"message": "Invalid input data."}),
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