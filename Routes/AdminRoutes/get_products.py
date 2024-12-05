import azure.functions as func
import logging
import json
from bson import ObjectId
from pymongo import MongoClient
import jwt
import os
import certifi
from datetime import datetime, timezone

get_products_bp = func.Blueprint()

# MongoDB connection settings
MONGO_URI_2 = os.environ.get('MONGO_URI_2')

if not MONGO_URI_2:
    raise ValueError("MONGO_URI_2 must be set in environment variables.")

DB_NAME_2 = "organic_products"
PRODUCTS_COLLECTION_NAME = "products"

# Connect to MongoDB
mongo_client_2 = MongoClient(MONGO_URI_2, tlsCAFile=certifi.where())
db_2 = mongo_client_2[DB_NAME_2]
products_collection = db_2[PRODUCTS_COLLECTION_NAME]


def serialize_document(doc):
    """
    Serializes a MongoDB document into a JSON-serializable format.
    Converts ObjectId and datetime fields.
    """
    if "_id" in doc:
        doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
    for key, value in doc.items():
        if isinstance(value, datetime):  # Check if the field is a datetime
            doc[key] = value.isoformat()  # Convert datetime to ISO 8601 string
    return doc


@get_products_bp.route(route="get_products", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def get_products(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Fetching all products.')

    try:
        # Fetch all products from the MongoDB collection
        products_cursor = products_collection.find()
        products = [serialize_document(product) for product in products_cursor]

        # Return a success response with product details
        return func.HttpResponse(
            json.dumps({"products": products}),
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
