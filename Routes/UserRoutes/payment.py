import azure.functions as func
import logging
import json
import jwt
from pymongo import MongoClient
from datetime import datetime, timezone, timedelta
import os
import certifi
import html
from dwolla_v2 import Client as DwollaClient

if os.path.exists('.env'):
    from dotenv import load_dotenv
    load_dotenv()

pay_bp = func.Blueprint()

# Load environment variables
MONGO_URI = os.environ.get('MONGO_URI')
JWT_SECRET = os.environ.get('JWT_SECRET')
DWOLLA_CLIENT_ID = os.environ.get('DWOLLA_CLIENT_ID')
DWOLLA_CLIENT_SECRET = os.environ.get('DWOLLA_CLIENT_SECRET')
DWOLLA_ENVIRONMENT = os.environ.get('DWOLLA_ENVIRONMENT', 'sandbox')

# Connect to MongoDB
mongo_client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = mongo_client['organic']
users_collection = db['users']

# Initialize Dwolla client
dwolla_client = DwollaClient(key=DWOLLA_CLIENT_ID, secret=DWOLLA_CLIENT_SECRET, environment=DWOLLA_ENVIRONMENT)

def authenticate_user_token(token):
    """Verifies the user token and returns the user document if valid."""
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=["HS512"])
        user_email = decoded_token['email']
        user = users_collection.find_one({'email': user_email})
        return user if user else None
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@pay_bp.route(route="pay", auth_level=func.AuthLevel.ANONYMOUS)
def pay(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing payment request")

    # Extract and validate JWT token
    token = req.headers.get('Authorization')
    if not token:
        return func.HttpResponse("Missing authorization token.", status_code=401)

    user = authenticate_user_token(token)
    if not user:
        return func.HttpResponse("Invalid or expired token.", status_code=401)

    try:
        # Parse request body
        req_body = req.get_json()
        amount = req_body.get('amount')
        recipient_id = req_body.get('recipientId')  # ID of the recipient in Dwolla or MongoDB

        if not amount or not recipient_id:
            return func.HttpResponse("Amount and recipient ID are required.", status_code=400)

        # Check that the user has a funding source
        funding_source_url = user.get('fundingSourceUrl')
        if not funding_source_url:
            return func.HttpResponse("User has no linked funding source.", status_code=400)

        # Retrieve recipient funding source (this could be from your own database or Dwolla API)
        recipient = users_collection.find_one({'_id': recipient_id})
        recipient_funding_source_url = recipient.get('fundingSourceUrl')
        if not recipient_funding_source_url:
            return func.HttpResponse("Recipient has no linked funding source.", status_code=400)

        # Initiate transfer in Dwolla
        transfer_request = {
            "_links": {
                "source": {"href": funding_source_url},
                "destination": {"href": recipient_funding_source_url}
            },
            "amount": {
                "currency": "USD",
                "value": str(amount)  # Dwolla expects the amount as a string
            },
            "metadata": {
                "sender": user['email'],
                "recipient": recipient['email']
            }
        }

        transfer = dwolla_client.post('transfers', transfer_request)

        # Return transfer result
        response_data = {
            "status": "success",
            "transferUrl": transfer.headers['location']
        }
        return func.HttpResponse(json.dumps(response_data), mimetype="application/json", status_code=200)

    except Exception as e:
        logging.error(f"An error occurred during payment: {e}")
        return func.HttpResponse(f"An error occurred: {str(e)}", status_code=500)
