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

import requests

url = "https://api.helcim.com/v2/helcim-pay/initialize"

payload = {
    "paymentType": "purchase",
    "amount": 100,
    "currency": "CAD",
    "customerCode": "CST1000",
    "invoiceNumber": "INV1000",
    "paymentMethod": "cc-ach",
    "allowPartial": 1,
    "hasConvenienceFee": 1,
    "taxAmount": 3.67,
    "hideExistingPaymentDetails": 1,
    "setAsDefaultPaymentMethod": 1,
    "terminalId": 1,
    "customerRequest": {
        "customerCode": "CST1000",
        "contactName": "John Smith",
        "businessName": "Best Company",
        "cellPhone": "123-456-7890",
        "billingAddress": {
            "name": "John Smith/Helcim",
            "street1": "123 Street",
            "street2": "string",
            "city": "Calgary",
            "province": "AB",
            "country": "CAN",
            "postalCode": "H0H0H0",
            "phone": "1234567890",
            "email": "john@example.com"
        },
        "shippingAddress": {
            "name": "John Smith/Helcim",
            "street1": "123 Street",
            "street2": "string",
            "city": "Calgary",
            "province": "AB",
            "country": "CAN",
            "postalCode": "H0H0H0",
            "phone": "1234567890",
            "email": "john@example.com"
        }
    },
    "invoiceRequest": {
        "invoiceNumber": "INV1000",
        "tipAmount": 0,
        "depositAmount": 0,
        "notes": "string",
        "shipping": {
            "amount": 0,
            "details": "Standard Shipping",
            "address": {
                "name": "John Smith/Helcim",
                "street1": "123 Street",
                "street2": "string",
                "city": "Calgary",
                "province": "AB",
                "country": "CAN",
                "postalCode": "H0H0H0",
                "phone": "1234567890",
                "email": "john@example.com"
            }
        },
        "pickup": {
            "date": "string",
            "name": "John Smith"
        },
        "tax": {
            "amount": 1.25,
            "details": "GST"
        },
        "discount": {
            "amount": 5.25,
            "details": "Spring Sale"
        },
        "lineItems": [
            {
                "sku": "string",
                "description": "string",
                "quantity": 0,
                "price": 0,
                "total": 0,
                "taxAmount": 0,
                "discountAmount": 0
            }
        ]
    }
}
headers = {
    "accept": "application/json",
    "content-type": "application/json"
}

response = requests.post(url, json=payload, headers=headers)

print(response.text)
    
    except Exception as e:
        logging.error(f"Error creating Dwolla customer: {e}")
        return func.HttpResponse("Error creating Dwolla customer.", status_code=500)
