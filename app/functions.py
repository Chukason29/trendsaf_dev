import re
import random
import string
import pendulum
import base64
import os
import hashlib
import json
import uuid
from flask import request, jsonify, abort, url_for
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer, SignatureExpired, BadSignature
from .config import Config


data = {
            "firstname" : "Victor",
            "surname" : "Polycarp",
            "email" : "chuksalaegbu@gmail.com",
            "phone": "09039444542",
            "role": ["aggregator"],
            "password": "54321",
            "street_name": "LordBridge",
            "city": "Lome",
            "zip": "500016",
            "province": "Kaduna",
            "country": "India"
        }

serializer = URLSafeSerializer(Config.AES_KEY)
timed_serializer = URLSafeTimedSerializer(Config.AES_KEY)

#encoding and decode IDs
def encode_id(id):
    return serializer.dumps(id)

# Function to decode the ID
def decode_id(encoded_id):
    return serializer.loads(encoded_id)

def generate_verification_link(email):
    token = timed_serializer.dumps(email, salt=Config.SECRET_KEY)
    link = url_for('signup.confirm_email', token=token, _external=True)
    return link

def generate_admin_link(email):
    token = timed_serializer.dumps(email, salt=Config.SECRET_KEY)
    link = url_for('admin.rest_password', token=token, _external=True)
    return link

def validate_verification_link(token):
    try:
        email = timed_serializer.loads(token, salt=Config.SECRET_KEY, max_age=3600)  # 1-hour expiration
    except SignatureExpired:
        return jsonify({
            "status": False,
            "message": "Expired Link"
        })
    return jsonify({
        "status": True,
        "message": "Email is verified",
        "email" : email
    })
def generate_password_link(id):
    token = timed_serializer.dumps(id, salt=Config.SECRET_KEY)
    link = url_for('auth.pwd_link_verify', token=token, _external=True)
    return {
        "token": token,
        "link" : link
    }

def validate_password_link(token):
    try:
        id = timed_serializer.loads(token, salt=Config.SECRET_KEY, max_age=900)  # 15 minutes
        return jsonify({
            "status": True,
            "id": id
        })
    except SignatureExpired:
        return jsonify({
            "status": False,
            "message": "Expired Link"
        })
        
# Generate a reset token for password reset
def generate_reset_token(user):
    timed_serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    return timed_serializer.dumps(str(user.user_uuid), salt=Config.RESET_PASSWORD_SALT)

# Validate a reset token
def validate_reset_token(token):
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    try:
        user_uuid = serializer.loads(token, salt=Config.RESET_PASSWORD_SALT, max_age=900)# 30 seconds
        user_uuid = encode_id(str(uuid.UUID(user_uuid)))
        return jsonify({ "id": user_uuid, "status" : True})
    except SignatureExpired:
        return jsonify({"status" : False, "message" : "token has expired"})
    except BadSignature:
        return jsonify({"status" : False, "message" : "invalid token"})

    

def is_valid_email(email):
    # Define the regular expression for validating an email
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    
    # Use re.match to check if the string matches the email pattern
    if re.match(email_regex, email):
        return True
    return False


def is_json(data):
    try:
        json.dumps(data)
        return True
    except (TypeError, ValueError):
        return False

#function to generate random code for registration and password resetting
def generate_random_code(length):
    # Combine letters and digits
    characters = string.ascii_letters + string.digits
    # Generate a random code
    return ''.join(random.choices(characters, k=length))

#Generate a random alphanumeric code of length 8
verify_code = generate_random_code(8)


#this function collects a time and adds a duration it
def time_duration(previous_time, added_duration):
    pass


def add_duration(hours):
    # Get the current time using Pendulum
    current_time = pendulum.now()
    
    # Add the specified duration (in days)
    new_time = current_time.add(hours=hours)
    return new_time

# A 24 hour expiration time for registration code
verify_code_expiration = add_duration(24)

def get_token_auth_header():
## check if authorization is not in request
    if 'Authorization' not in request.headers:
        abort(401)
## get the token   
    auth_header = request.headers['Authorization']
    header_parts = auth_header.split(' ')
## check if token is valid
    if len(header_parts) != 2:
        abort(401)
    elif header_parts[0].lower() != 'bearer':
        abort(401) 
    return header_parts[1]
