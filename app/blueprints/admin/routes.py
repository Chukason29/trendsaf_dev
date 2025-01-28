from flask import Blueprint, request, jsonify, abort, session, make_response, url_for, redirect, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer, String, and_
from datetime import timedelta
from ...functions import encode_id, decode_id, get_token_auth_header, generate_admin_link, is_valid_email, generate_reset_token, validate_reset_token, is_json, generate_verification_link,generate_password_link, validate_password_link
from ...models import Users, Admins, Profile, Tokens, Crops, Countries, Regions, CropCategories, ProcessLevel, CropVariety, Product
from ...config import Config
from ... import bcrypt, db, mail
from io import StringIO
import uuid
import jwt
import html
import secrets
import datetime
import json
import csv
import os
import base64
import pandas as pd
import requests

admin_bp = Blueprint('admin', __name__)




@admin_bp.route('/admin_reg', methods=['GET', 'POST'])
def admin_reg(): # The hashed uuid value will be appended to the url link
    try:
        #get json data from api body
        data = request.get_json()
        if not is_json(data):
            abort(415)
        
        #check if all required parameters are contained in the json body
        if 'firstname' not in data or 'lastname' not in data or 'email' not in data or 'password' not in data:
            abort(422)
        
        message = ""
        email = html.escape(data['email'])
        password = data["password"]
        if not is_valid_email(data['email']): #checking if email is in correct format
            return jsonify({"message": "invalid email"})
        else:
            #checking if email exists?
            if request.method == "POST":
                user_email = Admins.query.filter_by(email=email).first()
                if user_email:
                    return jsonify({"exists": True, "message": "Account with email already exists"}), 400
            
                firstname = html.escape(data['firstname'])
                lastname = html.escape(data['lastname'])
                #hash the password
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                #creating a user uuid for identification
                new_user_uuid = uuid.uuid4()

                #convert the uuid to a string and encrypt
                encrypted_id = encode_id(str(new_user_uuid))

                #TODO Instantiating an object of users
           
                new_user = Admins(
                            user_uuid = new_user_uuid, 
                            firstname = firstname, 
                            lastname = lastname, 
                            email = email,
                            password = hashed_password
                        )
                #message to send to the user
            
                
                #creating a link to be sent to mail
                link = generate_admin_link(email)
                
                #TODO Instantiating an object of tokens and store the link in the database
                token = Tokens(token = link, is_token_used = False)
                
                #TODO persist info to the data
                db.session.add(new_user)
                db.session.add(token)
                db.session.commit()
                
                
                # Render HTML template
                html_content = render_template("admin_mail.html", link=link, firstname=firstname)
                #TODO send mail to user
                #verify_mail_message = f""
                msg = Message("Admin Password Reset",
                    sender='victoralaegbu@gmail.com',
                    recipients=[email])  # Change to recipient's email
                msg.html = html_content  # Set HTML content for email
                mail.send(msg)

                #TODO return a json object
                return jsonify({
                        "status": 200, 
                        "message": "Registration successful"
                    }), 200
            else:
                abort(405)
    except Exception as e:
        db.session.rollback()
        raise
    finally:
        db.session.close()


@admin_bp.route('/crops/categories',  methods=['POST'])
@jwt_required()
def cropcategories():
    try:
        #TODOGetting the user's id
        id = uuid.UUID(decode_id(get_jwt_identity()))
  
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        
        user_query = Users.query.filter_by(user_uuid = id).first()
        
        if user_query and user_data['company_role'] == "Z":
            data = request.get_json()
            if not is_json(data):
                abort(415)
            if 'crop_category_name' not in data:
                abort(422)
            crop_category_name = request.json.get('crop_category_name')
            is_crop_category_exists= CropCategories.query.filter_by(crop_category_name = crop_category_name).first()
            if is_crop_category_exists :
                return jsonify({
                    "status": False,
                    "message" : "Crop category name already exists"
                })
            new_crop_category = CropCategories(crop_category_name = crop_category_name)
            db.session.add(new_crop_category)
            db.session.commit()
            
            return jsonify({
                "status": True,
                "message": "New crop category added"
            })
        else:
            return jsonify({
                "status": False,
                "message" : "Unauthorized access"
            })
    except:
        db.session.rollback()
        raise


@admin_bp.route('/crops',  methods=['POST'])
@jwt_required()
def addcrop():
    try:
        #TODOGetting the user's id
        id = uuid.UUID(decode_id(get_jwt_identity()))
  
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        
        user_query = Users.query.filter_by(user_uuid = id).first()
        
        if user_query and user_data['company_role'] == "Z":
            data = request.get_json()
            if not is_json(data):
                abort(415)
            if 'crop_name' not in data or 'crop_category_id' not in data:
                abort(422)
            crop_name = request.json.get('crop_name')
            crop_category_id = request.json.get('crop_category_id')
            is_crop_exists= Crops.query.filter_by(crop_name = crop_name).first()
            if is_crop_exists :
                return jsonify({
                    "status": False,
                    "message" : "Crop name already exists"
                })
            new_crop = Crops(crop_name = crop_name, crop_category_id = crop_category_id)
            db.session.add(new_crop)
            db.session.commit()
            
            return jsonify({
                "status": True,
                "message": "New crop added"
            })
        else:
            return jsonify({
                "status": False,
                "message" : "Unauthorized access"
            })
    except:
        db.session.rollback()
        raise

@admin_bp.route('/crops/variety',  methods=['POST'])
@jwt_required()
def addcrop_variety():
    try:
        #TODOGetting the user's id
        id = uuid.UUID(decode_id(get_jwt_identity()))
  
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        
        user_query = Users.query.filter_by(user_uuid = id).first()
        
        if user_query and user_data['company_role'] == "Z":
            data = request.get_json()
            if not is_json(data):
                abort(415)
            if 'crop_variety_name' not in data or 'crop_id' not in data:
                abort(422)
            crop_variety_name = request.json.get('crop_variety_name')
            crop_id = request.json.get('crop_id')
            is_crop_exists= CropVariety.query.filter_by(crop_variety_name = crop_variety_name).first()
            if is_crop_exists :
                return jsonify({
                    "status": False,
                    "message" : "Crop variety already exists"
                })
            new_crop_variety = CropVariety(crop_variety_name = crop_variety_name, crop_id = crop_id)
            db.session.add(new_crop_variety)
            db.session.commit()
            
            return jsonify({
                "status": True,
                "message": "New crop variety added"
            })
        else:
            return jsonify({
                "status": False,
                "message" : "Unauthorized access"
            })
    except:
        db.session.rollback()
        raise
    

@admin_bp.route('/countries', methods=['POST'])
@jwt_required()
def addcountry():
    try:
        id = uuid.UUID(decode_id(get_jwt_identity()))
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        user_query = Users.query.filter_by(user_uuid = id).first()
        if user_query and user_data['company_role'] == "Z":
            data = request.get_json()
            if not is_json(data):
                abort(415)
            if 'country_name' not in data or 'country_code' not in data:
                abort(422)
            country_name = request.json.get('country_name')
            country_code = request.json.get('country_code')
            is_country_exists= Countries.query.filter_by(country_name = country_name).first()
            if is_country_exists :
                return jsonify({
                    "status": False,
                    "message" : "Country name already exists"
                })
            new_country = Countries(country_name = country_name, country_code = country_code)
            db.session.add(new_country)
            db.session.commit()
            
            return jsonify({
                "status": True,
                "message": "New country added"
            })
        else:
            abort(403)
    except:
        db.session.rollback()
        raise
    

@admin_bp.route('countries/regions', methods=['POST'])
@jwt_required()
def addregion():
    try:
        id = uuid.UUID(decode_id(get_jwt_identity()))
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        
        
        user_query = Users.query.filter_by(user_uuid = id).first()
        if user_query and user_data['company_role'] == "Z":
            data = request.get_json()
            
            country = request.get_json()
            if not is_json(country):
                abort(415)
            if 'region_name' not in country or 'country_id' not in country:
                abort(422)
            region_name = request.json.get('region_name')
            country_id = request.json.get('country_id')
            new_region = Regions(region_name = region_name, country_id = country_id)
            db.session.add(new_region)
            db.session.commit()
            
            return jsonify({
                "status": True,
                "message": "New region added"
            })
        else:
            abort(403)
    except:
        db.session.rollback()
        raise

    
@admin_bp.route('/crops/process_state', methods=['POST'])
@jwt_required()
def process_state():
    try:
        id = uuid.UUID(decode_id(get_jwt_identity()))
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        
        
        user_query = Users.query.filter_by(user_uuid = id).first()
        if user_query and user_data['company_role'] == "Z":
            data = request.get_json()
            
            crop = request.get_json()
            if not is_json(crop):
                abort(415)
            if 'crop_id' not in crop or 'crop_variety_id' not in crop or 'process_state' not in crop:
                abort(422)
            process_state = request.json.get('process_state')
            crop_variety_id = request.json.get('crop_variety_id')
            crop_id = request.json.get('crop_id')
            new_process_state = ProcessLevel(crop_id = crop_id, crop_variety_id = crop_variety_id, process_state = process_state)
            db.session.add(new_process_state)
            db.session.commit()
            
            return jsonify({
                "status": True,
                "message": "New Process Level added"
            })
        else:
            abort(403)
    except:
        db.session.rollback()
        raise
    

@admin_bp.route('/products', methods=['POST'])
@jwt_required()
def addproduct():
    try:
        id = uuid.UUID(decode_id(get_jwt_identity()))
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        
        
        user_query = Users.query.filter_by(user_uuid = id).first()
        if user_query and user_data['company_role'] == "Z":
            data = request.get_json()
            
            country = request.get_json()
            if not is_json(country):
                abort(415)
            if 'crop_id' not in country or 'crop_variety_id' not in country or 'region_id' not in country or 'country_id' not in country or 'price' not in country:
                abort(422)
            crop_id = request.json.get('crop_id')
            crop_variety_id = request.json.get('crop_variety_id')
            country_id = request.json.get('country_id')
            region_id = request.json.get('region_id')
            price = request.json.get('price') * 100
            new_product = Product(crop_id = crop_id, crop_variety_id = crop_variety_id, country_id = country_id, region_id = region_id, price = price)
            db.session.add(new_product)
            db.session.commit()
            
            return jsonify({
                "status": True,
                "message": "New product added"
            })
        else:
            abort(403)
    except:
        db.session.rollback()
        raise


@admin_bp.route('/products/import', methods=['POST'])
@jwt_required()
def import_data():
    try:
        #get json data from api body
        data = request.get_json()
        if not is_json(data):
            abort(415)
        
        #check if all required parameters are contained in the json body
        if 'file_id' not in data:
            abort(404)
        file_id = data["file_id"]
        api_key = Config.FILE_API_KEY
        return jsonify({
            "data" : api_key
        })
        
        '''file_url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media&key={Config.FILE_API_KEY}"
        
        
        # Fetch the file content
        response = requests.get(file_url)
        
        # Check if the request was successful
        if response.status_code == 200:
            # Convert the response content to a StringIO object
            csv_data = StringIO(response.text)
            
            # Read the CSV data into a pandas DataFrame
            df = pd.read_csv(csv_data)
            
        # Ensure DataFrame columns match the table structure
        df.columns = ["crop_id","crop_variety_id", "country_id", "region_id", "price", "created_at"]
        for index, row in df.iterrows():
            product = Product(
                crop_id = row["crop_id"],
                crop_variety_id=row["crop_variety_id"],
                country_id=row["country_id"],
                region_id=row["region_id"],
                price=row["price"],
                created_at=row["created_at"]
            )
            db.session.add(product)
                
        db.session.commit()

        return "Data imported successfully." '''

    except:
        db.session.rollback()
        raise
    

@admin_bp.route('/import', methods=['POST'])
@jwt_required()
def import_product():
    try:
        #get json data from api body
        data = request.get_json()
        if not is_json(data):
            abort(415)
        
        #check if all required parameters are contained in the json body
        if 'file_id' not in data:
            abort(404)
        file_id = data["file_id"]
        api_key = Config.FILE_API_KEY
        return jsonify({
            "data" : api_key
        })
    except:
        pass