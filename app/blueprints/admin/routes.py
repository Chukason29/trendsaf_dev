from flask import Blueprint, request, jsonify, abort, session, make_response, url_for, redirect, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer, String, and_
from datetime import timedelta
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer
from ...functions import encode_id, decode_id, generate_admin_link, validate_admin_link, is_valid_email, is_json
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


@admin_bp.route('/reg', methods=['POST'])
def admin_reg(): # The hashed uuid value will be appended to the url link
    try:
        #get json data from api body
        data = request.get_json()
        if not is_json(data):
            abort(415)
        
        #check if all required parameters are contained in the json body
        if 'firstname' not in data or 'lastname' not in data or 'email' not in data:
            abort(422)
        
        message = ""
        email = html.escape(data['email'])
        
        #initial password for admin
        admin_password = str(uuid.uuid4())[:8]  # Extracts first 8 characters
        if not is_valid_email(data['email']): #checking if email is in correct format
            return jsonify({"message": "invalid email"})
        else:
            #checking if email exists?
            if request.method == "POST":
                user_email = Admins.query.filter_by(email=email).first()
                if user_email:
                    return jsonify({"exists": True, "message": "Account with email already exists"}), 400
            
                admin_firstname = html.escape(data['firstname'])
                admin_lastname = html.escape(data['lastname'])
                #hash the password
                admin_hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')

                #creating a user uuid for identification
                new_admin_uuid = uuid.uuid4()

                #convert the uuid to a string and encrypt
                encrypted_id = encode_id(str(new_admin_uuid))

                #TODO Instantiating an object of users
           
                new_user = Admins(
                            admin_uuid = new_admin_uuid, 
                            firstname = admin_firstname, 
                            lastname = admin_lastname,
                            email = email,
                            password = admin_hashed_password
                        )
                #message to send to the user
            
                
                #creating a link to be sent to mail
                admin_link = generate_admin_link(email)
                
                #TODO Instantiating an object of tokens and store the link in the database
                token = Tokens(token = admin_link, is_token_used = False)
                
                #TODO persist info to the data
                db.session.add(new_user)
                db.session.add(token)
                db.session.commit()
                
                
                # Render HTML template
                html_content = render_template("admin_mail.html", admin_link=admin_link, admin_firstname=admin_firstname, admin_password=admin_password)
                #TODO send mail to user
                #verify_mail_message = f""
                msg = Message("Admin Password Reset",
                    sender='support@trendsaf.co',
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

@admin_bp.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        link = url_for('admin.confirm_email', token=token, _external = True)
        
        #TODO querying token for usage and 
        
        token_filter = Tokens.query.filter(and_(Tokens.token == link)).first()
        if token_filter and token_filter.is_token_used==False:
            email_response = validate_admin_link(token).get_json()
            if email_response['status'] == True:
                email = email_response['email']
                user = Admins.query.filter(and_(Admins.email == email)).first()
                
                #collecting the admin' uuid
                admin_uuid = user.admin_uuid
                
                #create a token using the admin's uuid
                timed_serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
                admin_token = timed_serializer.dumps(str(admin_uuid), salt=Config.RESET_PASSWORD_SALT)
                
                #effect the change that the admin verification link has been used
                token_filter.is_token_used = True
                db.session.commit()
                #return redirect ('http://localhost:5173/success')
                return redirect(f"{Config.BASE_URL}/reset_password/{admin_token}")
        else:
            return redirect(f"{Config.BASE_URL}/reset_password?status=False&message=link has been used")
    except:
        db.session.rollback()
        return redirect(f"{Config.BASE_URL}/reset_password?status=False&message=link has expired")

@admin_bp.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    try:
        #get json data from api body
        data = request.get_json()
        if not is_json(data):
            abort(415)
        
        #check if all required parameters are contained in the json body
        if 'initial_password' not in data or 'new_password' not in data or 'confirm_password' not in data:
            abort(422)
        serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
        admin_uuid = serializer.loads(token, salt=Config.RESET_PASSWORD_SALT, max_age=3600)# 15 Minutes
        admin_uuid = str(uuid.UUID(admin_uuid))
        
        initial_password = data["initial_password"]
        new_password = data["new_password"]
        
        confirm_password = data["confirm_password"]
        #TODO checked if user exits
        user = Admins.query.filter_by(admin_uuid=admin_uuid).first()
        if user: 
            #TODO check if initial password matches the password in the database
            if not (initial_password and bcrypt.check_password_hash(user.password, initial_password)):
                return jsonify({
                    "status" : False,
                    "message" : "wrong initial password"
                })
            if new_password != confirm_password:
                return jsonify({
                    "status": False,
                    "message" : "password and confirm password not same"
                })
        
        else:
            return jsonify({
                "status" : False,
                "message": "admin does not exist"
            })
        user.password = bcrypt.generate_password_hash(data["new_password"]).decode('utf-8')
        db.session.commit()
        return jsonify({
            "status" : True,
            "message": "Password reset successful" 
        })
    except:
        db.session.rollback()
        raise


@admin_bp.route('/login', methods=['POST'])
def login():
    try:
        #TODO get email and password from
        data = request.get_json()
        if not is_json(data):
            abort(415)
        if 'email' not in data or 'password' not in data:
            abort(422)
        email = data['email']
        password = data["password"]

        #TODO perform rate limiting

        #TODO compare email and password if they are great
        #TODO checked if user exits
        user = Admins.query.filter_by(email=email).first()
        if not user:
            return jsonify({
                "status" : False,
                "message" : "wrong email or password",
            })
            #checked if there is a password match
        if not (password and bcrypt.check_password_hash(user.password, password)):
            return jsonify({
                "status" : False,
                "message" : "wrong email or password"
            })
        #TODO collected the uuid of the user encode it and use as the identity of the user in the JWT
        
        id = encode_id(str(user.admin_uuid)) #user's uuid
        user_id = user.admin_id #user's id
        
       
        if user:                 
            #TODO create a JWT token ==> On the jwt token i will add the verification and confirmation status to the client
            access_token = create_access_token(
                identity=id,
                expires_delta=timedelta(hours=24),
                additional_claims=(
                    {
                        "user_role": "admin"
                    }
                )
            )
            #TODO create a crsf token and set it as a coookie
            csrf_token = secrets.token_hex(16)
            response = jsonify({
                    "status": True,
                    "access_token": access_token,
                    "firstname": user.firstname,
                    "lastname": user.lastname
                })
            #Set access_token as an HttpOnly cookie
            response.set_cookie(
                'access_token',
                access_token,
                httponly=True,  # Prevents JavaScript access
                secure=False,    # Use True if using HTTPS
                samesite='None' # Change based on your requirements
            )

        return response, 200       
    except Exception as e:
        raise

@admin_bp.route('/crops/categories',  methods=['POST'])
@jwt_required()
def cropcategories():
    try:
        #TODOGetting the user's id
        id = uuid.UUID(decode_id(get_jwt_identity()))
  
        #Retrieve authorization token
        auth_token = request.headers.get("Authorization").split(" ")[1]
        user_data = decode_token(auth_token, allow_expired=False)
        
        user_query = Admins.query.filter_by(admin_uuid = id).first()
        
        if user_query and user_data['user_role'] == "admin":
            data = request.get_json()
            if not data:
                return jsonify({"status": False, "message": "Invalid or missing JSON body"}), 400
            if not is_json(data):
                abort(415)
            category_code = data.get('category_code')
            category_name = data.get('category_name')
            
            if not category_code or not category_name:
                abort(422)
            
            is_crop_category_exists= CropCategories.query.filter_by(category_code = category_code).first()
            if is_crop_category_exists :
                return jsonify({
                    "status": False,
                    "message" : "Crop category code already exists"
                })
            new_crop_category = CropCategories(category_code = category_code, category_name = category_name)
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
        
        user_query = Admins.query.filter_by(admin_uuid = id).first()
        
        if user_query and user_data['user_role'] == "admin":
            data = request.get_json()
            if not is_json(data):
                abort(415)
            if 'crop_name' not in data or 'category_code' not in data or 'crop_code' not in data:
                abort(422)
            crop_name = request.json.get('crop_name')
            category_code = request.json.get('category_code')
            crop_code = request.json.get('crop_code')
            
            #combining crop code and category code for db crop code
            db_crop_code = category_code + crop_code
            is_crop_exists= Crops.query.filter_by(crop_code = crop_code).first()
            if is_crop_exists :
                return jsonify({
                    "status": False,
                    "message" : "Crop Code already exists"
                })
            new_crop = Crops(crop_name = crop_name, crop_code = db_crop_code.upper(), category_code = category_code)
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
        
        user_query = Admins.query.filter_by(admin_uuid = id).first()
        
        if user_query and user_data['user_role'] == "admin":
            data = request.get_json()
            if not is_json(data):
                abort(415)
            if 'variety_name' not in data or 'crop_code' not in data or 'variety_code' not in data:
                abort(422)
            variety_name = request.json.get('variety_name')
            variety_code = request.json.get('variety_code')
            crop_code = request.json.get('crop_code')
            
            # db_variety_code is the combination of crop code and variety code
            db_variety_code = crop_code + variety_code
            is_crop_exists= CropVariety.query.filter_by(variety_code = db_variety_code).first()
            if is_crop_exists :
                return jsonify({
                    "status": False,
                    "message" : "Crop variety already exists"
                })
            new_crop_variety = CropVariety(variety_name = variety_name, crop_code = crop_code, variety_code = db_variety_code)
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
        user_query = Admins.query.filter_by(admin_uuid = id).first()
        if user_query and user_data['user_role'] == "admin":
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
        
        
        user_query = Admins.query.filter_by(admin_uuid = id).first()
        if user_query and user_data['user_role'] == "admin":
            data = request.get_json()
            
            country = request.get_json()
            if not is_json(country):
                abort(415)
            if 'region_name' not in country or 'country_code' not in country or 'region_code' not in country:
                abort(422)
            region_name = request.json.get('region_name')
            country_code = request.json.get('country_code')
            region_code = request.json.get('region_code')
            new_region = Regions(region_name = region_name, region_code = region_code, country_code = country_code)
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
        
        
        user_query = Admins.query.filter_by(admin_uuid = id).first()
        if user_query and user_data['user_role'] == "admin":
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
        
        
        user_query = Admins.query.filter_by(admin_uuid = id).first()
        if user_query and user_data['user_role'] == "admin":
            data = request.get_json()
            
            country = request.get_json()
            if not is_json(country):
                abort(415)
            if 'crop_id' not in country or 'crop_variety_id' not in country or 'region_id' not in country or 'country_id' not in country or 'price' not in country or 'product_origin' not in country:
                abort(422)
            crop_id = request.json.get('crop_id')
            crop_variety_id = request.json.get('crop_variety_id')
            country_id = request.json.get('country_id')
            region_id = request.json.get('region_id')
            product_origin = request.json.get('product_origin')
            price = request.json.get('price') * 100
            new_product = Product(crop_id = crop_id, crop_variety_id = crop_variety_id, country_id = country_id, region_id = region_id, price = price, product_origin = product_origin)
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

        
        file_url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media&key={Config.FILE_API_KEY}"
        
        
        # Fetch the file content
        response = requests.get(file_url)
        
        # Check if the request was successful
        if response.status_code == 200:
            # Convert the response content to a StringIO object
            csv_data = StringIO(response.text)
            
            # Read the CSV data into a pandas DataFrame
            df = pd.read_csv(csv_data)
            
        # Ensure DataFrame columns match the table structure
        df.columns = ["variety_code", "country_code", "region_code", "price", "product_origin"]
        for index, row in df.iterrows():
            product = Product(
                variety_code=row["variety_code"],
                country_code=row["country_code"],
                region_code=row["region_code"],
                price=row["price"],
                product_origin=row["product_origin"]
            )
            db.session.add(product)
                
        db.session.commit()

        return jsonify({
            "status": True,
            "message" : "Product imported successfully"
        })

    except:
        db.session.rollback()
        raise
    