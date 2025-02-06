from flask import Blueprint, request, jsonify, abort, redirect, url_for, render_template
from ...models import Users, Profile, Tokens
from ...config import Config
from ... import db
from ... import bcrypt
from ... import mail
from ... import register_error_handlers
from ...functions import encode_id, decode_id, is_json, is_valid_email, verify_code, verify_code_expiration, generate_verification_link,validate_verification_link
from itsdangerous import URLSafeSerializer
from sqlalchemy import Column, Integer, String, and_
from flask_mail import Mail, Message
import re
import random
import string
import pendulum
import uuid
import base64
import os
import hashlib
import html


signup_bp = Blueprint('signup', __name__)


@signup_bp.route('/registration', methods=['GET', 'POST'])
def registration(): # The hashed uuid value will be appended to the url link
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
                user_email = Users.query.filter_by(email=email).first()
                if user_email:
                    return jsonify({"exists": True, "is_verified":False, "message": "Account with email already exists"}), 400
            
                firstname = html.escape(data['firstname'])
                lastname = html.escape(data['lastname'])
                #hash the password
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                #creating a user uuid for identification
                new_user_uuid = uuid.uuid4()

                #convert the uuid to a string and encrypt
                encrypted_id = encode_id(str(new_user_uuid))

                #TODO Instantiating an object of users
           
                new_user = Users(
                            user_uuid = new_user_uuid, 
                            firstname = firstname, 
                            lastname = lastname, 
                            email = email,
                            password = hashed_password, 
                            verify_code=verify_code, 
                            verify_code_expires=verify_code_expiration
                        )
                #message to send to the user
            
                
                #creating a link to be sent to mail
                link = generate_verification_link(email)
                
                #TODO Instantiating an object of tokens and store the link in th database
                token = Tokens(token = link, is_token_used = False)
                
                #TODO persist info to the data
                db.session.add(new_user)
                db.session.add(token)
                db.session.commit()
                
                
                # Render HTML template
                html_content = render_template("email_verification.html", link=link, firstname=firstname)
                #TODO send mail to user
                #verify_mail_message = f""
                msg = Message("BaseFood Email verification",
                    sender='support@trendsaf.co',
                    recipients=[email])  # Change to recipient's email
                msg.html = html_content  # Set HTML content for email
                mail.send(msg)

                #TODO return a json object
                return jsonify({
                        "status": 200, 
                        "message": "Registration successful", 
                        "is_confirmed": False, 
                        "is_verified":False
                    }), 200
            else:
                abort(405)
    except Exception as e:
        db.session.rollback()
        raise
    finally:
        db.session.close()

@signup_bp.route('/verification/<string:id>', methods=['GET', 'PATCH', 'POST'])
def verification(id):
    try:
        message = ""
        verify_data = request.get_json()
        #TODO collect verification code from form

        if "code" not in verify_data:
            abort(422)

        #TODO decode the encrypted uuid and covert back to uuid format
        decoded_uuid = uuid.UUID(decode_id(id))

        #TODO get record of the user
        user = Users.query.filter(and_(Users.user_uuid == decoded_uuid, Users.verify_code == verify_data['code'])).first()

        if user:
            if request.method == "PATCH":
                user.is_verified = True
                db.session.commit()
                return jsonify({"status": "verified", "is_verified": True, "is_confirmed":False, "message": "verification successful"})
        else:
            abort(401)
    except Exception as e:
        db.session.rollback()
        raise
    finally:
        db.session.close()

@signup_bp.route('/link_resend', methods=['POST'])
def link_resend():
    try:
        #TODO get email and password from
        data = request.get_json()
        if not is_json(data):
            abort(415)
        if 'email' not in data:
            abort(422)
        email = request.json.get('email')
        user = Users.query.filter_by(email=email).first()
        if not user:
            return jsonify({
                "status" : False,
                "message" : "email not registered"
            })
        #generates link
        link = generate_verification_link(email)
        
        #persists token to the database
        token = Tokens(token = link, is_token_used = False)
        db.session.add(token)
        db.session.commit()
        
        #TODO send mail to user
        mail_message = "Click this link to verify your email address: " + link
        msg = Message("Confirm Registration",
            sender='support@trendsaf.co',
            recipients=[email])  # Change to recipient's email
        msg.body = mail_message
        mail.send(msg)
        
        return jsonify({
            "status": True,
            "message": "Verification link sent"
        })
    except Exception as e:
        db.session.rollback()
        return str(e)
    finally:
        db.session.close()


@signup_bp.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        link = url_for('signup.confirm_email', token=token, _external = True)
        
        #TODO querying token for usage and 
        
        token_filter = Tokens.query.filter(and_(Tokens.token == link)).first()
        if token_filter and token_filter.is_token_used==False:
            email_response = validate_verification_link(token).get_json()
            if email_response['status'] == True:
                email = email_response['email']
                user = Users.query.filter(and_(Users.email == email)).first()
                user.is_verified = True
                token_filter.is_token_used = True
                db.session.commit()
                #return redirect ('http://localhost:5173/success')
                return redirect("https://app.trendsaf.co/confirm_email?status=True&message=success")
        else:
            return redirect("https://app.trendsaf.co/confirm_email?status=False&message=link has been used")
    except:
        db.session.rollback()
        return redirect("https://app.trendsaf.co/confirm_email?status=False&message=link has expired")
        
@signup_bp.route('/')
def index():
    return "Hello World"

