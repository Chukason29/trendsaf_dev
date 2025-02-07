from flask import Blueprint, request, jsonify, abort, session, make_response, url_for, redirect, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer, String, and_
from datetime import timedelta
from ...functions import encode_id, decode_id, get_token_auth_header, generate_reset_token, validate_reset_token, is_json, generate_verification_link,generate_password_link, validate_password_link
from ...models import Users, Profile, Tokens
from ...config import Config
from ... import bcrypt, db, mail
import uuid
import jwt
import html
import secrets
import datetime
import json

auth_bp = Blueprint('auth', __name__)

@auth_bp.before_request
def before_request():
    session.permanent = True
    auth_bp.permanent_session_lifetime = datetime.timedelta(hours=12) # session will be alive for 12 hours

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        #TODO get email and password from
        data = request.get_json()
        if not is_json(data):
            abort(415)
        if 'email' not in data or 'password' not in data:
            abort(422)
        email = request.json.get('email')
        password = request.json.get('password')

        #TODO perform rate limiting

        #TODO compare email and password if they are great
        #TODO checked if user exits
        user = Users.query.filter_by(email=email).first()
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
        
        id = encode_id(str(user.user_uuid)) #user's uuid
        user_id = user.user_id #user's id
        firstname = user.firstname
        
        # When user is both verified and confirmed
        if user.is_verified == True and  user.is_confirmed == True:
            result = db.session.query(Users, Profile).join(Profile).filter(Users.user_id == user_id).first()
            #TODO create a JWT token ==> On the jwt token i will add the verification and confirmation status to the client
            access_token = create_access_token(
                identity=id,
                expires_delta=timedelta(hours=2400),
                additional_claims=(
                    {
                        "is_confirmed": True,
                        "is_verified" : True,
                        "firstname" : result.Users.firstname,
                        "lastname" : result.Users.lastname,
                        "email" : result.Users.email,
                        "is_verified": result.Users.is_verified,
                        "is_confirmed": result.Users.is_confirmed,
                        "company_role" : result.Profile.company_role,
                        "company_name": result.Profile.company_name,
                        "company_type" : result.Profile.company_type,
                        "company_size" : result.Profile.company_size,
                        "start_year": result.Profile.start_year,
                        "province" : result.Profile.province 
                    }
                )
            )
            #TODO create a crsf token and set it as a coookie
            csrf_token = secrets.token_hex(16)
            result = db.session.query(Users, Profile).join(Profile).filter(Users.user_id == user_id).first()
            response =  jsonify({
                "auth_token" : access_token,
                "status": True,
            })
            #delete previous cookie
            response.delete_cookie('access_token')
            #Set access_token as an HttpOnly cookie
            response.set_cookie(
                'auth_token',
                access_token,
                httponly=True,  # Prevents JavaScript access
                secure=False,    # Use True if using HTTPS
                samesite='None' # Change based on your requirements
            )
            #session["user_role"] = result.role

            return response, 200
            
        if user.is_verified == False:
             #creating a link to be sent to mail
            link = generate_verification_link(email)
            token = Tokens(token = link, is_token_used = False)
            db.session.add(token)
            db.session.commit()
            #TODO send mail to user
            mail_message = render_template("email_verification.html", link=link, firstname=firstname)
            msg = Message("Email Verification",
                sender='support@trendsaf.co',
                recipients=[email])  # Change to recipient's email
            msg.body = mail_message
            mail.send(msg)
            
            return jsonify({
                "status": False,
                "message": "Verification link sent"
            })
        
        if user.is_verified == True:                 
            #TODO create a JWT token ==> On the jwt token i will add the verification and confirmation status to the client
            access_token = create_access_token(
                identity=id,
                expires_delta=timedelta(hours=24),
                additional_claims=({"is_confirmed": user.is_confirmed})
            )
            #TODO create a crsf token and set it as a coookie
            csrf_token = secrets.token_hex(16)
            response = jsonify({
                    "status": True,
                    "access_token": access_token,
                })
            #Set access_token as an HttpOnly cookie
            response.set_cookie(
                'access_token',
                access_token,
                httponly=True,  # Prevents JavaScript access
                secure=False,    # Use True if using HTTPS
                samesite='None' # Change based on your requirements
            )

            #Set CSRF token as a non-HttpOnly cookie
            #response.set_cookie('csrf_token', access_token, httponly=False)

            user_uuid = uuid.UUID(decode_id(id))
            #checking if the user is confirmed 
            if user.is_confirmed == True:             
                result = db.session.query(Users, Profile).join(Profile).filter(Users.user_id == user_id).first()
                #session["user_role"] = result.role
                response =  jsonify({
                    "status": True,
                    "access_token": access_token,
                    "is_verified": result.Users.is_verified,
                    "is_confirmed": result.Users.is_confirmed,
                    "user_role" : result.Profile.company_role,
                    "company_name": result.Profile.company_name,
                    "company_type" : result.Profile.company_type,
                    "company_size" : result.Profile.company_size,
                    "start_year": result.Profile.start_year,
                    "province" : result.Profile.province
                })

            return response, 200
                        
    except Exception as e:
        raise

@auth_bp.route('/logout', methods=['POST'])
def logout():
    #session.clear()
    return jsonify({"message": "logged out"})

@auth_bp.route('/password_reset_request', methods=['POST'])
def password_reset_request():
    try:
        #TODO get email and password from
        data = request.get_json()
        if not is_json(data):
            abort(415)
        if 'email' not in data:
            abort(422)
        email = request.json.get('email')

        #TODO checked if user exits
        user = Users.query.filter_by(email=email).first()
        if user:
            id = str(user.user_uuid)
            pass_link = generate_password_link(id)
            firstname = user.firstname
            
            #TODO Instantiating an object of tokens and store the link in the database
            token = Tokens(token = pass_link['link'], is_token_used = False)
            
            #TODO send mail to user
            mail_message = render_template("password_reset.html", pass_link=pass_link, firstname=firstname)
            msg = Message("Password  Reset",
                sender='Trendsaf Support',
                recipients=[email])  # Change to recipient's email
            msg.body = mail_message
            mail.send(msg)
            
            
            db.session.add(token)
            db.session.commit()
            return jsonify({
                "status": True,
                "message": "password link sent"
            })  
        else:
            return   jsonify({
                "status": False,
                "message": "user does not exist"
            })                    
    except Exception as e:
        db.session.rollback()


@auth_bp.route('/pwd_link_verify/<token>', methods = ['POST', 'GET'])
def pwd_link_verify(token):
    try:
        link = url_for('auth.pwd_link_verify', token=token, _external = True)
        
        #TODO querying token for usage
        token_filter = Tokens.query.filter(and_(Tokens.token == link)).first()
        if token_filter and token_filter.is_token_used==False:
            response = validate_password_link(token).get_json()
            if response['status'] == True:
                token_filter.is_token_used = True
                db.session.commit()
                return redirect(f"{Config.BASE_URL}/reset_password/{token}")
            else:
                return redirect(f"{Config.BASE_URL}/reset_password_error?message=link has expired")
        else:
            return redirect(f"{Config.BASE_URL}/reset_password_error?message=link has been used")
    except:
        db.session.rollback()
        return redirect(f"{Config.BASE_URL}/reset_password_error?message=link has expired")

@auth_bp.route('/password_reset/<token>', methods=['POST'])
def password_reset(token):
    try:
        #TODO extract the user uuid from the token
        id = validate_password_link(token).get_json()
        user_id = uuid.UUID(id['id'])           
        
        #TODO Collect the new password
        data = request.get_json()
        if not is_json(data):
            abort(415)
        if 'password' not in data:
            abort(422)
        password = html.escape(request.json.get('password'))
    
        
        #TODO query the user with the uuid
        user = Users.query.filter(and_(Users.user_uuid == user_id)).first()       
        
        if user:
            #TODO update the password
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            db.session.commit()
            return jsonify({
                "status" : True,
                "message": "password change is successful"
            })
        else:
            return jsonify({
                "status" : False,
                "message": "password change is unsuccessful"
            })
        
        #TODO return the appropriate value
        pass
    except Exception as e:
        db.session.rollback()
        raise
    finally:
        pass

@auth_bp.route('/auth_access', methods=['POST'])
@jwt_required()
def auth_access():
    try:
        id = uuid.UUID(decode_id(get_jwt_identity()))   
        return jsonify({
            "message": 'success'
        })
    except Exception as e:
        raise


@auth_bp.route('/confirmation', methods=["POST"])
@jwt_required()
def confirmation():
    try:
        #TODO Get the access token from the request
        csrf_token_in_cookie = request.cookies.get('access_token')

        #TODO Get the CSRF token from the request
        csrf_token_in_header = request.headers.get('X-CSRF-TOKEN')

        #TODO get the jwt token from the header and extract
        id = decode_id(get_jwt_identity()) 
        token_id = get_jwt_identity()
        
        user_profile = request.get_json()
        
        #TODO collect info from client and remove all htmlentities and make sure they are not empty
        company_name = html.escape(user_profile["company_name"])
        country = html.escape(user_profile["country"])
        company_type = html.escape(user_profile["company_type"])
        company_size = html.escape(user_profile["company_size"])
        start_year = html.escape(user_profile["start_year"])
        annual_revenue = html.escape(user_profile["annual_revenue"])
        company_role = html.escape(user_profile["company_role"])
        province = html.escape(user_profile["province"])
        phone = html.escape(user_profile["phone"])


        #TODO converting id to proper uuid and assign to a variable
        decoded_uuid = uuid.UUID(id)
        user_query = Users.query.filter_by(user_uuid=decoded_uuid).one_or_none()

        #TODO collect and assign user's id and email
        user_id = user_query.user_id
        user_email = user_query.email
        firstname = user_query.firstname
        lastname = user_query.lastname

        #TODO send data to the database
        user_query.is_confirmed = True #updating is_confirmed column

        user_query.user_profile = Profile(
                company_name=company_name,
                company_type=company_type,
                company_size=company_size,
                start_year=start_year,
                annual_revenue=annual_revenue,
                company_role=company_role,
                phone=phone,
                province=province,
                country=country
        )

        db.session.commit()
        #TODO send confirmation email to the user
        message = render_template("confirmation_email.html", firstname=firstname, link=f"https://{Config.BASE_URL}/login")
        msg = Message("Account Confirmation",
        sender='support@trendsaf.co',
        recipients=[user_email])  # Change to recipient's email
        msg.body = message
        mail.send(msg)
        access_token = create_access_token(
            identity=token_id,
            expires_delta=timedelta(days=90),
            additional_claims=(
                {
                    "is_confirmed": True,
                    "is_verified" : True,
                    "firstname" : firstname,
                    "lastname" : lastname,
                    "email" : user_email,
                    "company_name":company_name,
                    "company_type":company_type,
                    "company_size":company_size,
                    "start_year":start_year,
                    "annual_revenue":annual_revenue,
                    "company_role":company_role,
                    "phone":phone,
                    "province":province,
                    "country":country
                }
            )
        )
        response =  jsonify({
            "auth_token" : access_token,
            "is_confirmed": True,
            "message" : "user confirmed successfully",
            "status": 200
        })
        response.delete_cookie('access_token')
        response.set_cookie(
            'access_token',
            access_token,
            httponly=True,  # Prevents JavaScript access
            secure=False,    # Use True if using HTTPS
            samesite='None' # Change based on your requirements
        )
        return response, 200     
    except Exception as e:
        db.session.rollback()
        raise
    finally:
        db.session.close()

@auth_bp.route('/google_auth', methods = ['POST'])
def google_auth():
    return "Google_auth"