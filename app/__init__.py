from .functions import is_valid_email, verify_code, verify_code_expiration
from flask import Flask, jsonify, redirect, session, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import Column, Integer, String, and_
from flask_migrate import Migrate
from flask import Flask
from flask_cors import CORS, cross_origin
from flask_mail import Mail, Message
from sqlalchemy.dialects.postgresql import UUID
from .data import data, user_profile
from dotenv import load_dotenv
from datetime import datetime
from .config import Config #collecting the Config class from config.py to configure the app
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_swagger_ui import get_swaggerui_blueprint

# Load environment variables from .env
load_dotenv()

# Extensions
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
bcrypt = Bcrypt()
cors = CORS()
jwt = JWTManager()

def create_app(config_class=Config):
    
    #Application factory fro creating app
    app = Flask(__name__) # creates a flask app and sends store in an instance app
    
    

    #Configure app
    app.config.from_object(config_class)
    app.config.get(Config.SQLALCHEMY_DATABASE_URI)
    app.config.get(Config.SQLALCHEMY_TRACK_MODIFICATIONS)
    app.config.get(Config.SECRET_KEY)
    app.config.get(Config.JWT_SECRET_KEY)
    app.config.get(Config.JWT_ERROR_MESSAGE_KEY)
    app.config.get(Config.SECRET_KEY)
    app.config.get(Config.JWT_COOKIE_CSRF_PROTECT)
    app.config.get(Config.SESSION_COOKIE_SAMESITE)
    app.config.get(Config.SESSION_COOKIE_SECURE)
    app.config.get(Config.MAX_CONTENT_LENGTH)
    app.config.get(Config.FILE_API_KEY)
    
    app.config.get(Config.BASE_URL)


     # Initialize extensions with the app
    db.init_app(app)#create an instance of th SQLALCHEMY to access the database from here
    migrate.init_app(app, db) # connects flask migrate to the app an SQLAlchemy
    mail.init_app(app) #initializing the mail class with app
    bcrypt.init_app(app)
    jwt.init_app(app)
    cors.init_app(app, resources=
                  {
                      r"/auth/*": {
                          "origins": ["http://206.189.116.102:5001", "http://206.189.116.102:5080","https://app.trendsaf.co", "http://localhost:5001","*"],
                          "methods": ["POST", "GET", "PUT", "PATCH", "DELETE"],
                          "allow_headers": ["Content-Type", "Authorization", "true","X-CSRF-TOKEN"], 
                          "expose_headers": ["Authorization"],
                          "supports_credentials": True,
                        },
                        r"/signup/*": {
                          "origins": ["http://206.189.116.102:5001", "http://206.189.116.102:5080", "https://app.trendsaf.co", "http://localhost:5001","*"],
                          "methods": ["POST", "GET", "PUT", "PATCH", "DELETE"],
                          "allow_headers": ["Content-Type", "Authorization", "true", "X-CSRF-TOKEN"], 
                          "expose_headers": ["Authorization"],
                          "supports_credentials": True,
                        },
                        r"/admin/*": {
                          "origins": ["http://206.189.116.102:5001", "http://206.189.116.102:5080", "https://app.trendsaf.co", "http://localhost:5001","*"],
                          "methods": ["POST", "GET", "PUT", "PATCH", "DELETE"],
                          "allow_headers": ["Content-Type", "Authorization", "true", "X-CSRF-TOKEN"], 
                          "expose_headers": ["Authorization"],
                          "supports_credentials": True,
                        },
                        r"/general_routes/*": {
                          "origins": ["http://206.189.116.102:5001", "http://206.189.116.102:5080", "https://app.trendsaf.co", "http://localhost:5001","*"],
                          "methods": ["POST", "GET", "PUT", "PATCH", "DELETE"],
                          "allow_headers": ["Content-Type", "Authorization", "true", "X-CSRF-TOKEN"], 
                          "expose_headers": ["Authorization"],
                          "supports_credentials": True,
                        },
                        r"/user/*": {
                          "origins": ["http://206.189.116.102:5001", "http://206.189.116.102:5080", "https://app.trendsaf.co", "http://localhost:5001","*"],
                          "methods": ["POST", "GET", "PUT", "PATCH", "DELETE"],
                          "allow_headers": ["Content-Type", "Authorization", "true", "X-CSRF-TOKEN"], 
                          "expose_headers": ["Authorization"],
                          "supports_credentials": True,
                        }
                   })



    @app.route('/static/<path:path>')
    def send_static(path):
        return send_from_directory('static', path)
    
    SWAGGER_URL = '/swagger'
    API_URL = '/static/swagger.yaml'
    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={
            'TrendsAF' : "TrendsAF Endpoint for BaseFood"
        }
    )
    
    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)
    # Register blueprints

    #authentication/login blueprint
    from .blueprints.auth.routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    #registration, verification and confirmation blueprint
    from .blueprints.signup.routes import signup_bp
    app.register_blueprint(signup_bp, url_prefix='/signup')
    
    #admin blueprint
    from .blueprints.admin.routes import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    #General blueprint
    from .blueprints.general_routes.routes import general_bp
    app.register_blueprint(general_bp, url_prefix='/general_routes')
    
    #User blueprint
    from .blueprints.user.routes import user_bp
    app.register_blueprint(user_bp, url_prefix='/user')
    
    # Register error handlers
    register_error_handlers(app)

    @app.route('/')
    def index():
        return redirect('https://trendsaf.co')
    

    return app
    


#Handling errors
def register_error_handlers(app):
    """Register custom error pages for common HTTP errors."""
    @app.errorhandler(401)
    def not_found_error(error):
        return jsonify({
            "message": "unauthorized access",
            "status":False,
            "error": 401
            }), 401
    
    @app.errorhandler(403)
    def access_error(error):
        return jsonify({
            "message": "unauthorized access",
            "status":False,
            "error": 403
            }), 403
    
    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({
            "message": "Resource not found",
            "status":False,
            "error": 404
            }), 404
    
    @app.errorhandler(405)
    def wrong_method_error(error):
        return jsonify({
            "message": "api call method not permitted",
            "status":False,
            "error": 405
            }), 405
    
    @app.errorhandler(411)
    def authentication_error(error):
        return jsonify({
            "message": "wrong email or password",
            "status":False,
            "error": 411
            }), 411
    
    @app.errorhandler(415)
    def datatype_error(error):
        return jsonify({
            "message": "wrong data type, requires json data",
            "status":False,
            "error": 415
            }), 415

    @app.errorhandler(422)
    def missing_parameter_error(error):
        db.session.rollback()  # If using a database, rollback on error
        return jsonify({
            "message": "missing parameter",
            "status":False,
            "error": 422
            }), 422
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()  # If using a database, rollback on error
        return jsonify({
            "message": "Internal server error",
            "status":False,
            "error": 500
            }), 500