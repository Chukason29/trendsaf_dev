import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
class Config:
    """Base configuration."""
    SECRET_KEY = os.getenv('SECRET_KEY')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KE')
    RESET_PASSWORD_SALT = os.getenv('RESET_PASSWORD_SALT')
    JWT_ERROR_MESSAGE_KEY = os.getenv('JWT_ERROR_MESSAGE_KEY')
    JWT_COOKIE_CSRF_PROTECT = os.getenv('JWT_COOKIE_CSRF_PROTECT')
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
    BASE_URL = os.getenv("BASE_URL")
    MAX_CONTENT_LENGTH = os.getenv("MAX_CONTENT_LENGTH")
    FILE_API_KEY = os.getenv("FILE_API_KEY")
    
    
    SESSION_COOKIE_SAMESITE = os.getenv('.SESSION_COOKIE_SAMESITE')
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE')

    if SQLALCHEMY_TRACK_MODIFICATIONS == "True":
        SQLALCHEMY_TRACK_MODIFICATIONS = 1
    elif SQLALCHEMY_TRACK_MODIFICATIONS == "False" :
        SQLALCHEMY_TRACK_MODIFICATIONS = 0
    # Flask-Mail Configuration for Gmail SMTP
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587  # Use TLS port
    MAIL_USE_TLS = True  # Enable TLS encryption
    MAIL_USE_SSL = False  # Do not use SSL
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')  # Your Gmail username (email address)
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')  # Your Gmail password or app-specific password
    MAIL_DEFAULT_SENDER = 'support@trendsaf.co'  # Default sender (can be the same as username)
    MAIL_MAX_EMAILS = None
    MAIL_ASCII_ATTACHMENTS = False
    AES_KEY = os.getenv("AES_KEY")
    DEBUG = os.getenv("DEBUG")
    if DEBUG == "True":
        DEBUG = 1
    elif DEBUG == "False":
        DEBUG = 0


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    ENV = 'development'


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    ENV = 'production'



