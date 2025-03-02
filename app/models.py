from . import db
from sqlalchemy import Column, Integer, String, Numeric
#dfrom sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID
import pendulum

class Users(db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    user_uuid = db.Column(UUID(as_uuid=True), unique=True, index=True)
    firstname = db.Column(db.String(255), nullable=False)
    lastname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(70), nullable=False, unique=True, index=True)
    password = db.Column(db.String(1000), nullable=True)
    is_confirmed = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    verify_code = db.Column(db.String(8), nullable=True)
    verify_code_expires = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    user_profile = db.relationship('Profile', backref="profile", uselist=False)

    # Relationship to user profile and OAuth accounts
    oauth_accounts = db.relationship('OAuthAccount', backref='oauth', lazy=True)

class Admins(db.Model):
    __tablename__ = "admins"
    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    admin_uuid = db.Column(UUID(as_uuid=True), unique=True, index=True)
    firstname = db.Column(db.String(255), nullable=False)
    lastname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(70), nullable=False, unique=True)
    password = db.Column(db.String(1000), nullable=True)
    
class Profile(db.Model):
    __tablename__ = "profile"
    profile_id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), index=True) 
    company_name = db.Column(db.String(100), nullable=True)
    company_type = db.Column(db.String(50), nullable=True)
    company_size = db.Column(db.String(5), nullable=True)
    start_year = db.Column(db.String(50), nullable=True)
    annual_revenue = db.Column(db.String(5), nullable=True)
    company_role = db.Column(db.String(5), nullable=True)
    phone = db.Column(db.String(15), nullable=True)
    province = db.Column(db.String(50), nullable=True)
    country = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC')) 

class OAuthProvider(db.Model):
    __tablename__ = 'oauth_providers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)  # e.g., 'Google', 'Facebook'
    client_id = db.Column(db.String(100), nullable=True)
    client_secret = db.Column(db.String(100), nullable=False)
    redirect_uri = db.Column(db.String(200), nullable=False)


class OAuthAccount(db.Model):
    __tablename__ = 'oauth_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('oauth_providers.id'), nullable=False)
    provider_user_id = db.Column(db.String(100), nullable=False)  # User ID from the OAuth provider
    access_token = db.Column(db.String(200))  # Optional: for making API calls
    refresh_token = db.Column(db.String(200))  # Optional: for refreshing access token


class PasswordTable(db.Model):
    __tablename__ = "passwordtable"
    pwd_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))   
    reset_token = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    expires_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))


class LoginTable(db.Model):
    __tablename__ = "logintable"
    login_id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    auth_method = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    auth_method = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    user_agent = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    expires_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    
    
class Tokens(db.Model):
    __tablename__ = "tokens"
    token_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(1000), nullable=False)
    is_token_used = db.Column(db.Boolean, default=False)

class CropCategories(db.Model):
    __tablename__ = "cropcategories"
    category_id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    category_code = db.Column(db.String(5), nullable=False, unique=True, index=True)
    category_name = db.Column(db.String(30), nullable=False)
    # One category can have many crops
    crops = db.relationship('Crops', backref="category", lazy=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))

class Crops(db.Model):
    __tablename__ = "crops"
    crop_id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    crop_code = db.Column(db.String(10), nullable=False, unique=True, index=True)
    crop_name = db.Column(db.String(50), nullable=False)
    category_code = db.Column(db.String, db.ForeignKey('cropcategories.category_code'), index=True)
    
    # One crop can have many varieties and many products
    varieties = db.relationship('CropVariety', backref="crop", lazy=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))

class CropVariety(db.Model):
    __tablename__ = "cropvariety"
    variety_id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    variety_code = db.Column(db.String(15), nullable=False, unique=True, index=True)
    variety_name = db.Column(db.String(30), nullable=False)
    crop_code = db.Column(db.String, db.ForeignKey('crops.crop_code'), index=True)
    # One variety can have many process levels and many products
    products = db.relationship('Product', backref="cropvariety", lazy=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    
class ProcessLevel(db.Model):
    __tablename__ = "process_level"
    process_id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    process_state = db.Column(db.String(30), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    
class Countries(db.Model):
    __tablename__ = "countries"
    country_id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    country_name = db.Column(db.String(100), nullable=False)
    country_code = db.Column(db.String(5), nullable=False, unique=True, index=True)
    # One country can have many products and regions
    products = db.relationship('Product', backref="countries", lazy=True)
    regions = db.relationship('Regions', backref="countries", lazy=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    
class Regions(db.Model):
    __tablename__ = "regions"
    region_id = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    region_code = db.Column(db.String(100), nullable=False, unique=True, index=True)
    country_code = db.Column(db.String, db.ForeignKey('countries.country_code'), index=True)
    region_name = db.Column(db.String(100), nullable=False)
    # One region can have many products
    products = db.relationship('Product', backref="regions", lazy=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    
class Product(db.Model):
    __tablename__ = "product"
    product_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    variety_code = db.Column(db.String, db.ForeignKey('cropvariety.variety_code'))
    country_code = db.Column(db.String, db.ForeignKey('countries.country_code'))
    region_code = db.Column(db.String, db.ForeignKey('regions.region_code'))
    product_origin = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    # Relationships (access via .crop, .cropvariety, .country, and .region)