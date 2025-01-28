from . import db
from sqlalchemy import Column, Integer, String, Numeric
#dfrom sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID
import pendulum

class Users(db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_uuid = db.Column(UUID(as_uuid=True), unique=True)
    firstname = db.Column(db.String(255), nullable=False)
    lastname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(70), nullable=False, unique=True)
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
    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    admin_uuid = db.Column(UUID(as_uuid=True), unique=True)
    firstname = db.Column(db.String(255), nullable=False)
    lastname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(70), nullable=False, unique=True)
    password = db.Column(db.String(1000), nullable=True)
    
class Profile(db.Model):
    __tablename__ = "profile"
    profile_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id')) 
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
    login_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
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
    crop_category_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    crop_category_name = db.Column(db.String(30), nullable=False)
    crop = db.relationship('Crops', backref="crops", uselist=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))

class Crops(db.Model):
    __tablename__ = "crops"
    crop_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    crop_category_id = db.Column(db.Integer, db.ForeignKey('cropcategories.crop_category_id'))
    crop_name = db.Column(db.String(50), nullable=False)
    crop_variety = db.relationship('CropVariety', backref="cropvariety", uselist=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))

class CropVariety(db.Model):
    __tablename__ = "cropvariety"
    crop_variety_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    crop_id = db.Column(db.Integer, db.ForeignKey('crops.crop_id'))
    crop_variety_name = db.Column(db.String(30), nullable=False)
    crop_variety = db.relationship('ProcessLevel', backref="process_level", uselist=False)
    product = db.relationship('Product', backref="product", uselist=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))

class ProcessLevel(db.Model):
    __tablename__ = "process_level"
    process_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    crop_id = db.Column(db.Integer, db.ForeignKey('crops.crop_id'))
    crop_variety_id = db.Column(db.Integer, db.ForeignKey('cropvariety.crop_variety_id'))
    process_state = db.Column(db.String(30), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    
class Countries(db.Model):
    __tablename__ = "countries"
    country_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    country_name = db.Column(db.String(100), nullable=False)
    country_code = db.Column(db.String(5), nullable=False)
    products = db.relationship('Product', backref="products", uselist=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    
class Regions(db.Model):
    __tablename__ = "regions"
    region_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    country_id = db.Column(db.Integer, db.ForeignKey('countries.country_id'))
    region_name = db.Column(db.String(100), nullable=False)
    products = db.relationship('Product', backref="region_product", uselist=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))
    
class Product(db.Model):
    __tablename__ = "product"
    product_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    crop_id = db.Column(db.Integer, db.ForeignKey('crops.crop_id'))
    crop_variety_id = db.Column(db.Integer, db.ForeignKey('cropvariety.crop_variety_id'))
    country_id = db.Column(db.Integer, db.ForeignKey('countries.country_id'))
    region_id = db.Column(db.Integer, db.ForeignKey('regions.region_id'))
    price = db.Column(db.Integer)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: pendulum.now('UTC'))