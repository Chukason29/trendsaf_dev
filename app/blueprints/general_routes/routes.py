from flask import Blueprint, request, jsonify, abort
from sqlalchemy import Column, Integer, String, and_, desc, asc
from ...models import Users, Crops, Countries, Regions, CropCategories, CropVariety, ProcessLevel
from ...config import Config
import html
import json

general_bp = Blueprint('general_routes', __name__)
@general_bp.route('/crop/categories', methods = ['POST', 'GET'])
def get_cropcategories():
    crop_categories = CropCategories.query.all()
    all_crops = [{"id": crop_category.category_code, "name" : crop_category.category_name} for crop_category in crop_categories]
    return jsonify(all_crops)

@general_bp.route('/crops', methods = ['GET'])
def get_crops():
    crops = Crops.query.order_by(Crops.crop_name.asc()).all()
    all_crops = [
        {
            "id": crop.crop_code, 
            "name":crop.crop_name,
            "crop_category": crop.category_code
        } for crop in crops
    ]
    return jsonify(all_crops)


@general_bp.route('/crops/varieties', methods = ['GET'])
def get_varieties():
    #TODO check is certain params are missing
    crops = CropVariety.query.all()
    all_varieties = [
        {   
            "crop_id" : crop.crop_code,
            "id": crop.variety_code, 
            "name":crop.variety_name
        } for crop in crops]
    return jsonify(all_varieties)

'''@general_bp.route('/crops/process_state', methods = ['GET'])
def get_process_state():
    #TODO check is certain params are missing
    crops = ProcessLevel.query.all()
    all_varieties = [
        {   
            "crop_id" : crop.crop_code,
            "crop_variety_id": crop._variety_code, 
            "process_state":crop.process_state
        } for crop in crops]
    return jsonify(all_varieties)'''


@general_bp.route('/countries', methods = ['POST', 'GET'])
def get_countries():
    countries = Countries.query.all()
    all_countries = [{"id": country.country_code, "name": country.country_name, "code": country.country_code } for country in countries]
    return jsonify(all_countries)


@general_bp.route('/regions', methods = ['GET'])
def get_regions():

    #TODO query the regions table based on the id sent
    regions = Regions.query.order_by(Regions.country_code.asc()).all()
    allregions = [{"region_name" : region.region_name, "region_id" : region.region_code, "country_id" : region.country_code} for region in regions]
    return jsonify(allregions)
