from flask import request, Blueprint
from app import db
from models import User
from helpers import token_required
from werkzeug.security import generate_password_hash, check_password_hash

api = Blueprint('api', __name__)


@api.route('/signup', methods=['POST'])
def add_user() -> dict:
    """api for signup"""
    data = request.get_json()
    password = generate_password_hash(data['password'], method='sha256')
    existing_mobile = User.query.filter_by(mobile=data['mobile']).first()
    existing_mail = User.query.filter_by(email_address=data['email']).first()
    if existing_mobile:
        return {'message': "Mobile number already exists, try with another number!"}
    if existing_mail:
        return {'message': "Email address already exists, try with another email address!"}

    new_user = User(name=data['name'], mobile=data['mobile'], email_address=data['email'], password=password,
                    address=data['address'])
    db.session.add(new_user)
    db.session.commit()
    return {'message': 'new user added successfully'}


@api.route('/profile')
@token_required
def get_profile(current_user: User) -> dict:
    """api to get profile of current user"""
    return {
        "name": current_user.name,
        "mobile": current_user.mobile,
        "email": current_user.email_address,
        "address": current_user.address,
    }
