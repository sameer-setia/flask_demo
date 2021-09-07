import os
import jwt
import datetime
import random
from app import db
from models import User, Otp
from flask import request, Blueprint
from helpers import token_required
from twilio.rest import Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import and_

api = Blueprint('api_v1', __name__)


@api.route('/signup', methods=['POST'])
def add_user():
    data = request.get_json()
    password = generate_password_hash(data['password'], method='sha256')
    existing_mobile = User.query.filter_by(mobile=data['mobile']).first()
    existing_mail = User.query.filter_by(email_address=data['email']).first()
    if existing_mobile:
        return {'message': "Mobile number already exists, try with another number!"}
    if existing_mail:
        return {'message': "Email address already exists, try with another email address!"}

    new_user = User(name=data['name'], mobile=data['mobile'], email_address=data['email'], password=password)
    db.session.add(new_user)
    db.session.commit()
    return {'message': 'new user added successfully'}


@api.route('/login')
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    user = User.query.filter_by(email_address=email).first()
    if not user:
        return {'message': 'user does not exist'}
    if not password or not check_password_hash(user.password, password):
        return {'message': 'please enter valid password'}
    token = jwt.encode(
        {'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)},
        os.environ.get('SECRET_KEY'), algorithm="HS256")
    token = token.decode("utf-8")
    user.jwt_token = token
    db.session.add(user)
    db.session.commit()
    return {'message': 'you have successfully logged in', 'token': token}


@api.route('/change-password')
@token_required
def change_password(current_user):
    data = request.get_json()
    existing_password = data['password']
    if not check_password_hash(current_user.password, existing_password):
        return {'message': 'wrong existing password'}
    new_password = data['new_password']
    new_password1 = data['new_password1']
    if new_password != new_password1:
        return {'message': 'passwords do not match'}
    current_user.password = generate_password_hash(new_password, method='sha256')
    db.session.add(current_user)
    db.session.commit()
    return {'message': 'password changed successfully'}


@api.route('/logout')
@token_required
def logout(current_user):
    current_user.jwt_token = None
    db.session.add(current_user)
    db.session.commit()
    return {'message': 'you have successfully logged out'}


@api.route('/forgot-password-send-otp')
def send_otp():
    data = request.get_json()
    if data['email']:
        user = User.query.filter_by(email_address=data['email']).first()
    elif data['mobile']:
        user = User.query.filter_by(mobile=data['mobile']).first()
    else:
        return {'message': 'please enter a valid email/mobile.'}
    account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
    client = Client(account_sid, auth_token)
    existing_otp = Otp.query.filter(and_(Otp.user_id == user.id, Otp.expiry > db.func.now(), Otp.verified == 0)).\
        order_by(Otp.created_at.desc()).first()
    if existing_otp:
        otp = existing_otp.code
    else:
        otp = random.randint(1000, 9999)
        user_otp = Otp(user_id=user.id, code=otp, expiry=datetime.datetime.utcnow() + datetime.timedelta(minutes=5))
        db.session.add(user_otp)
        db.session.commit()
    message = client.messages.create(
        body=f"Hello {user.name} Your otp for forgot password is {otp}", from_='+13347218537', to=f"+91{data['mobile']}")
    message = Mail(
        from_email='sameersetia17@gmail.com',
        to_emails=data['email'],
        subject='Forgot Password - OTP',
        html_content=f'Hello {user.name} your otp for forget password is {otp}')

    sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
    try:
        sg.send(message)
    except Exception as e:
        print(e)
    return {'message': 'message sent successfully'}


@api.route('/forgot-password-validate-otp')
def validate_otp():
    data = request.get_json()
    if data['email']:
        user = User.query.filter_by(email_address=data['email']).first()
    elif data['mobile']:
        user = User.query.filter_by(mobile=data['mobile']).first()
    else:
        return {'message': 'please enter a valid email/mobile.'}
    user_otp = Otp.query.filter(and_(Otp.user_id == user.id, Otp.expiry > db.func.now(), Otp.verified == 0)).\
        order_by(Otp.created_at.desc()).first()
    if user_otp and user_otp.code == data['otp']:
        pass1 = data['pass1']
        pass2 = data['pass2']
        if pass1 != pass2:
            return {'message': 'passwords do not match'}
        user.password = generate_password_hash(pass1, method='sha256')
        db.session.add(user)
        user_otp.verified = 1
        db.session.add(user_otp)
        db.session.commit()
        return {'message': 'password reset successful'}
    else:
        return {'message': 'please enter a valid otp.'}
