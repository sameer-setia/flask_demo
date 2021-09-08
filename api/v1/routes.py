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
def add_user() -> dict:
    """api for signup of a new user"""
    data = request.get_json()
    password = generate_password_hash(data['password'], method='sha256')
    existing_mobile = User.query.filter_by(mobile=data['mobile']).first()
    existing_mail = User.query.filter_by(email_address=data['email']).first()
    if existing_mobile:
        # if another user with same mobile number exists
        return {'message': "Mobile number already exists, try with another number!"}
    if existing_mail:
        # if another user with same email address exists
        return {'message': "Email address already exists, try with another email address!"}

    # creating a new user
    new_user = User(name=data['name'], mobile=data['mobile'], email_address=data['email'], password=password)
    db.session.add(new_user)
    db.session.commit()
    return {'message': 'new user added successfully'}


@api.route('/login')
def login() -> dict:
    """api for login"""
    data = request.get_json()
    email = data['email']
    password = data['password']
    user = User.query.filter_by(email_address=email).first()
    if not user:
        # if user does not exists
        return {'message': 'user does not exist'}
    if not password or not check_password_hash(user.password, password):
        # if password not entered or password does not matches
        return {'message': 'please enter valid password'}
    # creating a jwt token for the current user with an expiry time of 15 minutes
    token = jwt.encode(
        {'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)},
        os.environ.get('SECRET_KEY'), algorithm="HS256")
    token = token.decode("utf-8")
    # saving the token so that multiple tokens for same user cannot be generated
    user.jwt_token = token
    db.session.add(user)
    db.session.commit()
    return {'message': 'you have successfully logged in', 'token': token}


@api.route('/change-password')
@token_required
def change_password(current_user: User) -> dict:
    """api to change password when user is logged in"""
    data = request.get_json()
    existing_password = data['password']
    if not check_password_hash(current_user.password, existing_password):
        # when the current password does not matches
        return {'message': 'wrong existing password'}
    new_password = data['new_password']
    new_password1 = data['new_password1']
    if new_password != new_password1:
        # when both passwords entered are different
        return {'message': 'passwords do not match'}
    if check_password_hash(current_user.password, new_password):
        return {'message': 'new password cannot be same as old password'}
    current_user.password = generate_password_hash(new_password, method='sha256')
    db.session.add(current_user)
    db.session.commit()
    return {'message': 'password changed successfully'}


@api.route('/logout')
@token_required
def logout(current_user: User) -> dict:
    """api for logout"""
    # setting the value of token to None when user logs out
    current_user.jwt_token = None
    db.session.add(current_user)
    db.session.commit()
    return {'message': 'you have successfully logged out'}


@api.route('/forgot-password-send-otp')
def send_otp() -> dict:
    """api to send otp when user forgets his password"""
    data = request.get_json()
    if data['email']:
        user = User.query.filter_by(email_address=data['email']).first()
    elif data['mobile']:
        user = User.query.filter_by(mobile=data['mobile']).first()
    else:
        # if no user exists with the given email id or mobile number
        return {'message': 'please enter a valid email/mobile.'}
    account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
    client = Client(account_sid, auth_token)
    # checking if otp exists which has not expired
    existing_otp = Otp.query.filter(and_(Otp.user_id == user.id, Otp.expiry > db.func.now(), Otp.verified == 0)).\
        order_by(Otp.created_at.desc()).first()
    if existing_otp:
        otp = existing_otp.code
    else:
        # generating a new 4 digit otp
        otp = random.randint(1000, 9999)
        user_otp = Otp(user_id=user.id, code=otp, expiry=datetime.datetime.utcnow() + datetime.timedelta(minutes=5))
        db.session.add(user_otp)
        db.session.commit()
    # twilio api is used to send messages to user mobile
    message = client.messages.create(
        body=f"Hello {user.name} Your otp for forgot password is {otp}", from_=os.environ.get('FROM_MOBILE'),
        to=f"+91{data['mobile']}")
    # sendgrid api is used to send otp on mail
    message = Mail(
        from_email=os.environ.get('FROM_EMAIL'),
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
def validate_otp() -> dict:
    """api for validating otp on forgot password request"""
    data = request.get_json()
    if data['email']:
        user = User.query.filter_by(email_address=data['email']).first()
    elif data['mobile']:
        user = User.query.filter_by(mobile=data['mobile']).first()
    else:
        # if no user exists with the given email id or mobile number
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
        # when the otp is not given or otp has expired or otp does not match
        return {'message': 'please enter a valid otp.'}
