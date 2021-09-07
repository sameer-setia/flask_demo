import datetime
import os
import jwt
from models import User
from flask import request
from functools import wraps


def token_required(f):
    """decorator to check the jwt token"""
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            # if no token provided in header
            return {'message': 'token is missing'}
        try:
            # decoding the token to check whether it is valid or not
            data = jwt.decode(token, os.environ.get('SECRET_KEY'), algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['id']).first()
            if current_user.jwt_token != token:
                return {'message': 'Invalid Token'}
        except Exception as e:
            print(e)
            return {'message': 'Token expired'}

        return f(current_user, *args, **kwargs)

    return decorator
