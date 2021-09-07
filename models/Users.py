from app import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    mobile = db.Column(db.String(), unique=True)
    email_address = db.Column(db.String(), unique=True)
    password = db.Column(db.TEXT())
    is_active = db.Column(db.Boolean(), default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    jwt_token = db.Column(db.String())
