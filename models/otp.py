from app import db


class Otp(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Integer(), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    expiry = db.Column(db.DateTime)
    verified = db.Column(db.Integer, default=0)
