import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
migrate = Migrate(app, db)

from api.v1.routes import api as api_v1
app.register_blueprint(api_v1, url_prefix='/v1')
app.register_blueprint(api_v1, url_prefix='/v2')
from api.v2.routes import api as api_v2
app.register_blueprint(api_v2, url_prefix='/v2')

app.debug = True
if __name__ == '__main__':
    app.run()
