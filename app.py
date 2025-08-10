from flask import Flask
from config import Config
from models import db
from flask_jwt_extended import JWTManager
from resources import auth_bp

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
jwt = JWTManager(app)

app.register_blueprint(auth_bp)

# @app.before_first_request
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
