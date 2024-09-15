import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # Import Migrate
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFProtect
from app.auth import auth_bp
from app.api_v1 import api_v1_bp

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/users.db'
app.config['SECRET_KEY'] = 'yoursecretkey'
app.config['JWT_SECRET_KEY'] = 'yourjwtsecretkey'
app.config['WTF_CSRF_SECRET_KEY'] = 'csrfsecretkey'

# Initialize extensions
db = SQLAlchemy(app)  # Initialize SQLAlchemy
migrate = Migrate(app, db)  # Initialize Flask-Migrate
print("Flask-Migrate initialized")
jwt = JWTManager(app)
csrf = CSRFProtect(app)

# Register Blueprints
app.register_blueprint(api_v1_bp, url_prefix='/api/v1')
app.register_blueprint(auth_bp)

@app.route('/debug')
def debug():
    return f"DB URI: {app.config['SQLALCHEMY_DATABASE_URI']}, Migrate: {migrate}"

@app.route('/test')
def test():
    return "Test route working"


if __name__ == '__main__':
    app.run(debug=True)
