from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../instance/users.db'
    app.config['SECRET_KEY'] = 'yoursecretkey'
    app.config['JWT_SECRET_KEY'] = 'yourjwtsecretkey'
    app.config['WTF_CSRF_SECRET_KEY'] = 'csrfsecretkey'

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    
    csrf = CSRFProtect(app)

    from app.api_v1 import api_v1_bp
    from app.routes import auth_bp
    app.register_blueprint(api_v1_bp, url_prefix='/api/v1')
    app.register_blueprint(auth_bp)

    csrf.exempt(api_v1_bp) 

    return app
