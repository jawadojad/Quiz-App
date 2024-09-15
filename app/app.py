from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)

# Configurations for SQLAlchemy and JWT
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable SQLAlchemy warnings
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this to a more secure key

# Initialize the database and JWT manager
db = SQLAlchemy(app)
jwt = JWTManager(app)

# User Model to define the users table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # Store hashed password
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    university = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(20), nullable=False)

# Route to register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()  # Get the request body as JSON

    # Check if the email already exists in the database
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 400

    # Hash the password using bcrypt
    hashed_password = generate_password_hash(data['password'], method='sha256')

    # Create a new user object
    new_user = User(
        email=data['email'],
        password=hashed_password,
        name=data['name'],
        age=data['age'],
        university=data['university'],
        country=data['country'],
        level=data['level']
    )

    # Add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Route to log in an existing user
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()  # Get the request body as JSON

    # Find the user by email
    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid email or password'}), 401

    # Create an access token for the user
    access_token = create_access_token(identity=user.email)
    return jsonify({'token': access_token}), 200

# Initialize the database
with app.app_context():
    db.create_all()  # Create the tables in the database

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
