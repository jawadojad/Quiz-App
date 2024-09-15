from flask import Blueprint, jsonify, request
from app.models import User, Quiz
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import db

api_v1_bp = Blueprint('api_v1', __name__)

@api_v1_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(email=data['email'], password=hashed_password, name=data['name'])

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@api_v1_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=user.email)
    return jsonify({"token": access_token}), 200

@api_v1_bp.route('/quiz/create', methods=['POST'])
@jwt_required()
def create_quiz():
    data = request.get_json()
    current_user_email = get_jwt_identity()  # Get the logged-in user's identity
    user = User.query.filter_by(email=current_user_email).first()

    if user:
        new_quiz = Quiz(title=data['title'], description=data['description'], creator_id=user.id)
        db.session.add(new_quiz)
        db.session.commit()
        return jsonify({"message": "Quiz created successfully"}), 201
    else:
        return jsonify({"message": "User not found"}), 404
