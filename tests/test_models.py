from app.models import User
from werkzeug.security import generate_password_hash

def test_user_model():
    user = User(email="test@example.com", password=generate_password_hash("password"), name="Test User")
    assert user.email == "test@example.com"
    assert user.password != "password"  # Password should be hashed
