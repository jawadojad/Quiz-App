import pytest
from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash

@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"
    })

    with app.app_context():
        db.create_all()
        user = User(email="newuser@example.com", password=generate_password_hash("password"), name="New User")
        db.session.add(user)
        db.session.commit()

    yield app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth(client):
    return AuthActions(client)

class AuthActions:
    def __init__(self, client):
        self._client = client

    def login(self, email='newuser@example.com', password='password'):
        return self._client.post('/api/v1/login', json={'email': email, 'password': password})

    def logout(self):
        return self._client.get('/logout')
