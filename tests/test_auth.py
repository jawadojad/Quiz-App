def test_register_user(client):
    response = client.post('/api/v1/register', json={
        'email': 'newuser@example.com',
        'password': 'password',
        'name': 'New User'
    })
    assert response.status_code == 201
    assert response.get_json()['message'] == "Registered successfully"

def test_login_user(client):
    response = client.post('/api/v1/login', json={
        'email': 'newuser@example.com',
        'password': 'password'
    })
    assert response.status_code == 200
    assert 'token' in response.get_json()
