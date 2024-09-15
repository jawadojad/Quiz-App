def test_create_quiz(client, auth):
    # Simulate login before creating a quiz
    auth.login()

    response = client.post('/quiz/create', json={
        'title': 'New Quiz',
        'description': 'Description of the new quiz'
    })
    assert response.status_code == 201
    assert response.get_json()['message'] == "Quiz created successfully"

def test_quiz_list(client, auth):
    auth.login()
    response = client.get('/quiz/list')
    assert response.status_code == 200
    assert len(response.get_json()) > 0
