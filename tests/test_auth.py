import pytest
from app import app, get_db
from security import hash_password

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            db = get_db()
            db.execute('DELETE FROM users')
            db.commit()
        yield client

def test_register(client):
    response = client.post('/register', data={
        'phone': '+79123456789',
        'name': 'Test User',
        'password': 'TestPass123'
    })
    assert response.status_code == 302  # Redirect after success

def test_login(client):
    # Сначала регистрируем пользователя
    client.post('/register', data={
        'phone': '+79123456789',
        'name': 'Test User',
        'password': 'TestPass123'
    })
    
    # Тестируем вход
    response = client.post('/login', data={
        'phone': '+79123456789',
        'password': 'TestPass123'
    })
    assert response.status_code == 302  # Redirect to profile
