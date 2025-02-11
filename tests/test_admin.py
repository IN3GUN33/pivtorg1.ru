import pytest
from app import app, get_db

@pytest.fixture
def admin_client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            db = get_db()
            # Создаем тестового админа
            db.execute('INSERT INTO users (phone, name, password, is_admin) VALUES (?, ?, ?, ?)',
                      ('+79111111111', 'Admin', 'adminpass', True))
            db.commit()
        yield client

def test_admin_access(admin_client):
    # Логинимся как админ
    admin_client.post('/login', data={
        'phone': '+79111111111',
        'password': 'adminpass'
    })
    
    response = admin_client.get('/admin/dashboard')
    assert response.status_code == 200
    assert b'Админ-панель' in response.data
