import os

import sqlite3

import re
import random
import logging
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session
)
from werkzeug.utils import secure_filename
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import redis
import bcrypt
import uuid
import json
from flask import send_from_directory
from datetime import datetime
from config import Config
from utils.sms_sender import SMSSender  # Добавьте эту строку
from utils.security import hash_password


# Инициализация приложения
from dotenv import load_dotenv
load_dotenv('/var/www/u2996175/data/www/pivtorg1.ru/.env')
application = Flask(__name__)
application.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key')
application.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
application.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB
application.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}



# Защита от CSRF
csrf = CSRFProtect(application)

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('Pivtorg1')

# Инициализация Redis

# Лимитер запросов
limiter = Limiter(
    app=application,
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

def get_db():
    conn = sqlite3.connect(Config.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with application.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT UNIQUE NOT NULL,
                name TEXT,
                code TEXT NOT NULL,
                code_expiry DATETIME NOT NULL,
                bonus_points INTEGER DEFAULT 0,
                discount INTEGER DEFAULT 3, 
                is_verified BOOLEAN DEFAULT FALSE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users (phone)')
        db.execute('''
            CREATE TABLE IF NOT EXISTS promotions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                start_date DATETIME,
                end_date DATETIME
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                bonuses_used INTEGER DEFAULT 0,
                discount_applied INTEGER DEFAULT 0,
                final_amount REAL NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS sms_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS beers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                style TEXT,
                abv REAL, 
                price REAL,
                image_url TEXT,
                is_available BOOLEAN DEFAULT TRUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')


        db.commit()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def generate_code():
    return str(random.randint(100000, 999999))

def validate_phone(phone):
    return re.match(r'^\+7\d{10}$', phone)

# loyalty_program/app.py

def send_sms(phone, message):
    try:
        # Убираем '+' и пробелы из номера
        cleaned_phone = phone.lstrip('+').replace(' ', '')
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        payload = {
            "login": os.getenv('PROSTOR_SMS_LOGIN', 't89039735851'),
            "password": os.getenv('PROSTOR_SMS_PASSWORD', '138102'),
            "messages": [
                {
                    "clientId": str(uuid.uuid4()),
                    "phone": cleaned_phone,
                    "text": message,
                    "sender": "Prostor-R",  # Ваше активированное имя отправителя
                    "channel": "DIRECT"
                }
            ]
        }

        logger.info(f"Отправка SMS: {json.dumps(payload, indent=2)}")
        
        response = requests.post(
            "https://api.prostor-sms.ru/messages/v2/send/",
            json=payload,
            headers=headers,
            timeout=10
        )
        
        response_data = response.json()
        logger.info(f"Ответ SMS API: {response_data}")
        
        return response_data.get('status') == 'ok'
        
    except Exception as e:
        logger.error(f"SMS error: {str(e)}")
        return False
        
    except Exception as e:
        logger.error(f"SMS error: {str(e)}")
        return False

def check_balance():
    try:
        response = requests.post(
            "https://api.prostor-sms.ru/messages/v2/balance.json",
            json={
                "login": os.getenv('PROSTOR_SMS_LOGIN'),
                "password": os.getenv('PROSTOR_SMS_PASSWORD')
            },
            timeout=10
        )
        data = response.json()
        logger.info(f"Balance response: {data}")
        if data.get('status') == 'ok':
            return float(data['balance'][0]['balance'])
        return 0.0
    except Exception as e:
        logger.error(f"Ошибка проверки баланса: {str(e)}")
        return 0.0
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in application.config['ALLOWED_EXTENSIONS']

@application.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(application.config['UPLOAD_FOLDER'], filename)
application.permanent_session_lifetime = timedelta(days=1)  # Срок действия сессии
@application.template_filter('datetime_format')
def datetime_format(value, format="%d.%m.%Y %H:%M"):
    if isinstance(value, str):
        try:
            # Правильный отступ (4 пробела)
            value = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return "Некорректная дата"
    # Возврат вне блока try/except
    return value.strftime(format)
@application.route('/')
@application.route('/')
def index():
    db = get_db()
    beers = db.execute('SELECT * FROM beers WHERE is_available = TRUE').fetchall()
    return render_template('index.html', beers=beers)
@application.route('/admin/clients', methods=['GET', 'POST'])
@admin_required
def manage_clients():
    if request.method == 'POST':
        phone = request.form['phone'].strip()
        
        # Валидация номера
        if not re.match(r'^\+7\d{10}$', phone):
            flash('Неверный формат номера. Используйте +7XXXXXXXXXX', 'danger')
            return redirect(url_for('manage_clients'))
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE phone = ?', (phone,)).fetchone()
        
        if user:
            return redirect(url_for('client_detail', user_id=user['id']))
        else:
            # Генерация кода
            code = generate_code()
            expiry = datetime.now() + timedelta(minutes=10)
            
            # Логирование перед отправкой
            logger.info(f"Генерация кода {code} для {phone}")
            
            # Сохраняем данные в сессии
            session['admin_reg_data'] = {
                'phone': phone,
                'code': code,
                'expiry': expiry.isoformat()
            }
            
            # Отправка SMS
            message = f"Ваш код подтверждения: {code}"
            if send_sms(phone, message):
                flash('SMS с кодом отправлено', 'success')
                return redirect(url_for('confirm_admin_registration'))
            else:
                flash('Ошибка отправки SMS', 'danger')
                return redirect(url_for('manage_clients'))
    
    return render_template('admin/clients_search.html')

@application.route('/admin/clients/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def client_detail(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    transactions = db.execute('''
    SELECT 
        id,
        user_id,
        amount,
        bonuses_used,
        discount_applied,
        final_amount,
        created_at
    FROM transactions 
    WHERE user_id = ?
    ORDER BY created_at DESC
''', (user_id,)).fetchall()
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            bonuses_used = int(request.form.get('bonuses_used', 0))
            discount = int(request.form.get('discount', user['discount']))
            
            # Валидация
            if bonuses_used > user['bonus_points']:
                flash('Недостаточно бонусных баллов', 'danger')
                return redirect(url_for('client_detail', user_id=user_id))

            # Расчеты
            discounted_amount = amount * (1 - discount/100)
            final_amount = max(0, discounted_amount - bonuses_used)
            accrued_bonuses = int(discounted_amount * 0.05)  # 5% от суммы после скидки

            # Обновление пользователя
            new_bonuses = user['bonus_points'] - bonuses_used + accrued_bonuses
            db.execute('''
                UPDATE users 
                SET bonus_points = ?, discount = ?
                WHERE id = ?
            ''', (new_bonuses, discount, user_id))

            # Добавление транзакции
            db.execute('''
                INSERT INTO transactions 
                (user_id, amount, bonuses_used, discount_applied, final_amount)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, amount, bonuses_used, discount, final_amount))

            db.commit()
            flash(f'Покупка на {amount:.2f}₽ оформлена. Начислено {accrued_bonuses} бонусов', 'success')
            
        except ValueError as e:
            flash('Ошибка ввода данных', 'danger')
            logger.error(f"Transaction error: {str(e)}")
        
        return redirect(url_for('client_detail', user_id=user_id))

    return render_template('admin/client_detail.html', 
                         user=user,
                         transactions=transactions)

@application.route('/admin/clients/<int:user_id>/update', methods=['POST'])
@admin_required
def update_client_info(user_id):
    db = get_db()
    about = request.form['about']
    discount = int(request.form['discount'])
    
    db.execute('''
        UPDATE users 
        SET about = ?, discount = ?
        WHERE id = ?
    ''', (about, discount, user_id))
    db.commit()
    
    flash('Информация обновлена', 'success')
    return redirect(url_for('client_detail', user_id=user_id))
@application.route('/admin/promotions/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_promotion(id):
    db = get_db()
    promo = db.execute('SELECT * FROM promotions WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        db.execute('''
            UPDATE promotions SET
                title = ?,
                description = ?,
                start_date = ?,
                end_date = ?
            WHERE id = ?
        ''', (title, description, start_date, end_date, id))
        db.commit()
        flash('Акция успешно обновлена', 'success')
        return redirect(url_for('manage_promotions'))

    return render_template('admin/edit_promotion.html', promo=promo)
@application.route('/admin/beers')
@admin_required
def manage_beers():
    db = get_db()
    beers = db.execute('SELECT * FROM beers ORDER BY name').fetchall()
    return render_template('admin/beers.html', beers=beers)

@application.route('/admin/beers/add', methods=['GET', 'POST'])
@admin_required
def add_beer():
    if request.method == 'POST':
        # Получаем данные формы
        name = request.form['name']
        description = request.form['description']
        style = request.form['style']
        abv = float(request.form['abv'])
        price = float(request.form['price'])
        is_available = 'is_available' in request.form
        
        # Обработка изображения
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)  # Теперь функция доступна
                unique_name = f"{uuid.uuid4().hex}_{filename}"
                file.save(os.path.join(application.config['UPLOAD_FOLDER'], unique_name))
                image_url = unique_name

        # Сохранение в БД
        db = get_db()
        db.execute('''
            INSERT INTO beers (name, description, style, abv, price, image_url, is_available)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, description, style, abv, price, image_url, is_available))
        db.commit()
        
        flash('Пиво успешно добавлено', 'success')
        return redirect(url_for('manage_beers'))
    return render_template('admin/add_beer.html')
@application.route('/admin/beers/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_beer(id):
    db = get_db()
    beer = db.execute('SELECT * FROM beers WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        style = request.form['style']
        abv = float(request.form['abv'])
        price = float(request.form['price'])
        image_url = request.form['image_url']
        is_available = 'is_available' in request.form

        db.execute('''
            UPDATE beers 
            SET name = ?, description = ?, style = ?, abv = ?, price = ?, image_url = ?, is_available = ?
            WHERE id = ?
        ''', (name, description, style, abv, price, image_url, is_available, id))
        db.commit()
        flash('Пиво успешно обновлено', 'success')
        return redirect(url_for('manage_beers'))

    return render_template('admin/edit_beer.html', beer=beer)

@application.route('/admin/beers/delete/<int:id>')
@admin_required
def delete_beer(id):
    db = get_db()
    db.execute('DELETE FROM beers WHERE id = ?', (id,))
    db.commit()
    flash('Пиво удалено', 'success')
    return redirect(url_for('manage_beers'))
@application.route('/admin/promotions/delete/<int:id>')
@admin_required
def delete_promotion(id):
    db = get_db()
    db.execute('DELETE FROM promotions WHERE id = ?', (id,))
    db.commit()
    flash('Акция удалена', 'success')
    return redirect(url_for('manage_promotions'))
@application.route('/admin/promotions/add', methods=['POST'])
@admin_required
def add_promotion():
    title = request.form.get('title')
    description = request.form.get('description')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')

    try:
        db = get_db()
        db.execute('''
            INSERT INTO promotions (title, description, start_date, end_date)
            VALUES (?, ?, ?, ?)
        ''', (title, description, start_date, end_date))
        db.commit()

        flash('Акция успешно добавлена', 'success')

    except Exception as e:
        logger.error(f"Ошибка добавления акции: {str(e)}")
        flash('Ошибка при добавлении акции', 'danger')
    
    return redirect(url_for('manage_promotions'))
    
@application.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Заполните все поля', 'danger')
            return redirect(url_for('admin_login'))
        
        db = get_db()
        admin = db.execute(
            'SELECT * FROM admins WHERE username = ?', 
            (username,)
        ).fetchone()

        if admin and check_password(password, admin['password_hash']):
            session['admin_logged_in'] = True
            session.permanent = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Неверные учетные данные', 'danger')
    
    return render_template('admin/login.html')

@application.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    
    stats = {
        'total_users': db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'total_points': db.execute('SELECT SUM(bonus_points) FROM users').fetchone()[0] or 0,
        'active_promos': db.execute('''
            SELECT COUNT(*) FROM promotions 
            WHERE date('now') BETWEEN start_date AND end_date
        ''').fetchone()[0]
    }
    
    transactions = db.execute('''
        SELECT 
            users.phone,
            transactions.amount,
            transactions.created_at,
            CASE 
                WHEN transactions.amount > 0 THEN 'accrual' 
                ELSE 'withdrawal' 
            END as type
        FROM transactions
        JOIN users ON transactions.user_id = users.id
        ORDER BY transactions.created_at DESC
        LIMIT 10
    ''').fetchall()
    period = request.args.get('period', 'day')
    
    # Запрос для графика
    sales_query = """
        SELECT 
            DATE(created_at) as date,
            SUM(final_amount) as total
        FROM transactions
        WHERE created_at >= DATE('now', '-1 month')
        GROUP BY strftime('%Y-%m-%d', created_at)
        ORDER BY date
    """
    
    if period == 'week':
        sales_query = """
            SELECT 
                strftime('%Y-%W', created_at) as week,
                SUM(final_amount) as total
            FROM transactions
            GROUP BY week
            ORDER BY week
        """
    elif period == 'month':
        sales_query = """
            SELECT 
                strftime('%Y-%m', created_at) as month,
                SUM(final_amount) as total
            FROM transactions
            GROUP BY month
            ORDER BY month
        """
    
    sales_data = db.execute(sales_query).fetchall()
    
    return render_template(
        'admin/dashboard.html', 
        stats=stats,
        transactions=transactions,
        sales_data=sales_data,
        period=period
    )
@application.route('/admin/users')
@admin_required
def manage_users():
    db = get_db()
    users = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    return render_template('admin/users.html', users=users)

@application.route('/admin/promotions')
@admin_required
def manage_promotions():
    db = get_db()
    promotions = db.execute('SELECT * FROM promotions').fetchall()
    
    # Преобразуем строки в даты
    processed_promotions = []
    for promo in promotions:
        processed_promotions.append({
            **dict(promo),
            'start_date': datetime.strptime(promo['start_date'], '%Y-%m-%d').date(),
            'end_date': datetime.strptime(promo['end_date'], '%Y-%m-%d').date()
        })
    
    current_date = datetime.now().date()
    
    return render_template(
        'admin/promotions.html', 
        promotions=processed_promotions,
        current_date=current_date
    )
@application.route('/register', methods=['GET', 'POST'])
@limiter.limit("100/hour")
def register():
    if request.method == 'POST':
        phone = request.form['phone'].strip()
        name = request.form.get('name', '').strip()
        
        if not validate_phone(phone):
            flash('Неверный формат номера (+7XXXXXXXXXX)', 'danger')
            return redirect(url_for('register'))

            
        code = generate_code()
        expiry = datetime.now() + timedelta(minutes=10)
        
        try:
            db = get_db()
            # Проверяем существование пользователя
            user = db.execute(
                'SELECT * FROM users WHERE phone = ?', 
                (phone,)
            ).fetchone()

            if user:
                if user['is_verified']:
                    flash('Этот номер уже зарегистрирован', 'danger')
                    return redirect(url_for('register'))
                # Обновляем данные для неверифицированного пользователя
                db.execute('''
                    UPDATE users 
                    SET name = ?, code = ?, code_expiry = ?
                    WHERE phone = ?
                ''', (name, code, expiry, phone))
            else:
                # Создаем нового пользователя
                db.execute('''
                    INSERT INTO users (phone, name, code, code_expiry)
                    VALUES (?, ?, ?, ?)
                ''', (phone, name, code, expiry))
            
            db.commit()
            
            if send_sms(phone, code):
                session['verification_phone'] = phone
                return redirect(url_for('verify'))
                
            flash('Ошибка отправки SMS', 'danger')
            
        except sqlite3.IntegrityError as e:
            logger.error(f"Ошибка регистрации: {str(e)}")
            flash('Произошла ошибка при регистрации', 'danger')
        
    return render_template('auth/register.html')
@application.route('/admin/promotions/send-sms/<int:id>')
@admin_required
def send_promotion_sms(id):
    db = get_db()
    
    # Получаем акцию
    promo = db.execute('SELECT * FROM promotions WHERE id = ?', (id,)).fetchone()
    if not promo:
        flash('Акция не найдена', 'danger')
        return redirect(url_for('manage_promotions'))
    
    # Получаем всех пользователей
    users = db.execute('SELECT phone FROM users').fetchall()
    if not users:
        flash('Нет пользователей для рассылки', 'warning')
        return redirect(url_for('manage_promotions'))
    
    # Формируем сообщение
    message = f"ПИВТОРГ№1 Новая акция: {promo['title']}\n{promo['description']}"
    
    # Отправляем SMS
    sms_sender = SMSSender()  # Теперь класс доступен
    success_count = 0
    
    for user in users:
        if sms_sender._send_sms(user['phone'], message):
            success_count += 1
    
    flash(f"Отправлено {success_count}/{len(users)} SMS", 'success')
    return redirect(url_for('manage_promotions'))
@application.route('/login', methods=['GET', 'POST'])
@limiter.limit("100/hour")
def login():
    if request.method == 'POST':
        phone = request.form['phone'].strip()
        
        if not validate_phone(phone):
            flash('Неверный формат номера', 'danger')
            return redirect(url_for('login'))
            
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE phone = ?', 
            (phone,)
        ).fetchone()
        
        if not user:
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('register'))
            
        # Проверяем верификацию аккаунта
        if not user['is_verified']:
            flash('Аккаунт не активирован. Завершите регистрацию', 'danger')
            return redirect(url_for('verify'))
            
        code = generate_code()
        expiry = datetime.now() + timedelta(minutes=10)
        
        db.execute('''
            UPDATE users 
            SET code = ?, code_expiry = ?
            WHERE id = ?
        ''', (code, expiry, user['id']))
        db.commit()
        
        if send_sms(phone, code):
            session['verification_phone'] = phone
            return redirect(url_for('verify'))
            
        flash('Ошибка отправки SMS', 'danger')
    
    return render_template('auth/login.html')

@application.route('/verify', methods=['GET', 'POST'])
def verify():
    phone = session.get('verification_phone')
    if not phone:
        return redirect(url_for('login'))
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE phone = ?', (phone,)).fetchone()
    
    if not user:
        flash('Сессия устарела', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        code = request.form['code'].strip()
        
        if datetime.now() > datetime.fromisoformat(user['code_expiry']):
            flash('Код устарел', 'danger')
            return redirect(url_for('login'))
            
        if code == user['code']:
            db.execute('UPDATE users SET is_verified = 1 WHERE id = ?', (user['id'],))
            db.commit()
            

            session.clear()

            session['user_id'] = user['id']
            return redirect(url_for('profile'))
            
        flash('Неверный код подтверждения', 'danger')
    
    return render_template('auth/verify.html', phone=phone)

@application.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Получаем активные акции
    promotions = db.execute('''
        SELECT * FROM promotions 
        WHERE date('now') BETWEEN start_date AND end_date
        ORDER BY end_date ASC
    ''').fetchall()

    return render_template('profile/index.html', 
                         user=user,
                         promotions=promotions)

@application.route('/logout')
def logout():
    session.clear()
    flash('Вы успешно вышли', 'success')
    return redirect(url_for('index'))

@application.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@application.errorhandler(500)
def internal_error(e):
    logger.error(f"Ошибка 500: {str(e)}")
    return render_template('errors/500.html'), 500
@application.route('/admin/clients/register', methods=['GET', 'POST'])
@admin_required
def admin_register_client():
    if request.method == 'POST':
        phone = request.form['phone'].strip()
        name = request.form.get('name', '')
        
        if not validate_phone(phone):
            flash('Неверный формат номера', 'danger')
            return redirect(url_for('manage_clients'))

        code = generate_code()
        session['admin_reg_data'] = {
            'phone': phone,
            'name': name,
            'code': code,
            'expiry': datetime.now() + timedelta(minutes=10)
        }

        # Отправка SMS
        message = f"Код подтверждения регистрации: {code}"
        if send_sms(phone, message):
            flash('SMS с кодом отправлено', 'success')
            return redirect(url_for('confirm_admin_registration'))
        else:
            flash('Ошибка отправки SMS', 'danger')
            return redirect(url_for('manage_clients'))

    return render_template('admin/client_registration.html')

@application.route('/admin/clients/confirm', methods=['GET', 'POST'])
@admin_required
def confirm_admin_registration():
    # Получаем данные регистрации из сессии
    reg_data = session.get('admin_reg_data')
    
    # Если данных нет - перенаправляем обратно
    if not reg_data:
        flash('Сессия истекла или не найдена', 'danger')
        return redirect(url_for('manage_clients'))

    if request.method == 'POST':
        user_code = request.form.get('code', '').strip()
        
        # Проверяем срок действия кода
        if datetime.now() > datetime.fromisoformat(reg_data['expiry']):
            flash('Код подтверждения истек', 'danger')
            return redirect(url_for('manage_clients'))
            
        # Проверяем совпадение кода
        if user_code == reg_data['code']:
            try:
                db = get_db()
                db.execute('''
                    INSERT INTO users (phone, name, code, code_expiry, is_verified)
                    VALUES (?, ?, ?, ?, 1)
                ''', (
                    reg_data['phone'],
                    reg_data['name'],
                    reg_data['code'],
                    reg_data['expiry']
                ))
                db.commit()
                
                # Очищаем сессию и перенаправляем
                session.pop('admin_reg_data', None)
                flash('Клиент успешно зарегистрирован', 'success')
                return redirect(url_for('manage_clients'))
                
            except sqlite3.IntegrityError:
                flash('Этот номер уже зарегистрирован', 'danger')
        else:
            flash('Неверный код подтверждения', 'danger')

        return redirect(url_for('confirm_admin_registration'))

    # GET-запрос: показываем форму ввода кода
    return render_template('admin/client_confirm.html')  # Убедитесь, что шаблон существует
@application.route('/admin/sms-balance')
@admin_required
def check_sms_balance():
    try:
        balance_url = "https://api.prostor-sms.ru/users/balance"
        response = requests.get(
            balance_url,
            params={
                "login": Config.SMS_LOGIN,
                "password": Config.SMS_PASSWORD
            }
        )
        balance_data = response.json()
        return f"Баланс: {balance_data.get('balance')} руб."
    except Exception as e:
        return f"Ошибка: {str(e)}"
if __name__ == '__main__':
    init_db()
    application.run(host='0.0.0.0')




