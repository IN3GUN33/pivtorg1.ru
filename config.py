import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-secret-key')
    DATABASE = os.getenv('DATABASE', 'pivtorg1.db')
    SMS_API_KEY = os.getenv('F1CA2326-5975-C7F1-016B-9944C2FAC778')
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  
    SMS_API_KEY = "F1CA2326-5975-C7F1-016B-9944C2FAC778"
    RATE_LIMIT = os.getenv('RATE_LIMIT', '1000 per hour')
    SMS_PROMO_TEMPLATE = "В ПИВТОРГ№1 акция {title}: {description} Действует до {end_date}"
    SMS_URL = "https://api.prostor-sms.ru/messages/v2/send/"  # Актуальный URL из документации
    SMS_LOGIN = os.getenv('PROSTOR_SMS_LOGIN') # Логин от аккаунта
    SMS_PASSWORD = os.getenv('138102') # Пароль
    SMS_SENDER = os.getenv('SMS_SENDER', 'Prostor-R') 
