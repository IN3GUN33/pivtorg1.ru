import requests
import logging
from config import Config

class SMSSender:
    def __init__(self):
        self.api_key = Config.SMS_API_KEY
        self.base_url = "https://sms.ru"
        self.sender = Config.SMS_SENDER
        self.max_length = 1000  # Максимальная длина SMS

    def send_verification_code(self, phone, code):
        message = f"Ваш код подтверждения Pivtorg1: {code}"
        return self._send_sms(phone, message)

    def send_promotion(self, phone, promotion_text):
        truncated_msg = self._truncate_message(promotion_text)
        return self._send_sms(phone, truncated_msg)

    def _truncate_message(self, text):
        if len(text) > self.max_length:
            return text[:self.max_length-3] + "..."
        return text

    def _send_sms(self, phone, message):
        try:
            # Подготовка параметров
            params = {
                "api_id": self.api_key,
                "to": phone,
                "msg": message,
                "json": 1,
                "from": self.sender
            }

            # Отправка POST-запроса
            response = requests.post(
                f"{self.base_url}/sms/send",
                data=params,
                timeout=15
            )

            data = response.json()

            if data.get("status") == "OK":
                status_code = data['sms'][phone]['status_code']
                if status_code == 100:
                    logging.info(f"SMS успешно отправлено на {phone}")
                    return True
                else:
                    error_msg = data['sms'][phone]['status_text']
                    logging.error(f"Ошибка SMS: {error_msg} (код {status_code})")
                    return False
            else:
                error_msg = data.get('status_text', 'Неизвестная ошибка')
                logging.error(f"Ошибка API: {error_msg}")
                return False

        except requests.exceptions.RequestException as e:
            logging.error(f"Ошибка соединения: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Общая ошибка: {str(e)}")
            return False

    def check_balance(self):
        try:
            response = requests.get(
                f"{self.base_url}/my/balance",
                params={"api_id": self.api_key, "json": 1},
                timeout=10
            )
            data = response.json()
            if data.get('status') == 'OK':
                return float(data['balance'])
            return 0.0
        except Exception as e:
            logging.error(f"Ошибка проверки баланса: {str(e)}")
            return 0.0
