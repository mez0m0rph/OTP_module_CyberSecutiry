import base64
import os

import pyotp

from entropy import has_enough_entropy
from weather_random import mix_weather_with_system_random


def generate_totp_secret() -> str:
    """
    Генерирует секретный ключ для TOTP.

    Сначала проверяется энтропия хоста.
    Если энтропии достаточно, используется системная криптографическая случайность.
    Также системная случайность смешивается с данными внешнего погодного API,
    чтобы выполнить дополнительное требование задания.

    Если на Linux энтропии слишком мало, генерация ключа запрещается.
    """
    if not has_enough_entropy():
        raise RuntimeError("Not enough system entropy to generate TOTP secret")

    system_random = os.urandom(32)
    random_bytes = mix_weather_with_system_random(system_random)

    return base64.b32encode(random_bytes).decode("utf-8").rstrip("=")


def get_current_totp(secret: str) -> str:
    """
    Возвращает текущий 6-значный TOTP-код.
    """
    totp = pyotp.TOTP(secret)
    return totp.now()


def verify_totp(secret: str, code: str) -> bool:
    """
    Проверяет TOTP-код пользователя.

    valid_window=1 разрешает небольшое расхождение времени:
    текущий интервал, предыдущий и следующий.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def get_totp_uri(username: str, secret: str) -> str:
    """
    Возвращает URI для подключения к Google Authenticator / Aegis / 2FAS.
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="OTP_module_CyberSecurity"
    )
