import json
import os

import bcrypt

from totp_service import generate_totp_secret, verify_totp, get_totp_uri


USERS_FILE = "users.json"


def load_users() -> dict:
    """
    Загружает пользователей из JSON-файла.
    """
    if not os.path.exists(USERS_FILE):
        return {}

    with open(USERS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_users(users: dict) -> None:
    """
    Сохраняет пользователей в JSON-файл.
    """
    with open(USERS_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)


def hash_password(password: str) -> str:
    """
    Хеширует пароль с помощью bcrypt.
    """
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password_bytes, salt)
    return password_hash.decode("utf-8")


def check_password(password: str, password_hash: str) -> bool:
    """
    Проверяет пароль по сохранённому bcrypt-хешу.
    """
    password_bytes = password.encode("utf-8")
    hash_bytes = password_hash.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hash_bytes)


def register_user(username: str, password: str) -> dict:
    """
    Регистрирует пользователя:
    - проверяет, что такого пользователя ещё нет;
    - хеширует пароль;
    - создаёт TOTP-секрет;
    - сохраняет пользователя.
    """
    users = load_users()

    if username in users:
        return {
            "success": False,
            "message": "User already exists"
        }

    password_hash = hash_password(password)
    totp_secret = generate_totp_secret()
    totp_uri = get_totp_uri(username, totp_secret)

    users[username] = {
        "password_hash": password_hash,
        "totp_secret": totp_secret
    }

    save_users(users)

    return {
        "success": True,
        "message": "User registered successfully",
        "username": username,
        "totp_secret": totp_secret,
        "totp_uri": totp_uri
    }


def login_user(username: str, password: str, totp_code: str) -> dict:
    """
    Проверяет вход:
    - существует ли пользователь;
    - верный ли пароль;
    - верный ли TOTP-код.
    """
    users = load_users()

    if username not in users:
        return {
            "success": False,
            "message": "User not found"
        }

    user = users[username]

    if not check_password(password, user["password_hash"]):
        return {
            "success": False,
            "message": "Invalid password"
        }

    if not verify_totp(user["totp_secret"], totp_code):
        return {
            "success": False,
            "message": "Invalid TOTP code"
        }

    return {
        "success": True,
        "message": "Login successful"
    }
