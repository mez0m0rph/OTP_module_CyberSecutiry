import hashlib
import time
import requests


WEATHER_API_URL = (
    "https://api.open-meteo.com/v1/forecast"
    "?latitude=54.6872&longitude=25.2797"
    "&current=temperature_2m,relative_humidity_2m,wind_speed_10m,pressure_msl"
)


def get_weather_random_data() -> str:
    """
    Получает данные о погоде из внешнего API.

    Эти данные не используются как основной источник криптографической случайности.
    Они используются только как дополнительный материал для смешивания.
    """
    try:
        response = requests.get(WEATHER_API_URL, timeout=5)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return "weather_api_unavailable"


def mix_weather_with_system_random(system_random: bytes) -> bytes:
    """
    Смешивает системную случайность, данные погоды и текущее время через SHA-256.
    """
    weather_data = get_weather_random_data()
    current_time = str(time.time())

    mixed_data = system_random + weather_data.encode() + current_time.encode()

    return hashlib.sha256(mixed_data).digest()
