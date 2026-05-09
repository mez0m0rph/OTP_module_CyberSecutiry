import os


ENTROPY_PATH = "/proc/sys/kernel/random/entropy_avail"
MIN_ENTROPY = 100


def get_entropy() -> int | None:
    """
    Возвращает количество доступной энтропии в системе.

    На Linux читаем /proc/sys/kernel/random/entropy_avail.
    """
    if not os.path.exists(ENTROPY_PATH):
        return None

    try:
        with open(ENTROPY_PATH, "r", encoding="utf-8") as file:
            return int(file.read().strip())
    except (OSError, ValueError):
        return None


def has_enough_entropy() -> bool:
    """
    Проверяет, достаточно ли энтропии для генерации ключа.

    Если система не Linux и значение энтропии получить нельзя,
    считаем, что системный генератор случайности доступен.
    """
    entropy = get_entropy()

    if entropy is None:
        return True

    return entropy >= MIN_ENTROPY
