"""Дополнительные функции."""

import re


def validate_ip_address(ip: str) -> bool:
    """Валидация ip адреса."""
    ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

    if re.match(ip_pattern, ip):
        return True
    return False
