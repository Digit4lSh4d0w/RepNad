"""Добавление адресов в репутационный список."""

import warnings
import requests
from main import url_nad
from utils import validate_ip_address


def add(session: requests.Session) -> None:
    """Функция добавления адреса(ов) в реп.список"""
    warnings.filterwarnings("ignore")
    name = input("Введите название репутационного списка: ")

    response = session.get(url_nad + f"/replists?search={name}")
    checker = response.json()

    if "count" in checker and checker["count"] > 0:
        print(f"Список {name} найден.")
        ext_key = checker["results"][0].get("external_key")
        if ext_key:
            print(f'Список {name} был создан через API. Значение уникального параметра "external_key": {ext_key}')
        else:
            print(f"Список {name} не был создан через API и доступен для изменения в NAD!")
            return

    else:
        print(f"Список {name} не был найден!")
        return

    ips = input(f"Введите IP адреса для добавления в список {name} (через пробел): ").split()

    for ip in ips:
        if validate_ip_address(ip):
            continue
        print(f"Ошибка: Введен некорректный IP адрес {ip}.")
        return

    session.headers = {
        "X-CSRFToken": session.cookies.get_dict()["csrftoken"],
        "Referer": url_nad,
    }  # если не будет работать, то в качестве реферера указывайте просто https://your_nad_ip/
    json = [{"value": ip} for ip in ips]

    response = session.post(url_nad + f"/replists/dynamic/{ext_key}/_bulk", json=json)
    if response.status_code == 200:
        print("Успех")
    else:
        print("Что-то пошло не так:")
        print(response.text)
