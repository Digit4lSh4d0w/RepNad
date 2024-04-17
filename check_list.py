"""Проверка репутационного листа."""

import warnings
import requests
from main import url_nad


def check(session: requests.Session) -> None:
    """Функция вывода содержимого репутационного списка."""
    warnings.filterwarnings("ignore")
    name = input("Введите название репутационного списка: ")

    response = session.get(url_nad + f"/replists?search={name}")
    checker = response.json()
    list_id = checker["results"][0].get("id")
    response = session.get(url_nad + f"/replists/{list_id}")

    if "items_count" in checker:
        size = checker["items_count"]

    if "content" in checker and len(checker["content"]) > 0:
        content = checker["content"]
        print(f"Список {name} найден.")
        print(f"Количество элементов: {size}")
        print(f"Содержимое списка: \n{content}")

    else:
        print(f"Список {name} не был найден!")
        return
