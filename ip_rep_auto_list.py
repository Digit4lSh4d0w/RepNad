"""Точка входа."""

import os
import json
import sys
import warnings
import wget
import requests
import urllib3
from add import add
from remove import remove
from check_list import check


def connect(session: requests.Session, url_nad: str) -> None:
    """Функция установки соединения."""
    wget.download("https://feodotracker.abuse.ch/downloads/ipblocklist.json") # Скачивание таблицы
    print()
    warnings.filterwarnings("ignore")

    temp_cock = session.cookies.get("sessionid")
    if not temp_cock:
        print("SESSIONID не найден.")
        sys.exit(1)

    csrf_token = session.cookies.get("csrftoken")
    if csrf_token:
        csrf = csrf_token
    else:
        print("CSRF токен не найден.")
        sys.exit(1)

    parse_file("ipblocklist.json", csrf, session, url_nad)


def parse_file(filename, csrf, session, url_nad):
    """Функция парсинга файла по ВПО."""
    ip_malware_pairs = []
    malwares_temp = []

    with open(filename, "r", encoding="utf8") as file:
        data = json.load(file)

    for item in data:
        ip_address = item.get("ip_address")
        malware = item.get("malware")

        if ip_address or malware:
            if ip_address == "":
                continue
            if malware == "":
                ip_malware_pairs.append((ip_address, "null"))
            else:
                ip_malware_pairs.append((ip_address, malware))
                malwares_temp.append(malware)

    malwares = list(set(malwares_temp))

    print("Найден следующий список ВПО: ", end="")
    for i, mlw in enumerate(malwares):
        if i != len(malwares) - 1:
            print(mlw, end=", ")
        else:
            print(mlw)

    os.remove("ipblocklist.json") # Удаляем в конце таблицу
    sort(ip_malware_pairs, malwares, csrf, session, url_nad)


def sort(ip_malware_pairs, malwares, csrf, session, url_nad):
    """Функция сортировки по малварям."""
    filtered_arrays = dict() # Dывод будет ключ-значение, где ключ- малварь, значения- ипшники

    for mlw in malwares:
        filtered_array = [pair[0] for pair in ip_malware_pairs if pair[1] == mlw]
        filtered_arrays[mlw] = filtered_array

    check_names_and_create_tables(malwares, filtered_arrays, csrf, session, url_nad)


def check_names_and_create_tables(malwares, filtered_arrays, csrf, session, url_nad):
    """Функция проверки/создания реп листа ( с external_key!!!)."""
    warnings.filterwarnings("ignore")

    for name in malwares:
        session.headers = {
            "X-CSRFToken": csrf,
            "Referer": url_nad,
        }  # обязательное условие для POST запроса #если не будет работать, то в качестве реферера указывайте просто https://your_nad_ip/
        response = session.get(
            url_nad + "/replists?search=LOC_auto_" + name + "_IP", verify=False
        )

        if response.status_code == 403:
            print("Доступ запрещен!")
            print(response.status_code)
            sys.exit(1)

        elif response.status_code == 401:
            print("Нарушение аутентификации. Попробуйте снова")
            print(response.status_code)
            sys.exit(1)

        elif response.json()["count"] != 0:
            print(f"Список для ВПО {name} найден!")

        else:
            print(f"Список для ВПО {name} не найден в базе. Выполняется создание...")

            create = session.post(
                url_nad + "/replists",
                json={
                    "color": "7",
                    "name": "LOC_auto_" + name + "_IP",
                    "type": "ip",
                    "external_key": name,
                },
                verify=False,
            )

            if create.status_code == 201:
                print(f"Создание списка LOC_auto_{name}_IP выполнено успешно")

            else:
                print(f"Не удалось создать список LOC_auto_{name}_IP")
                print("Ответ сервера:")
                print(create.status_code)
                print(create.text)

    id_of_names(malwares, filtered_arrays, session, url_nad)


def id_of_names(malwares, filtered_arrays, session, url_nad):
    """Функция присваивания id по имени реп списка."""
    id_of_name = dict()
    for name in malwares:
        response = session.get(url_nad + f"/replists?search=LOC_auto_{name}_IP", verify=False)
        response_json = response.json()

        if "results" in response_json and len(response_json["results"]) > 0:
            # Получаем значение параметра 'id' для первого элемента в списке 'results'
            id_value = response_json["results"][0].get("external_key")
            if id_value:
                id_of_name[name] = id_value
                print(f"Значение параметра 'external_key' для списка {name}: {id_value}")
            else:
                print(f"Параметр 'external_key' не найден в элементе для списка {name}")
                sys.exit(1)
        else:
            print("Ответ от сервера некорректный.")
            print(response.text)
            sys.exit(1)

    filtered_arrays = sorted(filtered_arrays.items())
    id_of_name = sorted(id_of_name.items())

    send_data(id_of_name, filtered_arrays, session, url_nad)


def send_data(id_of_name, filtered_arrays, session, url_nad):
    """Функция добавления адресов в реп список."""
    warnings.filterwarnings("ignore")
    name_id_pairs = {}
    name_id_pairs = dict(sorted(id_of_name))

    for name, _ in name_id_pairs.items():
        temp_ip = []
        ips_to_add = []
        for arr in filtered_arrays:
            if arr[0] == name:
                for i in arr[1]:
                    ips_to_add.append({"value": i})
                    temp_ip.append(i)

        _ = session.post(url_nad + f"/replists/dynamic/{name}/_bulk",
                           json=ips_to_add,
                           verify=False)
        print(f"Добавлены IP {', '.join(temp_ip)} в список с названием LOC_auto_{name}_IP")


if __name__ == "__main__":
    print("""RᴇᴘNAD ʙʏ ᴀʀᴛʀᴏɴᴇ""")

    url_nad = input("Введите адрес вашего NAD в формате https://<your_nad_ip>/api/v2 : ")
    login = input("Введите логин: ")
    password = input("Введите пароль: ")

    session = requests.Session()
    response = session.post(
        url_nad + "/auth/login",
        json={"username": login, "password": password},
        verify=False,
    )
    if response.status_code == 200:
        print("Авторизация успешна.")
    else:
        print("Авторизация неуспешна.")
        sys.exit(1)

    warnings.filterwarnings("ignore") # Игнорирование ошибок
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning())

    while True:
        print("Выберите действие:")
        print("Автоматическое создание/добавление в реп. список [1]")
        print("Ручное добавление адреса [2]")
        print("Ручное удаление адреса [3]")
        print("Показать содержимое реп. списка [4]")
        print("Выход [0]")

        try:
            choice = int(input())
        except ValueError:
            print("Ошибка: Введено нечисловое значение")
            continue

        if choice == 1:
            connect(session, url_nad)
        elif choice == 2:
            add(session)
        elif choice == 3:
            remove(session)
        elif choice == 4:
            check(session)
        elif choice == 0:
            sys.exit()
        else:
            continue
