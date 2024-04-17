# RepNad

## Почему это небесполезно?

Данная программа позволяет немного автоматизировать работу с NAD, посредством использования API.
Достаточно лишь раз в некоторое время запускать программу для обновления репутационных листов. Программа сама распарсит ВПО и добавит адреса в списки.

### Основные функции программы

1. Автоматическое создание/добавление контента в репутационный список.
2. Ручное управление данными:
    1. Ручное добавление адреса(ов) в репутационный список.
    2. Ручное удаление адреса(ов) из репутационного списка.
3. Просмотр содержимого репутационного списка.

### Алгоритм работы

1. Установка соединения / создание сессии.
2. Автоматическое скачивание списка в формате JSON с сайта [feodotracker.abuse.ch](https://feodotracker.abuse.ch/).
3. Сортировка IP адресов по ВПО.
4. Создание репутационных списков. Программа автоматически проверяет наличие необходимого списка на основе ВПО из файла и, при его отсутствии, создает новый список для удобного хранения контента. *создание с использованием ключа "external_key"!*
    1. Проверка доступности изменения репутационного листа. Если список не был создан через API, то изменений не будет.
5. Добавление контента в списки. Автоматическое добавление контента в репутационные списки для упрощения процесса управления и обновления списков.

## Запуск

Установка зависимостей:

```bash
python -m pip install -r requirements.txt
```

Запуск:

```bash
python main.py
```

## P.s.

Я не программист и понимаю, что данный код не самый чистый и правильный. Данная реализация является способом прокачать скиллы. Спасибо 😉

## Автор

project by [**artrone**](https://github.com/artroneee)