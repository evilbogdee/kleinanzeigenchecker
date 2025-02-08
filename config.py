import os


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# files
PROXY_FILE_PATH = os.path.join(PROJECT_ROOT, "proxies", "proxies.txt") # proxies - название папки с прокси, proxies.txt - файл с прокси
COOKIES_FILE_PATH = os.path.join(PROJECT_ROOT, "cookies") # cookies - название папки с куки
LOGS_FILE_PATH = os.path.join(PROJECT_ROOT, "logs.txt")

# urls
SMS_URL = "https://www.kleinanzeigen.de/m-nachrichten.html"
# PROFILE_URL = "https://www.kleinanzeigen.de/m-meine-anzeigen.html"
PROFILE_URL = "https://www.kleinanzeigen.de/"
