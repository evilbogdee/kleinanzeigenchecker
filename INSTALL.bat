@echo off

if not exist .venv\ (
  echo Создание виртуального окружения .venv...
  python -m venv .venv
) else (
  echo Виртуальное окружение .venv уже существует.
)

echo Активация виртуального окружения...
call .venv\Scripts\activate

echo Установка библиотек из requirements.txt...
pip install -r requirements.txt

echo Готово.
pause
