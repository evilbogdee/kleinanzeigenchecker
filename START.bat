@echo off

echo Активация виртуального окружения .venv...
call .venv\Scripts\activate

echo Запуск main.py...
python main.py

echo Выполнение main.py завершено.
pause
