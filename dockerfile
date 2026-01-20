# Dockerfile для деплоя Scooter Parts Shop на Render
FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Копируем зависимости
COPY requirements.txt .

# Устанавливаем Python зависимости
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Копируем весь проект
COPY . .

# Создаем директории
RUN mkdir -p static/images static/uploads static/favicon templates data

# Создаем __init__.py для импорта
RUN touch /app/__init__.py

# Проверяем что main.py существует
RUN ls -la /app/main.py || echo "ERROR: main.py not found!"

# Устанавливаем порт
EXPOSE 8000

# Команда запуска - указываем полный путь
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--worker-class", "uvicorn.workers.UvicornWorker", "--chdir", "/app", "main:app"]