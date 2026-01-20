# Dockerfile для деплоя Scooter Parts Shop на Render

# Используем официальный образ Python с slim-версией для уменьшения размера
FROM python:3.11-slim as builder

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файлы зависимостей
COPY requirements.txt .

# Создаем виртуальное окружение и устанавливаем зависимости
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ============================================
# Финальный образ
# ============================================
FROM python:3.11-slim

# Устанавливаем системные зависимости для runtime
RUN apt-get update && apt-get install -y \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Создаем пользователя для безопасности
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/static /app/templates /app/data && \
    chown -R appuser:appuser /app

# Копируем виртуальное окружение из builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем исходный код
COPY --chown=appuser:appuser . .

# Создаем необходимые директории
RUN mkdir -p /app/static/images /app/static/uploads /app/static/favicon /app/data /app/templates && \
    chown -R appuser:appuser /app/static /app/data /app/templates

# Переключаемся на непривилегированного пользователя
USER appuser

# Создаем .env файл с дефолтными значениями для Render
RUN echo "ADMIN_PASSWORD=admin123" > .env && \
    echo "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" >> .env && \
    echo "DATABASE_URL=postgresql://user:password@localhost/scooter_shop" >> .env

# Экспортируем порт
EXPOSE 8000

# Здоровьечек для Render
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/test-auth || exit 1

# Команда запуска с gunicorn для production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "main:app"]