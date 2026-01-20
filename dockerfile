# Dockerfile для деплоя Scooter Parts Shop на Render
# Используем многоступенчатую сборку для оптимизации размера

# ============================================
# Этап сборки
# ============================================
FROM python:3.11-slim as builder

# Устанавливаем системные зависимости для сборки
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем зависимости
COPY requirements.txt .

# Создаем виртуальное окружение
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Устанавливаем зависимости
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# ============================================
# Финальный образ
# ============================================
FROM python:3.11-slim

# Устанавливаем системные зависимости для runtime
RUN apt-get update && apt-get install -y \
    libpq-dev \
    curl \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Создаем пользователя для безопасности
RUN adduser --disabled-password --gecos "" appuser && \
    mkdir -p /app && \
    chown -R appuser:appuser /app

# Копируем виртуальное окружение из builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH=/app

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем исходный код
COPY --chown=appuser:appuser . .

# Создаем необходимые директории
RUN mkdir -p /app/static/images /app/static/uploads /app/static/favicon && \
    chown -R appuser:appuser /app/static

# Переключаемся на непривилегированного пользователя
USER appuser

# Экспортируем порт
EXPOSE 8000

# Health check для Render
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/test-auth || exit 1

# Команда запуска
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--worker-class", "uvicorn.workers.UvicornWorker", "--timeout", "120", "main:app"]