# backend/main.py
from fastapi import FastAPI, HTTPException, Depends, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, validator
from typing import List, Optional, Dict
import uvicorn
from datetime import datetime
import os
from pathlib import Path
import jwt
import hashlib
import hmac
import json
from uuid import uuid4
import secrets

# Загрузка переменных окружения
from dotenv import load_dotenv

load_dotenv()

# ========== НАСТРОЙКА ==========
BASE_DIR = Path(__file__).parent.parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Создание директорий
STATIC_DIR.mkdir(parents=True, exist_ok=True)
(STATIC_DIR / "images").mkdir(exist_ok=True)
(STATIC_DIR / "favicon").mkdir(exist_ok=True)

# Пароль для админки (из переменных окружения или по умолчанию)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
ADMIN_USERNAME = "admin"  # Фиксированное имя пользователя для админки

app = FastAPI(
    title="Scooter Parts Shop",
    description="Премиум запчасти для электросамокатов",
    version="4.4.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Монтирование статических файлов
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ========== МОДЕЛИ ==========
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str
    phone: Optional[str] = None

    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Имя пользователя должно содержать минимум 3 символа')
        if len(v) > 50:
            raise ValueError('Имя пользователя должно содержать не более 50 символов')
        return v

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Пароль должен содержать минимум 6 символов')
        return v


class UserLogin(BaseModel):
    username: str
    password: str


class Product(BaseModel):
    id: int
    name: str
    category: str
    price: float
    description: str
    image_url: str
    stock: int = 0
    featured: bool = False


class CartItem(BaseModel):
    product_id: int
    quantity: int


class CartUpdate(BaseModel):
    product_id: int
    quantity: int


# Модели для админки
class AdminLogin(BaseModel):
    username: str
    password: str


class ProductCreate(BaseModel):
    name: str
    category: str
    price: float
    description: str
    stock: int = 0
    featured: bool = False


class ProductUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    price: Optional[float] = None
    description: Optional[str] = None
    stock: Optional[int] = None
    featured: Optional[bool] = None


# ========== АУТЕНТИФИКАЦИЯ ==========
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
security = HTTPBearer()


# Альтернативный хэшер на основе PBKDF2 (без bcrypt)
class PasswordHasher:
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Генерация соли и хэша пароля"""
        # Генерируем случайную соль
        salt = secrets.token_hex(16)
        # Используем PBKDF2 с SHA256 для хэширования
        iterations = 100000
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            iterations
        )
        # Формат: алгоритм:итерации:соль:хэш
        return f"pbkdf2_sha256:{iterations}:{salt}:{key.hex()}"

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Проверка пароля"""
        try:
            # Разбираем сохраненный хэш
            parts = hashed_password.split(':')
            if len(parts) != 4:
                return False

            algorithm, iterations_str, salt, stored_hash = parts
            if algorithm != 'pbkdf2_sha256':
                return False

            iterations = int(iterations_str)

            # Вычисляем хэш для введенного пароля
            key = hashlib.pbkdf2_hmac(
                'sha256',
                plain_password.encode('utf-8'),
                salt.encode('utf-8'),
                iterations
            )

            # Сравниваем хэши безопасным способом
            return hmac.compare_digest(key.hex(), stored_hash)

        except (ValueError, AttributeError):
            return False


# Создаем экземпляр хэшера
hasher = PasswordHasher()


def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if user_id is None:
            return None
        return load_user(user_id)
    except:
        return None


def verify_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Проверка админских прав"""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        is_admin = payload.get("is_admin")
        if not is_admin:
            raise HTTPException(status_code=403, detail="Доступ запрещен")
        return payload
    except:
        raise HTTPException(status_code=401, detail="Не авторизован")


# ========== ХРАНИЛИЩЕ ДАННЫХ ==========
def load_data(filename: str):
    """Загрузка данных из JSON файла"""
    filepath = DATA_DIR / f"{filename}.json"
    if filepath.exists():
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Ошибка загрузки {filename}: {e}")
            return {}
    return {}


def save_data(filename: str, data):
    """Сохранение данных в JSON файл"""
    filepath = DATA_DIR / f"{filename}.json"
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        print(f"Ошибка сохранения {filename}: {e}")


# Инициализация данных
users_db = load_data("users") or {}
products_db = load_data("products") or {}
carts_db = load_data("carts") or {}

# Если продуктов нет, создаем демо-данные
if not products_db:
    products_db = [
        {
            "id": 1,
            "name": "Аккумулятор Premium 36V 15Ah",
            "category": "batteries",
            "price": 16500,
            "description": "Высокоёмкий литий-ионный аккумулятор с системой защиты BMS. Гарантия 24 месяца.",
            "image_url": "/static/images/battery.jpg",
            "stock": 8,
            "featured": True
        },
        {
            "id": 2,
            "name": "Мотор-колесо Ultra 500W",
            "category": "motors",
            "price": 12500,
            "description": "Бесщёточный мотор с прямым приводом. Максимальная скорость 45 км/ч.",
            "image_url": "/static/images/motor.jpg",
            "stock": 5,
            "featured": True
        },
        {
            "id": 3,
            "name": "Контроллер Smart 36V",
            "category": "electronics",
            "price": 4900,
            "description": "Интеллектуальный контроллер с Bluetooth и мобильным приложением.",
            "image_url": "/static/images/controller.jpg",
            "stock": 15,
            "featured": False
        },
        {
            "id": 4,
            "name": "Дисплей Color LCD",
            "category": "electronics",
            "price": 3200,
            "description": "Цветной LCD дисплей с подсветкой и индикацией всех параметров.",
            "image_url": "/static/images/display.jpg",
            "stock": 12,
            "featured": True
        },
        {
            "id": 5,
            "name": "Тормозные диски Premium",
            "category": "brakes",
            "price": 2200,
            "description": "Вентилируемые тормозные диски из нержавеющей стали.",
            "image_url": "/static/images/brakes.jpg",
            "stock": 25,
            "featured": False
        },
        {
            "id": 6,
            "name": "Колесо 10\" All-Terrain",
            "category": "tires",
            "price": 1800,
            "description": "Пневматическое колесо для бездорожья с усиленными стенками.",
            "image_url": "/static/images/wheel.jpg",
            "stock": 20,
            "featured": False
        },
        {
            "id": 7,
            "name": "Тормозные колодки Premium",
            "category": "brakes",
            "price": 1200,
            "description": "Керамические тормозные колодки для дисковых тормозов.",
            "image_url": "/static/images/brake-pads.jpg",
            "stock": 30,
            "featured": True
        },
        {
            "id": 8,
            "name": "Руль алюминиевый",
            "category": "accessories",
            "price": 2500,
            "description": "Алюминиевый руль с резиновыми накладками.",
            "image_url": "/static/images/handlebar.jpg",
            "stock": 15,
            "featured": False
        }
    ]
    save_data("products", products_db)

# Создаем тестового пользователя если нет пользователей
if not users_db:
    test_user_id = str(uuid4())
    users_db[test_user_id] = {
        "id": test_user_id,
        "username": "demo",
        "email": "demo@scooterparts.ru",
        "full_name": "Демо Пользователь",
        "phone": "+79991234567",
        "password_hash": hasher.get_password_hash("demo123"),
        "created_at": datetime.now().isoformat(),
        "is_admin": False
    }
    save_data("users", users_db)

    # Создаем пустую корзину для тестового пользователя
    carts_db[test_user_id] = []
    save_data("carts", carts_db)


def load_user(user_id: str):
    return users_db.get(user_id)


def get_user_cart(user_id: str):
    if user_id not in carts_db:
        carts_db[user_id] = []
    return carts_db[user_id]


def save_user_cart(user_id: str, cart):
    carts_db[user_id] = cart
    save_data("carts", carts_db)


# ========== API ЭНДПОИНТЫ ==========
@app.post("/api/register")
async def register(user_data: UserRegister):
    """Регистрация нового пользователя"""
    try:
        # Проверяем, существует ли пользователь
        for user in users_db.values():
            if user.get("username") == user_data.username:
                raise HTTPException(status_code=400, detail="Имя пользователя уже занято")
            if user.get("email") == user_data.email:
                raise HTTPException(status_code=400, detail="Email уже используется")

        # Создаем нового пользователя
        user_id = str(uuid4())
        users_db[user_id] = {
            "id": user_id,
            "username": user_data.username,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "phone": user_data.phone,
            "password_hash": hasher.get_password_hash(user_data.password),
            "created_at": datetime.now().isoformat(),
            "is_admin": False
        }

        save_data("users", users_db)

        # Создаем пустую корзину
        carts_db[user_id] = []
        save_data("carts", carts_db)

        # Создаем токен
        access_token = create_access_token({"user_id": user_id})

        return {
            "message": "Регистрация успешна",
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user_id,
                "username": user_data.username,
                "email": user_data.email,
                "full_name": user_data.full_name
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Ошибка регистрации: {e}")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера")


@app.post("/api/login")
async def login(login_data: UserLogin):
    """Вход пользователя"""
    try:
        for user_id, user in users_db.items():
            if user.get("username") == login_data.username:
                if hasher.verify_password(login_data.password, user.get("password_hash", "")):
                    access_token = create_access_token({"user_id": user_id})
                    return {
                        "access_token": access_token,
                        "token_type": "bearer",
                        "user": {
                            "id": user_id,
                            "username": user.get("username"),
                            "email": user.get("email"),
                            "full_name": user.get("full_name")
                        }
                    }

        raise HTTPException(status_code=401, detail="Неверное имя пользователя или пароль")
    except Exception as e:
        print(f"Ошибка входа: {e}")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера")


@app.get("/api/profile")
async def get_profile(user=Depends(get_current_user)):
    """Получить профиль пользователя"""
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "email": user.get("email"),
        "full_name": user.get("full_name"),
        "phone": user.get("phone"),
        "created_at": user.get("created_at")
    }


# Корзина
@app.get("/api/cart")
async def get_cart(user=Depends(get_current_user)):
    """Получить корзину пользователя"""
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    cart = get_user_cart(user.get("id"))
    cart_with_details = []
    total = 0

    for item in cart:
        product = next((p for p in products_db if p["id"] == item.get("product_id")), None)
        if product:
            item_total = product["price"] * item.get("quantity", 0)
            total += item_total
            cart_with_details.append({
                **item,
                "product": product,
                "item_total": item_total
            })

    return {
        "items": cart_with_details,
        "total": total,
        "items_count": len(cart)
    }


@app.post("/api/cart")
async def add_to_cart(cart_item: CartUpdate, user=Depends(get_current_user)):
    """Добавить товар в корзину"""
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    if cart_item.quantity <= 0:
        raise HTTPException(status_code=400, detail="Количество должно быть больше 0")

    # Проверяем, есть ли товар
    product = next((p for p in products_db if p["id"] == cart_item.product_id), None)
    if not product:
        raise HTTPException(status_code=404, detail="Товар не найден")

    # Проверяем наличие на складе
    if product["stock"] < cart_item.quantity:
        raise HTTPException(status_code=400, detail="Недостаточно товара на складе")

    cart = get_user_cart(user.get("id"))

    # Ищем товар в корзине
    item_index = next((i for i, item in enumerate(cart) if item.get("product_id") == cart_item.product_id), None)

    if item_index is not None:
        # Обновляем количество
        cart[item_index]["quantity"] = cart_item.quantity
    else:
        # Добавляем новый товар
        cart.append({
            "product_id": cart_item.product_id,
            "quantity": cart_item.quantity,
            "added_at": datetime.now().isoformat()
        })

    save_user_cart(user.get("id"), cart)

    return {"message": "Товар добавлен в корзину"}


@app.delete("/api/cart/{product_id}")
async def remove_from_cart(product_id: int, user=Depends(get_current_user)):
    """Удалить товар из корзины"""
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    cart = get_user_cart(user.get("id"))

    # Ищем товар в корзине
    item_index = next((i for i, item in enumerate(cart) if item.get("product_id") == product_id), None)

    if item_index is None:
        raise HTTPException(status_code=404, detail="Товар не найден в корзине")

    # Удаляем товар
    cart.pop(item_index)
    save_user_cart(user.get("id"), cart)

    return {"message": "Товар удален из корзины"}


@app.delete("/api/cart")
async def clear_cart(user=Depends(get_current_user)):
    """Очистить корзину"""
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    save_user_cart(user.get("id"), [])

    return {"message": "Корзина очищена"}


# Продукты
@app.get("/api/products")
async def get_products(category: Optional[str] = None, featured: Optional[bool] = None):
    """Получить список товаров"""
    filtered = products_db.copy()

    if category:
        filtered = [p for p in filtered if p.get("category") == category]

    if featured is not None:
        filtered = [p for p in filtered if p.get("featured") == featured]

    return filtered


@app.get("/api/products/{product_id}")
async def get_product(product_id: int):
    """Получить товар по ID"""
    product = next((p for p in products_db if p.get("id") == product_id), None)
    if not product:
        raise HTTPException(status_code=404, detail="Товар не найден")
    return product


@app.get("/api/categories")
async def get_categories():
    """Получить список категорий"""
    categories_count = {}
    for product in products_db:
        category = product.get("category")
        categories_count[category] = categories_count.get(category, 0) + 1

    category_names = {
        "batteries": "Аккумуляторы",
        "motors": "Моторы",
        "electronics": "Электроника",
        "brakes": "Тормоза",
        "tires": "Колёса",
        "accessories": "Аксессуары"
    }

    categories = []
    for cat_id, count in categories_count.items():
        categories.append({
            "id": cat_id,
            "name": category_names.get(cat_id, cat_id),
            "count": count
        })

    return {"categories": categories}


@app.get("/api/stats")
async def get_stats():
    """Получить статистику магазина"""
    return {
        "total_products": len(products_db),
        "total_orders": 0,
        "categories": len(set(p.get("category") for p in products_db)),
        "total_stock": sum(p.get("stock", 0) for p in products_db),
        "featured_products": len([p for p in products_db if p.get("featured")])
    }


# Админские эндпоинты
@app.post("/api/admin/login")
async def admin_login(login_data: AdminLogin):
    """Вход в админку"""
    if login_data.username != ADMIN_USERNAME:
        raise HTTPException(status_code=401, detail="Неверные данные для входа")

    if login_data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Неверные данные для входа")

    # Создаем токен для админа
    admin_token = create_access_token({
        "user_id": "admin",
        "username": ADMIN_USERNAME,
        "is_admin": True
    })

    return {
        "access_token": admin_token,
        "token_type": "bearer",
        "user": {
            "username": ADMIN_USERNAME,
            "is_admin": True
        }
    }


@app.get("/api/admin/stats")
async def get_admin_stats(admin=Depends(verify_admin)):
    """Получить расширенную статистику для админки"""
    total_users = len(users_db)
    total_carts = len(carts_db)
    carts_with_items = sum(1 for cart in carts_db.values() if len(cart) > 0)

    return {
        "users": {
            "total": total_users,
            "with_carts": carts_with_items,
            "without_carts": total_users - carts_with_items
        },
        "products": {
            "total": len(products_db),
            "in_stock": sum(1 for p in products_db if p["stock"] > 0),
            "out_of_stock": sum(1 for p in products_db if p["stock"] == 0),
            "featured": sum(1 for p in products_db if p["featured"])
        },
        "carts": {
            "total": total_carts,
            "empty": sum(1 for cart in carts_db.values() if len(cart) == 0),
            "with_items": carts_with_items
        }
    }


@app.post("/api/admin/products")
async def create_product(
        product_data: ProductCreate,
        admin=Depends(verify_admin)
):
    """Создать новый товар"""
    try:
        # Генерируем ID для нового товара
        new_id = max(p["id"] for p in products_db) + 1 if products_db else 1

        new_product = {
            "id": new_id,
            "name": product_data.name,
            "category": product_data.category,
            "price": product_data.price,
            "description": product_data.description,
            "image_url": f"/static/images/product_{new_id}.jpg",  # Заглушка для изображения
            "stock": product_data.stock,
            "featured": product_data.featured
        }

        products_db.append(new_product)
        save_data("products", products_db)

        return {
            "message": "Товар успешно создан",
            "product": new_product
        }

    except Exception as e:
        print(f"Ошибка создания товара: {e}")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера")


@app.put("/api/admin/products/{product_id}")
async def update_product(
        product_id: int,
        product_data: ProductUpdate,
        admin=Depends(verify_admin)
):
    """Обновить товар"""
    try:
        # Ищем товар
        product_index = next((i for i, p in enumerate(products_db) if p["id"] == product_id), None)
        if product_index is None:
            raise HTTPException(status_code=404, detail="Товар не найден")

        # Обновляем поля
        product = products_db[product_index]
        update_data = product_data.dict(exclude_unset=True)

        for key, value in update_data.items():
            if value is not None:
                product[key] = value

        products_db[product_index] = product
        save_data("products", products_db)

        return {
            "message": "Товар успешно обновлен",
            "product": product
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Ошибка обновления товара: {e}")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера")


@app.delete("/api/admin/products/{product_id}")
async def delete_product(
        product_id: int,
        admin=Depends(verify_admin)
):
    """Удалить товар"""
    try:
        # Ищем товар
        product_index = next((i for i, p in enumerate(products_db) if p["id"] == product_id), None)
        if product_index is None:
            raise HTTPException(status_code=404, detail="Товар не найден")

        # Удаляем товар
        deleted_product = products_db.pop(product_index)
        save_data("products", products_db)

        # Удаляем товар из всех корзин
        for user_id in carts_db:
            carts_db[user_id] = [item for item in carts_db[user_id] if item.get("product_id") != product_id]
        save_data("carts", carts_db)

        return {
            "message": "Товар успешно удален",
            "product": deleted_product
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Ошибка удаления товара: {e}")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера")


# Тестовый эндпоинт для проверки
@app.get("/api/test-auth")
async def test_auth():
    """Тестирование аутентификации"""
    test_password = "test123"
    hashed = hasher.get_password_hash(test_password)
    verified = hasher.verify_password(test_password, hashed)

    return {
        "status": "ok",
        "hash_working": verified,
        "users_count": len(users_db),
        "demo_user_exists": "demo" in [u.get("username") for u in users_db.values()],
        "admin_password_set": ADMIN_PASSWORD != "admin123"  # Если пароль не дефолтный
    }


# ========== ГЛАВНАЯ СТРАНИЦА ==========
@app.get("/")
async def root(request: Request):
    """Главная страница магазина"""

    html_content = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
        <meta http-equiv="Pragma" content="no-cache">
        <meta http-equiv="Expires" content="0">

        <!-- Иконки -->
        <link rel="apple-touch-icon" sizes="180x180" href="/static/favicon/apple-touch-icon.png">
        <link rel="icon" type="image/png" sizes="32x32" href="/static/favicon/favicon-32x32.png">
        <link rel="icon" type="image/png" sizes="16x16" href="/static/favicon/favicon-16x16.png">
        <link rel="icon" href="/static/favicon/favicon.ico">
        <link rel="manifest" href="/static/favicon/site.webmanifest">
        <meta name="theme-color" content="#000000">

        <title>Scooter Parts | Премиум запчасти</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --white: #ffffff;
                --black: #000000;
                --gray-50: #fafafa;
                --gray-100: #f5f5f5;
                --gray-200: #e5e5e5;
                --gray-300: #d4d4d4;
                --gray-600: #525252;
                --gray-900: #171717;
                --blue: #3b82f6;
                --green: #10b981;
                --red: #ef4444;
                --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
                --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
                --radius: 0.5rem;
            }

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Inter', -apple-system, sans-serif;
                background: var(--white);
                color: var(--gray-900);
                line-height: 1.5;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
            }

            .container {
                max-width: 1280px;
                margin: 0 auto;
                padding: 0 1.5rem;
            }

            /* Header */
            .header {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: var(--white);
                border-bottom: 1px solid var(--gray-200);
                z-index: 100;
                padding: 1rem 0;
            }

            .header-content {
                display: flex;
                align-items: center;
                justify-content: space-between;
            }

            .logo {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                font-size: 1.5rem;
                font-weight: 700;
                color: var(--black);
                text-decoration: none;
            }

            .logo-icon {
                width: 32px;
                height: 32px;
                background-image: url('/static/favicon/favicon-32x32.png');
                background-size: contain;
                background-repeat: no-repeat;
                background-position: center;
            }

            .nav {
                display: flex;
                align-items: center;
                gap: 2rem;
            }

            .nav-link {
                color: var(--gray-600);
                text-decoration: none;
                font-weight: 500;
                transition: color 0.2s;
            }

            .nav-link:hover,
            .nav-link.active {
                color: var(--black);
            }

            .header-actions {
                display: flex;
                align-items: center;
                gap: 1rem;
            }

            .btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 0.5rem 1rem;
                font-size: 0.875rem;
                font-weight: 500;
                border-radius: var(--radius);
                border: none;
                cursor: pointer;
                transition: all 0.2s;
                text-decoration: none;
            }

            .btn-primary {
                background: var(--black);
                color: var(--white);
            }

            .btn-primary:hover {
                background: var(--gray-900);
            }

            .btn-outline {
                background: transparent;
                border: 1px solid var(--gray-300);
                color: var(--gray-900);
            }

            .btn-outline:hover {
                background: var(--gray-100);
            }

            .cart-btn {
                position: relative;
            }

            .cart-count {
                position: absolute;
                top: -0.5rem;
                right: -0.5rem;
                background: var(--red);
                color: var(--white);
                font-size: 0.75rem;
                width: 1.25rem;
                height: 1.25rem;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            /* Hero */
            .hero {
                padding-top: 8rem;
                padding-bottom: 4rem;
                background: linear-gradient(to bottom, var(--white), var(--gray-50));
            }

            .hero-content {
                text-align: center;
                max-width: 768px;
                margin: 0 auto;
            }

            .hero-title {
                font-size: 3rem;
                font-weight: 700;
                line-height: 1.1;
                margin-bottom: 1.5rem;
            }

            .hero-description {
                font-size: 1.125rem;
                color: var(--gray-600);
                margin-bottom: 2rem;
            }

            /* Features */
            .features {
                padding: 4rem 0;
                background: var(--white);
            }

            .section-title {
                font-size: 2rem;
                font-weight: 700;
                margin-bottom: 2rem;
                text-align: center;
            }

            .features-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 2rem;
            }

            .feature-card {
                padding: 2rem;
                background: var(--gray-50);
                border-radius: var(--radius);
                text-align: center;
            }

            .feature-icon {
                font-size: 3rem;
                margin-bottom: 1rem;
            }

            .feature-title {
                font-size: 1.25rem;
                font-weight: 600;
                margin-bottom: 0.5rem;
            }

            .feature-description {
                color: var(--gray-600);
            }

            /* Products */
            .products {
                padding: 4rem 0;
                background: var(--gray-50);
            }

            .products-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
                gap: 2rem;
            }

            .product-card {
                border: 1px solid var(--gray-200);
                border-radius: var(--radius);
                overflow: hidden;
                background: var(--white);
                transition: all 0.3s;
            }

            .product-card:hover {
                transform: translateY(-2px);
                box-shadow: var(--shadow-lg);
            }

            .product-image {
                width: 100%;
                height: 200px;
                background: var(--gray-100);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 3rem;
            }

            .product-content {
                padding: 1.5rem;
            }

            .product-title {
                font-size: 1.125rem;
                font-weight: 600;
                margin-bottom: 0.5rem;
            }

            .product-description {
                color: var(--gray-600);
                font-size: 0.875rem;
                margin-bottom: 1rem;
            }

            .product-footer {
                display: flex;
                align-items: center;
                justify-content: space-between;
            }

            .product-price {
                font-size: 1.25rem;
                font-weight: 700;
            }

            .add-to-cart-btn {
                padding: 0.5rem 1rem;
                background: var(--black);
                color: var(--white);
                border: none;
                border-radius: var(--radius);
                cursor: pointer;
                font-weight: 500;
                transition: background 0.2s;
            }

            .add-to-cart-btn:hover {
                background: var(--gray-900);
            }

            .add-to-cart-btn:disabled {
                background: var(--gray-300);
                cursor: not-allowed;
            }

            /* Categories */
            .categories {
                padding: 4rem 0;
                background: var(--white);
            }

            .categories-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1.5rem;
            }

            .category-card {
                padding: 2rem;
                background: var(--gray-50);
                border-radius: var(--radius);
                text-align: center;
                text-decoration: none;
                color: inherit;
                transition: all 0.3s;
            }

            .category-card:hover {
                background: var(--gray-100);
                transform: translateY(-2px);
            }

            .category-icon {
                font-size: 2.5rem;
                margin-bottom: 1rem;
            }

            .category-title {
                font-size: 1.125rem;
                font-weight: 600;
                margin-bottom: 0.25rem;
            }

            .category-count {
                color: var(--gray-600);
                font-size: 0.875rem;
            }

            /* Footer */
            .footer {
                background: var(--gray-900);
                color: var(--white);
                padding: 4rem 0 2rem;
                margin-top: auto;
            }

            .footer-content {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 3rem;
                margin-bottom: 3rem;
            }

            .footer-logo {
                font-size: 1.5rem;
                font-weight: 700;
                margin-bottom: 1rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .footer-description {
                color: var(--gray-400);
                font-size: 0.95rem;
                line-height: 1.6;
                margin-bottom: 1.5rem;
            }

            .footer-heading {
                font-size: 1rem;
                font-weight: 600;
                margin-bottom: 1.25rem;
                color: var(--white);
            }

            .footer-links {
                list-style: none;
            }

            .footer-link {
                color: var(--gray-400);
                text-decoration: none;
                font-size: 0.95rem;
                margin-bottom: 0.75rem;
                display: block;
                transition: color 0.2s;
            }

            .footer-link:hover {
                color: var(--white);
            }

            .contact-info {
                color: var(--gray-400);
                font-size: 0.95rem;
                line-height: 1.6;
            }

            .contact-item {
                margin-bottom: 0.75rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .footer-bottom {
                padding-top: 2rem;
                border-top: 1px solid var(--gray-800);
                text-align: center;
                color: var(--gray-400);
                font-size: 0.875rem;
            }

            .social-links {
                display: flex;
                gap: 1rem;
                margin-top: 1rem;
            }

            .social-link {
                color: var(--gray-400);
                text-decoration: none;
                transition: color 0.2s;
            }

            .social-link:hover {
                color: var(--white);
            }

            /* Auth Modal */
            .modal {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.5);
                z-index: 1000;
                align-items: center;
                justify-content: center;
            }

            .modal.active {
                display: flex;
            }

            .modal-content {
                background: var(--white);
                border-radius: var(--radius);
                padding: 2rem;
                width: 100%;
                max-width: 400px;
                max-height: 90vh;
                overflow-y: auto;
            }

            .modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1.5rem;
            }

            .modal-close {
                background: none;
                border: none;
                font-size: 1.5rem;
                cursor: pointer;
                color: var(--gray-600);
            }

            .form-group {
                margin-bottom: 1rem;
            }

            .form-label {
                display: block;
                margin-bottom: 0.5rem;
                font-weight: 500;
            }

            .form-input {
                width: 100%;
                padding: 0.75rem;
                border: 1px solid var(--gray-300);
                border-radius: var(--radius);
                font-family: inherit;
                font-size: 1rem;
            }

            .form-input:focus {
                outline: none;
                border-color: var(--black);
            }

            .auth-tabs {
                display: flex;
                gap: 1rem;
                margin-bottom: 1.5rem;
                border-bottom: 1px solid var(--gray-200);
            }

            .auth-tab {
                padding: 0.5rem 0;
                background: none;
                border: none;
                color: var(--gray-600);
                cursor: pointer;
                font-weight: 500;
                position: relative;
            }

            .auth-tab.active {
                color: var(--black);
            }

            .auth-tab.active::after {
                content: '';
                position: absolute;
                bottom: -1px;
                left: 0;
                right: 0;
                height: 2px;
                background: var(--black);
            }

            /* Cart Modal */
            .cart-modal {
                position: fixed;
                top: 0;
                right: 0;
                bottom: 0;
                width: 400px;
                background: var(--white);
                border-left: 1px solid var(--gray-200);
                transform: translateX(100%);
                transition: transform 0.3s;
                z-index: 1000;
                display: flex;
                flex-direction: column;
            }

            .cart-modal.active {
                transform: translateX(0);
            }

            .cart-header {
                padding: 1.5rem;
                border-bottom: 1px solid var(--gray-200);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            .cart-body {
                flex: 1;
                padding: 1.5rem;
                overflow-y: auto;
            }

            .cart-footer {
                padding: 1.5rem;
                border-top: 1px solid var(--gray-200);
            }

            .cart-total {
                display: flex;
                justify-content: space-between;
                font-size: 1.125rem;
                font-weight: 600;
                margin-bottom: 1rem;
            }

            .cart-item {
                display: flex;
                gap: 1rem;
                padding: 1rem 0;
                border-bottom: 1px solid var(--gray-200);
            }

            .cart-item-image {
                width: 60px;
                height: 60px;
                background: var(--gray-100);
                border-radius: var(--radius);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.5rem;
            }

            .cart-item-content {
                flex: 1;
            }

            .cart-item-title {
                font-weight: 500;
                margin-bottom: 0.25rem;
            }

            .cart-item-price {
                color: var(--gray-600);
                font-size: 0.875rem;
            }

            .cart-item-actions {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                margin-top: 0.5rem;
            }

            .quantity-btn {
                width: 24px;
                height: 24px;
                border: 1px solid var(--gray-300);
                background: var(--white);
                border-radius: 4px;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .quantity-input {
                width: 40px;
                text-align: center;
                border: 1px solid var(--gray-300);
                border-radius: 4px;
                padding: 0.25rem;
            }

            .remove-btn {
                color: var(--red);
                background: none;
                border: none;
                cursor: pointer;
                font-size: 0.875rem;
            }

            /* User Menu */
            .user-menu {
                position: relative;
            }

            .user-btn {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.5rem 1rem;
                background: none;
                border: 1px solid var(--gray-300);
                border-radius: var(--radius);
                cursor: pointer;
                font-family: inherit;
                font-size: 0.875rem;
            }

            .user-dropdown {
                position: absolute;
                top: 100%;
                right: 0;
                background: var(--white);
                border: 1px solid var(--gray-200);
                border-radius: var(--radius);
                padding: 0.5rem;
                min-width: 200px;
                display: none;
                box-shadow: var(--shadow-lg);
                z-index: 100;
            }

            .user-dropdown.active {
                display: block;
            }

            .user-info {
                padding: 0.5rem;
                border-bottom: 1px solid var(--gray-200);
                margin-bottom: 0.5rem;
            }

            .dropdown-item {
                display: block;
                width: 100%;
                padding: 0.5rem;
                text-align: left;
                background: none;
                border: none;
                cursor: pointer;
                color: var(--gray-900);
                border-radius: 4px;
                font-family: inherit;
                font-size: 0.875rem;
            }

            .dropdown-item:hover {
                background: var(--gray-100);
            }

            /* Loading */
            .loading {
                text-align: center;
                padding: 2rem;
                color: var(--gray-600);
            }

            /* Messages */
            .message {
                padding: 1rem;
                border-radius: var(--radius);
                margin-bottom: 1rem;
                font-size: 0.875rem;
            }

            .message-success {
                background: #d1fae5;
                color: #065f46;
                border: 1px solid #a7f3d0;
            }

            .message-error {
                background: #fee2e2;
                color: #991b1b;
                border: 1px solid #fecaca;
            }

            /* Admin Link */
            .admin-link {
                margin-left: 1rem;
                font-size: 0.75rem;
                color: var(--gray-500);
                text-decoration: none;
            }

            .admin-link:hover {
                color: var(--gray-700);
            }

            /* Responsive */
            @media (max-width: 768px) {
                .hero-title {
                    font-size: 2rem;
                }

                .cart-modal {
                    width: 100%;
                }

                .nav {
                    display: none;
                }

                .footer-content {
                    grid-template-columns: 1fr;
                    gap: 2rem;
                }
            }
        </style>
    </head>
    <body>
        <!-- Header -->
        <header class="header">
            <div class="container">
                <div class="header-content">
                    <a href="/" class="logo">
                        <div class="logo-icon"></div>
                        <span>ScooterParts</span>
                    </a>

                    <nav class="nav">
                        <a href="#products" class="nav-link">Товары</a>
                        <a href="/products" class="nav-link">Все товары</a>
                        <a href="#categories" class="nav-link">Категории</a>
                        <a href="#features" class="nav-link">Преимущества</a>
                        <a href="#about" class="nav-link">О нас</a>
                    </nav>

                    <div class="header-actions">
                        <button class="btn btn-outline cart-btn" id="cartBtn">
                            🛒 Корзина
                            <span class="cart-count" id="cartCount">0</span>
                        </button>

                        <div class="user-menu" id="userMenu">
                            <button class="btn btn-outline" id="authBtn">Войти</button>
                        </div>
                    </div>
                </div>
            </div>
        </header>

        <!-- Hero -->
        <section class="hero">
            <div class="container">
                <div class="hero-content">
                    <h1 class="hero-title">Запчасти для электросамокатов</h1>
                    <p class="hero-description">
                        Оригинальные компоненты и аксессуары от ведущих производителей. 
                        Гарантия качества, быстрая доставка и профессиональная поддержка.
                    </p>
                    <div>
                        <a href="/products" class="btn btn-primary">Смотреть все товары</a>
                        <a href="/admin" class="admin-link" style="margin-left: 1rem;">Админка</a>
                    </div>
                </div>
            </div>
        </section>

        <!-- Features -->
        <section class="features" id="features">
            <div class="container">
                <h2 class="section-title">Почему выбирают нас</h2>
                <div class="features-grid">
                    <div class="feature-card">
                        <div class="feature-icon">🏭</div>
                        <h3 class="feature-title">Оригинальные производители</h3>
                        <p class="feature-description">
                            Работаем напрямую с ведущими производителями запчастей
                        </p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🛡️</div>
                        <h3 class="feature-title">Гарантия качества</h3>
                        <p class="feature-description">
                            Гарантия на все товары от 12 до 24 месяцев
                        </p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🚚</div>
                        <h3 class="feature-title">Быстрая доставка</h3>
                        <p class="feature-description">
                            Отправка в день заказа по всей России
                        </p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🔧</div>
                        <h3 class="feature-title">Техподдержка</h3>
                        <p class="feature-description">
                            Бесплатная консультация по подбору запчастей
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Products -->
        <section class="products" id="products">
            <div class="container">
                <h2 class="section-title">Популярные товары</h2>
                <div class="products-grid" id="productsGrid">
                    <div class="loading">Загрузка товаров...</div>
                </div>
                <div style="text-align: center; margin-top: 3rem;">
                    <a href="/products" class="btn btn-outline">Показать все товары</a>
                </div>
            </div>
        </section>

        <!-- Categories -->
        <section class="categories" id="categories">
            <div class="container">
                <h2 class="section-title">Категории товаров</h2>
                <div class="categories-grid" id="categoriesGrid">
                    <!-- Категории загружаются через JS -->
                </div>
            </div>
        </section>

        <!-- Footer -->
        <footer class="footer" id="about">
            <div class="container">
                <div class="footer-content">
                    <div>
                        <div class="footer-logo">
                            <span>🛴</span>
                            <span>ScooterParts</span>
                        </div>
                        <p class="footer-description">
                            Ведущий поставщик запчастей для электросамокатов в России. 
                            Обеспечиваем качество и надёжность с 2020 года.
                        </p>
                        <div class="social-links">
                            <a href="#" class="social-link">Instagram</a>
                            <a href="#" class="social-link">VK</a>
                            <a href="#" class="social-link">Telegram</a>
                        </div>
                    </div>

                    <div>
                        <h3 class="footer-heading">Магазин</h3>
                        <ul class="footer-links">
                            <li><a href="/" class="footer-link">Главная</a></li>
                            <li><a href="/products" class="footer-link">Все товары</a></li>
                            <li><a href="#categories" class="footer-link">Категории</a></li>
                            <li><a href="#features" class="footer-link">Преимущества</a></li>
                        </ul>
                    </div>

                    <div>
                        <h3 class="footer-heading">Помощь</h3>
                        <ul class="footer-links">
                            <li><a href="#" class="footer-link">Гарантия</a></li>
                            <li><a href="#" class="footer-link">Возврат</a></li>
                            <li><a href="#" class="footer-link">Контакты</a></li>
                            <li><a href="#" class="footer-link">FAQ</a></li>
                        </ul>
                    </div>

                    <div>
                        <h3 class="footer-heading">Контакты</h3>
                        <div class="contact-info">
                            <div class="contact-item">📍 Москва, ул. Примерная, 123</div>
                            <div class="contact-item">📞 <a href="tel:+78001234567" class="footer-link">8 (800) 123-45-67</a></div>
                            <div class="contact-item">✉️ <a href="mailto:info@scooterparts.ru" class="footer-link">info@scooterparts.ru</a></div>
                            <div class="contact-item">🕐 Ежедневно с 9:00 до 21:00</div>
                        </div>
                    </div>
                </div>

                <div class="footer-bottom">
                    <p>© 2024 ScooterParts. Все права защищены.</p>
                </div>
            </div>
        </footer>

        <!-- Auth Modal -->
        <div class="modal" id="authModal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>Вход / Регистрация</h2>
                    <button class="modal-close" id="closeAuthModal">&times;</button>
                </div>

                <div class="auth-tabs">
                    <button class="auth-tab active" data-tab="login">Вход</button>
                    <button class="auth-tab" data-tab="register">Регистрация</button>
                </div>

                <div id="authMessages"></div>

                <form id="loginForm" class="auth-form">
                    <div class="form-group">
                        <label class="form-label">Имя пользователя</label>
                        <input type="text" class="form-input" name="username" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Пароль</label>
                        <input type="password" class="form-input" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width: 100%;">Войти</button>
                </form>

                <form id="registerForm" class="auth-form" style="display: none;">
                    <div class="form-group">
                        <label class="form-label">Имя пользователя*</label>
                        <input type="text" class="form-input" name="username" required minlength="3" maxlength="50">
                        <small style="color: var(--gray-600); font-size: 0.75rem;">От 3 до 50 символов</small>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Email*</label>
                        <input type="email" class="form-input" name="email" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Полное имя*</label>
                        <input type="text" class="form-input" name="full_name" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Пароль*</label>
                        <input type="password" class="form-input" name="password" required minlength="6">
                        <small style="color: var(--gray-600); font-size: 0.75rem;">Минимум 6 символов</small>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Телефон (опционально)</label>
                        <input type="tel" class="form-input" name="phone">
                    </div>
                    <button type="submit" class="btn btn-primary" style="width: 100%;">Зарегистрироваться</button>
                </form>
            </div>
        </div>

        <!-- Cart Modal -->
        <div class="cart-modal" id="cartModal">
            <div class="cart-header">
                <h2>Корзина</h2>
                <button class="modal-close" id="closeCartModal">&times;</button>
            </div>
            <div class="cart-body" id="cartBody">
                <!-- Товары в корзине -->
            </div>
            <div class="cart-footer">
                <div class="cart-total">
                    <span>Итого:</span>
                    <span id="cartTotal">0 ₽</span>
                </div>
                <button class="btn btn-primary" style="width: 100%;" id="checkoutBtn">Оформить заказ</button>
            </div>
        </div>

        <script>
            // Глобальные переменные
            let currentUser = null;
            let cart = [];

            // DOM элементы
            const authBtn = document.getElementById('authBtn');
            const authModal = document.getElementById('authModal');
            const closeAuthModal = document.getElementById('closeAuthModal');
            const cartBtn = document.getElementById('cartBtn');
            const cartModal = document.getElementById('cartModal');
            const closeCartModal = document.getElementById('closeCartModal');
            const cartCount = document.getElementById('cartCount');
            const cartBody = document.getElementById('cartBody');
            const cartTotal = document.getElementById('cartTotal');
            const productsGrid = document.getElementById('productsGrid');
            const categoriesGrid = document.getElementById('categoriesGrid');
            const authTabs = document.querySelectorAll('.auth-tab');
            const loginForm = document.getElementById('loginForm');
            const registerForm = document.getElementById('registerForm');
            const userMenu = document.getElementById('userMenu');
            const authMessages = document.getElementById('authMessages');
            const checkoutBtn = document.getElementById('checkoutBtn');

            // Инициализация
            document.addEventListener('DOMContentLoaded', () => {
                // Проверяем токен при загрузке
                const token = localStorage.getItem('token');
                if (token) {
                    checkAuth(token);
                }

                loadProducts();
                loadCategories();
                loadCart();

                // События
                authBtn.addEventListener('click', showAuthModal);
                closeAuthModal.addEventListener('click', hideAuthModal);
                cartBtn.addEventListener('click', showCartModal);
                closeCartModal.addEventListener('click', hideCartModal);

                // Клик вне модальных окон
                authModal.addEventListener('click', (e) => {
                    if (e.target === authModal) hideAuthModal();
                });

                // Табы авторизации
                authTabs.forEach(tab => {
                    tab.addEventListener('click', () => {
                        authTabs.forEach(t => t.classList.remove('active'));
                        tab.classList.add('active');
                        clearAuthMessages();

                        if (tab.dataset.tab === 'login') {
                            loginForm.style.display = 'block';
                            registerForm.style.display = 'none';
                        } else {
                            loginForm.style.display = 'none';
                            registerForm.style.display = 'block';
                        }
                    });
                });

                // Форма входа
                loginForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    clearAuthMessages();

                    const formData = new FormData(loginForm);
                    const data = Object.fromEntries(formData);

                    try {
                        const response = await fetch('/api/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(data)
                        });

                        if (response.ok) {
                            const result = await response.json();
                            localStorage.setItem('token', result.access_token);
                            currentUser = result.user;
                            updateAuthUI();
                            hideAuthModal();
                            loadCart();
                            showMessage('success', 'Вход выполнен успешно!');
                        } else {
                            const error = await response.json();
                            showMessage('error', error.detail || 'Ошибка входа');
                        }
                    } catch (error) {
                        console.error('Ошибка:', error);
                        showMessage('error', 'Ошибка сети. Проверьте подключение к интернету.');
                    }
                });

                // Форма регистрации
                registerForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    clearAuthMessages();

                    const formData = new FormData(registerForm);
                    const data = Object.fromEntries(formData);

                    // Валидация
                    if (data.username.length < 3 || data.username.length > 50) {
                        showMessage('error', 'Имя пользователя должно содержать от 3 до 50 символов');
                        return;
                    }

                    if (data.password.length < 6) {
                        showMessage('error', 'Пароль должен содержать минимум 6 символов');
                        return;
                    }

                    try {
                        const response = await fetch('/api/register', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(data)
                        });

                        const result = await response.json();

                        if (response.ok) {
                            localStorage.setItem('token', result.access_token);
                            currentUser = result.user;
                            updateAuthUI();
                            hideAuthModal();
                            loadCart();
                            showMessage('success', 'Регистрация успешна! Добро пожаловать!');
                        } else {
                            showMessage('error', result.detail || 'Ошибка регистрации');
                        }
                    } catch (error) {
                        console.error('Ошибка регистрации:', error);
                        showMessage('error', 'Ошибка сети. Проверьте подключение к интернету.');
                    }
                });

                // Оформление заказа
                checkoutBtn.addEventListener('click', () => {
                    if (!currentUser) {
                        showAuthModal();
                        return;
                    }

                    if (cart.length === 0) {
                        alert('Корзина пуста');
                        return;
                    }

                    alert('Функция оформления заказа будет доступна в следующем обновлении!');
                });
            });

            // Функции
            async function checkAuth(token) {
                try {
                    const response = await fetch('/api/profile', {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });

                    if (response.ok) {
                        currentUser = await response.json();
                        updateAuthUI();
                    } else {
                        localStorage.removeItem('token');
                    }
                } catch (error) {
                    console.error('Ошибка проверки авторизации:', error);
                    localStorage.removeItem('token');
                }
            }

            function updateAuthUI() {
                if (currentUser) {
                    authBtn.textContent = currentUser.username;
                    authBtn.onclick = toggleUserDropdown;

                    // Создаем выпадающее меню
                    userMenu.innerHTML = `
                        <button class="user-btn" id="userBtn">
                            ${currentUser.username}
                            <span>▼</span>
                        </button>
                        <div class="user-dropdown" id="userDropdown">
                            <div class="user-info">
                                <div><strong>${currentUser.full_name}</strong></div>
                                <div style="font-size: 0.875rem; color: var(--gray-600);">${currentUser.email}</div>
                            </div>
                            <button class="dropdown-item" onclick="logout()">Выйти</button>
                        </div>
                    `;

                    document.getElementById('userBtn').addEventListener('click', toggleUserDropdown);
                } else {
                    authBtn.textContent = 'Войти';
                    authBtn.onclick = showAuthModal;
                    userMenu.innerHTML = '<button class="btn btn-outline" id="authBtn">Войти</button>';
                    document.getElementById('authBtn').addEventListener('click', showAuthModal);
                }
            }

            function toggleUserDropdown() {
                const dropdown = document.getElementById('userDropdown');
                dropdown.classList.toggle('active');
            }

            function logout() {
                localStorage.removeItem('token');
                currentUser = null;
                cart = [];
                updateAuthUI();
                updateCartUI();
                showMessage('success', 'Вы вышли из системы');
            }

            async function loadProducts() {
                try {
                    const response = await fetch('/api/products?featured=true');
                    const products = await response.json();

                    productsGrid.innerHTML = products.map(product => `
                        <div class="product-card" data-id="${product.id}">
                            <div class="product-image">
                                ${getProductIcon(product.category)}
                            </div>
                            <div class="product-content">
                                <h3 class="product-title">${product.name}</h3>
                                <p class="product-description">${product.description}</p>
                                <div class="product-footer">
                                    <div class="product-price">${formatPrice(product.price)} ₽</div>
                                    <button class="add-to-cart-btn" 
                                            onclick="addToCart(${product.id})"
                                            ${product.stock === 0 ? 'disabled' : ''}>
                                        ${product.stock > 0 ? 'В корзину' : 'Нет в наличии'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    `).join('');
                } catch (error) {
                    console.error('Ошибка загрузки товаров:', error);
                    productsGrid.innerHTML = '<div class="loading">Ошибка загрузки товаров. Попробуйте обновить страницу.</div>';
                }
            }

            async function loadCategories() {
                try {
                    const response = await fetch('/api/categories');
                    const data = await response.json();
                    const categories = data.categories;

                    categoriesGrid.innerHTML = categories.map(category => `
                        <a href="#" class="category-card" onclick="filterByCategory('${category.id}'); return false;">
                            <div class="category-icon">
                                ${getCategoryIcon(category.id)}
                            </div>
                            <h3 class="category-title">${category.name}</h3>
                            <p class="category-count">${category.count} товаров</p>
                        </a>
                    `).join('');
                } catch (error) {
                    console.error('Ошибка загрузки категорий:', error);
                }
            }

            async function filterByCategory(categoryId) {
                try {
                    const response = await fetch(`/api/products?category=${categoryId}`);
                    const products = await response.json();

                    productsGrid.innerHTML = products.map(product => `
                        <div class="product-card" data-id="${product.id}">
                            <div class="product-image">
                                ${getProductIcon(product.category)}
                            </div>
                            <div class="product-content">
                                <h3 class="product-title">${product.name}</h3>
                                <p class="product-description">${product.description}</p>
                                <div class="product-footer">
                                    <div class="product-price">${formatPrice(product.price)} ₽</div>
                                    <button class="add-to-cart-btn" 
                                            onclick="addToCart(${product.id})"
                                            ${product.stock === 0 ? 'disabled' : ''}>
                                        ${product.stock > 0 ? 'В корзину' : 'Нет в наличии'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    `).join('');
                } catch (error) {
                    console.error('Ошибка фильтрации:', error);
                }
            }

            async function loadCart() {
                const token = localStorage.getItem('token');
                if (!token) {
                    cart = [];
                    updateCartUI();
                    return;
                }

                try {
                    const response = await fetch('/api/cart', {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });

                    if (response.ok) {
                        const data = await response.json();
                        cart = data.items;
                        updateCartUI();
                    } else if (response.status === 401) {
                        localStorage.removeItem('token');
                        currentUser = null;
                        updateAuthUI();
                        cart = [];
                        updateCartUI();
                    }
                } catch (error) {
                    console.error('Ошибка загрузки корзины:', error);
                }
            }

            async function addToCart(productId) {
                if (!currentUser) {
                    showAuthModal();
                    return;
                }

                try {
                    const response = await fetch('/api/cart', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${localStorage.getItem('token')}`
                        },
                        body: JSON.stringify({
                            product_id: productId,
                            quantity: 1
                        })
                    });

                    if (response.ok) {
                        loadCart();
                        showMessage('success', 'Товар добавлен в корзину');
                    } else {
                        const error = await response.json();
                        showMessage('error', error.detail || 'Ошибка добавления в корзину');
                    }
                } catch (error) {
                    console.error('Ошибка:', error);
                    showMessage('error', 'Ошибка сети');
                }
            }

            function updateCartUI() {
                // Обновляем счетчик
                const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
                cartCount.textContent = totalItems;
                cartCount.style.display = totalItems > 0 ? 'flex' : 'none';

                // Обновляем содержимое корзины
                if (cart.length === 0) {
                    cartBody.innerHTML = '<p style="text-align: center; color: var(--gray-600);">Корзина пуста</p>';
                    cartTotal.textContent = '0 ₽';
                    checkoutBtn.disabled = true;
                } else {
                    cartBody.innerHTML = cart.map(item => `
                        <div class="cart-item">
                            <div class="cart-item-image">
                                ${getProductIcon(item.product.category)}
                            </div>
                            <div class="cart-item-content">
                                <div class="cart-item-title">${item.product.name}</div>
                                <div class="cart-item-price">${formatPrice(item.product.price)} ₽ × ${item.quantity}</div>
                                <div class="cart-item-actions">
                                    <button class="quantity-btn" onclick="updateCartQuantity(${item.product_id}, ${item.quantity - 1})">-</button>
                                    <input type="number" class="quantity-input" value="${item.quantity}" 
                                           min="1" onchange="updateCartQuantity(${item.product_id}, this.value)">
                                    <button class="quantity-btn" onclick="updateCartQuantity(${item.product_id}, ${item.quantity + 1})">+</button>
                                    <button class="remove-btn" onclick="removeFromCart(${item.product_id})">Удалить</button>
                                </div>
                            </div>
                        </div>
                    `).join('');

                    const total = cart.reduce((sum, item) => sum + (item.product.price * item.quantity), 0);
                    cartTotal.textContent = formatPrice(total) + ' ₽';
                    checkoutBtn.disabled = false;
                }
            }

            async function updateCartQuantity(productId, quantity) {
                quantity = parseInt(quantity);
                if (quantity < 1) return;

                const token = localStorage.getItem('token');
                if (!token) return;

                try {
                    const response = await fetch('/api/cart', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify({
                            product_id: productId,
                            quantity: quantity
                        })
                    });

                    if (response.ok) {
                        loadCart();
                    }
                } catch (error) {
                    console.error('Ошибка обновления корзины:', error);
                }
            }

            async function removeFromCart(productId) {
                const token = localStorage.getItem('token');
                if (!token) return;

                try {
                    const response = await fetch(`/api/cart/${productId}`, {
                        method: 'DELETE',
                        headers: { 'Authorization': `Bearer ${token}` }
                    });

                    if (response.ok) {
                        loadCart();
                        showMessage('success', 'Товар удален из корзины');
                    }
                } catch (error) {
                    console.error('Ошибка удаления из корзины:', error);
                }
            }

            function showAuthModal() {
                authModal.classList.add('active');
                clearAuthMessages();
            }

            function hideAuthModal() {
                authModal.classList.remove('active');
                loginForm.reset();
                registerForm.reset();
                clearAuthMessages();
            }

            function showCartModal() {
                cartModal.classList.add('active');
            }

            function hideCartModal() {
                cartModal.classList.remove('active');
            }

            function getProductIcon(category) {
                const icons = {
                    'batteries': '🔋',
                    'motors': '⚙️',
                    'electronics': '📱',
                    'brakes': '🛑',
                    'tires': '🛞',
                    'accessories': '🔧'
                };
                return icons[category] || '📦';
            }

            function getCategoryIcon(categoryId) {
                const icons = {
                    'batteries': '🔋',
                    'motors': '⚙️',
                    'electronics': '📱',
                    'brakes': '🛑',
                    'tires': '🛞',
                    'accessories': '🔧'
                };
                return icons[categoryId] || '📦';
            }

            function formatPrice(price) {
                return new Intl.NumberFormat('ru-RU').format(price);
            }

            function showMessage(type, text) {
                const messageDiv = document.createElement('div');
                messageDiv.className = `message message-${type}`;
                messageDiv.textContent = text;
                document.body.appendChild(messageDiv);

                setTimeout(() => {
                    messageDiv.remove();
                }, 5000);
            }

            function clearAuthMessages() {
                authMessages.innerHTML = '';
            }

            // Закрытие выпадающего меню при клике вне его
            document.addEventListener('click', (e) => {
                const dropdown = document.getElementById('userDropdown');
                if (dropdown && !userMenu.contains(e.target)) {
                    dropdown.classList.remove('active');
                }

                const authModal = document.getElementById('authModal');
                if (authModal && authModal.classList.contains('active') && e.target === authModal) {
                    hideAuthModal();
                }
            });

            // Плавная прокрутка для навигации
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    const href = this.getAttribute('href');
                    if (href === '#') return;

                    e.preventDefault();
                    const element = document.querySelector(href);
                    if (element) {
                        element.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            });
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)


# ========== СТРАНИЦА ВСЕХ ТОВАРОВ ==========
@app.get("/products")
async def products_page(request: Request):
    """Страница со всеми товарами"""

    html_content = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
        <meta http-equiv="Pragma" content="no-cache">
        <meta http-equiv="Expires" content="0">

        <!-- Иконки -->
        <link rel="apple-touch-icon" sizes="180x180" href="/static/favicon/apple-touch-icon.png">
        <link rel="icon" type="image/png" sizes="32x32" href="/static/favicon/favicon-32x32.png">
        <link rel="icon" type="image/png" sizes="16x16" href="/static/favicon/favicon-16x16.png">
        <link rel="icon" href="/static/favicon/favicon.ico">
        <link rel="manifest" href="/static/favicon/site.webmanifest">
        <meta name="theme-color" content="#000000">

        <title>Все товары | Scooter Parts</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --white: #ffffff;
                --black: #000000;
                --gray-50: #fafafa;
                --gray-100: #f5f5f5;
                --gray-200: #e5e5e5;
                --gray-300: #d4d4d4;
                --gray-600: #525252;
                --gray-900: #171717;
                --blue: #3b82f6;
                --green: #10b981;
                --red: #ef4444;
                --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
                --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
                --radius: 0.5rem;
            }

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Inter', -apple-system, sans-serif;
                background: var(--white);
                color: var(--gray-900);
                line-height: 1.5;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
            }

            .container {
                max-width: 1280px;
                margin: 0 auto;
                padding: 0 1.5rem;
            }

            /* Header */
            .header {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: var(--white);
                border-bottom: 1px solid var(--gray-200);
                z-index: 100;
                padding: 1rem 0;
            }

            .header-content {
                display: flex;
                align-items: center;
                justify-content: space-between;
            }

            .logo {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                font-size: 1.5rem;
                font-weight: 700;
                color: var(--black);
                text-decoration: none;
            }

            .logo-icon {
                width: 32px;
                height: 32px;
                background-image: url('/static/favicon/favicon-32x32.png');
                background-size: contain;
                background-repeat: no-repeat;
                background-position: center;
            }

            .nav {
                display: flex;
                align-items: center;
                gap: 2rem;
            }

            .nav-link {
                color: var(--gray-600);
                text-decoration: none;
                font-weight: 500;
                transition: color 0.2s;
            }

            .nav-link:hover,
            .nav-link.active {
                color: var(--black);
            }

            .header-actions {
                display: flex;
                align-items: center;
                gap: 1rem;
            }

            .btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 0.5rem 1rem;
                font-size: 0.875rem;
                font-weight: 500;
                border-radius: var(--radius);
                border: none;
                cursor: pointer;
                transition: all 0.2s;
                text-decoration: none;
            }

            .btn-primary {
                background: var(--black);
                color: var(--white);
            }

            .btn-primary:hover {
                background: var(--gray-900);
            }

            .btn-outline {
                background: transparent;
                border: 1px solid var(--gray-300);
                color: var(--gray-900);
            }

            .btn-outline:hover {
                background: var(--gray-100);
            }

            .cart-btn {
                position: relative;
            }

            .cart-count {
                position: absolute;
                top: -0.5rem;
                right: -0.5rem;
                background: var(--red);
                color: var(--white);
                font-size: 0.75rem;
                width: 1.25rem;
                height: 1.25rem;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            /* Page Header */
            .page-header {
                padding-top: 8rem;
                padding-bottom: 2rem;
                background: linear-gradient(to bottom, var(--white), var(--gray-50));
            }

            .page-title {
                font-size: 2.5rem;
                font-weight: 700;
                line-height: 1.1;
                margin-bottom: 1rem;
            }

            .page-description {
                font-size: 1.125rem;
                color: var(--gray-600);
                max-width: 768px;
            }

            /* Filters */
            .filters {
                padding: 1rem 0;
                background: var(--white);
                border-bottom: 1px solid var(--gray-200);
            }

            .filters-content {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 1rem;
                flex-wrap: wrap;
            }

            .filter-group {
                display: flex;
                align-items: center;
                gap: 1rem;
            }

            .filter-select {
                padding: 0.5rem 1rem;
                border: 1px solid var(--gray-300);
                border-radius: var(--radius);
                background: var(--white);
                font-family: inherit;
                font-size: 0.875rem;
                color: var(--gray-900);
                cursor: pointer;
            }

            .filter-select:focus {
                outline: none;
                border-color: var(--black);
            }

            .filter-btn {
                padding: 0.5rem 1rem;
                background: var(--gray-100);
                border: 1px solid var(--gray-300);
                border-radius: var(--radius);
                font-family: inherit;
                font-size: 0.875rem;
                color: var(--gray-900);
                cursor: pointer;
                transition: all 0.2s;
            }

            .filter-btn:hover,
            .filter-btn.active {
                background: var(--black);
                color: var(--white);
                border-color: var(--black);
            }

            /* Products */
            .products-section {
                padding: 3rem 0;
                background: var(--gray-50);
                flex: 1;
            }

            .products-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
                gap: 2rem;
            }

            .product-card {
                border: 1px solid var(--gray-200);
                border-radius: var(--radius);
                overflow: hidden;
                background: var(--white);
                transition: all 0.3s;
            }

            .product-card:hover {
                transform: translateY(-2px);
                box-shadow: var(--shadow-lg);
            }

            .product-image {
                width: 100%;
                height: 200px;
                background: var(--gray-100);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 3rem;
            }

            .product-content {
                padding: 1.5rem;
            }

            .product-category {
                display: inline-block;
                padding: 0.25rem 0.5rem;
                background: var(--gray-100);
                border-radius: 4px;
                font-size: 0.75rem;
                color: var(--gray-600);
                margin-bottom: 0.5rem;
            }

            .product-title {
                font-size: 1.125rem;
                font-weight: 600;
                margin-bottom: 0.5rem;
            }

            .product-description {
                color: var(--gray-600);
                font-size: 0.875rem;
                margin-bottom: 1rem;
                line-height: 1.4;
            }

            .product-footer {
                display: flex;
                align-items: center;
                justify-content: space-between;
            }

            .product-price {
                font-size: 1.25rem;
                font-weight: 700;
            }

            .product-stock {
                font-size: 0.875rem;
                color: var(--gray-600);
                margin-top: 0.25rem;
            }

            .product-stock.in-stock {
                color: var(--green);
            }

            .product-stock.out-of-stock {
                color: var(--red);
            }

            .add-to-cart-btn {
                padding: 0.5rem 1rem;
                background: var(--black);
                color: var(--white);
                border: none;
                border-radius: var(--radius);
                cursor: pointer;
                font-weight: 500;
                transition: background 0.2s;
                white-space: nowrap;
            }

            .add-to-cart-btn:hover {
                background: var(--gray-900);
            }

            .add-to-cart-btn:disabled {
                background: var(--gray-300);
                cursor: not-allowed;
            }

            /* Loading */
            .loading {
                text-align: center;
                padding: 4rem;
                color: var(--gray-600);
                grid-column: 1 / -1;
            }

            .empty-state {
                text-align: center;
                padding: 4rem;
                color: var(--gray-600);
                grid-column: 1 / -1;
            }

            /* Footer */
            .footer {
                background: var(--gray-900);
                color: var(--white);
                padding: 4rem 0 2rem;
                margin-top: auto;
            }

            .footer-content {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 3rem;
                margin-bottom: 3rem;
            }

            .footer-logo {
                font-size: 1.5rem;
                font-weight: 700;
                margin-bottom: 1rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .footer-description {
                color: var(--gray-400);
                font-size: 0.95rem;
                line-height: 1.6;
                margin-bottom: 1.5rem;
            }

            .footer-heading {
                font-size: 1rem;
                font-weight: 600;
                margin-bottom: 1.25rem;
                color: var(--white);
            }

            .footer-links {
                list-style: none;
            }

            .footer-link {
                color: var(--gray-400);
                text-decoration: none;
                font-size: 0.95rem;
                margin-bottom: 0.75rem;
                display: block;
                transition: color 0.2s;
            }

            .footer-link:hover {
                color: var(--white);
            }

            .contact-info {
                color: var(--gray-400);
                font-size: 0.95rem;
                line-height: 1.6;
            }

            .contact-item {
                margin-bottom: 0.75rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .footer-bottom {
                padding-top: 2rem;
                border-top: 1px solid var(--gray-800);
                text-align: center;
                color: var(--gray-400);
                font-size: 0.875rem;
            }

            .social-links {
                display: flex;
                gap: 1rem;
                margin-top: 1rem;
            }

            .social-link {
                color: var(--gray-400);
                text-decoration: none;
                transition: color 0.2s;
            }

            .social-link:hover {
                color: var(--white);
            }

            /* Auth Modal */
            .modal {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.5);
                z-index: 1000;
                align-items: center;
                justify-content: center;
            }

            .modal.active {
                display: flex;
            }

            .modal-content {
                background: var(--white);
                border-radius: var(--radius);
                padding: 2rem;
                width: 100%;
                max-width: 400px;
                max-height: 90vh;
                overflow-y: auto;
            }

            .modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1.5rem;
            }

            .modal-close {
                background: none;
                border: none;
                font-size: 1.5rem;
                cursor: pointer;
                color: var(--gray-600);
            }

            .form-group {
                margin-bottom: 1rem;
            }

            .form-label {
                display: block;
                margin-bottom: 0.5rem;
                font-weight: 500;
            }

            .form-input {
                width: 100%;
                padding: 0.75rem;
                border: 1px solid var(--gray-300);
                border-radius: var(--radius);
                font-family: inherit;
                font-size: 1rem;
            }

            .form-input:focus {
                outline: none;
                border-color: var(--black);
            }

            .auth-tabs {
                display: flex;
                gap: 1rem;
                margin-bottom: 1.5rem;
                border-bottom: 1px solid var(--gray-200);
            }

            .auth-tab {
                padding: 0.5rem 0;
                background: none;
                border: none;
                color: var(--gray-600);
                cursor: pointer;
                font-weight: 500;
                position: relative;
            }

            .auth-tab.active {
                color: var(--black);
            }

            .auth-tab.active::after {
                content: '';
                position: absolute;
                bottom: -1px;
                left: 0;
                right: 0;
                height: 2px;
                background: var(--black);
            }

            /* Cart Modal */
            .cart-modal {
                position: fixed;
                top: 0;
                right: 0;
                bottom: 0;
                width: 400px;
                background: var(--white);
                border-left: 1px solid var(--gray-200);
                transform: translateX(100%);
                transition: transform 0.3s;
                z-index: 1000;
                display: flex;
                flex-direction: column;
            }

            .cart-modal.active {
                transform: translateX(0);
            }

            .cart-header {
                padding: 1.5rem;
                border-bottom: 1px solid var(--gray-200);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            .cart-body {
                flex: 1;
                padding: 1.5rem;
                overflow-y: auto;
            }

            .cart-footer {
                padding: 1.5rem;
                border-top: 1px solid var(--gray-200);
            }

            .cart-total {
                display: flex;
                justify-content: space-between;
                font-size: 1.125rem;
                font-weight: 600;
                margin-bottom: 1rem;
            }

            .cart-item {
                display: flex;
                gap: 1rem;
                padding: 1rem 0;
                border-bottom: 1px solid var(--gray-200);
            }

            .cart-item-image {
                width: 60px;
                height: 60px;
                background: var(--gray-100);
                border-radius: var(--radius);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.5rem;
            }

            .cart-item-content {
                flex: 1;
            }

            .cart-item-title {
                font-weight: 500;
                margin-bottom: 0.25rem;
            }

            .cart-item-price {
                color: var(--gray-600);
                font-size: 0.875rem;
            }

            .cart-item-actions {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                margin-top: 0.5rem;
            }

            .quantity-btn {
                width: 24px;
                height: 24px;
                border: 1px solid var(--gray-300);
                background: var(--white);
                border-radius: 4px;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .quantity-input {
                width: 40px;
                text-align: center;
                border: 1px solid var(--gray-300);
                border-radius: 4px;
                padding: 0.25rem;
            }

            .remove-btn {
                color: var(--red);
                background: none;
                border: none;
                cursor: pointer;
                font-size: 0.875rem;
            }

            /* User Menu */
            .user-menu {
                position: relative;
            }

            .user-btn {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.5rem 1rem;
                background: none;
                border: 1px solid var(--gray-300);
                border-radius: var(--radius);
                cursor: pointer;
                font-family: inherit;
                font-size: 0.875rem;
            }

            .user-dropdown {
                position: absolute;
                top: 100%;
                right: 0;
                background: var(--white);
                border: 1px solid var(--gray-200);
                border-radius: var(--radius);
                padding: 0.5rem;
                min-width: 200px;
                display: none;
                box-shadow: var(--shadow-lg);
                z-index: 100;
            }

            .user-dropdown.active {
                display: block;
            }

            .user-info {
                padding: 0.5rem;
                border-bottom: 1px solid var(--gray-200);
                margin-bottom: 0.5rem;
            }

            .dropdown-item {
                display: block;
                width: 100%;
                padding: 0.5rem;
                text-align: left;
                background: none;
                border: none;
                cursor: pointer;
                color: var(--gray-900);
                border-radius: 4px;
                font-family: inherit;
                font-size: 0.875rem;
            }

            .dropdown-item:hover {
                background: var(--gray-100);
            }

            /* Messages */
            .message {
                padding: 1rem;
                border-radius: var(--radius);
                margin-bottom: 1rem;
                font-size: 0.875rem;
            }

            .message-success {
                background: #d1fae5;
                color: #065f46;
                border: 1px solid #a7f3d0;
            }

            .message-error {
                background: #fee2e2;
                color: #991b1b;
                border: 1px solid #fecaca;
            }

            /* Responsive */
            @media (max-width: 768px) {
                .page-title {
                    font-size: 2rem;
                }

                .nav {
                    display: none;
                }

                .filters-content {
                    flex-direction: column;
                    align-items: stretch;
                }

                .filter-group {
                    flex-wrap: wrap;
                }

                .products-grid {
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    gap: 1.5rem;
                }

                .footer-content {
                    grid-template-columns: 1fr;
                    gap: 2rem;
                }

                .cart-modal {
                    width: 100%;
                }
            }

            @media (max-width: 480px) {
                .products-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <!-- Header -->
        <header class="header">
            <div class="container">
                <div class="header-content">
                    <a href="/" class="logo">
                        <div class="logo-icon"></div>
                        <span>ScooterParts</span>
                    </a>

                    <nav class="nav">
                        <a href="/" class="nav-link">Главная</a>
                        <a href="/products" class="nav-link active">Все товары</a>
                        <a href="/#categories" class="nav-link">Категории</a>
                        <a href="/#features" class="nav-link">Преимущества</a>
                        <a href="/#about" class="nav-link">О нас</a>
                    </nav>

                    <div class="header-actions">
                        <button class="btn btn-outline cart-btn" id="cartBtn">
                            🛒 Корзина
                            <span class="cart-count" id="cartCount">0</span>
                        </button>

                        <div class="user-menu" id="userMenu">
                            <button class="btn btn-outline" id="authBtn">Войти</button>
                        </div>
                    </div>
                </div>
            </div>
        </header>

        <!-- Page Header -->
        <section class="page-header">
            <div class="container">
                <h1 class="page-title">Все товары</h1>
                <p class="page-description">
                    Полный каталог запчастей для электросамокатов. Фильтруйте по категориям, 
                    ищите нужные компоненты и добавляйте в корзину.
                </p>
            </div>
        </section>

        <!-- Filters -->
        <section class="filters">
            <div class="container">
                <div class="filters-content">
                    <div class="filter-group">
                        <select class="filter-select" id="categoryFilter">
                            <option value="">Все категории</option>
                            <option value="batteries">Аккумуляторы</option>
                            <option value="motors">Моторы</option>
                            <option value="electronics">Электроника</option>
                            <option value="brakes">Тормоза</option>
                            <option value="tires">Колёса</option>
                            <option value="accessories">Аксессуары</option>
                        </select>

                        <select class="filter-select" id="sortFilter">
                            <option value="default">По умолчанию</option>
                            <option value="price_asc">Цена: по возрастанию</option>
                            <option value="price_desc">Цена: по убыванию</option>
                            <option value="name_asc">Название: А-Я</option>
                            <option value="name_desc">Название: Я-А</option>
                        </select>
                    </div>

                    <div class="filter-group">
                        <button class="filter-btn active" data-filter="all">Все товары</button>
                        <button class="filter-btn" data-filter="featured">Популярные</button>
                        <button class="filter-btn" data-filter="in_stock">В наличии</button>
                    </div>
                </div>
            </div>
        </section>

        <!-- Products -->
        <section class="products-section">
            <div class="container">
                <div class="products-grid" id="productsGrid">
                    <div class="loading">Загрузка товаров...</div>
                </div>
            </div>
        </section>

        <!-- Footer -->
        <footer class="footer">
            <div class="container">
                <div class="footer-content">
                    <div>
                        <div class="footer-logo">
                            <span>🛴</span>
                            <span>ScooterParts</span>
                        </div>
                        <p class="footer-description">
                            Ведущий поставщик запчастей для электросамокатов в России. 
                            Обеспечиваем качество и надёжность с 2020 года.
                        </p>
                        <div class="social-links">
                            <a href="#" class="social-link">Instagram</a>
                            <a href="#" class="social-link">VK</a>
                            <a href="#" class="social-link">Telegram</a>
                        </div>
                    </div>

                    <div>
                        <h3 class="footer-heading">Магазин</h3>
                        <ul class="footer-links">
                            <li><a href="/" class="footer-link">Главная</a></li>
                            <li><a href="/products" class="footer-link">Все товары</a></li>
                            <li><a href="/#categories" class="footer-link">Категории</a></li>
                            <li><a href="/#features" class="footer-link">Преимущества</a></li>
                        </ul>
                    </div>

                    <div>
                        <h3 class="footer-heading">Помощь</h3>
                        <ul class="footer-links">
                            <li><a href="#" class="footer-link">Гарантия</a></li>
                            <li><a href="#" class="footer-link">Возврат</a></li>
                            <li><a href="#" class="footer-link">Контакты</a></li>
                            <li><a href="#" class="footer-link">FAQ</a></li>
                        </ul>
                    </div>

                    <div>
                        <h3 class="footer-heading">Контакты</h3>
                        <div class="contact-info">
                            <div class="contact-item">📍 Москва, ул. Примерная, 123</div>
                            <div class="contact-item">📞 <a href="tel:+78001234567" class="footer-link">8 (800) 123-45-67</a></div>
                            <div class="contact-item">✉️ <a href="mailto:info@scooterparts.ru" class="footer-link">info@scooterparts.ru</a></div>
                            <div class="contact-item">🕐 Ежедневно с 9:00 до 21:00</div>
                        </div>
                    </div>
                </div>

                <div class="footer-bottom">
                    <p>© 2024 ScooterParts. Все права защищены.</p>
                </div>
            </div>
        </footer>

        <!-- Auth Modal -->
        <div class="modal" id="authModal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>Вход / Регистрация</h2>
                    <button class="modal-close" id="closeAuthModal">&times;</button>
                </div>

                <div class="auth-tabs">
                    <button class="auth-tab active" data-tab="login">Вход</button>
                    <button class="auth-tab" data-tab="register">Регистрация</button>
                </div>

                <div id="authMessages"></div>

                <form id="loginForm" class="auth-form">
                    <div class="form-group">
                        <label class="form-label">Имя пользователя</label>
                        <input type="text" class="form-input" name="username" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Пароль</label>
                        <input type="password" class="form-input" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width: 100%;">Войти</button>
                </form>

                <form id="registerForm" class="auth-form" style="display: none;">
                    <div class="form-group">
                        <label class="form-label">Имя пользователя*</label>
                        <input type="text" class="form-input" name="username" required minlength="3" maxlength="50">
                        <small style="color: var(--gray-600); font-size: 0.75rem;">От 3 до 50 символов</small>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Email*</label>
                        <input type="email" class="form-input" name="email" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Полное имя*</label>
                        <input type="text" class="form-input" name="full_name" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Пароль*</label>
                        <input type="password" class="form-input" name="password" required minlength="6">
                        <small style="color: var(--gray-600); font-size: 0.75rem;">Минимум 6 символов</small>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Телефон (опционально)</label>
                        <input type="tel" class="form-input" name="phone">
                    </div>
                    <button type="submit" class="btn btn-primary" style="width: 100%;">Зарегистрироваться</button>
                </form>
            </div>
        </div>

        <!-- Cart Modal -->
        <div class="cart-modal" id="cartModal">
            <div class="cart-header">
                <h2>Корзина</h2>
                <button class="modal-close" id="closeCartModal">&times;</button>
            </div>
            <div class="cart-body" id="cartBody">
                <!-- Товары в корзине -->
            </div>
            <div class="cart-footer">
                <div class="cart-total">
                    <span>Итого:</span>
                    <span id="cartTotal">0 ₽</span>
                </div>
                <button class="btn btn-primary" style="width: 100%;" id="checkoutBtn">Оформить заказ</button>
            </div>
        </div>

        <script>
            // Глобальные переменные
            let currentUser = null;
            let cart = [];
            let allProducts = [];
            let currentFilter = 'all';
            let currentCategory = '';
            let currentSort = 'default';

            // DOM элементы
            const authBtn = document.getElementById('authBtn');
            const authModal = document.getElementById('authModal');
            const closeAuthModal = document.getElementById('closeAuthModal');
            const cartBtn = document.getElementById('cartBtn');
            const cartModal = document.getElementById('cartModal');
            const closeCartModal = document.getElementById('closeCartModal');
            const cartCount = document.getElementById('cartCount');
            const cartBody = document.getElementById('cartBody');
            const cartTotal = document.getElementById('cartTotal');
            const productsGrid = document.getElementById('productsGrid');
            const categoryFilter = document.getElementById('categoryFilter');
            const sortFilter = document.getElementById('sortFilter');
            const filterBtns = document.querySelectorAll('.filter-btn');
            const authTabs = document.querySelectorAll('.auth-tab');
            const loginForm = document.getElementById('loginForm');
            const registerForm = document.getElementById('registerForm');
            const userMenu = document.getElementById('userMenu');
            const authMessages = document.getElementById('authMessages');
            const checkoutBtn = document.getElementById('checkoutBtn');

            // Инициализация
            document.addEventListener('DOMContentLoaded', () => {
                // Проверяем токен при загрузке
                const token = localStorage.getItem('token');
                if (token) {
                    checkAuth(token);
                }

                loadAllProducts();
                loadCart();

                // События
                authBtn.addEventListener('click', showAuthModal);
                closeAuthModal.addEventListener('click', hideAuthModal);
                cartBtn.addEventListener('click', showCartModal);
                closeCartModal.addEventListener('click', hideCartModal);

                // Клик вне модальных окон
                authModal.addEventListener('click', (e) => {
                    if (e.target === authModal) hideAuthModal();
                });

                // Табы авторизации
                authTabs.forEach(tab => {
                    tab.addEventListener('click', () => {
                        authTabs.forEach(t => t.classList.remove('active'));
                        tab.classList.add('active');
                        clearAuthMessages();

                        if (tab.dataset.tab === 'login') {
                            loginForm.style.display = 'block';
                            registerForm.style.display = 'none';
                        } else {
                            loginForm.style.display = 'none';
                            registerForm.style.display = 'block';
                        }
                    });
                });

                // Форма входа
                loginForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    clearAuthMessages();

                    const formData = new FormData(loginForm);
                    const data = Object.fromEntries(formData);

                    try {
                        const response = await fetch('/api/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(data)
                        });

                        if (response.ok) {
                            const result = await response.json();
                            localStorage.setItem('token', result.access_token);
                            currentUser = result.user;
                            updateAuthUI();
                            hideAuthModal();
                            loadCart();
                            showMessage('success', 'Вход выполнен успешно!');
                        } else {
                            const error = await response.json();
                            showMessage('error', error.detail || 'Ошибка входа');
                        }
                    } catch (error) {
                        console.error('Ошибка:', error);
                        showMessage('error', 'Ошибка сети. Проверьте подключение к интернету.');
                    }
                });

                // Форма регистрации
                registerForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    clearAuthMessages();

                    const formData = new FormData(registerForm);
                    const data = Object.fromEntries(formData);

                    // Валидация
                    if (data.username.length < 3 || data.username.length > 50) {
                        showMessage('error', 'Имя пользователя должно содержать от 3 до 50 символов');
                        return;
                    }

                    if (data.password.length < 6) {
                        showMessage('error', 'Пароль должен содержать минимум 6 символов');
                        return;
                    }

                    try {
                        const response = await fetch('/api/register', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(data)
                        });

                        const result = await response.json();

                        if (response.ok) {
                            localStorage.setItem('token', result.access_token);
                            currentUser = result.user;
                            updateAuthUI();
                            hideAuthModal();
                            loadCart();
                            showMessage('success', 'Регистрация успешна! Добро пожаловать!');
                        } else {
                            showMessage('error', result.detail || 'Ошибка регистрации');
                        }
                    } catch (error) {
                        console.error('Ошибка регистрации:', error);
                        showMessage('error', 'Ошибка сети. Проверьте подключение к интернету.');
                    }
                });

                // События фильтров
                categoryFilter.addEventListener('change', () => {
                    currentCategory = categoryFilter.value;
                    applyFilters();
                });

                sortFilter.addEventListener('change', () => {
                    currentSort = sortFilter.value;
                    applyFilters();
                });

                filterBtns.forEach(btn => {
                    btn.addEventListener('click', () => {
                        filterBtns.forEach(b => b.classList.remove('active'));
                        btn.classList.add('active');
                        currentFilter = btn.dataset.filter;
                        applyFilters();
                    });
                });

                // Оформление заказа
                checkoutBtn.addEventListener('click', () => {
                    if (!currentUser) {
                        showAuthModal();
                        return;
                    }

                    if (cart.length === 0) {
                        alert('Корзина пуста');
                        return;
                    }

                    alert('Функция оформления заказа будет доступна в следующем обновлении!');
                });
            });

            // Функции
            async function checkAuth(token) {
                try {
                    const response = await fetch('/api/profile', {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });

                    if (response.ok) {
                        currentUser = await response.json();
                        updateAuthUI();
                    } else {
                        localStorage.removeItem('token');
                    }
                } catch (error) {
                    console.error('Ошибка проверки авторизации:', error);
                    localStorage.removeItem('token');
                }
            }

            function updateAuthUI() {
                if (currentUser) {
                    authBtn.textContent = currentUser.username;
                    authBtn.onclick = toggleUserDropdown;

                    // Создаем выпадающее меню
                    userMenu.innerHTML = `
                        <button class="user-btn" id="userBtn">
                            ${currentUser.username}
                            <span>▼</span>
                        </button>
                        <div class="user-dropdown" id="userDropdown">
                            <div class="user-info">
                                <div><strong>${currentUser.full_name}</strong></div>
                                <div style="font-size: 0.875rem; color: var(--gray-600);">${currentUser.email}</div>
                            </div>
                            <button class="dropdown-item" onclick="logout()">Выйти</button>
                        </div>
                    `;

                    document.getElementById('userBtn').addEventListener('click', toggleUserDropdown);
                } else {
                    authBtn.textContent = 'Войти';
                    authBtn.onclick = showAuthModal;
                    userMenu.innerHTML = '<button class="btn btn-outline" id="authBtn">Войти</button>';
                    document.getElementById('authBtn').addEventListener('click', showAuthModal);
                }
            }

            function toggleUserDropdown() {
                const dropdown = document.getElementById('userDropdown');
                if (dropdown) {
                    dropdown.classList.toggle('active');
                }
            }

            function logout() {
                localStorage.removeItem('token');
                currentUser = null;
                cart = [];
                updateAuthUI();
                updateCartUI();
                showMessage('success', 'Вы вышли из системы');
            }

            async function loadAllProducts() {
                try {
                    const response = await fetch('/api/products');
                    allProducts = await response.json();
                    applyFilters();
                } catch (error) {
                    console.error('Ошибка загрузки товаров:', error);
                    productsGrid.innerHTML = '<div class="loading">Ошибка загрузки товаров. Попробуйте обновить страницу.</div>';
                }
            }

            function applyFilters() {
                let filteredProducts = [...allProducts];

                // Фильтрация по категории
                if (currentCategory) {
                    filteredProducts = filteredProducts.filter(p => p.category === currentCategory);
                }

                // Фильтрация по статусу
                if (currentFilter === 'featured') {
                    filteredProducts = filteredProducts.filter(p => p.featured);
                } else if (currentFilter === 'in_stock') {
                    filteredProducts = filteredProducts.filter(p => p.stock > 0);
                }

                // Сортировка
                filteredProducts.sort((a, b) => {
                    switch (currentSort) {
                        case 'price_asc':
                            return a.price - b.price;
                        case 'price_desc':
                            return b.price - a.price;
                        case 'name_asc':
                            return a.name.localeCompare(b.name);
                        case 'name_desc':
                            return b.name.localeCompare(a.name);
                        default:
                            return a.id - b.id;
                    }
                });

                displayProducts(filteredProducts);
            }

            function displayProducts(products) {
                if (products.length === 0) {
                    productsGrid.innerHTML = '<div class="empty-state">Товары не найдены</div>';
                    return;
                }

                productsGrid.innerHTML = products.map(product => `
                    <div class="product-card" data-id="${product.id}">
                        <div class="product-image">
                            ${getProductIcon(product.category)}
                        </div>
                        <div class="product-content">
                            <span class="product-category">${getCategoryName(product.category)}</span>
                            <h3 class="product-title">${product.name}</h3>
                            <p class="product-description">${product.description}</p>
                            <div class="product-stock ${product.stock > 0 ? 'in-stock' : 'out-of-stock'}">
                                ${product.stock > 0 ? `В наличии: ${product.stock} шт.` : 'Нет в наличии'}
                            </div>
                            <div class="product-footer">
                                <div>
                                    <div class="product-price">${formatPrice(product.price)} ₽</div>
                                </div>
                                <button class="add-to-cart-btn" 
                                        onclick="addToCart(${product.id})"
                                        ${product.stock === 0 ? 'disabled' : ''}>
                                    ${product.stock > 0 ? 'В корзину' : 'Нет в наличии'}
                                </button>
                            </div>
                        </div>
                    </div>
                `).join('');
            }

            async function loadCart() {
                const token = localStorage.getItem('token');
                if (!token) {
                    cart = [];
                    updateCartUI();
                    return;
                }

                try {
                    const response = await fetch('/api/cart', {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });

                    if (response.ok) {
                        const data = await response.json();
                        cart = data.items;
                        updateCartUI();
                    } else if (response.status === 401) {
                        localStorage.removeItem('token');
                        currentUser = null;
                        updateAuthUI();
                        cart = [];
                        updateCartUI();
                    }
                } catch (error) {
                    console.error('Ошибка загрузки корзины:', error);
                }
            }

            async function addToCart(productId) {
                if (!currentUser) {
                    showAuthModal();
                    return;
                }

                try {
                    const response = await fetch('/api/cart', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${localStorage.getItem('token')}`
                        },
                        body: JSON.stringify({
                            product_id: productId,
                            quantity: 1
                        })
                    });

                    if (response.ok) {
                        loadCart();
                        showMessage('success', 'Товар добавлен в корзину');
                    } else {
                        const error = await response.json();
                        showMessage('error', error.detail || 'Ошибка добавления в корзину');
                    }
                } catch (error) {
                    console.error('Ошибка:', error);
                    showMessage('error', 'Ошибка сети');
                }
            }

            function updateCartUI() {
                // Обновляем счетчик
                const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
                cartCount.textContent = totalItems;
                cartCount.style.display = totalItems > 0 ? 'flex' : 'none';

                // Обновляем содержимое корзины
                if (cart.length === 0) {
                    cartBody.innerHTML = '<p style="text-align: center; color: var(--gray-600);">Корзина пуста</p>';
                    cartTotal.textContent = '0 ₽';
                    checkoutBtn.disabled = true;
                } else {
                    cartBody.innerHTML = cart.map(item => `
                        <div class="cart-item">
                            <div class="cart-item-image">
                                ${getProductIcon(item.product.category)}
                            </div>
                            <div class="cart-item-content">
                                <div class="cart-item-title">${item.product.name}</div>
                                <div class="cart-item-price">${formatPrice(item.product.price)} ₽ × ${item.quantity}</div>
                                <div class="cart-item-actions">
                                    <button class="quantity-btn" onclick="updateCartQuantity(${item.product_id}, ${item.quantity - 1})">-</button>
                                    <input type="number" class="quantity-input" value="${item.quantity}" 
                                           min="1" onchange="updateCartQuantity(${item.product_id}, this.value)">
                                    <button class="quantity-btn" onclick="updateCartQuantity(${item.product_id}, ${item.quantity + 1})">+</button>
                                    <button class="remove-btn" onclick="removeFromCart(${item.product_id})">Удалить</button>
                                </div>
                            </div>
                        </div>
                    `).join('');

                    const total = cart.reduce((sum, item) => sum + (item.product.price * item.quantity), 0);
                    cartTotal.textContent = formatPrice(total) + ' ₽';
                    checkoutBtn.disabled = false;
                }
            }

            async function updateCartQuantity(productId, quantity) {
                quantity = parseInt(quantity);
                if (quantity < 1) return;

                const token = localStorage.getItem('token');
                if (!token) return;

                try {
                    const response = await fetch('/api/cart', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify({
                            product_id: productId,
                            quantity: quantity
                        })
                    });

                    if (response.ok) {
                        loadCart();
                    }
                } catch (error) {
                    console.error('Ошибка обновления корзины:', error);
                }
            }

            async function removeFromCart(productId) {
                const token = localStorage.getItem('token');
                if (!token) return;

                try {
                    const response = await fetch(`/api/cart/${productId}`, {
                        method: 'DELETE',
                        headers: { 'Authorization': `Bearer ${token}` }
                    });

                    if (response.ok) {
                        loadCart();
                        showMessage('success', 'Товар удален из корзины');
                    }
                } catch (error) {
                    console.error('Ошибка удаления из корзины:', error);
                }
            }

            function showAuthModal() {
                authModal.classList.add('active');
                clearAuthMessages();
            }

            function hideAuthModal() {
                authModal.classList.remove('active');
                loginForm.reset();
                registerForm.reset();
                clearAuthMessages();
            }

            function showCartModal() {
                cartModal.classList.add('active');
            }

            function hideCartModal() {
                cartModal.classList.remove('active');
            }

            function getCategoryName(categoryId) {
                const names = {
                    'batteries': 'Аккумулятор',
                    'motors': 'Мотор',
                    'electronics': 'Электроника',
                    'brakes': 'Тормоза',
                    'tires': 'Колёса',
                    'accessories': 'Аксессуар'
                };
                return names[categoryId] || categoryId;
            }

            function getProductIcon(category) {
                const icons = {
                    'batteries': '🔋',
                    'motors': '⚙️',
                    'electronics': '📱',
                    'brakes': '🛑',
                    'tires': '🛞',
                    'accessories': '🔧'
                };
                return icons[category] || '📦';
            }

            function formatPrice(price) {
                return new Intl.NumberFormat('ru-RU').format(price);
            }

            function showMessage(type, text) {
                const messageDiv = document.createElement('div');
                messageDiv.className = `message message-${type}`;
                messageDiv.textContent = text;

                // Добавляем в начало body
                document.body.insertBefore(messageDiv, document.body.firstChild);

                // Позиционируем под header
                messageDiv.style.position = 'fixed';
                messageDiv.style.top = '80px';
                messageDiv.style.left = '50%';
                messageDiv.style.transform = 'translateX(-50%)';
                messageDiv.style.zIndex = '1000';

                setTimeout(() => {
                    messageDiv.remove();
                }, 5000);
            }

            function clearAuthMessages() {
                authMessages.innerHTML = '';
            }

            // Закрытие выпадающего меню при клике вне его
            document.addEventListener('click', (e) => {
                const dropdown = document.getElementById('userDropdown');
                if (dropdown && !userMenu.contains(e.target)) {
                    dropdown.classList.remove('active');
                }

                const authModal = document.getElementById('authModal');
                if (authModal && authModal.classList.contains('active') && e.target === authModal) {
                    hideAuthModal();
                }

                const cartModal = document.getElementById('cartModal');
                if (cartModal && cartModal.classList.contains('active') && e.target === cartModal) {
                    hideCartModal();
                }
            });

            // Плавная прокрутка для навигации
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    const href = this.getAttribute('href');
                    if (href === '#') return;

                    e.preventDefault();
                    const element = document.querySelector(href);
                    if (element) {
                        element.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            });
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)


# ========== АДМИНСКАЯ ПАНЕЛЬ ==========
@app.get("/admin")
async def admin_panel(request: Request):
    """Админская панель"""

    html_content = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
        <meta http-equiv="Pragma" content="no-cache">
        <meta http-equiv="Expires" content="0">

        <!-- Иконки -->
        <link rel="apple-touch-icon" sizes="180x180" href="/static/favicon/apple-touch-icon.png">
        <link rel="icon" type="image/png" sizes="32x32" href="/static/favicon/favicon-32x32.png">
        <link rel="icon" type="image/png" sizes="16x16" href="/static/favicon/favicon-16x16.png">
        <link rel="icon" href="/static/favicon/favicon.ico">
        <link rel="manifest" href="/static/favicon/site.webmanifest">

        <title>Админка | Scooter Parts</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --white: #ffffff;
                --black: #000000;
                --gray-50: #fafafa;
                --gray-100: #f5f5f5;
                --gray-200: #e5e5e5;
                --gray-300: #d4d4d4;
                --gray-600: #525252;
                --gray-900: #171717;
                --blue: #3b82f6;
                --green: #10b981;
                --red: #ef4444;
                --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
                --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
                --radius: 0.5rem;
            }

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Inter', -apple-system, sans-serif;
                background: var(--gray-50);
                color: var(--gray-900);
                line-height: 1.5;
                min-height: 100vh;
            }

            .container {
                max-width: 1280px;
                margin: 0 auto;
                padding: 0 1.5rem;
            }

            /* Admin Login */
            .admin-login {
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 2rem;
            }

            .login-card {
                background: var(--white);
                border-radius: var(--radius);
                box-shadow: var(--shadow-lg);
                padding: 3rem;
                width: 100%;
                max-width: 400px;
            }

            .login-header {
                text-align: center;
                margin-bottom: 2rem;
            }

            .login-title {
                font-size: 1.875rem;
                font-weight: 700;
                margin-bottom: 0.5rem;
            }

            .login-subtitle {
                color: var(--gray-600);
                font-size: 0.95rem;
            }

            /* Admin Panel */
            .admin-panel {
                display: none;
                min-height: 100vh;
            }

            .admin-header {
                background: var(--white);
                border-bottom: 1px solid var(--gray-200);
                padding: 1rem 0;
                position: sticky;
                top: 0;
                z-index: 100;
            }

            .admin-header-content {
                display: flex;
                align-items: center;
                justify-content: space-between;
            }

            .admin-logo {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                font-size: 1.25rem;
                font-weight: 700;
                color: var(--black);
            }

            .admin-nav {
                display: flex;
                gap: 1rem;
            }

            .admin-nav-btn {
                padding: 0.5rem 1rem;
                background: none;
                border: 1px solid var(--gray-300);
                border-radius: var(--radius);
                color: var(--gray-600);
                cursor: pointer;
                font-family: inherit;
                font-size: 0.875rem;
                transition: all 0.2s;
            }

            .admin-nav-btn:hover,
            .admin-nav-btn.active {
                background: var(--black);
                color: var(--white);
                border-color: var(--black);
            }

            .admin-logout-btn {
                padding: 0.5rem 1rem;
                background: var(--red);
                color: var(--white);
                border: none;
                border-radius: var(--radius);
                cursor: pointer;
                font-family: inherit;
                font-size: 0.875rem;
                transition: background 0.2s;
            }

            .admin-logout-btn:hover {
                background: #dc2626;
            }

            /* Admin Content */
            .admin-content {
                padding: 2rem 0;
            }

            .admin-section {
                background: var(--white);
                border-radius: var(--radius);
                box-shadow: var(--shadow);
                padding: 2rem;
                margin-bottom: 2rem;
            }

            .section-title {
                font-size: 1.5rem;
                font-weight: 600;
                margin-bottom: 1.5rem;
                padding-bottom: 1rem;
                border-bottom: 1px solid var(--gray-200);
            }

            /* Stats Grid */
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }

            .stat-card {
                background: var(--gray-50);
                border-radius: var(--radius);
                padding: 1.5rem;
                text-align: center;
            }

            .stat-value {
                font-size: 2rem;
                font-weight: 700;
                margin-bottom: 0.5rem;
            }

            .stat-label {
                color: var(--gray-600);
                font-size: 0.875rem;
            }

            /* Forms */
            .form-group {
                margin-bottom: 1.5rem;
            }

            .form-row {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1rem;
                margin-bottom: 1rem;
            }

            .form-label {
                display: block;
                margin-bottom: 0.5rem;
                font-weight: 500;
            }

            .form-input,
            .form-select,
            .form-textarea {
                width: 100%;
                padding: 0.75rem;
                border: 1px solid var(--gray-300);
                border-radius: var(--radius);
                font-family: inherit;
                font-size: 1rem;
                background: var(--white);
            }

            .form-input:focus,
            .form-select:focus,
            .form-textarea:focus {
                outline: none;
                border-color: var(--black);
            }

            .form-textarea {
                min-height: 100px;
                resize: vertical;
            }

            .form-checkbox {
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .form-checkbox input {
                width: 18px;
                height: 18px;
            }

            /* Buttons */
            .btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 0.75rem 1.5rem;
                font-size: 0.875rem;
                font-weight: 500;
                border-radius: var(--radius);
                border: none;
                cursor: pointer;
                transition: all 0.2s;
                text-decoration: none;
                gap: 0.5rem;
            }

            .btn-primary {
                background: var(--black);
                color: var(--white);
            }

            .btn-primary:hover {
                background: var(--gray-900);
            }

            .btn-secondary {
                background: var(--gray-200);
                color: var(--gray-900);
            }

            .btn-secondary:hover {
                background: var(--gray-300);
            }

            .btn-danger {
                background: var(--red);
                color: var(--white);
            }

            .btn-danger:hover {
                background: #dc2626;
            }

            .btn-success {
                background: var(--green);
                color: var(--white);
            }

            .btn-success:hover {
                background: #059669;
            }

            /* Table */
            .table-container {
                overflow-x: auto;
            }

            .admin-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 1rem;
            }

            .admin-table th,
            .admin-table td {
                padding: 1rem;
                text-align: left;
                border-bottom: 1px solid var(--gray-200);
            }

            .admin-table th {
                background: var(--gray-50);
                font-weight: 600;
                color: var(--gray-900);
                position: sticky;
                top: 0;
            }

            .admin-table tr:hover {
                background: var(--gray-50);
            }

            .table-actions {
                display: flex;
                gap: 0.5rem;
            }

            /* Messages */
            .message {
                padding: 1rem;
                border-radius: var(--radius);
                margin-bottom: 1rem;
                font-size: 0.875rem;
            }

            .message-success {
                background: #d1fae5;
                color: #065f46;
                border: 1px solid #a7f3d0;
            }

            .message-error {
                background: #fee2e2;
                color: #991b1b;
                border: 1px solid #fecaca;
            }

            .message-info {
                background: #dbeafe;
                color: #1e40af;
                border: 1px solid #bfdbfe;
            }

            /* Loading */
            .loading {
                text-align: center;
                padding: 2rem;
                color: var(--gray-600);
            }

            /* Responsive */
            @media (max-width: 768px) {
                .login-card {
                    padding: 2rem;
                }

                .admin-header-content {
                    flex-direction: column;
                    gap: 1rem;
                }

                .admin-nav {
                    flex-wrap: wrap;
                    justify-content: center;
                }

                .stats-grid {
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                }

                .form-row {
                    grid-template-columns: 1fr;
                }

                .table-actions {
                    flex-direction: column;
                }
            }
        </style>
    </head>
    <body>
        <!-- Admin Login -->
        <div class="admin-login" id="adminLogin">
            <div class="login-card">
                <div class="login-header">
                    <h1 class="login-title">🛠️ Админка</h1>
                    <p class="login-subtitle">Управление магазином Scooter Parts</p>
                </div>

                <div id="loginMessages"></div>

                <form id="adminLoginForm">
                    <div class="form-group">
                        <label class="form-label">Имя пользователя</label>
                        <input type="text" class="form-input" name="username" value="admin" required readonly>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Пароль</label>
                        <input type="password" class="form-input" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width: 100%;">
                        🔐 Войти в админку
                    </button>
                </form>

                <div style="margin-top: 1.5rem; text-align: center;">
                    <a href="/" style="color: var(--gray-600); text-decoration: none; font-size: 0.875rem;">
                        ← Вернуться на главную
                    </a>
                </div>
            </div>
        </div>

        <!-- Admin Panel -->
        <div class="admin-panel" id="adminPanel">
            <!-- Header -->
            <header class="admin-header">
                <div class="container">
                    <div class="admin-header-content">
                        <div class="admin-logo">
                            <span>🛠️</span>
                            <span>Админка Scooter Parts</span>
                        </div>

                        <div class="admin-nav">
                            <button class="admin-nav-btn active" data-section="stats">📊 Статистика</button>
                            <button class="admin-nav-btn" data-section="products">📦 Товары</button>
                            <button class="admin-nav-btn" data-section="add-product">➕ Добавить товар</button>
                        </div>

                        <button class="admin-logout-btn" id="adminLogoutBtn">🚪 Выйти</button>
                    </div>
                </div>
            </header>

            <!-- Content -->
            <main class="admin-content">
                <div class="container">
                    <!-- Статистика -->
                    <div class="admin-section" id="statsSection">
                        <h2 class="section-title">📊 Общая статистика</h2>
                        <div class="stats-grid" id="statsGrid">
                            <div class="loading">Загрузка статистики...</div>
                        </div>

                        <h3 class="section-title">📦 Товары по категориям</h3>
                        <div class="table-container">
                            <table class="admin-table" id="categoriesTable">
                                <thead>
                                    <tr>
                                        <th>Категория</th>
                                        <th>Количество товаров</th>
                                        <th>В наличии</th>
                                        <th>Нет в наличии</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <!-- Данные загружаются через JS -->
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Управление товарами -->
                    <div class="admin-section" id="productsSection" style="display: none;">
                        <h2 class="section-title">📦 Управление товарами</h2>
                        <div class="table-container">
                            <table class="admin-table" id="productsTable">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Название</th>
                                        <th>Категория</th>
                                        <th>Цена</th>
                                        <th>Наличие</th>
                                        <th>Популярный</th>
                                        <th>Действия</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <!-- Товары загружаются через JS -->
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Добавление товара -->
                    <div class="admin-section" id="addProductSection" style="display: none;">
                        <h2 class="section-title">➕ Добавить новый товар</h2>
                        <div id="addProductMessages"></div>

                        <form id="addProductForm">
                            <div class="form-row">
                                <div class="form-group">
                                    <label class="form-label">Название товара *</label>
                                    <input type="text" class="form-input" name="name" required>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Категория *</label>
                                    <select class="form-select" name="category" required>
                                        <option value="">Выберите категорию</option>
                                        <option value="batteries">Аккумуляторы</option>
                                        <option value="motors">Моторы</option>
                                        <option value="electronics">Электроника</option>
                                        <option value="brakes">Тормоза</option>
                                        <option value="tires">Колёса</option>
                                        <option value="accessories">Аксессуары</option>
                                    </select>
                                </div>
                            </div>

                            <div class="form-row">
                                <div class="form-group">
                                    <label class="form-label">Цена (руб) *</label>
                                    <input type="number" class="form-input" name="price" min="0" step="0.01" required>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Количество на складе *</label>
                                    <input type="number" class="form-input" name="stock" min="0" required>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="form-label">Описание *</label>
                                <textarea class="form-textarea" name="description" required></textarea>
                            </div>

                            <div class="form-group">
                                <label class="form-checkbox">
                                    <input type="checkbox" name="featured">
                                    <span>Популярный товар (отображать на главной)</span>
                                </label>
                            </div>

                            <div class="form-group">
                                <button type="submit" class="btn btn-primary">
                                    💾 Сохранить товар
                                </button>
                                <button type="button" class="btn btn-secondary" id="resetFormBtn">
                                    ↺ Очистить форму
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </main>
        </div>

        <!-- Модальное окно редактирования товара -->
        <div class="modal" id="editProductModal">
            <div class="modal-content" style="max-width: 500px;">
                <div class="modal-header">
                    <h2>✏️ Редактировать товар</h2>
                    <button class="modal-close" id="closeEditModal">&times;</button>
                </div>
                <div class="modal-body">
                    <div id="editProductMessages"></div>
                    <form id="editProductForm">
                        <input type="hidden" name="id" id="editProductId">

                        <div class="form-group">
                            <label class="form-label">Название товара</label>
                            <input type="text" class="form-input" name="name" id="editProductName" required>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">Категория</label>
                                <select class="form-select" name="category" id="editProductCategory" required>
                                    <option value="batteries">Аккумуляторы</option>
                                    <option value="motors">Моторы</option>
                                    <option value="electronics">Электроника</option>
                                    <option value="brakes">Тормоза</option>
                                    <option value="tires">Колёса</option>
                                    <option value="accessories">Аксессуары</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Цена (руб)</label>
                                <input type="number" class="form-input" name="price" id="editProductPrice" min="0" step="0.01" required>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Количество на складе</label>
                            <input type="number" class="form-input" name="stock" id="editProductStock" min="0" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Описание</label>
                            <textarea class="form-textarea" name="description" id="editProductDescription" required></textarea>
                        </div>

                        <div class="form-group">
                            <label class="form-checkbox">
                                <input type="checkbox" name="featured" id="editProductFeatured">
                                <span>Популярный товар</span>
                            </label>
                        </div>

                        <div class="form-group" style="display: flex; gap: 1rem;">
                            <button type="submit" class="btn btn-success">
                                💾 Сохранить изменения
                            </button>
                            <button type="button" class="btn btn-danger" id="deleteProductBtn">
                                🗑️ Удалить товар
                            </button>
                            <button type="button" class="btn btn-secondary" id="cancelEditBtn">
                                Отмена
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <script>
            // Переменные админки
            let adminToken = null;
            let currentProducts = [];
            let editingProductId = null;

            // DOM элементы
            const adminLogin = document.getElementById('adminLogin');
            const adminPanel = document.getElementById('adminPanel');
            const adminLoginForm = document.getElementById('adminLoginForm');
            const loginMessages = document.getElementById('loginMessages');
            const adminLogoutBtn = document.getElementById('adminLogoutBtn');
            const adminNavBtns = document.querySelectorAll('.admin-nav-btn');
            const adminSections = ['statsSection', 'productsSection', 'addProductSection'];

            // Элементы статистики
            const statsGrid = document.getElementById('statsGrid');
            const categoriesTable = document.getElementById('categoriesTable');

            // Элементы товаров
            const productsTable = document.getElementById('productsTable');
            const addProductForm = document.getElementById('addProductForm');
            const addProductMessages = document.getElementById('addProductMessages');
            const resetFormBtn = document.getElementById('resetFormBtn');

            // Модальное окно редактирования
            const editProductModal = document.getElementById('editProductModal');
            const closeEditModal = document.getElementById('closeEditModal');
            const editProductForm = document.getElementById('editProductForm');
            const editProductMessages = document.getElementById('editProductMessages');
            const deleteProductBtn = document.getElementById('deleteProductBtn');
            const cancelEditBtn = document.getElementById('cancelEditBtn');

            // Инициализация
            document.addEventListener('DOMContentLoaded', () => {
                // Проверяем админский токен
                const token = localStorage.getItem('adminToken');
                if (token) {
                    // Пытаемся проверить токен
                    checkAdminAuth(token);
                }

                // Форма входа в админку
                adminLoginForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    clearMessages(loginMessages);

                    const formData = new FormData(adminLoginForm);
                    const data = Object.fromEntries(formData);

                    try {
                        const response = await fetch('/api/admin/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(data)
                        });

                        if (response.ok) {
                            const result = await response.json();
                            adminToken = result.access_token;
                            localStorage.setItem('adminToken', adminToken);

                            // Переключаемся на админку
                            adminLogin.style.display = 'none';
                            adminPanel.style.display = 'block';

                            // Загружаем данные
                            loadAdminStats();
                            loadProductsForAdmin();
                        } else {
                            const error = await response.json();
                            showMessage('error', error.detail || 'Ошибка входа', loginMessages);
                        }
                    } catch (error) {
                        console.error('Ошибка входа в админку:', error);
                        showMessage('error', 'Ошибка сети. Проверьте подключение к интернету.', loginMessages);
                    }
                });

                // Выход из админки
                adminLogoutBtn.addEventListener('click', () => {
                    localStorage.removeItem('adminToken');
                    adminToken = null;
                    adminPanel.style.display = 'none';
                    adminLogin.style.display = 'flex';
                    adminLoginForm.reset();
                    clearMessages(loginMessages);
                });

                // Навигация по админке
                adminNavBtns.forEach(btn => {
                    btn.addEventListener('click', () => {
                        // Убираем активный класс у всех кнопок
                        adminNavBtns.forEach(b => b.classList.remove('active'));
                        // Добавляем активный класс текущей кнопке
                        btn.classList.add('active');
                        // Показываем соответствующую секцию
                        const section = btn.dataset.section;
                        showAdminSection(section);
                    });
                });

                // Форма добавления товара
                addProductForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    clearMessages(addProductMessages);

                    const formData = new FormData(addProductForm);
                    const data = {
                        name: formData.get('name'),
                        category: formData.get('category'),
                        price: parseFloat(formData.get('price')),
                        description: formData.get('description'),
                        stock: parseInt(formData.get('stock')),
                        featured: formData.get('featured') === 'on'
                    };

                    try {
                        const response = await fetch('/api/admin/products', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${adminToken}`
                            },
                            body: JSON.stringify(data)
                        });

                        if (response.ok) {
                            const result = await response.json();
                            showMessage('success', 'Товар успешно добавлен!', addProductMessages);
                            addProductForm.reset();

                            // Перезагружаем список товаров
                            loadProductsForAdmin();
                            loadAdminStats();

                            // Переключаемся на список товаров
                            showAdminSection('products');
                        } else {
                            const error = await response.json();
                            showMessage('error', error.detail || 'Ошибка добавления товара', addProductMessages);
                        }
                    } catch (error) {
                        console.error('Ошибка добавления товара:', error);
                        showMessage('error', 'Ошибка сети', addProductMessages);
                    }
                });

                // Сброс формы
                resetFormBtn.addEventListener('click', () => {
                    addProductForm.reset();
                    clearMessages(addProductMessages);
                });

                // Закрытие модального окна
                closeEditModal.addEventListener('click', () => {
                    editProductModal.style.display = 'none';
                });

                cancelEditBtn.addEventListener('click', () => {
                    editProductModal.style.display = 'none';
                });

                // Клик вне модального окна
                editProductModal.addEventListener('click', (e) => {
                    if (e.target === editProductModal) {
                        editProductModal.style.display = 'none';
                    }
                });

                // Форма редактирования товара
                editProductForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    clearMessages(editProductMessages);

                    if (!editingProductId) return;

                    const formData = new FormData(editProductForm);
                    const data = {};

                    // Собираем только измененные поля
                    if (formData.get('name')) data.name = formData.get('name');
                    if (formData.get('category')) data.category = formData.get('category');
                    if (formData.get('price')) data.price = parseFloat(formData.get('price'));
                    if (formData.get('description')) data.description = formData.get('description');
                    if (formData.get('stock')) data.stock = parseInt(formData.get('stock'));
                    data.featured = formData.get('featured') === 'on';

                    try {
                        const response = await fetch(`/api/admin/products/${editingProductId}`, {
                            method: 'PUT',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${adminToken}`
                            },
                            body: JSON.stringify(data)
                        });

                        if (response.ok) {
                            const result = await response.json();
                            showMessage('success', 'Товар успешно обновлен!', editProductMessages);

                            // Закрываем модальное окно через секунду
                            setTimeout(() => {
                                editProductModal.style.display = 'none';
                                loadProductsForAdmin();
                                loadAdminStats();
                            }, 1000);
                        } else {
                            const error = await response.json();
                            showMessage('error', error.detail || 'Ошибка обновления товара', editProductMessages);
                        }
                    } catch (error) {
                        console.error('Ошибка обновления товара:', error);
                        showMessage('error', 'Ошибка сети', editProductMessages);
                    }
                });

                // Удаление товара
                deleteProductBtn.addEventListener('click', async () => {
                    if (!editingProductId) return;

                    if (!confirm('Вы уверены, что хотите удалить этот товар? Это действие нельзя отменить.')) {
                        return;
                    }

                    try {
                        const response = await fetch(`/api/admin/products/${editingProductId}`, {
                            method: 'DELETE',
                            headers: {
                                'Authorization': `Bearer ${adminToken}`
                            }
                        });

                        if (response.ok) {
                            showMessage('success', 'Товар успешно удален!', editProductMessages);

                            // Закрываем модальное окно через секунду
                            setTimeout(() => {
                                editProductModal.style.display = 'none';
                                loadProductsForAdmin();
                                loadAdminStats();
                            }, 1000);
                        } else {
                            const error = await response.json();
                            showMessage('error', error.detail || 'Ошибка удаления товара', editProductMessages);
                        }
                    } catch (error) {
                        console.error('Ошибка удаления товара:', error);
                        showMessage('error', 'Ошибка сети', editProductMessages);
                    }
                });
            });

            // Функции админки
            async function checkAdminAuth(token) {
                try {
                    // Пытаемся получить статистику для проверки токена
                    const response = await fetch('/api/admin/stats', {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });

                    if (response.ok) {
                        adminToken = token;
                        adminLogin.style.display = 'none';
                        adminPanel.style.display = 'block';
                        loadAdminStats();
                        loadProductsForAdmin();
                    } else {
                        localStorage.removeItem('adminToken');
                    }
                } catch (error) {
                    console.error('Ошибка проверки админской авторизации:', error);
                    localStorage.removeItem('adminToken');
                }
            }

            function showAdminSection(sectionName) {
                // Скрываем все секции
                adminSections.forEach(section => {
                    document.getElementById(section).style.display = 'none';
                });

                // Показываем выбранную секцию
                document.getElementById(`${sectionName}Section`).style.display = 'block';
            }

            async function loadAdminStats() {
                try {
                    const response = await fetch('/api/admin/stats', {
                        headers: { 'Authorization': `Bearer ${adminToken}` }
                    });

                    if (response.ok) {
                        const stats = await response.json();
                        displayStats(stats);
                    }
                } catch (error) {
                    console.error('Ошибка загрузки статистики:', error);
                    statsGrid.innerHTML = '<div class="message message-error">Ошибка загрузки статистики</div>';
                }
            }

            function displayStats(stats) {
                // Общая статистика
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-value">${stats.users.total}</div>
                        <div class="stat-label">Пользователей</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${stats.products.total}</div>
                        <div class="stat-label">Товаров</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${stats.products.in_stock}</div>
                        <div class="stat-label">Товаров в наличии</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${stats.carts.with_items}</div>
                        <div class="stat-label">Активных корзин</div>
                    </div>
                `;

                // Загружаем категории отдельно
                loadCategoriesStats();
            }

            async function loadCategoriesStats() {
                try {
                    const response = await fetch('/api/categories');
                    const data = await response.json();
                    const categories = data.categories;

                    // Загружаем все товары для подсчета по категориям
                    const productsResponse = await fetch('/api/products');
                    const allProducts = await productsResponse.json();

                    let categoriesHtml = '';

                    categories.forEach(category => {
                        const categoryProducts = allProducts.filter(p => p.category === category.id);
                        const inStock = categoryProducts.filter(p => p.stock > 0).length;
                        const outOfStock = categoryProducts.filter(p => p.stock === 0).length;

                        categoriesHtml += `
                            <tr>
                                <td>${category.name}</td>
                                <td>${category.count}</td>
                                <td>${inStock}</td>
                                <td>${outOfStock}</td>
                            </tr>
                        `;
                    });

                    const tbody = categoriesTable.querySelector('tbody');
                    tbody.innerHTML = categoriesHtml;

                } catch (error) {
                    console.error('Ошибка загрузки статистики по категориям:', error);
                }
            }

            async function loadProductsForAdmin() {
                try {
                    const response = await fetch('/api/products');
                    currentProducts = await response.json();
                    displayProductsForAdmin(currentProducts);
                } catch (error) {
                    console.error('Ошибка загрузки товаров:', error);
                    productsTable.innerHTML = '<tr><td colspan="7" class="message message-error">Ошибка загрузки товаров</td></tr>';
                }
            }

            function displayProductsForAdmin(products) {
                const tbody = productsTable.querySelector('tbody');

                if (products.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 2rem;">Товары не найдены</td></tr>';
                    return;
                }

                tbody.innerHTML = products.map(product => `
                    <tr>
                        <td>${product.id}</td>
                        <td>${product.name}</td>
                        <td>${getCategoryName(product.category)}</td>
                        <td>${formatPrice(product.price)} ₽</td>
                        <td>
                            <span style="color: ${product.stock > 0 ? 'var(--green)' : 'var(--red)'}; font-weight: 500;">
                                ${product.stock > 0 ? `${product.stock} шт.` : 'Нет в наличии'}
                            </span>
                        </td>
                        <td>
                            <span style="color: ${product.featured ? 'var(--green)' : 'var(--gray-600)'}">
                                ${product.featured ? '✓' : '✗'}
                            </span>
                        </td>
                        <td>
                            <div class="table-actions">
                                <button class="btn btn-secondary" onclick="editProduct(${product.id})" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">
                                    ✏️ Редактировать
                                </button>
                            </div>
                        </td>
                    </tr>
                `).join('');
            }

            function editProduct(productId) {
                const product = currentProducts.find(p => p.id === productId);
                if (!product) return;

                editingProductId = productId;

                // Заполняем форму данными товара
                document.getElementById('editProductId').value = product.id;
                document.getElementById('editProductName').value = product.name;
                document.getElementById('editProductCategory').value = product.category;
                document.getElementById('editProductPrice').value = product.price;
                document.getElementById('editProductStock').value = product.stock;
                document.getElementById('editProductDescription').value = product.description;
                document.getElementById('editProductFeatured').checked = product.featured;

                // Очищаем сообщения
                clearMessages(editProductMessages);

                // Показываем модальное окно
                editProductModal.style.display = 'flex';
            }

            function getCategoryName(categoryId) {
                const names = {
                    'batteries': 'Аккумуляторы',
                    'motors': 'Моторы',
                    'electronics': 'Электроника',
                    'brakes': 'Тормоза',
                    'tires': 'Колёса',
                    'accessories': 'Аксессуары'
                };
                return names[categoryId] || categoryId;
            }

            function formatPrice(price) {
                return new Intl.NumberFormat('ru-RU').format(price);
            }

            function showMessage(type, text, container) {
                const messageDiv = document.createElement('div');
                messageDiv.className = `message message-${type}`;
                messageDiv.textContent = text;
                container.appendChild(messageDiv);

                // Автоматически удаляем сообщение через 5 секунд
                setTimeout(() => {
                    if (messageDiv.parentNode) {
                        messageDiv.remove();
                    }
                }, 5000);
            }

            function clearMessages(container) {
                container.innerHTML = '';
            }

            // Утилиты
            function formatNumber(num) {
                return new Intl.NumberFormat('ru-RU').format(num);
            }
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)


# ========== ЗАПУСК ==========
if __name__ == "__main__":
    print("=" * 70)
    print("🛴 Scooter Parts Shop v4.4")
    print("=" * 70)
    print("✅ Админская панель с защитой паролем")
    print("✅ Управление товарами (добавление/редактирование/удаление)")
    print("✅ Полная статистика магазина")
    print(f"✅ Админский логин: admin / пароль из .env файла")
    print("✅ Тестовый пользователь: demo / demo123")
    print("✅ Отдельная страница всех товаров")
    print("✅ Корзина товаров")
    print("🌐 Сервер запущен:")
    print("   • http://localhost:8000              - Главная страница")
    print("   • http://localhost:8000/products     - Все товары")
    print("   • http://localhost:8000/admin        - Админка")
    print("   • http://localhost:8000/api/test-auth - Тест аутентификации")
    print("=" * 70)
    print("⚠️  Важно! Создайте файл .env с переменными:")
    print("   ADMIN_PASSWORD=ваш_пароль_для_админки")
    print("   SECRET_KEY=ваш_секретный_ключ_для_jwt")
    print("=" * 70)

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)