# TaskFlow — Менеджер задач

Веб-приложение для управления задачами с бэкендом на FastAPI и базой данных SQLite.

## Функциональность

- **Аутентификация** — регистрация и вход (пароли хешируются SHA-256)
- **3 связанные таблицы** — `users`, `categories`, `tasks` (One-to-Many)
- **CRUD** — создание, чтение, обновление, удаление задач и категорий
- **REST API** — GET, POST, PATCH, DELETE эндпоинты
- **Валидация** — проверка email, длины полей, обязательных данных
- **Поиск и фильтрация** — по названию, статусу, категории, приоритету
- **Защита от SQL-инъекций** — параметризованные запросы

## Схема базы данных

```
users
├── id           INTEGER PK AUTOINCREMENT
├── username     TEXT UNIQUE NOT NULL
├── email        TEXT UNIQUE NOT NULL
├── password_hash TEXT NOT NULL
├── token        TEXT
└── created_at   TEXT

categories
├── id      INTEGER PK AUTOINCREMENT
├── name    TEXT UNIQUE NOT NULL
└── user_id INTEGER FK → users.id

tasks
├── id          INTEGER PK AUTOINCREMENT
├── title       TEXT NOT NULL
├── description TEXT
├── status      INTEGER (0=активная, 1=выполнена)
├── priority    INTEGER (1=низкий, 2=средний, 3=высокий)
├── user_id     INTEGER FK → users.id
├── category_id INTEGER FK → categories.id
└── created_at  TEXT
```

## Установка и запуск

### Требования
- Python 3.8+

### 1. Клонировать репозиторий
```bash
git clone https://github.com/ВАШ_USERNAME/taskflow.git
cd taskflow
```

### 2. Установить зависимости
```bash
pip install fastapi uvicorn
```

### 3. Запустить сервер
```bash
python -m uvicorn main:app --reload
```

### 4. Открыть в браузере
```
http://localhost:8000
```

### 5. API документация (Swagger)
```
http://localhost:8000/docs
```

## API Эндпоинты

### Аутентификация
| Метод | URL | Описание |
|-------|-----|----------|
| POST | `/auth/register` | Регистрация |
| POST | `/auth/login` | Вход |
| GET | `/auth/me` | Текущий пользователь |

### Категории
| Метод | URL | Описание |
|-------|-----|----------|
| GET | `/categories` | Список категорий |
| POST | `/categories` | Создать категорию |
| DELETE | `/categories/{id}` | Удалить категорию |

### Задачи
| Метод | URL | Описание |
|-------|-----|----------|
| GET | `/tasks` | Список задач (с фильтрацией) |
| GET | `/tasks?search=текст` | Поиск по названию |
| GET | `/tasks?status=0` | Только активные |
| GET | `/tasks?category_id=1` | По категории |
| GET | `/tasks/{id}` | Одна задача |
| POST | `/tasks` | Создать задачу |
| PATCH | `/tasks/{id}` | Обновить задачу |
| DELETE | `/tasks/{id}` | Удалить задачу |

### Пользователи
| Метод | URL | Описание |
|-------|-----|----------|
| GET | `/users/tasks` | Пользователь + все его задачи (JOIN) |

## Технологии

- **Backend:** Python, FastAPI
- **База данных:** SQLite (встроена в Python)
- **Авторизация:** Bearer Token
- **Frontend:** HTML/CSS/JavaScript (встроен в main.py)

## Зависимости (requirements.txt)

```
fastapi>=0.100.0
uvicorn>=0.23.0
```
