from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
import sqlite3, hashlib, secrets, re, os

# ─────────────────────────────────────────
#  БАЗА ДАННЫХ
# ─────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(__file__), "todo.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

@asynccontextmanager
async def lifespan(app: FastAPI):
    db = get_db()
    # Таблица пользователей
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            password_salt TEXT    NOT NULL DEFAULT '',
            token         TEXT,
            created_at    TEXT    DEFAULT (datetime('now'))
        )
    """)
    # Таблица категорий
    db.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            name    TEXT    NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    # Таблица задач (связана с users и categories)
    db.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            description TEXT,
            status      INTEGER NOT NULL DEFAULT 0,
            priority    INTEGER NOT NULL DEFAULT 1,
            user_id     INTEGER NOT NULL,
            category_id INTEGER,
            created_at  TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id)     REFERENCES users(id)      ON DELETE CASCADE,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
        )
    """)
    db.commit()
    db.close()
    yield

app = FastAPI(title="TaskFlow API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# ─────────────────────────────────────────
#  УТИЛИТЫ: хеш паролей и токены
# ─────────────────────────────────────────

def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """PBKDF2-HMAC-SHA256 хеш пароля с уникальной солью"""
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return key.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    return hash_password(password, salt)[0] == stored_hash

def generate_token() -> str:
    return secrets.token_hex(32)

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    """Проверяет токен и возвращает текущего пользователя"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    token = credentials.credentials
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
    db.close()
    if not user:
        raise HTTPException(status_code=401, detail="Недействительный токен")
    return dict(user)

# ─────────────────────────────────────────
#  МОДЕЛИ ДАННЫХ (с валидацией)
# ─────────────────────────────────────────

class RegisterModel(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: str = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=6, max_length=100)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if not re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", v):
            raise ValueError("Неверный формат email")
        return v.lower()

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Имя пользователя: только буквы, цифры и _")
        return v

class LoginModel(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)

class CategoryCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)

class TaskCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    status: int = Field(0, ge=0, le=1)
    priority: int = Field(1, ge=1, le=3)
    category_id: Optional[int] = None

class TaskUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    status: Optional[int] = Field(None, ge=0, le=1)
    priority: Optional[int] = Field(None, ge=1, le=3)
    category_id: Optional[int] = None

# ─────────────────────────────────────────
#  АУТЕНТИФИКАЦИЯ
# ─────────────────────────────────────────

@app.post("/auth/register", tags=["Auth"])
async def register(data: RegisterModel):
    """Регистрация нового пользователя"""
    db = get_db()
    # Проверяем уникальность
    exists = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        (data.username, data.email)
    ).fetchone()
    if exists:
        raise HTTPException(400, "Пользователь с таким именем или email уже существует")

    token = generate_token()
    pwd_hash, pwd_salt = hash_password(data.password)
    db.execute(
        "INSERT INTO users (username, email, password_hash, password_salt, token) VALUES (?, ?, ?, ?, ?)",
        (data.username, data.email, pwd_hash, pwd_salt, token)
    )
    db.commit()
    user_id = db.execute("SELECT id FROM users WHERE username = ?", (data.username,)).fetchone()["id"]
    db.close()
    return {"message": "Регистрация успешна", "token": token, "user_id": user_id, "username": data.username}

@app.post("/auth/login", tags=["Auth"])
async def login(data: LoginModel):
    """Вход в систему"""
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (data.username,)
    ).fetchone()
    if not user or not verify_password(data.password, user["password_hash"], user["password_salt"]):
        raise HTTPException(401, "Неверное имя пользователя или пароль")

    # Обновляем токен при каждом входе
    token = generate_token()
    db.execute("UPDATE users SET token = ? WHERE id = ?", (token, user["id"]))
    db.commit()
    db.close()
    return {"message": "Вход выполнен", "token": token, "user_id": user["id"], "username": user["username"]}

@app.get("/auth/me", tags=["Auth"])
async def get_me(current_user: dict = Depends(get_current_user)):
    """Информация о текущем пользователе"""
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "email": current_user["email"],
        "created_at": current_user["created_at"]
    }

# ─────────────────────────────────────────
#  КАТЕГОРИИ
# ─────────────────────────────────────────

@app.get("/categories", tags=["Categories"])
async def get_categories(current_user: dict = Depends(get_current_user)):
    """Список категорий текущего пользователя"""
    db = get_db()
    cats = db.execute(
        "SELECT * FROM categories WHERE user_id = ? ORDER BY name",
        (current_user["id"],)
    ).fetchall()
    db.close()
    return [dict(c) for c in cats]

@app.post("/categories", tags=["Categories"])
async def create_category(data: CategoryCreate, current_user: dict = Depends(get_current_user)):
    """Создать категорию"""
    db = get_db()
    exists = db.execute(
        "SELECT id FROM categories WHERE name = ? AND user_id = ?",
        (data.name, current_user["id"])
    ).fetchone()
    if exists:
        raise HTTPException(400, "Категория с таким именем уже существует")
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO categories (name, user_id) VALUES (?, ?)",
        (data.name, current_user["id"])
    )
    db.commit()
    new_id = cursor.lastrowid
    db.close()
    return {"id": new_id, "name": data.name, "user_id": current_user["id"]}

@app.delete("/categories/{cat_id}", tags=["Categories"])
async def delete_category(cat_id: int, current_user: dict = Depends(get_current_user)):
    """Удалить категорию"""
    db = get_db()
    cat = db.execute(
        "SELECT id FROM categories WHERE id = ? AND user_id = ?",
        (cat_id, current_user["id"])
    ).fetchone()
    if not cat:
        raise HTTPException(404, "Категория не найдена")
    db.execute("DELETE FROM categories WHERE id = ?", (cat_id,))
    db.commit()
    db.close()
    return {"status": "success"}

# ─────────────────────────────────────────
#  ЗАДАЧИ — с поиском и фильтрацией
# ─────────────────────────────────────────

@app.get("/tasks", tags=["Tasks"])
async def get_tasks(
    search: Optional[str] = None,
    status: Optional[int] = None,
    category_id: Optional[int] = None,
    priority: Optional[int] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Получить задачи с фильтрацией:
    - search: поиск по названию
    - status: 0=активные, 1=выполненные
    - category_id: фильтр по категории
    - priority: 1=низкий, 2=средний, 3=высокий
    """
    db = get_db()
    query = """
        SELECT t.*, c.name as category_name
        FROM tasks t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = ?
    """
    params: list = [current_user["id"]]

    if search:
        query += " AND t.title LIKE ?"
        params.append(f"%{search}%")
    if status is not None:
        query += " AND t.status = ?"
        params.append(status)
    if category_id is not None:
        query += " AND t.category_id = ?"
        params.append(category_id)
    if priority is not None:
        query += " AND t.priority = ?"
        params.append(priority)

    query += " ORDER BY t.created_at DESC"
    tasks = db.execute(query, params).fetchall()
    db.close()
    return [dict(t) for t in tasks]

@app.get("/tasks/{task_id}", tags=["Tasks"])
async def get_task(task_id: int, current_user: dict = Depends(get_current_user)):
    """Получить одну задачу по ID"""
    db = get_db()
    task = db.execute(
        """SELECT t.*, c.name as category_name FROM tasks t
           LEFT JOIN categories c ON t.category_id = c.id
           WHERE t.id = ? AND t.user_id = ?""",
        (task_id, current_user["id"])
    ).fetchone()
    db.close()
    if not task:
        raise HTTPException(404, "Задача не найдена")
    return dict(task)

@app.post("/tasks", tags=["Tasks"])
async def create_task(data: TaskCreate, current_user: dict = Depends(get_current_user)):
    """Создать задачу"""
    db = get_db()
    # Проверяем что категория принадлежит этому пользователю
    if data.category_id:
        cat = db.execute(
            "SELECT id FROM categories WHERE id = ? AND user_id = ?",
            (data.category_id, current_user["id"])
        ).fetchone()
        if not cat:
            db.close()
            raise HTTPException(400, "Категория не найдена")

    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO tasks (title, description, status, priority, user_id, category_id) VALUES (?,?,?,?,?,?)",
        (data.title, data.description, data.status, data.priority, current_user["id"], data.category_id)
    )
    db.commit()
    new_id = cursor.lastrowid
    task = db.execute(
        "SELECT t.*, c.name as category_name FROM tasks t LEFT JOIN categories c ON t.category_id = c.id WHERE t.id = ?",
        (new_id,)
    ).fetchone()
    db.close()
    return dict(task)

@app.patch("/tasks/{task_id}", tags=["Tasks"])
async def update_task(task_id: int, data: TaskUpdate, current_user: dict = Depends(get_current_user)):
    """Обновить задачу (частично)"""
    db = get_db()
    task = db.execute(
        "SELECT id FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, current_user["id"])
    ).fetchone()
    if not task:
        raise HTTPException(404, "Задача не найдена")

    updates = []
    params = []
    if data.title is not None:
        updates.append("title = ?"); params.append(data.title)
    if data.description is not None:
        updates.append("description = ?"); params.append(data.description)
    if data.status is not None:
        updates.append("status = ?"); params.append(data.status)
    if data.priority is not None:
        updates.append("priority = ?"); params.append(data.priority)
    if data.category_id is not None:
        updates.append("category_id = ?"); params.append(data.category_id)

    if updates:
        params.append(task_id)
        db.execute(f"UPDATE tasks SET {', '.join(updates)} WHERE id = ?", params)
        db.commit()

    task = db.execute(
        "SELECT t.*, c.name as category_name FROM tasks t LEFT JOIN categories c ON t.category_id = c.id WHERE t.id = ?",
        (task_id,)
    ).fetchone()
    db.close()
    return dict(task)

@app.delete("/tasks/{task_id}", tags=["Tasks"])
async def delete_task(task_id: int, current_user: dict = Depends(get_current_user)):
    """Удалить задачу"""
    db = get_db()
    task = db.execute(
        "SELECT id FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, current_user["id"])
    ).fetchone()
    if not task:
        raise HTTPException(404, "Задача не найдена")
    db.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    db.commit()
    db.close()
    return {"status": "success"}

# ─────────────────────────────────────────
#  ФРОНТЕНД (встроен)
# ─────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_frontend():
    return HTML

HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>TaskFlow</title>
  <link href="https://fonts.googleapis.com/css2?family=Russo+One&family=Nunito:wght@400;500;600;700&subset=cyrillic&display=swap" rel="stylesheet"/>
  <style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0c0c0f;--surface:#13131a;--surface2:#1c1c28;
  --border:rgba(255,255,255,0.07);--border-hover:rgba(255,255,255,0.15);
  --accent:#c8f04d;--accent-dim:rgba(200,240,77,0.12);--accent-glow:rgba(200,240,77,0.25);
  --text:#f0f0f5;--text-muted:#6b6b82;--text-dim:#9999b3;
  --done:#3d3d55;--danger:#ff5a5a;--danger-dim:rgba(255,90,90,0.1);
  --warning:#ffaa32;--radius:16px;--radius-sm:8px;
  --font-d:'Russo One',sans-serif;--font-b:'Nunito',sans-serif;
}
body{background:var(--bg);color:var(--text);font-family:var(--font-b);min-height:100vh;line-height:1.6}
.app{max-width:820px;margin:0 auto;padding:40px 20px 80px}

/* AUTH */
.auth-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:80vh;gap:24px}
.auth-box{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:36px;width:100%;max-width:400px}
.auth-title{font-family:var(--font-d);font-size:22px;margin-bottom:24px;color:var(--accent)}
.field{display:flex;flex-direction:column;gap:5px;margin-bottom:16px}
.field label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted)}
.field input{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:11px 14px;font-family:var(--font-b);font-size:14px;color:var(--text);outline:none;transition:border-color .2s}
.field input:focus{border-color:var(--accent)}
.field input.error{border-color:var(--danger)}
.field-error{font-size:11px;color:var(--danger);margin-top:2px}
.btn{display:flex;align-items:center;justify-content:center;gap:8px;border:none;border-radius:var(--radius-sm);padding:12px 24px;font-family:var(--font-d);font-size:14px;cursor:pointer;transition:all .2s;width:100%}
.btn-primary{background:var(--accent);color:#0c0c0f}
.btn-primary:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 8px 24px var(--accent-glow)}
.btn-secondary{background:var(--surface2);color:var(--text);border:1px solid var(--border)}
.btn-secondary:hover{border-color:var(--border-hover)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.auth-switch{font-size:13px;color:var(--text-muted);text-align:center}
.auth-switch span{color:var(--accent);cursor:pointer;text-decoration:underline}

/* HEADER */
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;flex-wrap:wrap;gap:12px}
.logo{font-family:var(--font-d);font-size:20px;color:var(--accent);display:flex;align-items:center;gap:8px}
.logo-dot{width:8px;height:8px;border-radius:50%;background:var(--accent);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.user-info{display:flex;align-items:center;gap:10px;font-size:13px;color:var(--text-muted)}
.btn-logout{background:none;border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-muted);padding:6px 14px;cursor:pointer;font-size:12px;transition:all .2s}
.btn-logout:hover{border-color:var(--danger);color:var(--danger)}

/* STATS */
.stats{display:flex;gap:10px;margin-bottom:28px;flex-wrap:wrap}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 18px;flex:1;min-width:100px;text-align:center}
.stat-num{font-family:var(--font-d);font-size:24px;color:var(--accent)}
.stat-label{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em}

/* CATEGORIES */
.cats-section{margin-bottom:24px}
.section-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--text-muted)}
.cats-list{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.cat-chip{display:flex;align-items:center;gap:6px;background:var(--surface2);border:1px solid var(--border);border-radius:100px;padding:4px 12px 4px 10px;font-size:12px;cursor:pointer;transition:all .2s}
.cat-chip.active{border-color:var(--accent);color:var(--accent)}
.cat-chip:hover{border-color:var(--border-hover)}
.cat-del{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:11px;padding:0;line-height:1;transition:color .2s}
.cat-del:hover{color:var(--danger)}
.add-cat{display:flex;gap:8px}
.add-cat input{flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 12px;font-family:var(--font-b);font-size:13px;color:var(--text);outline:none;transition:border-color .2s}
.add-cat input:focus{border-color:var(--accent)}
.btn-sm{background:var(--accent);color:#0c0c0f;border:none;border-radius:var(--radius-sm);padding:8px 16px;font-family:var(--font-d);font-size:12px;cursor:pointer;white-space:nowrap;transition:all .2s}
.btn-sm:hover{transform:translateY(-1px);box-shadow:0 4px 12px var(--accent-glow)}

/* ADD TASK FORM */
.add-form{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:22px;margin-bottom:24px;transition:border-color .3s}
.add-form:focus-within{border-color:var(--border-hover)}
.form-grid{display:grid;grid-template-columns:1fr 130px 130px;gap:10px;margin-bottom:14px}
@media(max-width:560px){.form-grid{grid-template-columns:1fr}}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}
.form-footer{display:flex;align-items:center;justify-content:flex-end}
.inp{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 13px;font-family:var(--font-b);font-size:14px;color:var(--text);outline:none;width:100%;transition:border-color .2s}
.inp:focus{border-color:var(--accent)}
select.inp{cursor:pointer}
.inp-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);display:block;margin-bottom:4px}

/* FILTERS */
.filters{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.search-box{flex:1;min-width:160px;position:relative}
.search-box input{width:100%;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:9px 14px 9px 36px;font-family:var(--font-b);font-size:13px;color:var(--text);outline:none;transition:border-color .2s}
.search-box input:focus{border-color:var(--accent)}
.search-icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text-muted);font-size:14px;pointer-events:none}
.filter-tabs{display:flex;background:var(--surface);border:1px solid var(--border);border-radius:100px;padding:3px}
.ftab{background:none;border:none;color:var(--text-muted);font-size:12px;font-weight:600;padding:5px 12px;border-radius:100px;cursor:pointer;transition:all .2s}
.ftab.active{background:var(--surface2);color:var(--text)}

/* TASK LIST */
.task-list{display:flex;flex-direction:column;gap:8px}
.task-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;display:flex;align-items:center;gap:14px;animation:slideIn .25s ease both;transition:border-color .2s,transform .2s}
@keyframes slideIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.task-card:hover{border-color:var(--border-hover);transform:translateX(3px)}
.task-card.done{background:rgba(19,19,26,.5);border-color:rgba(255,255,255,.04)}
.toggle{width:22px;height:22px;min-width:22px;border-radius:50%;border:2px solid var(--border-hover);background:none;cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:11px;font-weight:700;transition:all .2s}
.task-card.done .toggle{background:var(--accent-dim);border-color:var(--accent)}
.toggle:hover{border-color:var(--accent);background:var(--accent-dim)}
.task-body{flex:1;min-width:0}
.task-title{font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:4px}
.task-card.done .task-title{color:var(--done);text-decoration:line-through}
.task-desc{font-size:12px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:5px}
.task-meta{display:flex;gap:6px;flex-wrap:wrap}
.chip{font-size:10px;color:var(--text-muted);background:var(--surface2);border-radius:4px;padding:2px 7px}
.chip.priority-3{background:rgba(255,90,90,.1);color:var(--danger)}
.chip.priority-2{background:rgba(255,170,50,.1);color:var(--warning)}
.chip.priority-1{background:rgba(200,240,77,.08);color:#8ab033}
.badge{font-size:10px;font-weight:700;padding:3px 10px;border-radius:100px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
.badge.pending{background:rgba(255,170,50,.1);color:var(--warning);border:1px solid rgba(255,170,50,.2)}
.badge.done{background:var(--accent-dim);color:var(--accent);border:1px solid rgba(200,240,77,.2)}
.btn-del{background:none;border:1px solid transparent;border-radius:var(--radius-sm);color:var(--text-muted);cursor:pointer;font-size:13px;padding:6px 9px;transition:all .2s;line-height:1}
.btn-del:hover{background:var(--danger-dim);border-color:rgba(255,90,90,.25);color:var(--danger)}

/* MISC */
.empty{text-align:center;padding:50px 20px;color:var(--text-muted)}
.empty-icon{font-size:28px;color:var(--accent);opacity:.4;margin-bottom:10px}
.empty p{font-family:var(--font-d);font-size:16px;color:var(--text-dim);margin-bottom:4px}
.loading{display:flex;flex-direction:column;align-items:center;padding:40px;gap:10px;color:var(--text-muted);font-size:13px}
.spinner{width:26px;height:26px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.hidden{display:none!important}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(100px);background:var(--surface2);border:1px solid var(--border);border-radius:100px;padding:11px 22px;font-size:13px;font-weight:500;box-shadow:0 12px 40px rgba(0,0,0,.5);transition:transform .3s cubic-bezier(.34,1.56,.64,1),opacity .3s;opacity:0;pointer-events:none;z-index:999;white-space:nowrap}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
.toast.success{border-color:rgba(200,240,77,.3)}
.toast.error{border-color:rgba(255,90,90,.3);color:var(--danger)}
.how-to{display:flex;gap:16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:9px 14px;font-size:11px;color:var(--text-muted);margin-bottom:12px;flex-wrap:wrap}
  </style>
</head>
<body>
<div class="app">

  <!-- АВТОРИЗАЦИЯ -->
  <div id="auth-section" class="auth-wrap">
    <!-- ВХОД -->
    <div id="login-box" class="auth-box">
      <div class="auth-title">Вход в TaskFlow</div>
      <div class="field">
        <label>Имя пользователя</label>
        <input id="l-username" type="text" placeholder="username" autocomplete="username"/>
      </div>
      <div class="field">
        <label>Пароль</label>
        <input id="l-password" type="password" placeholder="••••••" autocomplete="current-password"/>
      </div>
      <button class="btn btn-primary" id="btn-login" onclick="doLogin()">Войти</button>
      <div class="auth-switch" style="margin-top:16px">Нет аккаунта? <span onclick="showRegister()">Зарегистрироваться</span></div>
    </div>
    <!-- РЕГИСТРАЦИЯ -->
    <div id="register-box" class="auth-box hidden">
      <div class="auth-title">Регистрация</div>
      <div class="field">
        <label>Имя пользователя</label>
        <input id="r-username" type="text" placeholder="только буквы, цифры и _"/>
        <span class="field-error hidden" id="r-username-err"></span>
      </div>
      <div class="field">
        <label>Email</label>
        <input id="r-email" type="email" placeholder="example@mail.com"/>
        <span class="field-error hidden" id="r-email-err"></span>
      </div>
      <div class="field">
        <label>Пароль (минимум 6 символов)</label>
        <input id="r-password" type="password" placeholder="••••••"/>
        <span class="field-error hidden" id="r-pass-err"></span>
      </div>
      <button class="btn btn-primary" onclick="doRegister()">Создать аккаунт</button>
      <div class="auth-switch" style="margin-top:16px">Уже есть аккаунт? <span onclick="showLogin()">Войти</span></div>
    </div>
  </div>

  <!-- ОСНОВНОЕ ПРИЛОЖЕНИЕ -->
  <div id="main-section" class="hidden">
    <div class="header">
      <div class="logo"><span class="logo-dot"></span>TaskFlow</div>
      <div class="user-info">
        <span id="username-display"></span>
        <button class="btn-logout" onclick="doLogout()">Выйти</button>
      </div>
    </div>

    <!-- СТАТИСТИКА -->
    <div class="stats">
      <div class="stat"><div class="stat-num" id="s-total">0</div><div class="stat-label">Всего</div></div>
      <div class="stat"><div class="stat-num" id="s-active" style="color:var(--warning)">0</div><div class="stat-label">Активных</div></div>
      <div class="stat"><div class="stat-num" id="s-done" style="color:var(--accent)">0</div><div class="stat-label">Выполнено</div></div>
      <div class="stat"><div class="stat-num" id="s-cats">0</div><div class="stat-label">Категорий</div></div>
    </div>

    <!-- КАТЕГОРИИ -->
    <div class="cats-section">
      <div class="section-head">
        <span class="section-title">Категории</span>
      </div>
      <div id="cats-list" class="cats-list"></div>
      <div class="add-cat">
        <input id="new-cat" type="text" placeholder="Новая категория..." maxlength="50"/>
        <button class="btn-sm" onclick="addCategory()">+ Добавить</button>
      </div>
    </div>

    <!-- ФОРМА ДОБАВЛЕНИЯ ЗАДАЧИ -->
    <div class="add-form">
      <div class="section-title" style="margin-bottom:14px">✦ Новая задача</div>
      <div class="form-grid">
        <div>
          <span class="inp-label">Название *</span>
          <input class="inp" id="t-title" type="text" placeholder="Что нужно сделать?" maxlength="200"/>
        </div>
        <div>
          <span class="inp-label">Приоритет</span>
          <select class="inp" id="t-priority">
            <option value="1">🟢 Низкий</option>
            <option value="2" selected>🟡 Средний</option>
            <option value="3">🔴 Высокий</option>
          </select>
        </div>
        <div>
          <span class="inp-label">Категория</span>
          <select class="inp" id="t-category">
            <option value="">— без категории —</option>
          </select>
        </div>
      </div>
      <div style="margin-bottom:14px">
        <span class="inp-label">Описание (необязательно)</span>
        <input class="inp" id="t-desc" type="text" placeholder="Подробности..." maxlength="1000"/>
      </div>
      <div class="form-footer">
        <button class="btn btn-primary" style="width:auto;padding:11px 28px" id="btn-add" onclick="addTask()">
          + Добавить задачу
        </button>
      </div>
    </div>

    <!-- ФИЛЬТРЫ -->
    <div class="filters">
      <div class="search-box">
        <span class="search-icon">🔍</span>
        <input id="search-inp" type="text" placeholder="Поиск по названию..." oninput="onSearch()"/>
      </div>
      <div class="filter-tabs">
        <button class="ftab active" data-f="all" onclick="setFilter('all',this)">Все</button>
        <button class="ftab" data-f="0" onclick="setFilter('0',this)">Активные</button>
        <button class="ftab" data-f="1" onclick="setFilter('1',this)">Выполненные</button>
      </div>
    </div>

    <div id="how-to" class="how-to hidden">
      <span>○ — отметить выполненной</span>
      <span>✕ — удалить задачу</span>
    </div>

    <div id="task-list" class="task-list">
      <div class="loading"><div class="spinner"></div><p>Загрузка...</p></div>
    </div>
    <div id="empty" class="empty hidden">
      <div class="empty-icon">✦</div>
      <p id="empty-title">Задач нет</p>
      <span id="empty-sub">Добавьте первую задачу выше</span>
    </div>
  </div>

</div>
<div id="toast" class="toast"></div>

<script>
const API = '';
let token = localStorage.getItem('tf_token') || '';
let username = localStorage.getItem('tf_user') || '';
let allTasks = [], allCats = [];
let filterStatus = 'all', filterCat = null, searchQ = '';
let searchTimer = null;

// ── ИНИЦИАЛИЗАЦИЯ ──
window.onload = () => {
  if (token) { showApp(); loadAll(); }
  else showAuth();
};

// ── АВТ ──
function showAuth(){ document.getElementById('auth-section').classList.remove('hidden'); document.getElementById('main-section').classList.add('hidden'); }
function showApp(){ document.getElementById('auth-section').classList.add('hidden'); document.getElementById('main-section').classList.remove('hidden'); document.getElementById('username-display').textContent = '👤 ' + username; }
function showLogin(){ document.getElementById('login-box').classList.remove('hidden'); document.getElementById('register-box').classList.add('hidden'); }
function showRegister(){ document.getElementById('login-box').classList.add('hidden'); document.getElementById('register-box').classList.remove('hidden'); }

async function doLogin(){
  const u = document.getElementById('l-username').value.trim();
  const p = document.getElementById('l-password').value;
  if(!u||!p){ toast('Заполните все поля','error'); return; }
  const btn = document.getElementById('btn-login');
  btn.disabled = true; btn.textContent = 'Вход...';
  try{
    const res = await api('POST','/auth/login',{username:u,password:p});
    token = res.token; username = res.username;
    localStorage.setItem('tf_token', token);
    localStorage.setItem('tf_user', username);
    showApp(); loadAll(); toast('Добро пожаловать, '+username+'!');
  }catch(e){ toast(e.message,'error'); }
  finally{ btn.disabled=false; btn.textContent='Войти'; }
}

async function doRegister(){
  const u = document.getElementById('r-username').value.trim();
  const e = document.getElementById('r-email').value.trim();
  const p = document.getElementById('r-password').value;
  // Валидация на фронте
  let ok = true;
  if(!u||u.length<3){ showErr('r-username-err','Минимум 3 символа'); ok=false; } else hideErr('r-username-err');
  if(!e||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)){ showErr('r-email-err','Неверный формат email'); ok=false; } else hideErr('r-email-err');
  if(!p||p.length<6){ showErr('r-pass-err','Минимум 6 символов'); ok=false; } else hideErr('r-pass-err');
  if(!ok) return;
  try{
    const res = await api('POST','/auth/register',{username:u,email:e,password:p});
    token = res.token; username = res.username;
    localStorage.setItem('tf_token', token);
    localStorage.setItem('tf_user', username);
    showApp(); loadAll(); toast('Аккаунт создан!');
  }catch(err){ toast(err.message,'error'); }
}

function doLogout(){
  token=''; username='';
  localStorage.removeItem('tf_token'); localStorage.removeItem('tf_user');
  allTasks=[]; allCats=[]; showAuth(); showLogin();
  toast('Вы вышли из аккаунта');
}

function showErr(id, msg){ const el=document.getElementById(id); el.textContent=msg; el.classList.remove('hidden'); }
function hideErr(id){ document.getElementById(id).classList.add('hidden'); }

// ── ЗАГРУЗКА ──
async function loadAll(){ await Promise.all([loadCats(), loadTasks()]); }

async function loadCats(){
  try{
    allCats = await api('GET','/categories');
    renderCats();
    updateCatSelect();
  }catch(e){}
}

async function loadTasks(){
  showLoading(true);
  try{
    let url = '/tasks?';
    if(searchQ) url += 'search='+encodeURIComponent(searchQ)+'&';
    if(filterStatus!=='all') url += 'status='+filterStatus+'&';
    if(filterCat) url += 'category_id='+filterCat+'&';
    allTasks = await api('GET', url);
    renderTasks();
  }catch(e){ showLoading(false); }
}

// ── КАТЕГОРИИ ──
function renderCats(){
  const list = document.getElementById('cats-list');
  document.getElementById('s-cats').textContent = allCats.length;
  const all = document.createElement('div');
  all.className = 'cat-chip' + (!filterCat ? ' active' : '');
  all.textContent = 'Все'; all.onclick = () => { filterCat=null; loadTasks(); renderCats(); };
  list.innerHTML = ''; list.appendChild(all);
  allCats.forEach(c => {
    const chip = document.createElement('div');
    chip.className = 'cat-chip' + (filterCat===c.id ? ' active' : '');
    chip.innerHTML = `<span onclick="setCatFilter(${c.id})">${esc(c.name)}</span><button class="cat-del" onclick="delCat(${c.id})">✕</button>`;
    list.appendChild(chip);
  });
}

function setCatFilter(id){ filterCat = filterCat===id ? null : id; loadTasks(); renderCats(); }

function updateCatSelect(){
  const sel = document.getElementById('t-category');
  sel.innerHTML = '<option value="">— без категории —</option>';
  allCats.forEach(c => { const o=document.createElement('option'); o.value=c.id; o.textContent=c.name; sel.appendChild(o); });
}

async function addCategory(){
  const inp = document.getElementById('new-cat');
  const name = inp.value.trim();
  if(!name){ toast('Введите название категории','error'); return; }
  try{
    const cat = await api('POST','/categories',{name});
    allCats.push(cat); inp.value='';
    renderCats(); updateCatSelect(); toast('Категория добавлена');
  }catch(e){ toast(e.message,'error'); }
}

async function delCat(id){
  if(!confirm('Удалить категорию?')) return;
  try{
    await api('DELETE','/categories/'+id);
    allCats = allCats.filter(c => c.id!==id);
    if(filterCat===id) filterCat=null;
    renderCats(); updateCatSelect(); loadTasks(); toast('Категория удалена');
  }catch(e){ toast(e.message,'error'); }
}

// ── ЗАДАЧИ ──
function renderTasks(){
  const list = document.getElementById('task-list');
  const empty = document.getElementById('empty');
  showLoading(false);

  const done = allTasks.filter(t=>t.status==1).length;
  document.getElementById('s-total').textContent = allTasks.length;
  document.getElementById('s-active').textContent = allTasks.length - done;
  document.getElementById('s-done').textContent = done;
  document.getElementById('how-to').classList.toggle('hidden', allTasks.length===0);

  list.innerHTML='';
  if(allTasks.length===0){
    empty.classList.remove('hidden');
    const msgs = {all:['Задач нет','Добавьте первую задачу выше'],'0':['Активных нет','Все задачи выполнены 🎉'],'1':['Выполненных нет','Отметьте задачу кружком ○']};
    const [t,s] = msgs[filterStatus]||msgs.all;
    document.getElementById('empty-title').textContent = t;
    document.getElementById('empty-sub').textContent = s;
    return;
  }
  empty.classList.add('hidden');
  allTasks.forEach((t,i) => { const card=createCard(t,i); list.appendChild(card); });
}

function createCard(task, i){
  const done = task.status==1;
  const pLabels = {1:'🟢 Низкий',2:'🟡 Средний',3:'🔴 Высокий'};
  const card = document.createElement('div');
  card.className = 'task-card'+(done?' done':'');
  card.style.animationDelay = i*35+'ms';
  card.innerHTML = `
    <button class="toggle" title="${done?'Вернуть в работу':'Отметить выполненной'}">${done?'✓':''}</button>
    <div class="task-body">
      <div class="task-title">${esc(task.title)}</div>
      ${task.description?`<div class="task-desc">${esc(task.description)}</div>`:''}
      <div class="task-meta">
        <span class="chip priority-${task.priority}">${pLabels[task.priority]||''}</span>
        ${task.category_name?`<span class="chip">🏷️ ${esc(task.category_name)}</span>`:''}
        <span class="chip">#${task.id}</span>
      </div>
    </div>
    <span class="badge ${done?'done':'pending'}">${done?'✓ Готово':'● В работе'}</span>
    <button class="btn-del" title="Удалить">✕</button>`;
  card.querySelector('.toggle').onclick = () => toggleTask(task, card);
  card.querySelector('.btn-del').onclick = () => deleteTask(task.id, card);
  return card;
}

async function addTask(){
  const title = document.getElementById('t-title').value.trim();
  const desc = document.getElementById('t-desc').value.trim();
  const priority = parseInt(document.getElementById('t-priority').value);
  const cat = document.getElementById('t-category').value;
  if(!title){ toast('Введите название задачи','error'); document.getElementById('t-title').focus(); return; }
  const btn = document.getElementById('btn-add');
  btn.disabled=true; btn.textContent='Отправка...';
  try{
    const body = {title, status:0, priority};
    if(desc) body.description=desc;
    if(cat) body.category_id=parseInt(cat);
    const task = await api('POST','/tasks',body);
    allTasks.unshift(task);
    document.getElementById('t-title').value='';
    document.getElementById('t-desc').value='';
    renderTasks(); toast('✦ Задача добавлена!');
  }catch(e){ toast(e.message,'error'); }
  finally{ btn.disabled=false; btn.textContent='+ Добавить задачу'; }
}

async function deleteTask(id, card){
  if(!confirm('Удалить задачу?')) return;
  card.style.cssText+='transition:opacity .2s,transform .2s;opacity:0;transform:translateX(28px)';
  try{
    await api('DELETE','/tasks/'+id);
    allTasks = allTasks.filter(t=>t.id!==id);
    setTimeout(renderTasks, 220); toast('Задача удалена');
  }catch(e){ card.style.opacity='1'; card.style.transform=''; toast(e.message,'error'); }
}

async function toggleTask(task, card){
  const newStatus = task.status==1?0:1;
  task.status = newStatus;
  const done = newStatus==1;
  card.classList.toggle('done',done);
  card.querySelector('.toggle').textContent = done?'✓':'';
  const badge = card.querySelector('.badge');
  badge.className='badge '+(done?'done':'pending');
  badge.textContent = done?'✓ Готово':'● В работе';
  document.getElementById('s-done').textContent = allTasks.filter(t=>t.status==1).length;
  document.getElementById('s-active').textContent = allTasks.filter(t=>t.status==0).length;
  try{ await api('PATCH','/tasks/'+task.id,{status:newStatus}); toast(done?'✓ Выполнено':'● Возвращено в работу'); }
  catch{ renderTasks(); }
  if(filterStatus!=='all') setTimeout(loadTasks,300);
}

// ── ФИЛЬТРЫ ──
function setFilter(val, btn){
  filterStatus=val;
  document.querySelectorAll('.ftab').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active'); loadTasks();
}

function onSearch(){
  clearTimeout(searchTimer);
  searchTimer = setTimeout(()=>{ searchQ=document.getElementById('search-inp').value.trim(); loadTasks(); }, 350);
}

// ── УТИЛИТЫ ──
async function api(method, url, body){
  const opts = { method, headers:{'Content-Type':'application/json'} };
  if(token) opts.headers['Authorization']='Bearer '+token;
  if(body) opts.body=JSON.stringify(body);
  const res = await fetch(API+url, opts);
  const data = await res.json();
  if(!res.ok) throw new Error(data.detail||'Ошибка сервера');
  return data;
}

function showLoading(show){
  const list=document.getElementById('task-list');
  const loading=list.querySelector('.loading');
  if(show&&!loading) list.innerHTML='<div class="loading"><div class="spinner"></div><p>Загрузка...</p></div>';
  else if(!show&&loading) loading.remove();
}

let tTimer;
function toast(msg,type='success'){
  const t=document.getElementById('toast');
  t.textContent=msg; t.className='toast '+type+' show';
  clearTimeout(tTimer); tTimer=setTimeout(()=>t.classList.remove('show'),2800);
}

function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
</script>
</body>
</html>"""
