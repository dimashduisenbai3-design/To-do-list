import sqlite3

def init_db():
    conn = sqlite3.connect('todo.db') 
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL)''')
        
    cursor.execute('''CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL)''')
        
    cursor.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        status INTEGER DEFAULT 0,
        user_id INTEGER,
        category_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(category_id) REFERENCES categories(id))''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()