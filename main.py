
from flask import Flask, request, jsonify, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)

app.secret_key = os.environ.get(
    "VORTEX_SECRET_KEY",
    "change-this-secret-key-before-publishing"
)

DB_NAME = "vortex_site.db"


def get_db():
    db = sqlite3.connect(DB_NAME)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Миграция старой базы, в которой использовалась почта
    columns = [
        row["name"]
        for row in db.execute("PRAGMA table_info(users)").fetchall()
    ]

    if "email" in columns:
        db.execute("""
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        old_users = db.execute(
            "SELECT id, username, password FROM users ORDER BY id"
        ).fetchall()

        for user in old_users:
            name = user["username"].strip()
            if not name:
                name = f"user_{user['id']}"

            try:
                db.execute(
                    "INSERT INTO users_new (id, username, password) VALUES (?, ?, ?)",
                    (user["id"], name, user["password"])
                )
            except sqlite3.IntegrityError:
                continue

        db.execute("DROP TABLE users")
        db.execute("ALTER TABLE users_new RENAME TO users")

    db.commit()
    db.close()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if len(username) < 3 or len(username) > 30:
        return jsonify({
            "error": "Имя пользователя должно быть от 3 до 30 символов."
        }), 400

    if len(password) < 6:
        return jsonify({
            "error": "Пароль должен содержать минимум 6 символов."
        }), 400

    db = get_db()

    try:
        cursor = db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )

        db.commit()

        user_id = cursor.lastrowid
        session["user_id"] = user_id

        return jsonify({
            "message": "Аккаунт создан",
            "user": {
                "id": user_id,
                "username": username
            }
        })

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "Это имя пользователя уже занято."
        }), 409

    finally:
        db.close()


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    db.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({
            "error": "Неверное имя пользователя или пароль."
        }), 401

    session["user_id"] = user["id"]

    return jsonify({
        "message": "Вход выполнен",
        "user": {
            "id": user["id"],
            "username": user["username"]
        }
    })


@app.route("/api/me")
def me():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"user": None})

    db = get_db()

    user = db.execute(
        "SELECT id, username FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    db.close()

    if not user:
        session.clear()
        return jsonify({"user": None})

    return jsonify({"user": dict(user)})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Вы вышли из аккаунта"})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
