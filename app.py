from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from psycopg.rows import dict_row
import psycopg


# =========================
# Config
# =========================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL 未設定，請先在 Render 環境變數加入 DATABASE_URL")

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# =========================
# DB Helpers
# =========================
def get_db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db() -> None:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    display_name VARCHAR(100),
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS roles (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(50) UNIQUE NOT NULL,
                    description TEXT
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS permissions (
                    id SERIAL PRIMARY KEY,
                    code VARCHAR(100) UNIQUE NOT NULL,
                    description TEXT
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_roles (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                    UNIQUE(user_id, role_id)
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS role_permissions (
                    id SERIAL PRIMARY KEY,
                    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
                    UNIQUE(role_id, permission_id)
                );
                """
            )

        conn.commit()

    seed_basic_data()


def seed_basic_data() -> None:
    perms = [
        ("view_dashboard", "可查看 Dashboard"),
        ("view_talents", "可查看 Talents"),
        ("edit_talents", "可編輯 Talents"),
        ("view_projects", "可查看 Projects"),
        ("edit_projects", "可編輯 Projects"),
        ("view_partners", "可查看 Partnerships"),
        ("edit_partners", "可編輯 Partnerships"),
        ("view_finance", "可查看 Finance"),
        ("edit_finance", "可編輯 Finance"),
        ("admin_users", "可管理使用者"),
        ("admin_roles", "可管理角色權限"),
    ]

    with get_db() as conn:
        with conn.cursor() as cur:
            for code, desc in perms:
                cur.execute(
                    """
                    INSERT INTO permissions (code, description)
                    VALUES (%s, %s)
                    ON CONFLICT (code) DO NOTHING
                    """,
                    (code, desc),
                )

            cur.execute(
                """
                INSERT INTO roles (name, description)
                VALUES (%s, %s)
                ON CONFLICT (name) DO NOTHING
                """,
                ("Owner", "全權限"),
            )

            cur.execute(
                """
                INSERT INTO roles (name, description)
                VALUES (%s, %s)
                ON CONFLICT (name) DO NOTHING
                """,
                ("Viewer", "只讀"),
            )

        conn.commit()

    seed_admin_user()


def seed_admin_user() -> None:
    admin_username = os.environ.get("CREATEX_INIT_ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("CREATEX_INIT_ADMIN_PASSWORD", "admin123456")
    admin_display_name = os.environ.get("CREATEX_INIT_ADMIN_DISPLAY_NAME", "Createx Admin")

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (admin_username,))
            user = cur.fetchone()

            if not user:
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, display_name, is_active)
                    VALUES (%s, %s, %s, TRUE)
                    RETURNING id
                    """,
                    (
                        admin_username,
                        generate_password_hash(admin_password),
                        admin_display_name,
                    ),
                )
                user_id = cur.fetchone()["id"]
            else:
                user_id = user["id"]

            cur.execute("SELECT id FROM roles WHERE name = %s", ("Owner",))
            role = cur.fetchone()
            role_id = role["id"]

            cur.execute(
                """
                INSERT INTO user_roles (user_id, role_id)
                VALUES (%s, %s)
                ON CONFLICT (user_id, role_id) DO NOTHING
                """,
                (user_id, role_id),
            )

        conn.commit()


# =========================
# Login User
# =========================
class User(UserMixin):
    def __init__(self, user_id: int, username: str, display_name: Optional[str], is_active: bool = True):
        self.id = str(user_id)
        self.username = username
        self.display_name = display_name or username
        self.active = is_active

    @property
    def is_active(self):
        return self.active


@login_manager.user_loader
def load_user(user_id: str):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, display_name, is_active
                FROM users
                WHERE id = %s
                """,
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        return None

    return User(
        user_id=row["id"],
        username=row["username"],
        display_name=row["display_name"],
        is_active=row["is_active"],
    )


# =========================
# Routes
# =========================
@app.route("/")
def home():
    if current_user.is_authenticated:
        return render_template("home.html", user=current_user)
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, username, password_hash, display_name, is_active
                    FROM users
                    WHERE username = %s
                    """,
                    (username,),
                )
                row = cur.fetchone()

        if not row:
            flash("帳號不存在", "danger")
            return redirect(url_for("login"))

        if not row["is_active"]:
            flash("此帳號已停用", "danger")
            return redirect(url_for("login"))

        if not check_password_hash(row["password_hash"], password):
            flash("密碼錯誤", "danger")
            return redirect(url_for("login"))

        user = User(
            user_id=row["id"],
            username=row["username"],
            display_name=row["display_name"],
            is_active=row["is_active"],
        )
        login_user(user)
        flash("登入成功", "success")
        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("已登出", "success")
    return redirect(url_for("login"))


@app.route("/healthz")
def healthz():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 AS ok;")
                row = cur.fetchone()
        if row and row["ok"] == 1:
            return {"status": "ok"}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500

    return {"status": "error"}, 500


# =========================
# App start
# =========================
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))