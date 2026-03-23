from __future__ import annotations

import os
from functools import wraps
from typing import Optional, Set

from flask import Flask, render_template, request, redirect, url_for, flash, abort
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
# RBAC constants
# =========================
PERMS = [
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
    ("admin_roles", "可管理角色"),
    ("view_tasks", "可查看 Tasks"),
    ("edit_tasks", "可編輯 Tasks"),
    ("view_approvals", "可查看公文簽核"),
    ("create_approvals", "可建立公文"),
    ("approve_approvals", "可簽核公文"),
    ("admin_approvals", "可管理公文流程"),
    ("approve_level_2", "可進行第二層簽核"),
    ("approve_level_3", "可進行第三層最終簽核"),
]

DEFAULT_ROLES = {
    "Owner": {
        "description": "全權限",
        "permissions": [code for code, _ in PERMS],
    },
    "Manager": {
        "description": "管理與審核權限",
        "permissions": [
            "view_dashboard",
            "view_talents",
            "edit_talents",
            "view_projects",
            "edit_projects",
            "view_partners",
            "edit_partners",
            "view_finance",
            "view_tasks",
            "edit_tasks",
            "view_approvals",
            "create_approvals",
            "approve_approvals",
            "approve_level_2",
        ],
    },
    "Staff": {
        "description": "一般執行人員",
        "permissions": [
            "view_dashboard",
            "view_talents",
            "view_projects",
            "view_partners",
            "view_tasks",
            "edit_tasks",
            "view_approvals",
            "create_approvals",
        ],
    },
    "Viewer": {
        "description": "只讀",
        "permissions": [
            "view_dashboard",
            "view_talents",
            "view_projects",
            "view_partners",
            "view_finance",
            "view_tasks",
            "view_approvals",
        ],
    },
}


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
                    description TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS permissions (
                    id SERIAL PRIMARY KEY,
                    code VARCHAR(100) UNIQUE NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_roles (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
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
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    UNIQUE(role_id, permission_id)
                );
                """
            )

        conn.commit()

    seed_rbac()
    seed_admin_user()


def seed_rbac() -> None:
    with get_db() as conn:
        with conn.cursor() as cur:
            # 1. permissions
            for code, desc in PERMS:
                cur.execute(
                    """
                    INSERT INTO permissions (code, description)
                    VALUES (%s, %s)
                    ON CONFLICT (code) DO UPDATE
                    SET description = EXCLUDED.description
                    """,
                    (code, desc),
                )

            # 2. roles
            for role_name, role_info in DEFAULT_ROLES.items():
                cur.execute(
                    """
                    INSERT INTO roles (name, description)
                    VALUES (%s, %s)
                    ON CONFLICT (name) DO UPDATE
                    SET description = EXCLUDED.description
                    """,
                    (role_name, role_info["description"]),
                )

            # 3. role_permissions
            for role_name, role_info in DEFAULT_ROLES.items():
                cur.execute("SELECT id FROM roles WHERE name = %s", (role_name,))
                role_row = cur.fetchone()
                if not role_row:
                    continue
                role_id = role_row["id"]

                for perm_code in role_info["permissions"]:
                    cur.execute("SELECT id FROM permissions WHERE code = %s", (perm_code,))
                    perm_row = cur.fetchone()
                    if not perm_row:
                        continue
                    perm_id = perm_row["id"]

                    cur.execute(
                        """
                        INSERT INTO role_permissions (role_id, permission_id)
                        VALUES (%s, %s)
                        ON CONFLICT (role_id, permission_id) DO NOTHING
                        """,
                        (role_id, perm_id),
                    )

        conn.commit()


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
            if role:
                cur.execute(
                    """
                    INSERT INTO user_roles (user_id, role_id)
                    VALUES (%s, %s)
                    ON CONFLICT (user_id, role_id) DO NOTHING
                    """,
                    (user_id, role["id"]),
                )

        conn.commit()


# =========================
# RBAC helpers
# =========================
def get_user_roles(user_id: int) -> list[str]:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT r.name
                FROM user_roles ur
                JOIN roles r ON r.id = ur.role_id
                WHERE ur.user_id = %s
                ORDER BY r.name
                """,
                (user_id,),
            )
            rows = cur.fetchall()
    return [row["name"] for row in rows]


def get_user_permissions(user_id: int) -> Set[str]:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT p.code
                FROM user_roles ur
                JOIN role_permissions rp ON rp.role_id = ur.role_id
                JOIN permissions p ON p.id = rp.permission_id
                WHERE ur.user_id = %s
                """,
                (user_id,),
            )
            rows = cur.fetchall()
    return {row["code"] for row in rows}


def has_permission(user, perm_code: str) -> bool:
    if not user or not getattr(user, "is_authenticated", False):
        return False
    return perm_code in getattr(user, "permissions", set())


def permission_required(perm_code: str):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if not has_permission(current_user, perm_code):
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator

def get_all_permissions():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, code, description
                FROM permissions
                ORDER BY code ASC
                """
            )
            rows = cur.fetchall()
    return rows

# =========================
# User model
# =========================
class User(UserMixin):
    def __init__(
        self,
        user_id: int,
        username: str,
        display_name: Optional[str],
        is_active: bool = True,
        roles: Optional[list[str]] = None,
        permissions: Optional[Set[str]] = None,
    ):
        self.id = str(user_id)
        self.username = username
        self.display_name = display_name or username
        self.active = is_active
        self.roles = roles or []
        self.permissions = permissions or set()

    @property
    def is_active(self):
        return self.active

    def has_permission(self, perm_code: str) -> bool:
        return perm_code in self.permissions


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

    roles = get_user_roles(row["id"])
    permissions = get_user_permissions(row["id"])

    return User(
        user_id=row["id"],
        username=row["username"],
        display_name=row["display_name"],
        is_active=row["is_active"],
        roles=roles,
        permissions=permissions,
    )


# =========================
# Routes
# =========================
@app.route("/")
@login_required
@permission_required("view_dashboard")
def home():
    return render_template("home.html", user=current_user)


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

        roles = get_user_roles(row["id"])
        permissions = get_user_permissions(row["id"])

        user = User(
            user_id=row["id"],
            username=row["username"],
            display_name=row["display_name"],
            is_active=row["is_active"],
            roles=roles,
            permissions=permissions,
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


@app.route("/me/permissions")
@login_required
def my_permissions():
    return render_template(
        "my_permissions.html",
        user=current_user,
        roles=current_user.roles,
        permissions=sorted(current_user.permissions),
    )


@app.route("/admin/users")
@login_required
@permission_required("admin_users")
def admin_users():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, display_name, is_active, created_at
                FROM users
                ORDER BY id ASC
                """
            )
            users = cur.fetchall()

    return render_template("admin_users.html", users=users)

@app.route("/admin/users/create", methods=["GET", "POST"])
@login_required
@permission_required("admin_users")
def create_user():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        display_name = (request.form.get("display_name") or "").strip()
        password = request.form.get("password") or ""
        is_active = request.form.get("is_active") == "on"
        selected_role_ids = request.form.getlist("role_ids")

        if not username:
            flash("請輸入帳號", "danger")
            return redirect(url_for("create_user"))

        if not password:
            flash("請輸入密碼", "danger")
            return redirect(url_for("create_user"))

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                exists = cur.fetchone()
                if exists:
                    flash("此帳號已存在", "danger")
                    return redirect(url_for("create_user"))

                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, display_name, is_active)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        username,
                        generate_password_hash(password),
                        display_name or username,
                        is_active,
                    ),
                )
                new_user_id = cur.fetchone()["id"]

                for role_id in selected_role_ids:
                    cur.execute(
                        """
                        INSERT INTO user_roles (user_id, role_id)
                        VALUES (%s, %s)
                        ON CONFLICT (user_id, role_id) DO NOTHING
                        """,
                        (new_user_id, int(role_id)),
                    )

            conn.commit()

        flash("使用者建立成功", "success")
        return redirect(url_for("admin_users"))

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, description
                FROM roles
                ORDER BY id ASC
                """
            )
            all_roles = cur.fetchall()

    return render_template("create_user.html", all_roles=all_roles)

@app.route("/admin/roles")
@login_required
@permission_required("admin_roles")
def admin_roles():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT r.id, r.name, r.description,
                       COUNT(DISTINCT rp.permission_id) AS permission_count
                FROM roles r
                LEFT JOIN role_permissions rp ON rp.role_id = r.id
                GROUP BY r.id
                ORDER BY r.id ASC
                """
            )
            roles = cur.fetchall()

    return render_template("admin_roles.html", roles=roles)

@app.route("/admin/roles/create", methods=["GET", "POST"])
@login_required
@permission_required("admin_roles")
def create_role():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        permission_ids = request.form.getlist("permission_ids")

        if not name:
            flash("請輸入角色名稱", "danger")
            return redirect(url_for("create_role"))

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM roles WHERE name = %s", (name,))
                exists = cur.fetchone()
                if exists:
                    flash("角色名稱已存在", "danger")
                    return redirect(url_for("create_role"))

                cur.execute(
                    """
                    INSERT INTO roles (name, description)
                    VALUES (%s, %s)
                    RETURNING id
                    """,
                    (name, description),
                )
                role_id = cur.fetchone()["id"]

                for permission_id in permission_ids:
                    cur.execute(
                        """
                        INSERT INTO role_permissions (role_id, permission_id)
                        VALUES (%s, %s)
                        ON CONFLICT (role_id, permission_id) DO NOTHING
                        """,
                        (role_id, int(permission_id)),
                    )

            conn.commit()

        flash("角色建立成功", "success")
        return redirect(url_for("admin_roles"))

    permissions = get_all_permissions()
    return render_template("create_role.html", permissions=permissions)

@app.route("/admin/users/<int:user_id>/roles", methods=["GET", "POST"])
@login_required
@permission_required("admin_users")
def assign_user_roles(user_id: int):
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
            user_row = cur.fetchone()

            if not user_row:
                abort(404)

            if request.method == "POST":
                selected_role_ids = request.form.getlist("role_ids")

                cur.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))

                for role_id in selected_role_ids:
                    cur.execute(
                        """
                        INSERT INTO user_roles (user_id, role_id)
                        VALUES (%s, %s)
                        ON CONFLICT (user_id, role_id) DO NOTHING
                        """,
                        (user_id, int(role_id)),
                    )

                conn.commit()
                flash("使用者角色已更新", "success")
                return redirect(url_for("admin_users"))

            cur.execute(
                """
                SELECT id, name, description
                FROM roles
                ORDER BY id ASC
                """
            )
            all_roles = cur.fetchall()

            cur.execute(
                """
                SELECT role_id
                FROM user_roles
                WHERE user_id = %s
                """,
                (user_id,),
            )
            current_role_rows = cur.fetchall()
            current_role_ids = {row["role_id"] for row in current_role_rows}

    return render_template(
        "assign_user_roles.html",
        target_user=user_row,
        all_roles=all_roles,
        current_role_ids=current_role_ids,
    )

@app.route("/admin/roles/<int:role_id>/edit", methods=["GET", "POST"])
@login_required
@permission_required("admin_roles")
def edit_role(role_id: int):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, description
                FROM roles
                WHERE id = %s
                """,
                (role_id,),
            )
            role = cur.fetchone()

            if not role:
                abort(404)

            if request.method == "POST":
                name = (request.form.get("name") or "").strip()
                description = (request.form.get("description") or "").strip()
                permission_ids = request.form.getlist("permission_ids")

                if not name:
                    flash("請輸入角色名稱", "danger")
                    return redirect(url_for("edit_role", role_id=role_id))

                cur.execute(
                    """
                    SELECT id
                    FROM roles
                    WHERE name = %s AND id <> %s
                    """,
                    (name, role_id),
                )
                exists = cur.fetchone()
                if exists:
                    flash("角色名稱已被使用", "danger")
                    return redirect(url_for("edit_role", role_id=role_id))

                cur.execute(
                    """
                    UPDATE roles
                    SET name = %s, description = %s
                    WHERE id = %s
                    """,
                    (name, description, role_id),
                )

                cur.execute("DELETE FROM role_permissions WHERE role_id = %s", (role_id,))

                for permission_id in permission_ids:
                    cur.execute(
                        """
                        INSERT INTO role_permissions (role_id, permission_id)
                        VALUES (%s, %s)
                        ON CONFLICT (role_id, permission_id) DO NOTHING
                        """,
                        (role_id, int(permission_id)),
                    )

                conn.commit()
                flash("角色更新成功", "success")
                return redirect(url_for("admin_roles"))

            cur.execute(
                """
                SELECT permission_id
                FROM role_permissions
                WHERE role_id = %s
                """,
                (role_id,),
            )
            current_permission_rows = cur.fetchall()
            current_permission_ids = {row["permission_id"] for row in current_permission_rows}

    permissions = get_all_permissions()

    return render_template(
        "edit_role.html",
        role=role,
        permissions=permissions,
        current_permission_ids=current_permission_ids,
    )

@app.route("/forbidden")
def forbidden():
    return render_template("403.html"), 403


@app.errorhandler(403)
def handle_403(_error):
    return render_template("403.html"), 403


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