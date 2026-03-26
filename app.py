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

from datetime import datetime, date

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

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    description TEXT,
                    start_date DATE,
                    end_date DATE,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
                """
            )

            # 再建 finance_categories
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS finance_categories (
                    id SERIAL PRIMARY KEY,
                    category_type VARCHAR(20) NOT NULL,
                    name VARCHAR(100) NOT NULL,
                    sort_order INTEGER NOT NULL DEFAULT 0,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    UNIQUE(category_type, name)
                );
                """
            )

            # 再建 finance_records
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS finance_records (
                    id SERIAL PRIMARY KEY,
                    record_date DATE NOT NULL,
                    category_type VARCHAR(20) NOT NULL,
                    category_name VARCHAR(100) NOT NULL,
                    item_name VARCHAR(200) NOT NULL,
                    amount NUMERIC(12, 2) NOT NULL DEFAULT 0,
                    payment_method VARCHAR(50),
                    counterparty VARCHAR(100),
                    note TEXT,
                    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS receivable_payable_records (
                    id SERIAL PRIMARY KEY,
                    record_type VARCHAR(20) NOT NULL,
                    title VARCHAR(200) NOT NULL,
                    counterparty VARCHAR(100),
                    amount NUMERIC(12, 2) NOT NULL DEFAULT 0,
                    due_date DATE,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    note TEXT,
                    project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
                    finance_record_id INTEGER REFERENCES finance_records(id) ON DELETE SET NULL,
                    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    paid_received_at TIMESTAMP NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
                """
            )

            # 再補 category_id
            cur.execute(
                """
                ALTER TABLE finance_records
                ADD COLUMN IF NOT EXISTS category_id INTEGER REFERENCES finance_categories(id) ON DELETE SET NULL;
                """
            )

            # 再補 project_id
            cur.execute(
                """
                ALTER TABLE finance_records
                ADD COLUMN IF NOT EXISTS project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL;
                """
            )
    seed_rbac()
    seed_admin_user()
    seed_finance_categories()


def seed_finance_categories():
    default_categories = [
        ("income", "票務收入", 1),
        ("income", "周邊收入", 2),
        ("income", "贊助收入", 3),
        ("income", "合作分潤", 4),
        ("income", "其他收入", 99),

        ("expense", "活動成本", 1),
        ("expense", "場地費", 2),
        ("expense", "餐飲費", 3),
        ("expense", "設計費", 4),
        ("expense", "交通費", 5),
        ("expense", "住宿費", 6),
        ("expense", "人事費", 7),
        ("expense", "行銷費", 8),
        ("expense", "印刷製作費", 9),
        ("expense", "其他支出", 99),
    ]

    with get_db() as conn:
        with conn.cursor() as cur:
            for category_type, name, sort_order in default_categories:
                cur.execute(
                    """
                    INSERT INTO finance_categories (category_type, name, sort_order, is_active)
                    VALUES (%s, %s, %s, TRUE)
                    ON CONFLICT (category_type, name) DO NOTHING
                    """,
                    (category_type, name, sort_order),
                )
        conn.commit()


def get_finance_categories(category_type: str | None = None, only_active: bool = True):
    query = """
        SELECT id, category_type, name, sort_order, is_active
        FROM finance_categories
    """
    conditions = []
    params = []

    if only_active:
        conditions.append("is_active = TRUE")

    if category_type:
        conditions.append("category_type = %s")
        params.append(category_type)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY category_type ASC, sort_order ASC, id ASC"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()

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
    admin_password = os.environ.get("CREATEX_INIT_ADMIN_PASSWORD", "1234")
    admin_display_name = os.environ.get("CREATEX_INIT_ADMIN_DISPLAY_NAME", "劉建佑")

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

def parse_month_filter(month_str: str):
    if not month_str:
        return None, None

    try:
        year, month = month_str.split("-")
        year = int(year)
        month = int(month)

        start_date = f"{year:04d}-{month:02d}-01"

        if month == 12:
            end_date = f"{year + 1:04d}-01-01"
        else:
            end_date = f"{year:04d}-{month + 1:02d}-01"

        return start_date, end_date
    except Exception:
        return None, None

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

def create_finance_record_from_ar_ap(record_id: int) -> int | None:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT rp.id,
                       rp.record_type,
                       rp.title,
                       rp.counterparty,
                       rp.amount,
                       rp.due_date,
                       rp.status,
                       rp.note,
                       rp.project_id,
                       rp.finance_record_id
                FROM receivable_payable_records rp
                WHERE rp.id = %s
                """,
                (record_id,),
            )
            rp_record = cur.fetchone()

            if not rp_record:
                return None

            # 已經轉過正式財務紀錄就不要重複建立
            if rp_record["finance_record_id"]:
                return rp_record["finance_record_id"]

            # 只有 completed 才能轉
            if rp_record["status"] != "completed":
                return None

            category_type = "income" if rp_record["record_type"] == "receivable" else "expense"

            # 找預設分類
            if category_type == "income":
                fallback_category_name = "其他收入"
            else:
                fallback_category_name = "其他支出"

            cur.execute(
                """
                SELECT id, name
                FROM finance_categories
                WHERE category_type = %s
                  AND name = %s
                  AND is_active = TRUE
                LIMIT 1
                """,
                (category_type, fallback_category_name),
            )
            category = cur.fetchone()

            if not category:
                # 如果沒有預設分類，就抓同類型第一個啟用分類
                cur.execute(
                    """
                    SELECT id, name
                    FROM finance_categories
                    WHERE category_type = %s
                      AND is_active = TRUE
                    ORDER BY sort_order ASC, id ASC
                    LIMIT 1
                    """,
                    (category_type,),
                )
                category = cur.fetchone()

            if not category:
                raise RuntimeError(f"找不到可用的財務分類：{category_type}")

            record_date = rp_record["due_date"]
            if not record_date:
                cur.execute("SELECT CURRENT_DATE AS today")
                today_row = cur.fetchone()
                record_date = today_row["today"]

            finance_note = rp_record["note"] or ""
            finance_note = f"[由應收應付自動轉入] {finance_note}".strip()

            cur.execute(
                """
                INSERT INTO finance_records (
                    record_date,
                    category_type,
                    category_id,
                    category_name,
                    item_name,
                    amount,
                    payment_method,
                    counterparty,
                    note,
                    created_by,
                    project_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    record_date,
                    category_type,
                    category["id"],
                    category["name"],
                    rp_record["title"],
                    rp_record["amount"],
                    "應收應付轉入",
                    rp_record["counterparty"],
                    finance_note,
                    int(current_user.id),
                    rp_record["project_id"],
                ),
            )
            finance_record_id = cur.fetchone()["id"]

            cur.execute(
                """
                UPDATE receivable_payable_records
                SET finance_record_id = %s,
                    updated_at = NOW()
                WHERE id = %s
                """,
                (finance_record_id, record_id),
            )

            conn.commit()
            return finance_record_id


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

@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@permission_required("admin_users")
def edit_user(user_id: int):
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
                display_name = (request.form.get("display_name") or "").strip()
                password = request.form.get("password") or ""
                is_active = request.form.get("is_active") == "on"

                # 🚨 防止把自己停用
                if int(current_user.id) == user_id and not is_active:
                    flash("不能停用目前正在登入的帳號", "danger")
                    return redirect(url_for("edit_user", user_id=user_id))
                
                # 檢查該 user 是否為唯一 Owner
                with get_db() as conn_check:
                    with conn_check.cursor() as cur_check:
                        cur_check.execute(
                            """
                            SELECT COUNT(*) AS cnt
                            FROM user_roles ur
                            JOIN roles r ON r.id = ur.role_id
                            WHERE r.name = 'Owner'
                            """
                        )
                        owner_count = cur_check.fetchone()["cnt"]

                        cur_check.execute(
                            """
                            SELECT COUNT(*) AS is_owner
                            FROM user_roles ur
                            JOIN roles r ON r.id = ur.role_id
                            WHERE ur.user_id = %s AND r.name = 'Owner'
                            """,
                            (user_id,),
                        )
                        is_owner = cur_check.fetchone()["is_owner"]

                if is_owner and owner_count <= 1 and not is_active:
                    flash("至少需要一個 Owner，無法停用唯一管理員", "danger")
                    return redirect(url_for("edit_user", user_id=user_id))

                if not display_name:
                    display_name = user_row["username"]

                if password:
                    cur.execute(
                        """
                        UPDATE users
                        SET display_name = %s,
                            password_hash = %s,
                            is_active = %s
                        WHERE id = %s
                        """,
                        (
                            display_name,
                            generate_password_hash(password),
                            is_active,
                            user_id,
                        ),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE users
                        SET display_name = %s,
                            is_active = %s
                        WHERE id = %s
                        """,
                        (
                            display_name,
                            is_active,
                            user_id,
                        ),
                    )

                conn.commit()
                flash("使用者資料已更新", "success")
                return redirect(url_for("admin_users"))

    return render_template("edit_user.html", target_user=user_row)

@app.route("/admin/users/<int:user_id>/toggle-active", methods=["POST"])
@login_required
@permission_required("admin_users")
def toggle_user_active(user_id: int):
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

            new_active = not user_row["is_active"]

            # 不可停用自己
            if int(current_user.id) == user_id and not new_active:
                flash("不能停用目前正在登入的帳號", "danger")
                return redirect(url_for("admin_users"))

            # 不可停用唯一 Owner
            if not new_active:
                cur.execute(
                    """
                    SELECT COUNT(*) AS owner_count
                    FROM user_roles ur
                    JOIN roles r ON r.id = ur.role_id
                    WHERE r.name = 'Owner'
                    """
                )
                owner_count = cur.fetchone()["owner_count"]

                cur.execute(
                    """
                    SELECT COUNT(*) AS is_owner
                    FROM user_roles ur
                    JOIN roles r ON r.id = ur.role_id
                    WHERE ur.user_id = %s AND r.name = 'Owner'
                    """,
                    (user_id,),
                )
                is_owner = cur.fetchone()["is_owner"]

                if is_owner and owner_count <= 1:
                    flash("至少需要一個 Owner，無法停用唯一管理員", "danger")
                    return redirect(url_for("admin_users"))

            cur.execute(
                """
                UPDATE users
                SET is_active = %s
                WHERE id = %s
                """,
                (new_active, user_id),
            )
            conn.commit()

    flash("使用者狀態已更新", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/reset-password", methods=["GET", "POST"])
@login_required
@permission_required("admin_users")
def reset_user_password(user_id: int):
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
                new_password = request.form.get("new_password") or ""

                if not new_password.strip():
                    flash("請輸入新密碼", "danger")
                    return redirect(url_for("reset_user_password", user_id=user_id))

                cur.execute(
                    """
                    UPDATE users
                    SET password_hash = %s
                    WHERE id = %s
                    """,
                    (generate_password_hash(new_password), user_id),
                )
                conn.commit()

                flash("密碼已重設成功", "success")
                return redirect(url_for("admin_users"))

    return render_template("reset_user_password.html", target_user=user_row)

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@permission_required("admin_users")
def delete_user(user_id: int):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, display_name
                FROM users
                WHERE id = %s
                """,
                (user_id,),
            )
            user_row = cur.fetchone()

            if not user_row:
                abort(404)

            # 不可刪除自己
            if int(current_user.id) == user_id:
                flash("不能刪除目前正在登入的帳號", "danger")
                return redirect(url_for("admin_users"))

            # 不可刪除唯一 Owner
            cur.execute(
                """
                SELECT COUNT(*) AS owner_count
                FROM user_roles ur
                JOIN roles r ON r.id = ur.role_id
                WHERE r.name = 'Owner'
                """
            )
            owner_count = cur.fetchone()["owner_count"]

            cur.execute(
                """
                SELECT COUNT(*) AS is_owner
                FROM user_roles ur
                JOIN roles r ON r.id = ur.role_id
                WHERE ur.user_id = %s AND r.name = 'Owner'
                """,
                (user_id,),
            )
            is_owner = cur.fetchone()["is_owner"]

            if is_owner and owner_count <= 1:
                flash("至少需要一個 Owner，無法刪除唯一管理員", "danger")
                return redirect(url_for("admin_users"))

            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()

    flash("使用者已刪除", "success")
    return redirect(url_for("admin_users"))

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


@app.route("/finance")
@login_required
@permission_required("view_finance")
def finance_index():
    month = (request.args.get("month") or "").strip()
    start_date, end_date = parse_month_filter(month)

    query = """
        SELECT fr.id,
               fr.record_date,
               fr.category_type,
               fr.category_name,
               fr.item_name,
               fr.amount,
               fr.payment_method,
               fr.counterparty,
               fr.note,
               fr.created_at,
               u.display_name AS created_by_name
        FROM finance_records fr
        LEFT JOIN users u ON u.id = fr.created_by
    """
    params = []

    if start_date and end_date:
        query += " WHERE fr.record_date >= %s AND fr.record_date < %s"
        params.extend([start_date, end_date])

    query += " ORDER BY fr.record_date DESC, fr.id DESC"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            records = cur.fetchall()

    total_income = sum(float(r["amount"]) for r in records if r["category_type"] == "income")
    total_expense = sum(float(r["amount"]) for r in records if r["category_type"] == "expense")
    net_amount = total_income - total_expense

    return render_template(
        "finance/index.html",
        records=records,
        month=month,
        total_income=total_income,
        total_expense=total_expense,
        net_amount=net_amount,
    )


@app.route("/finance/dashboard")
@login_required
@permission_required("view_finance")
def finance_dashboard():
    today = date.today()
    month_str = f"{today.year:04d}-{today.month:02d}"
    start_date, end_date = parse_month_filter(month_str)

    with get_db() as conn:
        with conn.cursor() as cur:
            # 本月收入 / 支出
            cur.execute(
                """
                SELECT category_type, COALESCE(SUM(amount), 0) AS total_amount
                FROM finance_records
                WHERE record_date >= %s AND record_date < %s
                GROUP BY category_type
                """,
                (start_date, end_date),
            )
            summary_rows = cur.fetchall()

            total_income = 0
            total_expense = 0

            for row in summary_rows:
                if row["category_type"] == "income":
                    total_income = float(row["total_amount"] or 0)
                elif row["category_type"] == "expense":
                    total_expense = float(row["total_amount"] or 0)

            net_amount = total_income - total_expense

            # 最近 10 筆財務紀錄
            cur.execute(
                """
                SELECT fr.id,
                       fr.record_date,
                       fr.category_type,
                       fr.category_name,
                       fr.item_name,
                       fr.amount,
                       fr.payment_method,
                       fr.counterparty,
                       u.display_name AS created_by_name
                FROM finance_records fr
                LEFT JOIN users u ON u.id = fr.created_by
                ORDER BY fr.record_date DESC, fr.id DESC
                LIMIT 10
                """
            )
            recent_records = cur.fetchall()

            # 本月前 5 大支出分類
            cur.execute(
                """
                SELECT category_name,
                       SUM(amount) AS total_amount
                FROM finance_records
                WHERE record_date >= %s
                  AND record_date < %s
                  AND category_type = 'expense'
                GROUP BY category_name
                ORDER BY total_amount DESC
                LIMIT 5
                """,
                (start_date, end_date),
            )
            top_expense_categories = cur.fetchall()

    return render_template(
        "finance/dashboard.html",
        month_str=month_str,
        total_income=total_income,
        total_expense=total_expense,
        net_amount=net_amount,
        recent_records=recent_records,
        top_expense_categories=top_expense_categories,
    )

@app.route("/finance/create", methods=["GET", "POST"])
@login_required
@permission_required("edit_finance")
def finance_create():
    if request.method == "POST":
        record_date = (request.form.get("record_date") or "").strip()
        category_type = (request.form.get("category_type") or "").strip()
        category_id = (request.form.get("category_id") or "").strip()
        item_name = (request.form.get("item_name") or "").strip()
        amount = (request.form.get("amount") or "").strip()
        payment_method = (request.form.get("payment_method") or "").strip()
        counterparty = (request.form.get("counterparty") or "").strip()
        note = (request.form.get("note") or "").strip()
        project_id = (request.form.get("project_id") or "").strip()
       

        if not record_date:
            flash("請輸入日期", "danger")
            return redirect(url_for("finance_create"))

        if category_type not in ["income", "expense"]:
            flash("請選擇正確的收支類型", "danger")
            return redirect(url_for("finance_create"))
        
        if not category_id:
            flash("請選擇分類", "danger")
            return redirect(url_for("finance_create"))

        selected_category = None

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, category_type, name
                    FROM finance_categories
                    WHERE id = %s AND is_active = TRUE
                    """,
                    (int(category_id),),
                )
                selected_category = cur.fetchone()

        if not selected_category:
            flash("分類不存在", "danger")
            return redirect(url_for("finance_create"))

        if selected_category["category_type"] != category_type:
            flash("分類類型與收支類型不一致", "danger")
            return redirect(url_for("finance_create"))

        category_name = selected_category["name"]

        if not item_name:
            flash("請輸入項目名稱", "danger")
            return redirect(url_for("finance_create"))

        try:
            amount_value = float(amount)
        except ValueError:
            flash("金額格式錯誤", "danger")
            return redirect(url_for("finance_create"))

        project_id_value = int(project_id) if project_id else None

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO finance_records (
                        record_date, category_type, category_id, category_name, item_name,
                        amount, payment_method, counterparty, note, created_by, project_id
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        record_date,
                        category_type,
                        selected_category["id"],
                        category_name,
                        item_name,
                        amount_value,
                        payment_method,
                        counterparty,
                        note,
                        int(current_user.id),
                        project_id_value,
                    ),
                )
            conn.commit()

        flash("財務紀錄新增成功", "success")
        return redirect(url_for("finance_index"))

    income_categories = get_finance_categories("income")
    expense_categories = get_finance_categories("expense")


    projects = []
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name FROM projects WHERE is_active = TRUE ORDER BY id DESC")
            projects = cur.fetchall()

    return render_template(
    "finance/create.html",
    income_categories=income_categories,
    expense_categories=expense_categories,
    projects=projects,
    )

@app.route("/finance/<int:record_id>/edit", methods=["GET", "POST"])
@login_required
@permission_required("edit_finance")
def finance_edit(record_id: int):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM finance_records
                WHERE id = %s
                """,
                (record_id,),
            )
            record = cur.fetchone()

            if not record:
                abort(404)

            if request.method == "POST":
                record_date = (request.form.get("record_date") or "").strip()
                category_type = (request.form.get("category_type") or "").strip()
                category_id = (request.form.get("category_id") or "").strip()
                item_name = (request.form.get("item_name") or "").strip()
                amount = (request.form.get("amount") or "").strip()
                payment_method = (request.form.get("payment_method") or "").strip()
                counterparty = (request.form.get("counterparty") or "").strip()
                note = (request.form.get("note") or "").strip()
                project_id = (request.form.get("project_id") or "").strip()

                if not record_date:
                    flash("請輸入日期", "danger")
                    return redirect(url_for("finance_edit", record_id=record_id))

                if category_type not in ["income", "expense"]:
                    flash("請選擇正確的收支類型", "danger")
                    return redirect(url_for("finance_edit", record_id=record_id))

                if not category_id:
                    flash("請選擇分類", "danger")
                    return redirect(url_for("finance_edit", record_id=record_id))

                selected_category = None

                with get_db() as conn_check:
                    with conn_check.cursor() as cur_check:
                        cur_check.execute(
                            """
                            SELECT id, category_type, name
                            FROM finance_categories
                            WHERE id = %s AND is_active = TRUE
                            """,
                            (int(category_id),),
                        )
                        selected_category = cur_check.fetchone()

                if not selected_category:
                    flash("分類不存在", "danger")
                    return redirect(url_for("finance_edit", record_id=record_id))

                if selected_category["category_type"] != category_type:
                    flash("分類類型與收支類型不一致", "danger")
                    return redirect(url_for("finance_edit", record_id=record_id))

                if not item_name:
                    flash("請輸入項目名稱", "danger")
                    return redirect(url_for("finance_edit", record_id=record_id))

                try:
                    amount_value = float(amount)
                except ValueError:
                    flash("金額格式錯誤", "danger")
                    return redirect(url_for("finance_edit", record_id=record_id))
                
                project_id_value = int(project_id) if project_id else None

                cur.execute(
                    """
                    UPDATE finance_records
                    SET record_date = %s,
                        category_type = %s,
                        category_id = %s,
                        category_name = %s,
                        item_name = %s,
                        amount = %s,
                        payment_method = %s,
                        counterparty = %s,
                        note = %s,
                        project_id = %s,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (
                        record_date,
                        category_type,
                        selected_category["id"],
                        selected_category["name"],
                        item_name,
                        amount_value,
                        payment_method,
                        counterparty,
                        note,
                        project_id_value,
                        record_id,
                    ),
                )
                conn.commit()

                flash("財務紀錄更新成功", "success")
                return redirect(url_for("finance_index"))
            
    income_categories = get_finance_categories("income")
    expense_categories = get_finance_categories("expense")
    projects = []
    with get_db() as conn_projects:
        with conn_projects.cursor() as cur_projects:
            cur_projects.execute(
                """
                SELECT id, name
                FROM projects
                WHERE is_active = TRUE
                ORDER BY id DESC
                """
            )
            projects = cur_projects.fetchall()
    return render_template(
    "finance/edit.html",
    record=record,
    income_categories=income_categories,
    expense_categories=expense_categories,
    projects=projects,
)

@app.route("/finance/<int:record_id>/delete", methods=["POST"])
@login_required
@permission_required("edit_finance")
def finance_delete(record_id: int):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM finance_records WHERE id = %s", (record_id,))
            record = cur.fetchone()

            if not record:
                abort(404)

            cur.execute("DELETE FROM finance_records WHERE id = %s", (record_id,))
            conn.commit()

    flash("財務紀錄已刪除", "success")
    return redirect(url_for("finance_index"))

@app.route("/ar-ap")
@login_required
@permission_required("view_finance")
def ar_ap_index():
    record_type = (request.args.get("type") or "").strip()
    status = (request.args.get("status") or "").strip()

    query = """
        SELECT rp.id,
            rp.record_type,
            rp.title,
            rp.counterparty,
            rp.amount,
            rp.due_date,
            rp.status,
            rp.note,
            rp.project_id,
            rp.finance_record_id,
            rp.paid_received_at,
            p.name AS project_name
        FROM receivable_payable_records rp
        LEFT JOIN projects p ON p.id = rp.project_id
    """
    conditions = []
    params = []

    if record_type in ["receivable", "payable"]:
        conditions.append("rp.record_type = %s")
        params.append(record_type)

    if status in ["pending", "completed", "cancelled"]:
        conditions.append("rp.status = %s")
        params.append(status)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY rp.due_date ASC NULLS LAST, rp.id DESC"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            records = cur.fetchall()

    total_receivable = sum(float(r["amount"]) for r in records if r["record_type"] == "receivable" and r["status"] == "pending")
    total_payable = sum(float(r["amount"]) for r in records if r["record_type"] == "payable" and r["status"] == "pending")

    return render_template(
        "ar_ap/index.html",
        records=records,
        record_type=record_type,
        status=status,
        total_receivable=total_receivable,
        total_payable=total_payable,
    )

@app.route("/ar-ap/create", methods=["GET", "POST"])
@login_required
@permission_required("edit_finance")
def ar_ap_create():
    if request.method == "POST":
        record_type = (request.form.get("record_type") or "").strip()
        title = (request.form.get("title") or "").strip()
        counterparty = (request.form.get("counterparty") or "").strip()
        amount = (request.form.get("amount") or "").strip()
        due_date = (request.form.get("due_date") or "").strip()
        status = (request.form.get("status") or "").strip()
        note = (request.form.get("note") or "").strip()
        project_id = (request.form.get("project_id") or "").strip()

        if record_type not in ["receivable", "payable"]:
            flash("請選擇正確的帳款類型", "danger")
            return redirect(url_for("ar_ap_create"))

        if not title:
            flash("請輸入標題", "danger")
            return redirect(url_for("ar_ap_create"))

        try:
            amount_value = float(amount)
        except ValueError:
            flash("金額格式錯誤", "danger")
            return redirect(url_for("ar_ap_create"))

        if status not in ["pending", "completed", "cancelled"]:
            status = "pending"

        project_id_value = int(project_id) if project_id else None

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO receivable_payable_records (
                        record_type, title, counterparty, amount, due_date,
                        status, note, project_id, created_by
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        record_type,
                        title,
                        counterparty,
                        amount_value,
                        due_date or None,
                        status,
                        note,
                        project_id_value,
                        int(current_user.id),
                    ),
                )
            conn.commit()

        flash("應收 / 應付紀錄建立成功", "success")
        return redirect(url_for("ar_ap_index"))

    projects = []
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name
                FROM projects
                WHERE is_active = TRUE
                ORDER BY id DESC
                """
            )
            projects = cur.fetchall()

    return render_template("ar_ap/create.html", projects=projects)

@app.route("/ar-ap/<int:record_id>/edit", methods=["GET", "POST"])
@login_required
@permission_required("edit_finance")
def ar_ap_edit(record_id: int):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM receivable_payable_records
                WHERE id = %s
                """,
                (record_id,),
            )
            record = cur.fetchone()

            if not record:
                abort(404)

            if request.method == "POST":
                record_type = (request.form.get("record_type") or "").strip()
                title = (request.form.get("title") or "").strip()
                counterparty = (request.form.get("counterparty") or "").strip()
                amount = (request.form.get("amount") or "").strip()
                due_date = (request.form.get("due_date") or "").strip()
                status = (request.form.get("status") or "").strip()
                note = (request.form.get("note") or "").strip()
                project_id = (request.form.get("project_id") or "").strip()

                if record_type not in ["receivable", "payable"]:
                    flash("請選擇正確的帳款類型", "danger")
                    return redirect(url_for("ar_ap_edit", record_id=record_id))

                if not title:
                    flash("請輸入標題", "danger")
                    return redirect(url_for("ar_ap_edit", record_id=record_id))

                try:
                    amount_value = float(amount)
                except ValueError:
                    flash("金額格式錯誤", "danger")
                    return redirect(url_for("ar_ap_edit", record_id=record_id))

                if status not in ["pending", "completed", "cancelled"]:
                    status = "pending"

                project_id_value = int(project_id) if project_id else None

                cur.execute(
                    """
                    UPDATE receivable_payable_records
                    SET record_type = %s,
                        title = %s,
                        counterparty = %s,
                        amount = %s,
                        due_date = %s,
                        status = %s,
                        note = %s,
                        project_id = %s,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (
                        record_type,
                        title,
                        counterparty,
                        amount_value,
                        due_date or None,
                        status,
                        note,
                        project_id_value,
                        record_id,
                    ),
                )
                conn.commit()

                flash("應收 / 應付紀錄更新成功", "success")
                return redirect(url_for("ar_ap_index"))

    projects = []
    with get_db() as conn_projects:
        with conn_projects.cursor() as cur_projects:
            cur_projects.execute(
                """
                SELECT id, name
                FROM projects
                WHERE is_active = TRUE
                ORDER BY id DESC
                """
            )
            projects = cur_projects.fetchall()

    return render_template("ar_ap/edit.html", record=record, projects=projects)

@app.route("/ar-ap/<int:record_id>/mark-completed", methods=["POST"])
@login_required
@permission_required("edit_finance")
def ar_ap_mark_completed(record_id: int):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, status, finance_record_id
                FROM receivable_payable_records
                WHERE id = %s
                """,
                (record_id,),
            )
            record = cur.fetchone()

            if not record:
                abort(404)

            # 先標記完成
            if record["status"] != "completed":
                cur.execute(
                    """
                    UPDATE receivable_payable_records
                    SET status = 'completed',
                        paid_received_at = NOW(),
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (record_id,),
                )
                conn.commit()

    try:
        finance_record_id = create_finance_record_from_ar_ap(record_id)
    except Exception as e:
        flash(f"已標記完成，但轉正式財務紀錄失敗：{str(e)}", "danger")
        return redirect(url_for("ar_ap_index"))

    if finance_record_id:
        flash("已完成，並成功轉入正式財務紀錄", "success")
    else:
        flash("已更新為完成狀態", "success")

    return redirect(url_for("ar_ap_index"))


@app.route("/finance/categories")
@login_required
@permission_required("view_finance")
def finance_category_index():
    categories = get_finance_categories(category_type=None, only_active=False)
    return render_template("finance/categories_index.html", categories=categories)

@app.route("/finance/categories/create", methods=["GET", "POST"])
@login_required
@permission_required("edit_finance")
def finance_category_create():
    if request.method == "POST":
        category_type = (request.form.get("category_type") or "").strip()
        name = (request.form.get("name") or "").strip()
        sort_order = (request.form.get("sort_order") or "0").strip()
        is_active = request.form.get("is_active") == "on"

        if category_type not in ["income", "expense"]:
            flash("請選擇正確的分類類型", "danger")
            return redirect(url_for("finance_category_create"))

        if not name:
            flash("請輸入分類名稱", "danger")
            return redirect(url_for("finance_category_create"))

        try:
            sort_order_value = int(sort_order)
        except ValueError:
            flash("排序格式錯誤", "danger")
            return redirect(url_for("finance_category_create"))

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO finance_categories (category_type, name, sort_order, is_active)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (category_type, name) DO NOTHING
                    """,
                    (category_type, name, sort_order_value, is_active),
                )
            conn.commit()

        flash("財務分類新增成功", "success")
        return redirect(url_for("finance_category_index"))

    return render_template("finance/category_create.html")

@app.route("/finance/categories/<int:category_id>/edit", methods=["GET", "POST"])
@login_required
@permission_required("edit_finance")
def finance_category_edit(category_id: int):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, category_type, name, sort_order, is_active
                FROM finance_categories
                WHERE id = %s
                """,
                (category_id,),
            )
            category = cur.fetchone()

            if not category:
                abort(404)

            if request.method == "POST":
                category_type = (request.form.get("category_type") or "").strip()
                name = (request.form.get("name") or "").strip()
                sort_order = (request.form.get("sort_order") or "0").strip()
                is_active = request.form.get("is_active") == "on"

                if category_type not in ["income", "expense"]:
                    flash("請選擇正確的分類類型", "danger")
                    return redirect(url_for("finance_category_edit", category_id=category_id))

                if not name:
                    flash("請輸入分類名稱", "danger")
                    return redirect(url_for("finance_category_edit", category_id=category_id))

                try:
                    sort_order_value = int(sort_order)
                except ValueError:
                    flash("排序格式錯誤", "danger")
                    return redirect(url_for("finance_category_edit", category_id=category_id))

                cur.execute(
                    """
                    UPDATE finance_categories
                    SET category_type = %s,
                        name = %s,
                        sort_order = %s,
                        is_active = %s
                    WHERE id = %s
                    """,
                    (category_type, name, sort_order_value, is_active, category_id),
                )
                conn.commit()

                flash("財務分類更新成功", "success")
                return redirect(url_for("finance_category_index"))

    return render_template("finance/category_edit.html", category=category)


@app.route("/finance/reports/monthly")
@login_required
@permission_required("view_finance")
def finance_monthly_report():
    month = (request.args.get("month") or "").strip()
    start_date, end_date = parse_month_filter(month)

    if not start_date or not end_date:
        flash("請選擇月份", "danger")
        return render_template(
            "finance/monthly_report.html",
            month=month,
            summary=[],
            total_income=0,
            total_expense=0,
            net_amount=0,
            income_by_category=[],
            expense_by_category=[],
        )

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT category_type,
                       category_name,
                       SUM(amount) AS total_amount
                FROM finance_records
                WHERE record_date >= %s AND record_date < %s
                GROUP BY category_type, category_name
                ORDER BY category_type ASC, total_amount DESC
                """,
                (start_date, end_date),
            )
            summary = cur.fetchall()

    income_by_category = [r for r in summary if r["category_type"] == "income"]
    expense_by_category = [r for r in summary if r["category_type"] == "expense"]

    total_income = sum(float(r["total_amount"]) for r in income_by_category)
    total_expense = sum(float(r["total_amount"]) for r in expense_by_category)
    net_amount = total_income - total_expense

    return render_template(
        "finance/monthly_report.html",
        month=month,
        summary=summary,
        total_income=total_income,
        total_expense=total_expense,
        net_amount=net_amount,
        income_by_category=income_by_category,
        expense_by_category=expense_by_category,
    )

@app.route("/projects")
@login_required
def project_index():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, description, start_date, end_date, is_active
                FROM projects
                ORDER BY id DESC
                """
            )
            projects = cur.fetchall()

    return render_template("projects/index.html", projects=projects)

@app.route("/projects/create", methods=["GET", "POST"])
@login_required
def project_create():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        start_date = (request.form.get("start_date") or "").strip()
        end_date = (request.form.get("end_date") or "").strip()
        is_active = request.form.get("is_active") == "on"

        if not name:
            flash("請輸入專案名稱", "danger")
            return redirect(url_for("project_create"))

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO projects (name, description, start_date, end_date, is_active)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        name,
                        description,
                        start_date or None,
                        end_date or None,
                        is_active,
                    ),
                )
            conn.commit()

        flash("專案建立成功", "success")
        return redirect(url_for("project_index"))

    return render_template("projects/create.html")


@app.route("/projects/<int:project_id>/edit", methods=["GET", "POST"])
@login_required
def project_edit(project_id: int):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, description, start_date, end_date, is_active
                FROM projects
                WHERE id = %s
                """,
                (project_id,),
            )
            project = cur.fetchone()

            if not project:
                abort(404)

            if request.method == "POST":
                name = (request.form.get("name") or "").strip()
                description = (request.form.get("description") or "").strip()
                start_date = (request.form.get("start_date") or "").strip()
                end_date = (request.form.get("end_date") or "").strip()
                is_active = request.form.get("is_active") == "on"

                if not name:
                    flash("請輸入專案名稱", "danger")
                    return redirect(url_for("project_edit", project_id=project_id))

                cur.execute(
                    """
                    UPDATE projects
                    SET name = %s,
                        description = %s,
                        start_date = %s,
                        end_date = %s,
                        is_active = %s
                    WHERE id = %s
                    """,
                    (
                        name,
                        description,
                        start_date or None,
                        end_date or None,
                        is_active,
                        project_id,
                    ),
                )
                conn.commit()

                flash("專案更新成功", "success")
                return redirect(url_for("project_index"))

    return render_template("projects/edit.html", project=project)

@app.route("/projects/<int:project_id>/toggle-active", methods=["POST"])
@login_required
def project_toggle_active(project_id: int):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, is_active
                FROM projects
                WHERE id = %s
                """,
                (project_id,),
            )
            project = cur.fetchone()

            if not project:
                abort(404)

            new_active = not project["is_active"]

            cur.execute(
                """
                UPDATE projects
                SET is_active = %s
                WHERE id = %s
                """,
                (new_active, project_id),
            )
            conn.commit()

    flash("專案狀態已更新", "success")
    return redirect(url_for("project_index"))

@app.route("/projects/<int:project_id>/finance")
@login_required
def project_finance_report(project_id: int):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, description, start_date, end_date, is_active
                FROM projects
                WHERE id = %s
                """,
                (project_id,),
            )
            project = cur.fetchone()

            if not project:
                abort(404)

            cur.execute(
                """
                SELECT fr.id,
                       fr.record_date,
                       fr.category_type,
                       fr.category_name,
                       fr.item_name,
                       fr.amount,
                       fr.payment_method,
                       fr.counterparty,
                       fr.note,
                       fr.created_at
                FROM finance_records fr
                WHERE fr.project_id = %s
                ORDER BY fr.record_date DESC, fr.id DESC
                """,
                (project_id,),
            )
            records = cur.fetchall()

    total_income = sum(float(r["amount"]) for r in records if r["category_type"] == "income")
    total_expense = sum(float(r["amount"]) for r in records if r["category_type"] == "expense")
    net_amount = total_income - total_expense

    return render_template(
        "projects/finance_report.html",
        project=project,
        records=records,
        total_income=total_income,
        total_expense=total_expense,
        net_amount=net_amount,
    )

# =========================
# App start
# =========================
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))