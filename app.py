from __future__ import annotations

import os
import sqlite3
from datetime import datetime, date, timedelta
from functools import wraps
from typing import Any, Dict, Optional, Set, List

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


# =========================
# Config / Constants
# =========================
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "createx.db")

STAGES = ["lead", "need", "proposal", "negotiate", "contract", "execute", "closed"]

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
    ("admin_users", "可管理使用者/指派角色"),
    ("admin_roles", "可管理角色/權限"),
    ("view_tasks", "可查看 Tasks"),
    ("edit_tasks", "可編輯 Tasks"),
    ("view_approvals", "可查看公文簽核"),
    ("create_approvals", "可建立公文"),
    ("approve_approvals", "可簽核公文"),
    ("admin_approvals", "可管理公文流程"),
    ("view_approvals", "可查看公文簽核"),
    ("create_approvals", "可建立公文"),
    ("approve_approvals", "可簽核公文"),
    ("admin_approvals", "可管理公文流程"),
    ("approve_level_2", "可進行第二層簽核"),
    ("approve_level_3", "可進行第三層最終簽核"),
]


# =========================
# Flask app
# =========================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# =========================
# DB Helpers
# =========================
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def safe_add_column(conn: sqlite3.Connection, table: str, column_def: str) -> None:
    """
    SQLite 沒有 ADD COLUMN IF NOT EXISTS，所以用 try/except。
    column_def 範例: "is_active INTEGER NOT NULL DEFAULT 1"
    """
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_def};")
        conn.commit()
    except sqlite3.OperationalError:
        # column exists
        pass


def parse_yyyy_mm_dd(s: str) -> Optional[date]:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


def task_status_refresh() -> None:
    # 目前我們不改 status 為 overdue，只用 due_date 在 dashboard 判斷
    return


def get_tasks_for_dashboard() -> Dict[str, list[sqlite3.Row]]:
    today = date.today()
    in7 = today + timedelta(days=7)

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM tasks
            WHERE status = 'open'
            ORDER BY COALESCE(due_date,'9999-12-31') ASC, id DESC
            """
        ).fetchall()

    due_today, due7, overdue = [], [], []
    for r in rows:
        d = parse_yyyy_mm_dd(r["due_date"] or "")
        if not d:
            continue
        if d < today:
            overdue.append(r)
        elif d == today:
            due_today.append(r)
        elif today < d <= in7:
            due7.append(r)

    due_today.sort(key=lambda x: x["due_date"] or "")
    due7.sort(key=lambda x: x["due_date"] or "")
    overdue.sort(key=lambda x: x["due_date"] or "")

    return {"due_today": due_today, "due7": due7, "overdue": overdue}


# =========================
# RBAC Core
# =========================
def seed_rbac(conn: sqlite3.Connection) -> None:
    # ✅ 重要：永遠用 INSERT OR IGNORE 補齊 permissions（避免只看 COUNT 導致缺 code -> NoneType error）
    conn.executemany(
        "INSERT OR IGNORE INTO permissions (code, description) VALUES (?, ?)",
        PERMS,
    )

    # seed roles（只在空表時建立預設角色）
    cur = conn.execute("SELECT COUNT(*) as c FROM roles")
    if cur.fetchone()["c"] == 0:
        conn.executemany(
            "INSERT INTO roles (name, description) VALUES (?, ?)",
            [
                ("Owner", "全權限"),
                ("Ops", "營運：全模組可看可編"),
                ("Agent", "主經紀：Talents/Projects 可編；Partners/Finance 可看"),
                ("Assistant", "助理：Talents/Projects/Partners 只看"),
                ("Finance", "財務：Finance 可編；Projects 可看"),
                ("Viewer", "只讀：大多頁面只看"),
            ],
        )

    def role_id(name: str) -> int:
        row = conn.execute("SELECT id FROM roles WHERE name=?", (name,)).fetchone()
        if not row:
            raise RuntimeError(f"role not found: {name}")
        return int(row["id"])

    def perm_id(code: str) -> int:
        row = conn.execute("SELECT id FROM permissions WHERE code=?", (code,)).fetchone()
        if not row:
            # ✅ 防呆：如果真的缺，當場補上再查一次（避免 NoneType）
            desc = next((d for c, d in PERMS if c == code), code)
            conn.execute(
                "INSERT OR IGNORE INTO permissions (code, description) VALUES (?, ?)",
                (code, desc),
            )
            row = conn.execute("SELECT id FROM permissions WHERE code=?", (code,)).fetchone()
        if not row:
            raise RuntimeError(f"permission not found: {code}")
        return int(row["id"])

    role_perm_map = {
        "Owner": [p[0] for p in PERMS],
        "Ops": [
            "view_dashboard",
            "view_talents","edit_talents",
            "view_projects","edit_projects",
            "view_partners","edit_partners",
            "view_finance","edit_finance",
            "view_tasks","edit_tasks",
            "view_approvals","create_approvals","approve_approvals",
            "approve_level_2",
        ],
        "Agent": [
            "view_dashboard",
            "view_talents","edit_talents",
            "view_projects","edit_projects",
            "view_partners",
            "view_finance",
            "view_tasks","edit_tasks",
            "view_approvals","create_approvals",
            "approve_level_2",
        ],
        "Assistant": [
            "view_dashboard",
            "view_talents",
            "view_projects",
            "view_partners",
            "view_tasks",
            "view_approvals",
        ],
        "Finance": [
            "view_dashboard",
            "view_projects",
            "view_finance","edit_finance",
            "view_tasks",
            "view_approvals","approve_approvals",
            "approve_level_2",
        ],
        "Viewer": [
            "view_dashboard",
            "view_talents",
            "view_projects",
            "view_partners",
            "view_finance",
            "view_tasks",
            "view_approvals",
        ],
    }

    for rname, perm_codes in role_perm_map.items():
        rid = role_id(rname)
        for code in perm_codes:
            pid = perm_id(code)
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions (role_id, perm_id) VALUES (?, ?)",
                (rid, pid),
            )

    conn.commit()


def get_user_perm_codes(user_id: int) -> Set[str]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT p.code
            FROM user_roles ur
            JOIN role_permissions rp ON rp.role_id = ur.role_id
            JOIN permissions p ON p.id = rp.perm_id
            WHERE ur.user_id = ?
            """,
            (user_id,),
        ).fetchall()
    return set(r["code"] for r in rows)


def user_has_perm(code: str) -> bool:
    if not current_user.is_authenticated:
        return False
    try:
        uid = int(current_user.id)
    except Exception:
        return False
    return code in get_user_perm_codes(uid)


def _redirect_no_perm():
    # 避免 dashboard 也需要權限造成循環：沒有 view_dashboard 就直接 403
    if current_user.is_authenticated and user_has_perm("view_dashboard"):
        return redirect(url_for("dashboard"))
    abort(403)


def require_perm(code: str):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not user_has_perm(code):
                flash("你沒有權限瀏覽此頁面", "error")
                return _redirect_no_perm()
            return fn(*args, **kwargs)

        return wrapper

    return deco


# =========================
# ✅ Jinja Globals（修正：template 可用 user_has_perm）
# =========================
@app.context_processor
def inject_globals():
    return dict(user_has_perm=user_has_perm)


# =========================
# Init DB
# =========================
def init_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'owner',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS talents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stage_name TEXT NOT NULL,
                real_name TEXT,
                phone TEXT,
                email TEXT,
                status TEXT NOT NULL DEFAULT 'talking',
                price_note TEXT,
                notes TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                date TEXT,
                location TEXT,
                owner TEXT,
                budget_income INTEGER DEFAULT 0,
                budget_cost INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'planning',
                notes TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS partners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company TEXT NOT NULL,
                contact TEXT,
                phone TEXT,
                email TEXT,
                stage TEXT NOT NULL DEFAULT 'lead',
                next_action TEXT,
                next_due TEXT,
                notes TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS project_talents (
                project_id INTEGER NOT NULL,
                talent_id INTEGER NOT NULL,
                role_note TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY (project_id, talent_id),
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY (talent_id) REFERENCES talents(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS finance_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,                   -- AR / AP
                project_id INTEGER,
                partner_id INTEGER,
                talent_id INTEGER,
                title TEXT,
                amount INTEGER NOT NULL DEFAULT 0,
                due_date TEXT,                        -- YYYY-MM-DD
                status TEXT NOT NULL DEFAULT 'draft', -- draft/sent/paid/overdue
                notes TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL,
                FOREIGN KEY (partner_id) REFERENCES partners(id) ON DELETE SET NULL,
                FOREIGN KEY (talent_id) REFERENCES talents(id) ON DELETE SET NULL
            );

            -- RBAC
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INTEGER NOT NULL,
                perm_id INTEGER NOT NULL,
                PRIMARY KEY (role_id, perm_id),
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (perm_id) REFERENCES permissions(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                assignee TEXT,                       -- 負責人（先用文字，之後可改 user_id）
                due_date TEXT,                       -- YYYY-MM-DD
                priority TEXT NOT NULL DEFAULT 'P2',  -- P1/P2/P3
                status TEXT NOT NULL DEFAULT 'open',  -- open/done
                related_type TEXT,                   -- talent/project/partner/finance
                related_id INTEGER,                  -- 對應 id
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS approval_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                type TEXT NOT NULL, -- general / hr / finance
                creator_id INTEGER,
                department TEXT,
                status TEXT NOT NULL DEFAULT 'draft',
                -- draft / submitted / reviewing / approved / returned_to_previous / returned_to_creator / cancelled
                amount INTEGER NOT NULL DEFAULT 0,
                content TEXT,
                level_2_approver_id INTEGER,
                level_3_approver_id INTEGER,
                current_step INTEGER NOT NULL DEFAULT 1, -- 1 creator / 2 level2 / 3 level3
                created_at TEXT NOT NULL,
                updated_at TEXT,
                FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (level_2_approver_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (level_3_approver_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS approval_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                step_order INTEGER NOT NULL,   -- 1 / 2 / 3
                step_type TEXT NOT NULL,       -- creator / level_2 / level_3
                approver_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                -- pending / approved / returned / skipped
                comment TEXT,
                approved_at TEXT,
                FOREIGN KEY (document_id) REFERENCES approval_documents(id) ON DELETE CASCADE,
                FOREIGN KEY (approver_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS approval_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                -- create / submit / approve / return_to_previous / return_to_creator / resubmit / cancel
                user_id INTEGER,
                comment TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (document_id) REFERENCES approval_documents(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )
        conn.commit()

        # 補 users 新欄位（公司級後台需要）
        safe_add_column(conn, "users", "is_active INTEGER NOT NULL DEFAULT 1")
        safe_add_column(conn, "users", "must_change_password INTEGER NOT NULL DEFAULT 0")

        # ✅ 建立預設 admin（若不存在）
        admin_row = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not admin_row:
            # 初始密碼：admin1234（你可改成環境變數）
            init_pw = os.environ.get("CREATEX_INIT_ADMIN_PASSWORD", "admin1234")
            conn.execute(
                """
                INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "admin",
                    generate_password_hash(init_pw, method="pbkdf2:sha256"),
                    "owner",
                    1,
                    1,  # 首次登入強制改密碼
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()

        # seed RBAC（含 permissions/roles/role_permissions）
        seed_rbac(conn)

        # ensure admin has Owner role + Owner has all permissions
        admin_row = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        owner_row = conn.execute("SELECT id FROM roles WHERE name='Owner'").fetchone()
        if admin_row and owner_row:
            conn.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                (admin_row["id"], owner_row["id"]),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO role_permissions (role_id, perm_id)
                SELECT ?, id FROM permissions
                """,
                (owner_row["id"],),
            )
            conn.commit()


# =========================
# Model (Login)
# =========================
class User(UserMixin):
    def __init__(self, id: int, username: str, role: str):
        self.id = str(id)
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
        if not row:
            return None
        return User(int(row["id"]), row["username"], row["role"])


# =========================
# Small Lists
# =========================
def list_projects() -> list[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute("SELECT id, name, date FROM projects ORDER BY id DESC").fetchall()


def list_partners() -> list[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute("SELECT id, company, stage FROM partners ORDER BY id DESC").fetchall()


def list_talents_simple() -> list[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            "SELECT id, stage_name, status FROM talents ORDER BY stage_name COLLATE NOCASE ASC"
        ).fetchall()


def list_all_talents() -> list[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            "SELECT id, stage_name, real_name, status FROM talents ORDER BY stage_name COLLATE NOCASE ASC"
        ).fetchall()


def list_users_simple() -> list[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username, is_active FROM users WHERE is_active = 1 ORDER BY username COLLATE NOCASE ASC"
        ).fetchall()


def get_current_pending_step(document_id: int) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM approval_steps
            WHERE document_id = ?
              AND status = 'pending'
            ORDER BY step_order ASC, id ASC
            LIMIT 1
            """,
            (document_id,),
        ).fetchone()
    return row


def recalc_approval_document_status(document_id: int) -> None:
    with get_db() as conn:
        steps = conn.execute(
            "SELECT status FROM approval_steps WHERE document_id = ? ORDER BY step_order ASC, id ASC",
            (document_id,),
        ).fetchall()

        if not steps:
            new_status = "draft"
        elif any(r["status"] == "rejected" for r in steps):
            new_status = "rejected"
        elif all(r["status"] == "approved" for r in steps):
            new_status = "approved"
        elif any(r["status"] == "approved" for r in steps):
            new_status = "reviewing"
        else:
            new_status = "submitted"

        conn.execute(
            "UPDATE approval_documents SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, datetime.utcnow().isoformat(), document_id),
        )
        conn.commit()


def log_approval_action(document_id: int, action: str, user_id: Optional[int], comment: str = "") -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO approval_logs (document_id, action, user_id, comment, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                document_id,
                action,
                user_id,
                comment.strip() if comment else None,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()


def get_my_pending_approvals(user_id: int) -> list[sqlite3.Row]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT d.id, d.title, d.type, d.status, d.amount, d.created_at,
                   s.step_order
            FROM approval_steps s
            JOIN approval_documents d ON d.id = s.document_id
            WHERE s.approver_id = ?
              AND s.status = 'pending'
              AND d.status IN ('submitted', 'reviewing')
            ORDER BY d.created_at DESC, s.step_order ASC
            """,
            (user_id,),
        ).fetchall()
    return rows


def list_users_simple() -> list[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username, is_active FROM users WHERE is_active = 1 ORDER BY username COLLATE NOCASE ASC"
        ).fetchall()


def get_users_with_perm(code: str) -> list[sqlite3.Row]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT u.id, u.username
            FROM users u
            JOIN user_roles ur ON ur.user_id = u.id
            JOIN role_permissions rp ON rp.role_id = ur.role_id
            JOIN permissions p ON p.id = rp.perm_id
            WHERE u.is_active = 1
              AND p.code = ?
            ORDER BY u.username COLLATE NOCASE ASC
            """,
            (code,),
        ).fetchall()
    return rows


def log_approval_action(document_id: int, action: str, user_id: Optional[int], comment: str = "") -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO approval_logs (document_id, action, user_id, comment, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                document_id,
                action,
                user_id,
                comment.strip() if comment else None,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()


def get_approval_document(doc_id: int) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT d.*,
                   cu.username AS creator_name,
                   u2.username AS level_2_name,
                   u3.username AS level_3_name
            FROM approval_documents d
            LEFT JOIN users cu ON cu.id = d.creator_id
            LEFT JOIN users u2 ON u2.id = d.level_2_approver_id
            LEFT JOIN users u3 ON u3.id = d.level_3_approver_id
            WHERE d.id = ?
            """,
            (doc_id,),
        ).fetchone()
    return row


def get_approval_steps(doc_id: int) -> list[sqlite3.Row]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT s.*,
                   u.username AS approver_name
            FROM approval_steps s
            LEFT JOIN users u ON u.id = s.approver_id
            WHERE s.document_id = ?
            ORDER BY s.step_order ASC, s.id ASC
            """,
            (doc_id,),
        ).fetchall()
    return rows


def get_approval_logs(doc_id: int) -> list[sqlite3.Row]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT l.*,
                   u.username AS user_name
            FROM approval_logs l
            LEFT JOIN users u ON u.id = l.user_id
            WHERE l.document_id = ?
            ORDER BY l.id DESC
            """,
            (doc_id,),
        ).fetchall()
    return rows


def build_or_reset_approval_steps(doc_id: int, creator_id: int, level_2_id: int, level_3_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM approval_steps WHERE document_id = ?", (doc_id,))
        conn.execute(
            """
            INSERT INTO approval_steps (document_id, step_order, step_type, approver_id, status, approved_at)
            VALUES (?, 1, 'creator', ?, 'approved', ?)
            """,
            (doc_id, creator_id, datetime.utcnow().isoformat()),
        )
        conn.execute(
            """
            INSERT INTO approval_steps (document_id, step_order, step_type, approver_id, status)
            VALUES (?, 2, 'level_2', ?, 'pending')
            """,
            (doc_id, level_2_id),
        )
        conn.execute(
            """
            INSERT INTO approval_steps (document_id, step_order, step_type, approver_id, status)
            VALUES (?, 3, 'level_3', ?, 'pending')
            """,
            (doc_id, level_3_id),
        )
        conn.commit()


def approval_can_user_act(doc: sqlite3.Row, user_id: int) -> bool:
    if doc["status"] not in ("submitted", "reviewing"):
        return False
    if int(doc["current_step"]) == 2 and doc["level_2_approver_id"] and int(doc["level_2_approver_id"]) == int(user_id):
        return True
    if int(doc["current_step"]) == 3 and doc["level_3_approver_id"] and int(doc["level_3_approver_id"]) == int(user_id):
        return True
    return False


def get_my_pending_approvals(user_id: int) -> list[sqlite3.Row]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT d.*
            FROM approval_documents d
            WHERE d.status IN ('submitted', 'reviewing')
              AND (
                (d.current_step = 2 AND d.level_2_approver_id = ?)
                OR
                (d.current_step = 3 AND d.level_3_approver_id = ?)
              )
            ORDER BY d.id DESC
            """,
            (user_id, user_id),
        ).fetchall()
    return rows


def get_my_returned_approvals(user_id: int) -> list[sqlite3.Row]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM approval_documents
            WHERE creator_id = ?
              AND status = 'returned_to_creator'
            ORDER BY id DESC
            """,
            (user_id,),
        ).fetchall()
    return rows

# =========================
# Finance helpers
# =========================
def refresh_overdue_status() -> None:
    today = date.today().strftime("%Y-%m-%d")
    with get_db() as conn:
        conn.execute(
            """
            UPDATE finance_items
            SET status = 'overdue'
            WHERE due_date IS NOT NULL AND due_date != ''
              AND due_date < ?
              AND status IN ('draft','sent')
            """,
            (today,),
        )
        conn.commit()


# =========================
# Project-talents helpers
# =========================
def get_selected_talent_ids_for_project(project_id: int) -> list[int]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT talent_id FROM project_talents WHERE project_id = ?",
            (project_id,),
        ).fetchall()
        return [int(r["talent_id"]) for r in rows]


def find_date_conflicts(
    project_date: str, selected_talent_ids: list[int], ignore_project_id: Optional[int] = None
) -> list[str]:
    if not project_date or not selected_talent_ids:
        return []

    placeholders = ",".join(["?"] * len(selected_talent_ids))
    params: list[Any] = [project_date, *selected_talent_ids]
    sql = f"""
        SELECT p.id as project_id, p.name as project_name, p.date as project_date,
               t.id as talent_id, t.stage_name as stage_name
        FROM project_talents pt
        JOIN projects p ON p.id = pt.project_id
        JOIN talents t ON t.id = pt.talent_id
        WHERE p.date = ?
          AND pt.talent_id IN ({placeholders})
    """
    if ignore_project_id is not None:
        sql += " AND p.id != ?"
        params.append(ignore_project_id)

    with get_db() as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()

    conflicts = []
    for r in rows:
        conflicts.append(f"⚠ 檔期衝突：{r['stage_name']} 已被排在同日({r['project_date']})")
    return sorted(set(conflicts))


# =========================
# Auth Routes
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, role, is_active, must_change_password FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if not row:
            flash("帳號或密碼錯誤", "error")
            return render_template("login.html")

        if int(row["is_active"]) != 1:
            flash("此帳號已停用，請聯絡管理員", "error")
            return render_template("login.html")

        if check_password_hash(row["password_hash"], password):
            login_user(User(int(row["id"]), row["username"], row["role"]))
            if int(row["must_change_password"]) == 1:
                return redirect(url_for("force_change_password"))

            if user_has_perm("view_dashboard"):
                return redirect(url_for("dashboard"))
            abort(403)

        flash("帳號或密碼錯誤", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/force-change-password", methods=["GET", "POST"])
@login_required
def force_change_password():
    with get_db() as conn:
        row = conn.execute(
            "SELECT must_change_password FROM users WHERE id=?",
            (int(current_user.id),),
        ).fetchone()

    if not row or int(row["must_change_password"]) != 1:
        if user_has_perm("view_dashboard"):
            return redirect(url_for("dashboard"))
        abort(403)

    if request.method == "POST":
        pw1 = (request.form.get("password1") or "").strip()
        pw2 = (request.form.get("password2") or "").strip()

        if not pw1 or len(pw1) < 8:
            flash("密碼至少 8 碼", "error")
            return render_template("force_change_password.html")

        if pw1 != pw2:
            flash("兩次密碼不一致", "error")
            return render_template("force_change_password.html")

        with get_db() as conn:
            conn.execute(
                "UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                (generate_password_hash(pw1, method="pbkdf2:sha256"), int(current_user.id)),
            )
            conn.commit()

        flash("密碼已更新", "success")
        if user_has_perm("view_dashboard"):
            return redirect(url_for("dashboard"))
        abort(403)

    return render_template("force_change_password.html")


# =========================
# Dashboard
# =========================
@app.route("/")
@login_required
@require_perm("view_dashboard")
def dashboard():
    refresh_overdue_status()

    with get_db() as conn:
        t = conn.execute("SELECT COUNT(*) AS c FROM talents").fetchone()["c"]
        p = conn.execute("SELECT COUNT(*) AS c FROM projects").fetchone()["c"]
        s = conn.execute("SELECT COUNT(*) AS c FROM partners").fetchone()["c"]

        upcoming = conn.execute(
            """
            SELECT id, name, date, location, status
            FROM projects
            WHERE date IS NOT NULL AND date != ''
            ORDER BY date ASC
            LIMIT 6
            """
        ).fetchall()

        pipeline = conn.execute(
            """
            SELECT stage, COUNT(*) AS c
            FROM partners
            GROUP BY stage
            ORDER BY c DESC
            """
        ).fetchall()

        partners_all = conn.execute(
            "SELECT * FROM partners WHERE stage != 'closed' ORDER BY id DESC"
        ).fetchall()

        finance_all = conn.execute(
            "SELECT * FROM finance_items ORDER BY COALESCE(due_date,'') ASC, id DESC"
        ).fetchall()

    today = date.today()
    in7 = today + timedelta(days=7)

    due_partners = []
    for row in partners_all:
        d = parse_yyyy_mm_dd(row["next_due"] or "")
        if d and today <= d <= in7:
            due_partners.append(row)
    due_partners.sort(key=lambda r: (r["next_due"] or ""))

    ar_due7, ap_due7, ar_over, ap_over = [], [], [], []
    for r in finance_all:
        d = parse_yyyy_mm_dd(r["due_date"] or "")
        if r["status"] == "paid":
            continue
        if r["status"] == "overdue":
            (ar_over if r["type"] == "AR" else ap_over).append(r)
            continue
        if d and today <= d <= in7:
            (ar_due7 if r["type"] == "AR" else ap_due7).append(r)

    ar_due7.sort(key=lambda x: x["due_date"] or "")
    ap_due7.sort(key=lambda x: x["due_date"] or "")
    ar_over.sort(key=lambda x: x["due_date"] or "")
    ap_over.sort(key=lambda x: x["due_date"] or "")

    tasks_box = {"due_today": [], "due7": [], "overdue": []}
    if user_has_perm("view_tasks"):
        tasks_box = get_tasks_for_dashboard()

    my_approval_items = []
    my_returned_approval_items = []
    if user_has_perm("approve_approvals"):
        my_approval_items = get_my_pending_approvals(int(current_user.id))
    if user_has_perm("create_approvals"):
        my_returned_approval_items = get_my_returned_approvals(int(current_user.id))

    return render_template(
        "dashboard.html",
        stats={"talents": t, "projects": p, "partners": s},
        upcoming=upcoming,
        pipeline=pipeline,
        due_partners=due_partners,
        today=today.strftime("%Y-%m-%d"),
        in7=in7.strftime("%Y-%m-%d"),
        ar_due7=ar_due7,
        ap_due7=ap_due7,
        ar_over=ar_over,
        ap_over=ap_over,
        tasks_due_today=tasks_box["due_today"],
        tasks_due7=tasks_box["due7"],
        tasks_overdue=tasks_box["overdue"],
        my_approval_items=my_approval_items,
        my_returned_approval_items=my_returned_approval_items,
    )


# =========================
# Talents
# =========================
@app.route("/talents")
@login_required
@require_perm("view_talents")
def talents():
    q = (request.args.get("q") or "").strip()
    with get_db() as conn:
        if q:
            rows = conn.execute(
                """
                SELECT * FROM talents
                WHERE stage_name LIKE ? OR real_name LIKE ? OR notes LIKE ?
                ORDER BY id DESC
                """,
                (f"%{q}%", f"%{q}%", f"%{q}%"),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM talents ORDER BY id DESC").fetchall()
    return render_template("talents.html", rows=rows, q=q)


@app.route("/talents/new", methods=["GET", "POST"])
@login_required
@require_perm("edit_talents")
def talent_new():
    if request.method == "POST":
        data = {
            "stage_name": (request.form.get("stage_name") or "").strip(),
            "real_name": (request.form.get("real_name") or "").strip(),
            "phone": (request.form.get("phone") or "").strip(),
            "email": (request.form.get("email") or "").strip(),
            "status": (request.form.get("status") or "talking").strip(),
            "price_note": (request.form.get("price_note") or "").strip(),
            "notes": (request.form.get("notes") or "").strip(),
        }
        if not data["stage_name"]:
            flash("藝名/暱稱必填", "error")
            return render_template("talent_form.html", item=data, mode="new")

        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO talents (stage_name, real_name, phone, email, status, price_note, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["stage_name"],
                    data["real_name"],
                    data["phone"],
                    data["email"],
                    data["status"],
                    data["price_note"],
                    data["notes"],
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()
        return redirect(url_for("talents"))

    return render_template("talent_form.html", item={}, mode="new")


@app.route("/talents/<int:talent_id>/edit", methods=["GET", "POST"])
@login_required
@require_perm("edit_talents")
def talent_edit(talent_id: int):
    with get_db() as conn:
        item = conn.execute("SELECT * FROM talents WHERE id = ?", (talent_id,)).fetchone()
        if not item:
            flash("找不到該筆資料", "error")
            return redirect(url_for("talents"))

        if request.method == "POST":
            data = {
                "stage_name": (request.form.get("stage_name") or "").strip(),
                "real_name": (request.form.get("real_name") or "").strip(),
                "phone": (request.form.get("phone") or "").strip(),
                "email": (request.form.get("email") or "").strip(),
                "status": (request.form.get("status") or "talking").strip(),
                "price_note": (request.form.get("price_note") or "").strip(),
                "notes": (request.form.get("notes") or "").strip(),
            }
            conn.execute(
                """
                UPDATE talents
                SET stage_name=?, real_name=?, phone=?, email=?, status=?, price_note=?, notes=?
                WHERE id=?
                """,
                (
                    data["stage_name"],
                    data["real_name"],
                    data["phone"],
                    data["email"],
                    data["status"],
                    data["price_note"],
                    data["notes"],
                    talent_id,
                ),
            )
            conn.commit()
            return redirect(url_for("talents"))

    return render_template("talent_form.html", item=dict(item), mode="edit")


@app.route("/talents/<int:talent_id>/delete", methods=["POST"])
@login_required
@require_perm("edit_talents")
def talent_delete(talent_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM talents WHERE id = ?", (talent_id,))
        conn.commit()
    return redirect(url_for("talents"))


# =========================
# Projects
# =========================
@app.route("/projects")
@login_required
@require_perm("view_projects")
def projects():
    q = (request.args.get("q") or "").strip()
    with get_db() as conn:
        if q:
            rows = conn.execute(
                """
                SELECT * FROM projects
                WHERE name LIKE ? OR location LIKE ? OR notes LIKE ?
                ORDER BY id DESC
                """,
                (f"%{q}%", f"%{q}%", f"%{q}%"),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()

        counts = conn.execute(
            """
            SELECT project_id, COUNT(*) as c
            FROM project_talents
            GROUP BY project_id
            """
        ).fetchall()

    talent_counts = {int(r["project_id"]): int(r["c"]) for r in counts}
    return render_template("projects.html", rows=rows, q=q, talent_counts=talent_counts)


@app.route("/projects/new", methods=["GET", "POST"])
@login_required
@require_perm("edit_projects")
def project_new():
    talents = list_all_talents()

    if request.method == "POST":
        data = {
            "name": (request.form.get("name") or "").strip(),
            "date": (request.form.get("date") or "").strip(),
            "location": (request.form.get("location") or "").strip(),
            "owner": (request.form.get("owner") or "").strip(),
            "budget_income": int((request.form.get("budget_income") or "0") or 0),
            "budget_cost": int((request.form.get("budget_cost") or "0") or 0),
            "status": (request.form.get("status") or "planning").strip(),
            "notes": (request.form.get("notes") or "").strip(),
        }

        selected_ids = request.form.getlist("talent_ids")
        selected_ids_int = [int(x) for x in selected_ids if str(x).isdigit()]

        if not data["name"]:
            flash("專案名稱必填", "error")
            return render_template(
                "project_form.html",
                item=data,
                mode="new",
                talents=talents,
                selected_ids=selected_ids_int,
            )

        for msg in find_date_conflicts(data["date"], selected_ids_int):
            flash(msg, "error")

        with get_db() as conn:
            cur = conn.execute(
                """
                INSERT INTO projects (name, date, location, owner, budget_income, budget_cost, status, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["name"],
                    data["date"],
                    data["location"],
                    data["owner"],
                    data["budget_income"],
                    data["budget_cost"],
                    data["status"],
                    data["notes"],
                    datetime.utcnow().isoformat(),
                ),
            )
            project_id = cur.lastrowid

            for tid in selected_ids_int:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO project_talents (project_id, talent_id, role_note, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (project_id, tid, None, datetime.utcnow().isoformat()),
                )

            conn.commit()

        return redirect(url_for("projects"))

    return render_template("project_form.html", item={}, mode="new", talents=talents, selected_ids=[])


@app.route("/projects/<int:project_id>/edit", methods=["GET", "POST"])
@login_required
@require_perm("edit_projects")
def project_edit(project_id: int):
    talents = list_all_talents()

    with get_db() as conn:
        item = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if not item:
            flash("找不到該筆資料", "error")
            return redirect(url_for("projects"))

    selected_existing = get_selected_talent_ids_for_project(project_id)

    if request.method == "POST":
        data = {
            "name": (request.form.get("name") or "").strip(),
            "date": (request.form.get("date") or "").strip(),
            "location": (request.form.get("location") or "").strip(),
            "owner": (request.form.get("owner") or "").strip(),
            "budget_income": int((request.form.get("budget_income") or "0") or 0),
            "budget_cost": int((request.form.get("budget_cost") or "0") or 0),
            "status": (request.form.get("status") or "planning").strip(),
            "notes": (request.form.get("notes") or "").strip(),
        }

        selected_ids = request.form.getlist("talent_ids")
        selected_ids_int = [int(x) for x in selected_ids if str(x).isdigit()]

        if not data["name"]:
            flash("專案名稱必填", "error")
            return render_template(
                "project_form.html",
                item=data,
                mode="edit",
                talents=talents,
                selected_ids=selected_ids_int,
            )

        for msg in find_date_conflicts(data["date"], selected_ids_int, ignore_project_id=project_id):
            flash(msg, "error")

        with get_db() as conn:
            conn.execute(
                """
                UPDATE projects
                SET name=?, date=?, location=?, owner=?, budget_income=?, budget_cost=?, status=?, notes=?
                WHERE id=?
                """,
                (
                    data["name"],
                    data["date"],
                    data["location"],
                    data["owner"],
                    data["budget_income"],
                    data["budget_cost"],
                    data["status"],
                    data["notes"],
                    project_id,
                ),
            )

            conn.execute("DELETE FROM project_talents WHERE project_id = ?", (project_id,))
            for tid in selected_ids_int:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO project_talents (project_id, talent_id, role_note, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (project_id, tid, None, datetime.utcnow().isoformat()),
                )

            conn.commit()

        return redirect(url_for("projects"))

    return render_template(
        "project_form.html",
        item=dict(item),
        mode="edit",
        talents=talents,
        selected_ids=selected_existing,
    )


@app.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
@require_perm("edit_projects")
def project_delete(project_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        conn.commit()
    return redirect(url_for("projects"))


# =========================
# Partners
# =========================
@app.route("/partners")
@login_required
@require_perm("view_partners")
def partners():
    q = (request.args.get("q") or "").strip()
    with get_db() as conn:
        if q:
            rows = conn.execute(
                """
                SELECT * FROM partners
                WHERE company LIKE ? OR contact LIKE ? OR notes LIKE ? OR stage LIKE ?
                ORDER BY id DESC
                """,
                (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM partners ORDER BY id DESC").fetchall()
    return render_template("partners.html", rows=rows, q=q)


@app.route("/partners/new", methods=["GET", "POST"])
@login_required
@require_perm("edit_partners")
def partner_new():
    if request.method == "POST":
        data = {
            "company": (request.form.get("company") or "").strip(),
            "contact": (request.form.get("contact") or "").strip(),
            "phone": (request.form.get("phone") or "").strip(),
            "email": (request.form.get("email") or "").strip(),
            "stage": (request.form.get("stage") or "lead").strip(),
            "next_action": (request.form.get("next_action") or "").strip(),
            "next_due": (request.form.get("next_due") or "").strip(),
            "notes": (request.form.get("notes") or "").strip(),
        }
        if not data["company"]:
            flash("公司/單位名稱必填", "error")
            return render_template("partner_form.html", item=data, mode="new")

        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO partners (company, contact, phone, email, stage, next_action, next_due, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["company"],
                    data["contact"],
                    data["phone"],
                    data["email"],
                    data["stage"],
                    data["next_action"],
                    data["next_due"],
                    data["notes"],
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()
        return redirect(url_for("partners"))

    return render_template("partner_form.html", item={}, mode="new")


@app.route("/partners/<int:partner_id>/edit", methods=["GET", "POST"])
@login_required
@require_perm("edit_partners")
def partner_edit(partner_id: int):
    with get_db() as conn:
        item = conn.execute("SELECT * FROM partners WHERE id = ?", (partner_id,)).fetchone()
        if not item:
            flash("找不到該筆資料", "error")
            return redirect(url_for("partners"))

        if request.method == "POST":
            data = {
                "company": (request.form.get("company") or "").strip(),
                "contact": (request.form.get("contact") or "").strip(),
                "phone": (request.form.get("phone") or "").strip(),
                "email": (request.form.get("email") or "").strip(),
                "stage": (request.form.get("stage") or "lead").strip(),
                "next_action": (request.form.get("next_action") or "").strip(),
                "next_due": (request.form.get("next_due") or "").strip(),
                "notes": (request.form.get("notes") or "").strip(),
            }
            conn.execute(
                """
                UPDATE partners
                SET company=?, contact=?, phone=?, email=?, stage=?, next_action=?, next_due=?, notes=?
                WHERE id=?
                """,
                (
                    data["company"],
                    data["contact"],
                    data["phone"],
                    data["email"],
                    data["stage"],
                    data["next_action"],
                    data["next_due"],
                    data["notes"],
                    partner_id,
                ),
            )
            conn.commit()
            return redirect(url_for("partners"))

    return render_template("partner_form.html", item=dict(item), mode="edit")


@app.route("/partners/<int:partner_id>/delete", methods=["POST"])
@login_required
@require_perm("edit_partners")
def partner_delete(partner_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM partners WHERE id = ?", (partner_id,))
        conn.commit()
    return redirect(url_for("partners"))


@app.route("/partners/board")
@login_required
@require_perm("view_partners")
def partners_board():
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM partners
            ORDER BY
              CASE stage
                WHEN 'lead' THEN 1
                WHEN 'need' THEN 2
                WHEN 'proposal' THEN 3
                WHEN 'negotiate' THEN 4
                WHEN 'contract' THEN 5
                WHEN 'execute' THEN 6
                WHEN 'closed' THEN 7
                ELSE 99
              END,
              COALESCE(next_due, '') ASC,
              id DESC
            """
        ).fetchall()

    columns = {s: [] for s in STAGES}
    for r in rows:
        stage = r["stage"] or "lead"
        if stage not in columns:
            stage = "lead"
        columns[stage].append(r)

    return render_template("partners_board.html", columns=columns, stages=STAGES)


# =========================
# Finance
# =========================
@app.route("/finance")
@login_required
@require_perm("view_finance")
def finance():
    refresh_overdue_status()

    q = (request.args.get("q") or "").strip()
    f_type = (request.args.get("type") or "").strip()  # AR/AP
    f_status = (request.args.get("status") or "").strip()  # draft/sent/paid/overdue

    sql = """
    SELECT f.*,
           p.name as project_name,
           pa.company as partner_company,
           t.stage_name as talent_name
    FROM finance_items f
    LEFT JOIN projects p ON p.id = f.project_id
    LEFT JOIN partners pa ON pa.id = f.partner_id
    LEFT JOIN talents t ON t.id = f.talent_id
    WHERE 1=1
    """
    params: list[Any] = []

    if q:
        sql += " AND (COALESCE(f.title,'') LIKE ? OR COALESCE(f.notes,'') LIKE ? OR COALESCE(p.name,'') LIKE ? OR COALESCE(pa.company,'') LIKE ? OR COALESCE(t.stage_name,'') LIKE ?)"
        like = f"%{q}%"
        params += [like, like, like, like, like]

    if f_type in ("AR", "AP"):
        sql += " AND f.type = ?"
        params.append(f_type)

    if f_status in ("draft", "sent", "paid", "overdue"):
        sql += " AND f.status = ?"
        params.append(f_status)

    sql += " ORDER BY COALESCE(f.due_date,'9999-12-31') ASC, f.id DESC"

    with get_db() as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
        sum_rows = conn.execute(
            """
            SELECT type, COALESCE(SUM(amount),0) as total
            FROM finance_items
            WHERE status != 'paid'
            GROUP BY type
            """
        ).fetchall()

    totals = {r["type"]: int(r["total"]) for r in sum_rows}
    return render_template("finance.html", rows=rows, q=q, f_type=f_type, f_status=f_status, totals=totals)


@app.route("/finance/new", methods=["GET", "POST"])
@login_required
@require_perm("edit_finance")
def finance_new():
    projects_ = list_projects()
    partners_ = list_partners()
    talents_ = list_talents_simple()

    if request.method == "POST":
        data = {
            "type": (request.form.get("type") or "AR").strip(),
            "project_id": (request.form.get("project_id") or "").strip(),
            "partner_id": (request.form.get("partner_id") or "").strip(),
            "talent_id": (request.form.get("talent_id") or "").strip(),
            "title": (request.form.get("title") or "").strip(),
            "amount": int((request.form.get("amount") or "0") or 0),
            "due_date": (request.form.get("due_date") or "").strip(),
            "status": (request.form.get("status") or "draft").strip(),
            "notes": (request.form.get("notes") or "").strip(),
        }

        if data["type"] not in ("AR", "AP"):
            data["type"] = "AR"
        if data["status"] not in ("draft", "sent", "paid", "overdue"):
            data["status"] = "draft"

        def to_int_or_none(x: str) -> Optional[int]:
            return int(x) if x.isdigit() else None

        project_id = to_int_or_none(data["project_id"])
        partner_id = to_int_or_none(data["partner_id"])
        talent_id = to_int_or_none(data["talent_id"])

        if data["amount"] < 0:
            flash("金額不可為負數", "error")
            return render_template(
                "finance_form.html",
                item=data,
                mode="new",
                projects=projects_,
                partners=partners_,
                talents=talents_,
            )

        if data["due_date"] and not parse_yyyy_mm_dd(data["due_date"]):
            flash("到期日格式請用 YYYY-MM-DD", "error")
            return render_template(
                "finance_form.html",
                item=data,
                mode="new",
                projects=projects_,
                partners=partners_,
                talents=talents_,
            )

        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO finance_items (type, project_id, partner_id, talent_id, title, amount, due_date, status, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["type"],
                    project_id,
                    partner_id,
                    talent_id,
                    data["title"] or None,
                    data["amount"],
                    data["due_date"] or None,
                    data["status"],
                    data["notes"] or None,
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()

        return redirect(url_for("finance"))

    return render_template(
        "finance_form.html",
        item={},
        mode="new",
        projects=projects_,
        partners=partners_,
        talents=talents_,
    )


@app.route("/finance/<int:fid>/edit", methods=["GET", "POST"])
@login_required
@require_perm("edit_finance")
def finance_edit(fid: int):
    projects_ = list_projects()
    partners_ = list_partners()
    talents_ = list_talents_simple()

    with get_db() as conn:
        item = conn.execute("SELECT * FROM finance_items WHERE id = ?", (fid,)).fetchone()
        if not item:
            flash("找不到該筆資料", "error")
            return redirect(url_for("finance"))

    if request.method == "POST":
        data = {
            "type": (request.form.get("type") or "AR").strip(),
            "project_id": (request.form.get("project_id") or "").strip(),
            "partner_id": (request.form.get("partner_id") or "").strip(),
            "talent_id": (request.form.get("talent_id") or "").strip(),
            "title": (request.form.get("title") or "").strip(),
            "amount": int((request.form.get("amount") or "0") or 0),
            "due_date": (request.form.get("due_date") or "").strip(),
            "status": (request.form.get("status") or "draft").strip(),
            "notes": (request.form.get("notes") or "").strip(),
        }

        if data["type"] not in ("AR", "AP"):
            data["type"] = "AR"
        if data["status"] not in ("draft", "sent", "paid", "overdue"):
            data["status"] = "draft"

        def to_int_or_none(x: str) -> Optional[int]:
            return int(x) if x.isdigit() else None

        project_id = to_int_or_none(data["project_id"])
        partner_id = to_int_or_none(data["partner_id"])
        talent_id = to_int_or_none(data["talent_id"])

        if data["amount"] < 0:
            flash("金額不可為負數", "error")
            return render_template(
                "finance_form.html",
                item=data,
                mode="edit",
                projects=projects_,
                partners=partners_,
                talents=talents_,
            )

        if data["due_date"] and not parse_yyyy_mm_dd(data["due_date"]):
            flash("到期日格式請用 YYYY-MM-DD", "error")
            return render_template(
                "finance_form.html",
                item=data,
                mode="edit",
                projects=projects_,
                partners=partners_,
                talents=talents_,
            )

        with get_db() as conn:
            conn.execute(
                """
                UPDATE finance_items
                SET type=?, project_id=?, partner_id=?, talent_id=?, title=?, amount=?, due_date=?, status=?, notes=?
                WHERE id=?
                """,
                (
                    data["type"],
                    project_id,
                    partner_id,
                    talent_id,
                    data["title"] or None,
                    data["amount"],
                    data["due_date"] or None,
                    data["status"],
                    data["notes"] or None,
                    fid,
                ),
            )
            conn.commit()

        return redirect(url_for("finance"))

    return render_template(
        "finance_form.html",
        item=dict(item),
        mode="edit",
        projects=projects_,
        partners=partners_,
        talents=talents_,
    )


@app.route("/finance/<int:fid>/delete", methods=["POST"])
@login_required
@require_perm("edit_finance")
def finance_delete(fid: int):
    with get_db() as conn:
        conn.execute("DELETE FROM finance_items WHERE id = ?", (fid,))
        conn.commit()
    return redirect(url_for("finance"))


# =========================
# Admin: Users / Roles
# =========================
def get_user_perm_codes_for_admin(conn: sqlite3.Connection, user_id: int) -> list[str]:
    rows = conn.execute(
        """
        SELECT DISTINCT p.code
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        JOIN permissions p ON p.id = rp.perm_id
        WHERE ur.user_id = ?
        ORDER BY p.code
        """,
        (user_id,),
    ).fetchall()
    return [r["code"] for r in rows]


@app.route("/admin/users")
@login_required
@require_perm("admin_users")
def admin_users():
    with get_db() as conn:
        users = conn.execute(
            "SELECT id, username, role, is_active, must_change_password, created_at FROM users ORDER BY id ASC"
        ).fetchall()
        roles = conn.execute("SELECT id, name FROM roles ORDER BY id ASC").fetchall()
        ur = conn.execute("SELECT user_id, role_id FROM user_roles").fetchall()

        user_role_map: Dict[int, Set[int]] = {}
        for r in ur:
            user_role_map.setdefault(int(r["user_id"]), set()).add(int(r["role_id"]))

        user_perm_map: Dict[int, list[str]] = {}
        for u in users:
            user_perm_map[int(u["id"])] = get_user_perm_codes_for_admin(conn, int(u["id"]))

    role_templates = {
        "Ops（營運）": ["Ops"],
        "Agent（主經紀）": ["Agent"],
        "Assistant（助理）": ["Assistant"],
        "Finance（財務）": ["Finance"],
        "Viewer（只讀）": ["Viewer"],
        "Owner（全權限）": ["Owner"],
        "經紀+助理（雙角色）": ["Agent", "Assistant"],
    }

    return render_template(
        "admin_users.html",
        users=users,
        roles=roles,
        user_role_map=user_role_map,
        user_perm_map=user_perm_map,
        role_templates=role_templates,
    )


@app.route("/admin/users/new", methods=["POST"])
@login_required
@require_perm("admin_users")
def admin_user_new():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    must_change = 1 if (request.form.get("must_change_password") == "1") else 0

    if not username or not password:
        flash("帳號與密碼必填", "error")
        return redirect(url_for("admin_users"))

    if len(password) < 8:
        flash("初始密碼至少 8 碼", "error")
        return redirect(url_for("admin_users"))

    with get_db() as conn:
        try:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    generate_password_hash(password, method="pbkdf2:sha256"),
                    "member",
                    1,
                    must_change,
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()
            flash("已建立使用者", "success")
        except sqlite3.IntegrityError:
            flash("帳號已存在", "error")

    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/toggle_active", methods=["POST"])
@login_required
@require_perm("admin_users")
def admin_user_toggle_active(user_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT is_active FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            flash("找不到使用者", "error")
            return redirect(url_for("admin_users"))
        new_val = 0 if int(row["is_active"]) == 1 else 1
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (new_val, user_id))
        conn.commit()

    flash("已更新帳號狀態", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/roles", methods=["POST"])
@login_required
@require_perm("admin_users")
def admin_user_roles(user_id: int):
    role_ids = request.form.getlist("role_ids")
    role_ids_int = [int(x) for x in role_ids if str(x).isdigit()]

    with get_db() as conn:
        conn.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
        for rid in role_ids_int:
            conn.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                (user_id, rid),
            )
        conn.commit()

    flash("已更新角色", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/apply_template", methods=["POST"])
@login_required
@require_perm("admin_users")
def admin_user_apply_template(user_id: int):
    template_name = (request.form.get("template_name") or "").strip()

    role_templates = {
        "Ops（營運）": ["Ops"],
        "Agent（主經紀）": ["Agent"],
        "Assistant（助理）": ["Assistant"],
        "Finance（財務）": ["Finance"],
        "Viewer（只讀）": ["Viewer"],
        "Owner（全權限）": ["Owner"],
        "經紀+助理（雙角色）": ["Agent", "Assistant"],
    }

    role_names = role_templates.get(template_name)
    if not role_names:
        flash("找不到該模板", "error")
        return redirect(url_for("admin_users"))

    with get_db() as conn:
        role_rows = conn.execute(
            f"SELECT id, name FROM roles WHERE name IN ({','.join(['?']*len(role_names))})",
            tuple(role_names),
        ).fetchall()
        role_ids = [int(r["id"]) for r in role_rows]

        conn.execute("DELETE FROM user_roles WHERE user_id=?", (user_id,))
        for rid in role_ids:
            conn.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                (user_id, rid),
            )
        conn.commit()

    flash("已套用角色模板", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/reset_password", methods=["POST"])
@login_required
@require_perm("admin_users")
def admin_user_reset_password(user_id: int):
    newpw = (request.form.get("new_password") or "").strip()
    force = 1 if (request.form.get("force_change") == "1") else 0

    if not newpw:
        flash("新密碼必填", "error")
        return redirect(url_for("admin_users"))

    if len(newpw) < 8:
        flash("新密碼至少 8 碼", "error")
        return redirect(url_for("admin_users"))

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash=?, must_change_password=? WHERE id=?",
            (generate_password_hash(newpw, method="pbkdf2:sha256"), force, user_id),
        )
        conn.commit()

    flash("已重設密碼", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/roles")
@login_required
@require_perm("admin_roles")
def admin_roles():
    with get_db() as conn:
        roles_ = conn.execute("SELECT * FROM roles ORDER BY id ASC").fetchall()
    return render_template("admin_roles.html", roles=roles_)


@app.route("/admin/roles/<int:role_id>/edit", methods=["GET", "POST"])
@login_required
@require_perm("admin_roles")
def admin_role_edit(role_id: int):
    with get_db() as conn:
        role = conn.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()
        if not role:
            flash("找不到角色", "error")
            return redirect(url_for("admin_roles"))

        perms_ = conn.execute("SELECT * FROM permissions ORDER BY id ASC").fetchall()
        rp_rows = conn.execute(
            "SELECT perm_id FROM role_permissions WHERE role_id=?",
            (role_id,),
        ).fetchall()
        selected_perm_ids = {int(r["perm_id"]) for r in rp_rows}

        if request.method == "POST":
            new_name = (request.form.get("name") or "").strip()
            new_desc = (request.form.get("description") or "").strip()
            perm_ids = request.form.getlist("perm_ids")
            perm_ids_int = [int(x) for x in perm_ids if str(x).isdigit()]

            if new_name:
                conn.execute(
                    "UPDATE roles SET name=?, description=? WHERE id=?",
                    (new_name, new_desc or None, role_id),
                )

            conn.execute("DELETE FROM role_permissions WHERE role_id=?", (role_id,))
            for pid in perm_ids_int:
                conn.execute(
                    "INSERT OR IGNORE INTO role_permissions (role_id, perm_id) VALUES (?, ?)",
                    (role_id, pid),
                )
            conn.commit()

            flash("已更新角色權限", "success")
            return redirect(url_for("admin_roles"))

    return render_template(
        "admin_role_edit.html",
        role=role,
        perms=perms_,
        selected_perm_ids=selected_perm_ids,
    )


# =========================
# Approvals V2
# =========================
@app.route("/approvals")
@login_required
@require_perm("view_approvals")
def approvals():
    q = (request.args.get("q") or "").strip()
    f_type = (request.args.get("type") or "").strip()
    f_status = (request.args.get("status") or "").strip()

    sql = """
    SELECT d.*,
           cu.username AS creator_name,
           u2.username AS level_2_name,
           u3.username AS level_3_name
    FROM approval_documents d
    LEFT JOIN users cu ON cu.id = d.creator_id
    LEFT JOIN users u2 ON u2.id = d.level_2_approver_id
    LEFT JOIN users u3 ON u3.id = d.level_3_approver_id
    WHERE 1=1
    """
    params: list[Any] = []

    if q:
        like = f"%{q}%"
        sql += " AND (d.title LIKE ? OR COALESCE(d.content,'') LIKE ?)"
        params += [like, like]

    if f_type in ("general", "hr", "finance"):
        sql += " AND d.type = ?"
        params.append(f_type)

    if f_status in ("draft", "submitted", "reviewing", "approved", "returned_to_previous", "returned_to_creator", "cancelled"):
        sql += " AND d.status = ?"
        params.append(f_status)

    sql += " ORDER BY d.id DESC"

    with get_db() as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()

    return render_template(
        "approvals.html",
        rows=rows,
        q=q,
        f_type=f_type,
        f_status=f_status,
    )


@app.route("/approvals/new", methods=["GET", "POST"])
@login_required
@require_perm("create_approvals")
def approval_new():
    level_2_users = get_users_with_perm("approve_level_2")
    level_3_users = get_users_with_perm("approve_level_3")

    if request.method == "POST":
        data = {
            "title": (request.form.get("title") or "").strip(),
            "type": (request.form.get("type") or "general").strip(),
            "department": (request.form.get("department") or "").strip(),
            "amount": int((request.form.get("amount") or "0") or 0),
            "content": (request.form.get("content") or "").strip(),
            "level_2_approver_id": (request.form.get("level_2_approver_id") or "").strip(),
            "level_3_approver_id": (request.form.get("level_3_approver_id") or "").strip(),
        }

        if not data["title"]:
            flash("標題必填", "error")
            return render_template(
                "approval_form.html",
                item=data,
                mode="new",
                level_2_users=level_2_users,
                level_3_users=level_3_users,
            )

        if data["type"] not in ("general", "hr", "finance"):
            data["type"] = "general"

        if not data["level_2_approver_id"].isdigit():
            flash("請選擇第二層簽核人", "error")
            return render_template(
                "approval_form.html",
                item=data,
                mode="new",
                level_2_users=level_2_users,
                level_3_users=level_3_users,
            )

        if not data["level_3_approver_id"].isdigit():
            flash("請選擇第三層簽核人", "error")
            return render_template(
                "approval_form.html",
                item=data,
                mode="new",
                level_2_users=level_2_users,
                level_3_users=level_3_users,
            )

        level_2_id = int(data["level_2_approver_id"])
        level_3_id = int(data["level_3_approver_id"])

        with get_db() as conn:
            cur = conn.execute(
                """
                INSERT INTO approval_documents
                (title, type, creator_id, department, status, amount, content,
                 level_2_approver_id, level_3_approver_id, current_step, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["title"],
                    data["type"],
                    int(current_user.id),
                    data["department"] or None,
                    "submitted",
                    data["amount"],
                    data["content"] or None,
                    level_2_id,
                    level_3_id,
                    2,
                    datetime.utcnow().isoformat(),
                    datetime.utcnow().isoformat(),
                ),
            )
            doc_id = cur.lastrowid
            conn.commit()

        build_or_reset_approval_steps(doc_id, int(current_user.id), level_2_id, level_3_id)
        log_approval_action(doc_id, "submit", int(current_user.id), "建立並送出簽核")
        flash("公文已建立並送出簽核", "success")
        return redirect(url_for("approval_detail", doc_id=doc_id))

    return render_template(
        "approval_form.html",
        item={},
        mode="new",
        level_2_users=level_2_users,
        level_3_users=level_3_users,
    )


@app.route("/approvals/<int:doc_id>")
@login_required
@require_perm("view_approvals")
def approval_detail(doc_id: int):
    doc = get_approval_document(doc_id)
    if not doc:
        flash("找不到該公文", "error")
        return redirect(url_for("approvals"))

    steps = get_approval_steps(doc_id)
    logs = get_approval_logs(doc_id)

    can_act = approval_can_user_act(doc, int(current_user.id))

    return render_template(
        "approval_detail.html",
        doc=doc,
        steps=steps,
        logs=logs,
        can_act=can_act,
    )


@app.route("/approvals/<int:doc_id>/approve", methods=["POST"])
@login_required
@require_perm("approve_approvals")
def approval_approve(doc_id: int):
    comment = (request.form.get("comment") or "").strip()

    doc = get_approval_document(doc_id)
    if not doc:
        flash("找不到該公文", "error")
        return redirect(url_for("approvals"))

    if not approval_can_user_act(doc, int(current_user.id)):
        flash("目前不是你的簽核步驟", "error")
        return redirect(url_for("approval_detail", doc_id=doc_id))

    with get_db() as conn:
        if int(doc["current_step"]) == 2:
            conn.execute(
                """
                UPDATE approval_steps
                SET status='approved', comment=?, approved_at=?
                WHERE document_id=? AND step_order=2
                """,
                (comment or None, datetime.utcnow().isoformat(), doc_id),
            )
            conn.execute(
                """
                UPDATE approval_documents
                SET current_step=3, status='reviewing', updated_at=?
                WHERE id=?
                """,
                (datetime.utcnow().isoformat(), doc_id),
            )
        elif int(doc["current_step"]) == 3:
            conn.execute(
                """
                UPDATE approval_steps
                SET status='approved', comment=?, approved_at=?
                WHERE document_id=? AND step_order=3
                """,
                (comment or None, datetime.utcnow().isoformat(), doc_id),
            )
            conn.execute(
                """
                UPDATE approval_documents
                SET current_step=3, status='approved', updated_at=?
                WHERE id=?
                """,
                (datetime.utcnow().isoformat(), doc_id),
            )
        conn.commit()

    log_approval_action(doc_id, "approve", int(current_user.id), comment or "核准")
    flash("已核准", "success")
    return redirect(url_for("approval_detail", doc_id=doc_id))


@app.route("/approvals/<int:doc_id>/return-to-previous", methods=["POST"])
@login_required
@require_perm("approve_approvals")
def approval_return_to_previous(doc_id: int):
    comment = (request.form.get("comment") or "").strip()
    if not comment:
        flash("退回上一層請填寫原因", "error")
        return redirect(url_for("approval_detail", doc_id=doc_id))

    doc = get_approval_document(doc_id)
    if not doc:
        flash("找不到該公文", "error")
        return redirect(url_for("approvals"))

    if not approval_can_user_act(doc, int(current_user.id)):
        flash("目前不是你的簽核步驟", "error")
        return redirect(url_for("approval_detail", doc_id=doc_id))

    if int(doc["current_step"]) != 3:
        flash("只有第三層可退回上一層", "error")
        return redirect(url_for("approval_detail", doc_id=doc_id))

    with get_db() as conn:
        conn.execute(
            """
            UPDATE approval_steps
            SET status='returned', comment=?, approved_at=?
            WHERE document_id=? AND step_order=3
            """,
            (comment, datetime.utcnow().isoformat(), doc_id),
        )
        conn.execute(
            """
            UPDATE approval_steps
            SET status='pending', comment=NULL, approved_at=NULL
            WHERE document_id=? AND step_order=2
            """,
            (doc_id,),
        )
        conn.execute(
            """
            UPDATE approval_documents
            SET current_step=2, status='returned_to_previous', updated_at=?
            WHERE id=?
            """,
            (datetime.utcnow().isoformat(), doc_id),
        )
        conn.commit()

    log_approval_action(doc_id, "return_to_previous", int(current_user.id), comment)
    flash("已退回上一層簽核人", "success")
    return redirect(url_for("approval_detail", doc_id=doc_id))


@app.route("/approvals/<int:doc_id>/return-to-creator", methods=["POST"])
@login_required
@require_perm("approve_approvals")
def approval_return_to_creator(doc_id: int):
    comment = (request.form.get("comment") or "").strip()
    if not comment:
        flash("退回申請人請填寫原因", "error")
        return redirect(url_for("approval_detail", doc_id=doc_id))

    doc = get_approval_document(doc_id)
    if not doc:
        flash("找不到該公文", "error")
        return redirect(url_for("approvals"))

    if not approval_can_user_act(doc, int(current_user.id)):
        flash("目前不是你的簽核步驟", "error")
        return redirect(url_for("approval_detail", doc_id=doc_id))

    with get_db() as conn:
        conn.execute(
            """
            UPDATE approval_steps
            SET status='returned', comment=?, approved_at=?
            WHERE document_id=? AND step_order=?
            """,
            (comment, datetime.utcnow().isoformat(), doc_id, int(doc["current_step"])),
        )
        conn.execute(
            """
            UPDATE approval_documents
            SET current_step=1, status='returned_to_creator', updated_at=?
            WHERE id=?
            """,
            (datetime.utcnow().isoformat(), doc_id),
        )
        conn.commit()

    log_approval_action(doc_id, "return_to_creator", int(current_user.id), comment)
    flash("已退回申請人", "success")
    return redirect(url_for("approval_detail", doc_id=doc_id))


@app.route("/approvals/<int:doc_id>/resubmit", methods=["POST"])
@login_required
@require_perm("create_approvals")
def approval_resubmit(doc_id: int):
    doc = get_approval_document(doc_id)
    if not doc:
        flash("找不到該公文", "error")
        return redirect(url_for("approvals"))

    if int(doc["creator_id"]) != int(current_user.id):
        flash("只有申請人可重新送出", "error")
        return redirect(url_for("approval_detail", doc_id=doc_id))

    if doc["status"] != "returned_to_creator":
        flash("目前不可重新送出", "error")
        return redirect(url_for("approval_detail", doc_id=doc_id))

    build_or_reset_approval_steps(
        doc_id,
        int(doc["creator_id"]),
        int(doc["level_2_approver_id"]),
        int(doc["level_3_approver_id"]),
    )

    with get_db() as conn:
        conn.execute(
            """
            UPDATE approval_documents
            SET current_step=2, status='submitted', updated_at=?
            WHERE id=?
            """,
            (datetime.utcnow().isoformat(), doc_id),
        )
        conn.commit()

    log_approval_action(doc_id, "resubmit", int(current_user.id), "申請人重新送出")
    flash("已重新送出簽核", "success")
    return redirect(url_for("approval_detail", doc_id=doc_id))


# =========================
# Tasks
# =========================
@app.route("/tasks")
@login_required
@require_perm("view_tasks")
def tasks():
    q = (request.args.get("q") or "").strip()
    f_assignee = (request.args.get("assignee") or "").strip()
    f_status = (request.args.get("status") or "").strip()  # open/done
    f_related = (request.args.get("related") or "").strip()  # talent/project/partner/finance

    sql = "SELECT * FROM tasks WHERE 1=1"
    params: list[Any] = []

    if q:
        like = f"%{q}%"
        sql += " AND (title LIKE ? OR COALESCE(notes,'') LIKE ?)"
        params += [like, like]

    if f_assignee:
        sql += " AND COALESCE(assignee,'') LIKE ?"
        params.append(f"%{f_assignee}%")

    if f_status in ("open", "done"):
        sql += " AND status = ?"
        params.append(f_status)

    if f_related in ("talent", "project", "partner", "finance"):
        sql += " AND related_type = ?"
        params.append(f_related)

    sql += " ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, COALESCE(due_date,'9999-12-31') ASC, id DESC"

    with get_db() as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()

    return render_template(
        "tasks.html",
        rows=rows,
        q=q,
        f_assignee=f_assignee,
        f_status=f_status,
        f_related=f_related,
    )


@app.route("/tasks/new", methods=["GET", "POST"])
@login_required
@require_perm("edit_tasks")
def task_new():
    projects_ = list_projects()
    partners_ = list_partners()
    talents_ = list_talents_simple()

    if request.method == "POST":
        data = {
            "title": (request.form.get("title") or "").strip(),
            "assignee": (request.form.get("assignee") or "").strip(),
            "due_date": (request.form.get("due_date") or "").strip(),
            "priority": (request.form.get("priority") or "P2").strip(),
            "status": (request.form.get("status") or "open").strip(),
            "related_type": (request.form.get("related_type") or "").strip(),
            "related_id": (request.form.get("related_id") or "").strip(),
            "notes": (request.form.get("notes") or "").strip(),
        }

        if not data["title"]:
            flash("標題必填", "error")
            return render_template(
                "task_form.html",
                item=data,
                mode="new",
                projects=projects_,
                partners=partners_,
                talents=talents_,
            )

        if data["due_date"] and not parse_yyyy_mm_dd(data["due_date"]):
            flash("到期日格式請用 YYYY-MM-DD", "error")
            return render_template(
                "task_form.html",
                item=data,
                mode="new",
                projects=projects_,
                partners=partners_,
                talents=talents_,
            )

        if data["priority"] not in ("P1", "P2", "P3"):
            data["priority"] = "P2"
        if data["status"] not in ("open", "done"):
            data["status"] = "open"
        if data["related_type"] not in ("", "talent", "project", "partner", "finance"):
            data["related_type"] = ""

        rid = int(data["related_id"]) if data["related_id"].isdigit() else None
        if data["related_type"] == "":
            rid = None

        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO tasks (title, assignee, due_date, priority, status, related_type, related_id, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["title"],
                    data["assignee"] or None,
                    data["due_date"] or None,
                    data["priority"],
                    data["status"],
                    data["related_type"] or None,
                    rid,
                    data["notes"] or None,
                    datetime.utcnow().isoformat(),
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()

        return redirect(url_for("tasks"))

    return render_template(
        "task_form.html",
        item={},
        mode="new",
        projects=projects_,
        partners=partners_,
        talents=talents_,
    )


@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
@require_perm("edit_tasks")
def task_edit(task_id: int):
    projects_ = list_projects()
    partners_ = list_partners()
    talents_ = list_talents_simple()

    with get_db() as conn:
        item = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not item:
            flash("找不到該筆資料", "error")
            return redirect(url_for("tasks"))

    if request.method == "POST":
        data = {
            "title": (request.form.get("title") or "").strip(),
            "assignee": (request.form.get("assignee") or "").strip(),
            "due_date": (request.form.get("due_date") or "").strip(),
            "priority": (request.form.get("priority") or "P2").strip(),
            "status": (request.form.get("status") or "open").strip(),
            "related_type": (request.form.get("related_type") or "").strip(),
            "related_id": (request.form.get("related_id") or "").strip(),
            "notes": (request.form.get("notes") or "").strip(),
        }

        if not data["title"]:
            flash("標題必填", "error")
            return render_template(
                "task_form.html",
                item=data,
                mode="edit",
                projects=projects_,
                partners=partners_,
                talents=talents_,
            )

        if data["due_date"] and not parse_yyyy_mm_dd(data["due_date"]):
            flash("到期日格式請用 YYYY-MM-DD", "error")
            return render_template(
                "task_form.html",
                item=data,
                mode="edit",
                projects=projects_,
                partners=partners_,
                talents=talents_,
            )

        if data["priority"] not in ("P1", "P2", "P3"):
            data["priority"] = "P2"
        if data["status"] not in ("open", "done"):
            data["status"] = "open"
        if data["related_type"] not in ("", "talent", "project", "partner", "finance"):
            data["related_type"] = ""

        rid = int(data["related_id"]) if data["related_id"].isdigit() else None
        if data["related_type"] == "":
            rid = None

        with get_db() as conn:
            conn.execute(
                """
                UPDATE tasks
                SET title=?, assignee=?, due_date=?, priority=?, status=?, related_type=?, related_id=?, notes=?, updated_at=?
                WHERE id=?
                """,
                (
                    data["title"],
                    data["assignee"] or None,
                    data["due_date"] or None,
                    data["priority"],
                    data["status"],
                    data["related_type"] or None,
                    rid,
                    data["notes"] or None,
                    datetime.utcnow().isoformat(),
                    task_id,
                ),
            )
            conn.commit()

        return redirect(url_for("tasks"))

    return render_template(
        "task_form.html",
        item=dict(item),
        mode="edit",
        projects=projects_,
        partners=partners_,
        talents=talents_,
    )


@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
@login_required
@require_perm("edit_tasks")
def task_toggle(task_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row:
            flash("找不到該筆資料", "error")
            return redirect(url_for("tasks"))
        new_status = "done" if row["status"] == "open" else "open"
        conn.execute(
            "UPDATE tasks SET status=?, updated_at=? WHERE id=?",
            (new_status, datetime.utcnow().isoformat(), task_id),
        )
        conn.commit()
    return redirect(url_for("tasks"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
@require_perm("edit_tasks")
def task_delete(task_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        conn.commit()
    return redirect(url_for("tasks"))


# =========================
# Error pages
# =========================
@app.errorhandler(403)
def forbidden(_e):
    return render_template("403.html"), 403


# =========================
# Main
# =========================
if __name__ == "__main__":
    app.run()
