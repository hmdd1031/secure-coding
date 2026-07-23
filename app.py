from __future__ import annotations

import os
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
import unicodedata
import uuid
import warnings
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urljoin, urlparse
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.exceptions import SecurityError
from werkzeug.security import check_password_hash, generate_password_hash

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
REAL_NAME_RE = re.compile(r"^[가-힣A-Za-z][가-힣A-Za-z ]{1,29}$")
NICKNAME_RE = re.compile(r"^[가-힣A-Za-z0-9_]{2,20}$")
PHONE_RE = re.compile(r"^01(?:0|1|[6-9])-?\d{3,4}-?\d{4}$")
POSTAL_CODE_RE = re.compile(r"^\d{5}$")
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
ALLOWED_IMAGE_MIME_TYPES = {"image/png", "image/jpeg", "image/webp"}
PRODUCT_CATEGORIES = (
    "디지털기기",
    "의류",
    "생활용품",
    "도서",
    "취미/굿즈",
    "스포츠",
    "가구",
    "기타",
)
TRADE_STATUS_LABELS = {
    "active": "거래중",
    "reserved": "예약중",
    "sold": "거래완료",
}
BOARD_CATEGORIES = (
    "자유",
    "거래후기",
    "질문",
    "정보공유",
)
REPORT_REASON_CATEGORIES = (
    "금지 품목",
    "사기 의심",
    "허위·중복 게시물",
    "욕설·괴롭힘",
    "개인정보 노출",
    "기타",
)
PROHIBITED_PRODUCT_KEYWORDS = (
    "마약",
    "대마",
    "필로폰",
    "코카인",
    "총기",
    "권총",
    "소총",
    "실탄",
    "탄약",
    "폭발물",
    "수류탄",
    "도검",
    "위조지폐",
    "신분증",
    "여권판매",
    "개인정보판매",
    "처방전",
    "처방약",
    "담배",
    "전자담배",
    "주류판매",
    "계정판매",
    "불법복제품",
)
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5
LOGIN_IP_MAX_ATTEMPTS = 20
LOGIN_ACCOUNT_MAX_ATTEMPTS = 10
REPORT_THRESHOLD = 3
MAX_IMAGE_PIXELS = 25_000_000
UPLOAD_FILENAME_RE = re.compile(r"^[a-f0-9]{32}\.webp$")
SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
FORBIDDEN_CONTROL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))
KST = ZoneInfo("Asia/Seoul")


def format_kst(value: object) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(KST).strftime("%Y-%m-%d %H:%M KST")


def _load_or_create_secret_key(instance_path: str) -> str:
    """환경변수를 우선 사용하고, 로컬 개발용 키는 instance에 안전하게 보관한다."""
    configured = os.environ.get("SECRET_KEY", "")
    if configured:
        if len(configured) < 32:
            raise RuntimeError("SECRET_KEY는 32자 이상으로 설정해야 합니다.")
        return configured

    secret_path = Path(instance_path) / ".secret_key"
    try:
        existing = secret_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        existing = ""
    if len(existing) >= 32:
        return existing

    secret_path.parent.mkdir(parents=True, exist_ok=True)
    generated = secrets.token_hex(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(secret_path, flags, 0o600)
    except FileExistsError:
        existing = secret_path.read_text(encoding="utf-8").strip()
        if len(existing) < 32:
            raise RuntimeError("instance/.secret_key 파일이 손상되었습니다.")
        return existing
    with os.fdopen(descriptor, "w", encoding="utf-8") as secret_file:
        secret_file.write(generated)
    return generated


def _configured_trusted_hosts() -> list[str]:
    configured = os.environ.get("TRUSTED_HOSTS", "")
    if configured:
        hosts = [host.strip() for host in configured.split(",") if host.strip()]
        if hosts:
            return hosts
    return ["localhost", ".localhost", "127.0.0.1", "[::1]"]


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    default_upload_folder = str(Path(app.instance_path) / "uploads")
    configured_test_secret = (test_config or {}).get("SECRET_KEY")
    secret_key = (
        str(configured_test_secret)
        if configured_test_secret is not None
        else _load_or_create_secret_key(app.instance_path)
    )
    app.config.from_mapping(
        SECRET_KEY=secret_key,
        DATABASE=os.environ.get("DATABASE_PATH")
        or str(Path(app.instance_path) / "shop.db"),
        MAX_CONTENT_LENGTH=4 * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=1024 * 1024,
        MAX_FORM_PARTS=100,
        TRUSTED_HOSTS=_configured_trusted_hosts(),
        SESSION_COOKIE_NAME="white_market_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_SECURE_COOKIE") == "1",
        SESSION_REFRESH_EACH_REQUEST=False,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        UPLOAD_FOLDER=default_upload_folder,
        SEND_FILE_MAX_AGE_DEFAULT=timedelta(days=7),
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    try:
        Path(app.config["UPLOAD_FOLDER"]).chmod(0o700)
    except OSError:
        app.logger.warning("업로드 폴더 권한을 변경하지 못했습니다.")

    app.jinja_env.filters["kst"] = format_kst
    app.teardown_appcontext(close_db)
    register_security_hooks(app)
    register_routes(app)

    with app.app_context():
        init_db()

    return app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
            timeout=10,
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 10000")
        g.db.execute("PRAGMA trusted_schema = OFF")
    return g.db


def close_db(_error: Exception | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _safe_sql_identifier(value: str) -> str:
    if not SQL_IDENTIFIER_RE.fullmatch(value):
        raise ValueError("허용되지 않은 SQL 식별자입니다.")
    return f'"{value}"'


def _column_names(db: sqlite3.Connection, table_name: str) -> set[str]:
    safe_table_name = _safe_sql_identifier(table_name)
    return {row["name"] for row in db.execute(f"PRAGMA table_info({safe_table_name})")}


def _ensure_column(
    db: sqlite3.Connection, table_name: str, column_name: str, definition: str
) -> None:
    if column_name not in _column_names(db, table_name):
        safe_table_name = _safe_sql_identifier(table_name)
        safe_column_name = _safe_sql_identifier(column_name)
        db.execute(
            f"ALTER TABLE {safe_table_name} ADD COLUMN {safe_column_name} {definition}"
        )


def migrate_schema(db: sqlite3.Connection) -> None:
    """기존 과제 DB도 데이터를 잃지 않고 새 요구사항으로 확장한다."""
    for column_name, definition in (
        ("real_name", "TEXT NOT NULL DEFAULT ''"),
        ("nickname", "TEXT NOT NULL DEFAULT ''"),
        ("phone", "TEXT NOT NULL DEFAULT ''"),
        ("postal_code", "TEXT NOT NULL DEFAULT ''"),
        ("address", "TEXT NOT NULL DEFAULT ''"),
        ("address_city", "TEXT NOT NULL DEFAULT ''"),
        ("address_district", "TEXT NOT NULL DEFAULT ''"),
        ("address_neighborhood", "TEXT NOT NULL DEFAULT ''"),
        ("address_detail", "TEXT NOT NULL DEFAULT ''"),
        ("privacy_consent", "INTEGER NOT NULL DEFAULT 0"),
        ("third_party_consent", "INTEGER NOT NULL DEFAULT 0"),
        ("consent_at", "TEXT"),
        ("session_version", "INTEGER NOT NULL DEFAULT 0"),
    ):
        _ensure_column(db, "users", column_name, definition)

    db.execute("UPDATE users SET real_name = username WHERE length(trim(real_name)) = 0")
    db.execute("UPDATE users SET nickname = username WHERE length(trim(nickname)) = 0")
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nickname_unique "
        "ON users(nickname COLLATE NOCASE) WHERE length(trim(nickname)) > 0"
    )

    for column_name, definition in (
        ("category", "TEXT NOT NULL DEFAULT '기타'"),
        ("trade_status", "TEXT NOT NULL DEFAULT 'active'"),
    ):
        _ensure_column(db, "products", column_name, definition)

    for column_name, definition in (
        ("is_read", "INTEGER NOT NULL DEFAULT 0"),
        ("read_at", "TEXT"),
    ):
        _ensure_column(db, "messages", column_name, definition)

    _ensure_column(db, "reports", "reason_category", "TEXT NOT NULL DEFAULT '기타'")
    _ensure_column(db, "transfers", "request_token", "TEXT")

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS global_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS board_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL,
            category TEXT NOT NULL DEFAULT '자유',
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            view_count INTEGER NOT NULL DEFAULT 0 CHECK (view_count >= 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS board_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES board_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS product_submission_tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS auth_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rate_key TEXT NOT NULL,
            attempted_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS action_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_name TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            occurred_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor_id INTEGER,
            target_type TEXT,
            target_id INTEGER,
            ip_hash TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_unread
            ON messages(receiver_id, is_read);
        CREATE INDEX IF NOT EXISTS idx_global_messages_id
            ON global_messages(id);
        CREATE INDEX IF NOT EXISTS idx_board_posts_id
            ON board_posts(id);
        CREATE INDEX IF NOT EXISTS idx_board_comments_post
            ON board_comments(post_id, id);
        CREATE INDEX IF NOT EXISTS idx_auth_attempts_key_time
            ON auth_attempts(rate_key, attempted_at);
        CREATE INDEX IF NOT EXISTS idx_action_events_user_time
            ON action_events(action_name, user_id, occurred_at);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created
            ON audit_logs(id DESC);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_transfers_request_token
            ON transfers(request_token) WHERE request_token IS NOT NULL;

        CREATE TRIGGER IF NOT EXISTS trg_products_image_required_insert
        BEFORE INSERT ON products
        WHEN NEW.image_filename IS NULL OR length(trim(NEW.image_filename)) = 0
        BEGIN
            SELECT RAISE(ABORT, 'product image is required');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_products_image_required_update
        BEFORE UPDATE OF image_filename ON products
        WHEN NEW.image_filename IS NULL OR length(trim(NEW.image_filename)) = 0
        BEGIN
            SELECT RAISE(ABORT, 'product image is required');
        END;
        """
    )
    db.execute(
        """
        UPDATE products
        SET trade_status = CASE
            WHEN status = 'sold' THEN 'sold'
            WHEN trade_status NOT IN ('active', 'reserved', 'sold') THEN 'active'
            ELSE trade_status
        END
        """
    )
    # 공개 상태와 거래 상태를 분리한다. 기존 sold 공개 상태는 공개(active)로 이관한다.
    db.execute("UPDATE products SET status = 'active' WHERE status = 'sold'")
    # 관리자는 과제용 송금 주체가 아니므로 가상 잔액을 보유하지 않는다.
    db.execute("UPDATE users SET balance = 0 WHERE is_admin = 1")
    db.execute(
        "DELETE FROM auth_attempts WHERE attempted_at < ?",
        (int(time.time()) - 86_400,),
    )
    db.execute(
        "DELETE FROM action_events WHERE occurred_at < ?",
        (int(time.time()) - 86_400,),
    )
    db.execute(
        """
        UPDATE products
        SET image_filename = '../img/information.png'
        WHERE image_filename IS NULL OR length(trim(image_filename)) = 0
        """
    )


def init_db() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            real_name TEXT NOT NULL,
            nickname TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            bio TEXT NOT NULL DEFAULT '',
            phone TEXT NOT NULL DEFAULT '',
            postal_code TEXT NOT NULL DEFAULT '',
            address TEXT NOT NULL DEFAULT '',
            address_city TEXT NOT NULL DEFAULT '',
            address_district TEXT NOT NULL DEFAULT '',
            address_neighborhood TEXT NOT NULL DEFAULT '',
            address_detail TEXT NOT NULL DEFAULT '',
            privacy_consent INTEGER NOT NULL DEFAULT 0 CHECK (privacy_consent IN (0, 1)),
            third_party_consent INTEGER NOT NULL DEFAULT 0 CHECK (third_party_consent IN (0, 1)),
            consent_at TEXT,
            balance INTEGER NOT NULL DEFAULT 100000 CHECK (balance >= 0),
            is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
            is_suspended INTEGER NOT NULL DEFAULT 0 CHECK (is_suspended IN (0, 1)),
            session_version INTEGER NOT NULL DEFAULT 0 CHECK (session_version >= 0),
            report_count INTEGER NOT NULL DEFAULT 0 CHECK (report_count >= 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price INTEGER NOT NULL CHECK (price >= 0),
            image_filename TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '기타'
                CHECK (category IN ('디지털기기', '의류', '생활용품', '도서', '취미/굿즈', '스포츠', '가구', '기타')),
            trade_status TEXT NOT NULL DEFAULT 'active'
                CHECK (trade_status IN ('active', 'reserved', 'sold')),
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'sold', 'hidden')),
            report_count INTEGER NOT NULL DEFAULT 0 CHECK (report_count >= 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS qna (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0 CHECK (is_read IN (0, 1)),
            read_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER NOT NULL,
            target_type TEXT NOT NULL CHECK (target_type IN ('user', 'product')),
            target_id INTEGER NOT NULL,
            reason_category TEXT NOT NULL DEFAULT '기타',
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (reporter_id, target_type, target_id),
            FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            amount INTEGER NOT NULL CHECK (amount > 0),
            request_token TEXT UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS global_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS board_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL,
            category TEXT NOT NULL DEFAULT '자유',
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            view_count INTEGER NOT NULL DEFAULT 0 CHECK (view_count >= 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS board_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES board_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS product_submission_tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS auth_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rate_key TEXT NOT NULL,
            attempted_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS action_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_name TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            occurred_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor_id INTEGER,
            target_type TEXT,
            target_id INTEGER,
            ip_hash TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_products_name ON products(name);
        CREATE INDEX IF NOT EXISTS idx_qna_product ON qna(product_id);
        CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id);
        CREATE INDEX IF NOT EXISTS idx_global_messages_id ON global_messages(id);
        CREATE INDEX IF NOT EXISTS idx_board_posts_id ON board_posts(id);
        CREATE INDEX IF NOT EXISTS idx_board_comments_post ON board_comments(post_id, id);
        CREATE INDEX IF NOT EXISTS idx_auth_attempts_key_time
            ON auth_attempts(rate_key, attempted_at);
        CREATE INDEX IF NOT EXISTS idx_action_events_user_time
            ON action_events(action_name, user_id, occurred_at);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(id DESC);
        """
    )
    migrate_schema(db)

    # 환경변수가 없을 때는 예측 가능한 기본 비밀번호를 두지 않는다.
    # 환경변수를 제공한 경우에도 일반 회원과 동일한 강도 정책을 적용한다.
    admin_password = os.environ.get("ADMIN_PASSWORD") or f"Aa1!{secrets.token_urlsafe(24)}"
    demo_password = os.environ.get("DEMO_PASSWORD") or f"Aa1!{secrets.token_urlsafe(24)}"
    for variable_name, seed_password in (
        ("ADMIN_PASSWORD", admin_password),
        ("DEMO_PASSWORD", demo_password),
    ):
        password_error = validate_password(seed_password)
        if password_error:
            raise RuntimeError(f"{variable_name}: {password_error}")
    db.execute(
        """
        INSERT OR IGNORE INTO users
            (username, real_name, nickname, password_hash, bio, balance, is_admin)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        """,
        ("admin", "관리자", "화이트관리자", generate_password_hash(admin_password), "화이트 마켓 관리자", 0),
    )
    db.execute(
        """
        INSERT OR IGNORE INTO users
            (username, real_name, nickname, password_hash, bio, balance)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        ("ganadi", "가나디", "가나디상점", generate_password_hash(demo_password), "가나디 굿즈를 판매합니다.", 100_000),
    )
    seller = db.execute(
        "SELECT id FROM users WHERE username = ?", ("ganadi",)
    ).fetchone()
    product_count = db.execute("SELECT COUNT(*) AS count FROM products").fetchone()["count"]
    if seller and product_count == 0:
        db.execute(
            """
            INSERT INTO products
                (seller_id, name, description, price, image_filename, category, trade_status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                seller["id"],
                "가나디 나 안아 티셔츠",
                "깨끗하게 보관한 가나디 반팔 티셔츠입니다. 중고거래 실습용 상품입니다.",
                25_900,
                "../img/tee1.png",
                "취미/굿즈",
                "active",
            ),
        )
    db.commit()
    try:
        Path(current_app.config["DATABASE"]).chmod(0o600)
    except OSError:
        current_app.logger.warning("데이터베이스 파일 권한을 변경하지 못했습니다.")


def register_security_hooks(app: Flask) -> None:
    @app.before_request
    def protect_mutating_requests() -> None:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            expected = session.get("_csrf_token")
            supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not expected or not supplied or not secrets.compare_digest(expected, supplied):
                abort(400, "CSRF token validation failed")

    @app.context_processor
    def inject_security_values() -> dict:
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        user = get_current_user()
        unread_count = 0
        if user:
            unread_count = get_db().execute(
                "SELECT COUNT(*) AS count FROM messages WHERE receiver_id = ? AND is_read = 0",
                (user["id"],),
            ).fetchone()["count"]
        return {
            "csrf_token": token,
            "current_user": user,
            "unread_message_count": unread_count,
            "trade_status_labels": TRADE_STATUS_LABELS,
            "product_image_url": product_image_url,
        }

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; font-src 'self' data:; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if session.get("user_id") or request.endpoint in {"login", "signup", "update_password"}:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.errorhandler(400)
    def bad_request(error):
        # 신뢰하지 않는 Host 헤더는 URL 어댑터 생성 전에 거부된다. 이 경우
        # url_for를 사용하는 일반 템플릿을 렌더링하면 2차 예외가 발생하므로,
        # 외부 입력을 반영하지 않는 고정 응답을 반환한다.
        if isinstance(error, SecurityError):
            return (
                "<!doctype html><html lang='ko'><meta charset='utf-8'>"
                "<title>400</title><h1>잘못된 요청입니다.</h1></html>",
                400,
                {"Content-Type": "text/html; charset=utf-8"},
            )
        return render_template("error.html", code=400, message="잘못된 요청입니다."), 400

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="권한이 없습니다."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="페이지를 찾을 수 없습니다."), 404

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("error.html", code=413, message="이미지 파일은 4MB 이하여야 합니다."), 413

    @app.errorhandler(500)
    def internal_error(_error):
        db = g.get("db")
        if db is not None:
            db.rollback()
        return render_template("error.html", code=500, message="서버 오류가 발생했습니다."), 500


def get_current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or session.get("session_version") != user["session_version"]:
        session.clear()
        return None
    return user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        if user["is_suspended"]:
            session.clear()
            flash("휴면 처리된 계정입니다.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if not user or not user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def is_safe_next_url(target: str | None) -> bool:
    if not target:
        return False
    if "\\" in target or FORBIDDEN_CONTROL_RE.search(target) or "\r" in target or "\n" in target:
        return False
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return redirect_url.scheme in {"http", "https"} and host_url.netloc == redirect_url.netloc


def safe_back_url(default: str) -> str:
    referrer = request.referrer
    return referrer if is_safe_next_url(referrer) else default


def validate_password(password: str) -> str | None:
    if len(password) < 10 or len(password) > 128:
        return "비밀번호는 10자 이상 128자 이하여야 합니다."
    if not re.search(r"[a-z]", password):
        return "비밀번호에는 영문 소문자가 포함되어야 합니다."
    if not re.search(r"[A-Z]", password):
        return "비밀번호에는 영문 대문자가 포함되어야 합니다."
    if not re.search(r"\d", password):
        return "비밀번호에는 숫자가 포함되어야 합니다."
    if not re.search(r"[^A-Za-z0-9\s]", password):
        return "비밀번호에는 특수문자가 포함되어야 합니다."
    return None


def has_forbidden_text_controls(value: str, *, multiline: bool = False) -> bool:
    if FORBIDDEN_CONTROL_RE.search(value):
        return True
    if not multiline and ("\r" in value or "\n" in value):
        return True
    return any(unicodedata.category(character) == "Cf" for character in value)


def validate_user_text(value: str, *, multiline: bool = False) -> bool:
    return not has_forbidden_text_controls(value, multiline=multiline)


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def parse_bounded_int(value: str, *, minimum: int, maximum: int) -> int | None:
    if not value or len(value) > len(str(maximum)) or not value.isascii() or not value.isdigit():
        return None
    parsed = int(value)
    return parsed if minimum <= parsed <= maximum else None


def _hash_rate_key(value: str) -> str:
    secret = str(current_app.config["SECRET_KEY"]).encode("utf-8")
    return hmac.new(
        secret,
        value.encode("utf-8", errors="ignore"),
        hashlib.sha256,
    ).hexdigest()


def _client_ip_hash() -> str:
    return _hash_rate_key(request.remote_addr or "unknown")


def login_rate_keys(username: str) -> tuple[tuple[str, int], ...]:
    ip_address = request.remote_addr or "unknown"
    normalized_username = username.casefold()
    return (
        (_hash_rate_key(f"pair\0{ip_address}\0{normalized_username}"), LOGIN_MAX_ATTEMPTS),
        (_hash_rate_key(f"ip\0{ip_address}"), LOGIN_IP_MAX_ATTEMPTS),
        (_hash_rate_key(f"account\0{normalized_username}"), LOGIN_ACCOUNT_MAX_ATTEMPTS),
    )


def login_is_rate_limited(keys: tuple[tuple[str, int], ...]) -> bool:
    now = int(time.time())
    cutoff = now - LOGIN_WINDOW_SECONDS
    db = get_db()
    db.execute("DELETE FROM auth_attempts WHERE attempted_at < ?", (cutoff,))
    blocked = False
    for rate_key, limit in keys:
        count = db.execute(
            "SELECT COUNT(*) AS count FROM auth_attempts WHERE rate_key = ? AND attempted_at >= ?",
            (rate_key, cutoff),
        ).fetchone()["count"]
        if count >= limit:
            blocked = True
            break
    db.commit()
    return blocked


def write_audit_log(
    db: sqlite3.Connection,
    event_type: str,
    *,
    actor_id: int | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
    details: dict | None = None,
) -> None:
    if not re.fullmatch(r"[a-z0-9_.-]{3,50}", event_type):
        raise ValueError("잘못된 감사 로그 이벤트입니다.")
    serialized_details = json.dumps(details or {}, ensure_ascii=False, separators=(",", ":"))[:1000]
    db.execute(
        """
        INSERT INTO audit_logs
            (event_type, actor_id, target_type, target_id, ip_hash, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (event_type, actor_id, target_type, target_id, _client_ip_hash(), serialized_details),
    )


def record_failed_login(keys: tuple[tuple[str, int], ...], username: str) -> None:
    now = int(time.time())
    db = get_db()
    db.executemany(
        "INSERT INTO auth_attempts (rate_key, attempted_at) VALUES (?, ?)",
        ((rate_key, now) for rate_key, _limit in keys),
    )
    write_audit_log(db, "auth.login_failed", details={"username": username[:20]})
    db.commit()


def clear_login_failures(keys: tuple[tuple[str, int], ...]) -> None:
    db = get_db()
    pair_key, account_key = keys[0][0], keys[2][0]
    db.execute("DELETE FROM auth_attempts WHERE rate_key IN (?, ?)", (pair_key, account_key))
    db.commit()


def consume_action_quota(
    action_name: str,
    user_id: int,
    *,
    limit: int,
    window_seconds: int,
) -> bool:
    if not re.fullmatch(r"[a-z0-9_.-]{3,40}", action_name):
        raise ValueError("잘못된 요청 제한 이름입니다.")
    now = int(time.time())
    cutoff = now - window_seconds
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "DELETE FROM action_events WHERE action_name = ? AND user_id = ? AND occurred_at < ?",
            (action_name, user_id, cutoff),
        )
        count = db.execute(
            """
            SELECT COUNT(*) AS count FROM action_events
            WHERE action_name = ? AND user_id = ? AND occurred_at >= ?
            """,
            (action_name, user_id, cutoff),
        ).fetchone()["count"]
        if count >= limit:
            db.commit()
            return False
        db.execute(
            "INSERT INTO action_events (action_name, user_id, occurred_at) VALUES (?, ?, ?)",
            (action_name, user_id, now),
        )
        db.commit()
        return True
    except sqlite3.Error:
        db.rollback()
        raise


def normalize_phone(phone: str) -> str | None:
    compact = re.sub(r"[^0-9]", "", phone)
    if len(compact) == 10:
        normalized = f"{compact[:3]}-{compact[3:6]}-{compact[6:]}"
    elif len(compact) == 11:
        normalized = f"{compact[:3]}-{compact[3:7]}-{compact[7:]}"
    else:
        return None
    return normalized if PHONE_RE.fullmatch(normalized) else None


def validate_contact_fields(
    phone: str,
    postal_code: str,
    address_city: str,
    address_district: str,
    address_neighborhood: str,
    address_detail: str,
) -> tuple[str | None, str | None]:
    values = (phone, postal_code, address_city, address_district, address_neighborhood, address_detail)
    if any(not validate_user_text(value, multiline=False) for value in values):
        return None, "연락처와 주소에 허용되지 않은 제어 문자가 포함되어 있습니다."
    normalized_phone = normalize_phone(phone)
    if not normalized_phone:
        return None, "올바른 휴대전화 번호를 입력하세요."
    if not POSTAL_CODE_RE.fullmatch(postal_code):
        return None, "우편번호는 숫자 5자리로 입력하세요."
    if not 2 <= len(address_city) <= 30:
        return None, "시·도는 2~30자로 입력하세요."
    if not 2 <= len(address_district) <= 30:
        return None, "시·군·구는 2~30자로 입력하세요."
    if not 1 <= len(address_neighborhood) <= 30:
        return None, "읍·면·동은 1~30자로 입력하세요."
    if not 1 <= len(address_detail) <= 100:
        return None, "번지, 건물명, 동·호수 등 상세 주소를 1~100자로 입력하세요."
    return normalized_phone, None


def normalize_market_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).lower()
    return re.sub(r"[\s\W_]+", "", normalized, flags=re.UNICODE)


def find_prohibited_keyword(*values: str) -> str | None:
    text = normalize_market_text(" ".join(values))
    for keyword in PROHIBITED_PRODUCT_KEYWORDS:
        if normalize_market_text(keyword) in text:
            return keyword
    return None


def validate_product_fields(
    name: str, description: str, price_text: str, category: str
) -> tuple[int | None, str | None]:
    price = parse_bounded_int(price_text, minimum=0, maximum=10_000_000)
    if not validate_user_text(name) or not validate_user_text(description, multiline=True):
        return None, "상품 정보에 허용되지 않은 제어 문자가 포함되어 있습니다."
    if not 2 <= len(name) <= 80:
        return None, "상품명은 2~80자로 입력하세요."
    if not 5 <= len(description) <= 2000:
        return None, "상품 설명은 5~2000자로 입력하세요."
    if price is None:
        return None, "가격은 0원 이상 1천만 원 이하로 입력하세요."
    if category not in PRODUCT_CATEGORIES:
        return None, "올바른 상품 카테고리를 선택하세요."
    prohibited = find_prohibited_keyword(name, description)
    if prohibited:
        return None, f"중고거래 금지 품목에 해당하여 등록할 수 없습니다: {prohibited}"
    return price, None


def save_uploaded_image(file_storage, *, required: bool = False) -> str | None:
    if not file_storage or not file_storage.filename:
        if required:
            raise ValueError("상품 이미지는 반드시 등록해야 합니다.")
        return None

    if "." not in file_storage.filename:
        raise ValueError("이미지 파일의 확장자를 확인하세요.")
    extension = file_storage.filename.rsplit(".", 1)[-1].lower()
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("PNG, JPG, JPEG, WEBP 이미지만 업로드할 수 있습니다.")
    if file_storage.mimetype not in ALLOWED_IMAGE_MIME_TYPES:
        raise ValueError("이미지 MIME 형식이 올바르지 않습니다.")

    filename = f"{uuid.uuid4().hex}.webp"
    upload_folder = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    destination = upload_folder / filename
    temporary = upload_folder / f".{filename}.{secrets.token_hex(8)}.tmp"

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(file_storage.stream) as probe:
                actual_format = (probe.format or "").upper()
                if actual_format not in {"PNG", "JPEG", "WEBP"}:
                    raise ValueError("지원하지 않는 실제 이미지 형식입니다.")
                if probe.width <= 0 or probe.height <= 0:
                    raise ValueError("이미지 크기가 올바르지 않습니다.")
                if probe.width * probe.height > MAX_IMAGE_PIXELS:
                    raise ValueError("이미지 해상도가 너무 큽니다.")
                probe.verify()

            file_storage.stream.seek(0)
            with Image.open(file_storage.stream) as source:
                if source.width * source.height > MAX_IMAGE_PIXELS:
                    raise ValueError("이미지 해상도가 너무 큽니다.")
                source = ImageOps.exif_transpose(source)
                source.thumbnail((1600, 1600))
                if source.mode == "RGBA":
                    clean_image = Image.new("RGBA", source.size)
                else:
                    clean_image = Image.new("RGB", source.size, "white")
                    if source.mode != "RGB":
                        source = source.convert("RGB")
                clean_image.paste(source)
                clean_image.save(temporary, "WEBP", quality=88, method=6)
                clean_image.close()
        try:
            temporary.chmod(0o600)
        except OSError:
            current_app.logger.warning("임시 업로드 파일 권한을 변경하지 못했습니다.")
        os.replace(temporary, destination)
        return filename
    except ValueError:
        temporary.unlink(missing_ok=True)
        raise
    except (
        UnidentifiedImageError,
        OSError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as exc:
        temporary.unlink(missing_ok=True)
        raise ValueError("유효한 이미지 파일이 아닙니다.") from exc


def remove_uploaded_image(filename: str | None) -> None:
    if not filename or filename.startswith("../img/"):
        return
    if not UPLOAD_FILENAME_RE.fullmatch(filename):
        current_app.logger.warning("허용되지 않은 업로드 파일명 삭제 요청 차단: %r", filename)
        return
    upload_folder = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    target = (upload_folder / filename).resolve()
    if target.parent != upload_folder:
        current_app.logger.warning("업로드 경로 이탈 삭제 요청 차단: %s", target)
        return
    try:
        target.unlink(missing_ok=True)
    except OSError:
        current_app.logger.warning("업로드 이미지 삭제 실패: %s", target)


def product_image_url(filename: str | None) -> str:
    if filename and filename.startswith("../img/"):
        demo_name = Path(filename).name
        if demo_name in {"tee1.png", "information.png"}:
            return url_for("static", filename=f"img/{demo_name}")
    if filename and UPLOAD_FILENAME_RE.fullmatch(filename):
        return url_for("product_media", filename=filename)
    return url_for("static", filename="img/information.png")


def fetch_product_or_404(product_id: int, include_hidden: bool = False) -> sqlite3.Row:
    product = get_db().execute(
        """
        SELECT p.*, u.username AS seller_name,
               COALESCE(NULLIF(u.nickname, ''), u.username) AS seller_nickname,
               u.is_suspended AS seller_suspended, u.bio AS seller_bio
        FROM products p JOIN users u ON p.seller_id = u.id
        WHERE p.id = ?
        """,
        (product_id,),
    ).fetchone()
    if not product or (product["status"] == "hidden" and not include_hidden):
        abort(404)
    return product


def fetch_public_user_or_404(username: str) -> sqlite3.Row:
    user = get_db().execute(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
    ).fetchone()
    viewer = get_current_user()
    if not user or (user["is_suspended"] and not (viewer and viewer["is_admin"])):
        abort(404)
    return user


def apply_report(
    reporter: sqlite3.Row,
    target_type: str,
    target_id: int,
    reason_category: str,
    reason: str,
) -> str | None:
    if reason_category not in REPORT_REASON_CATEGORIES:
        return "신고 유형을 선택하세요."
    if not validate_user_text(reason, multiline=True):
        return "신고 사유에 허용되지 않은 제어 문자가 포함되어 있습니다."
    if not 10 <= len(reason) <= 300:
        return "신고 사유는 10~300자로 입력하세요."
    if not consume_action_quota("report.create", reporter["id"], limit=10, window_seconds=3600):
        return "신고 요청이 너무 많습니다. 잠시 후 다시 시도하세요."

    db = get_db()
    if target_type == "user":
        target = db.execute("SELECT * FROM users WHERE id = ?", (target_id,)).fetchone()
        if not target or target["id"] == reporter["id"] or target["is_admin"]:
            abort(400)
    elif target_type == "product":
        target = db.execute("SELECT * FROM products WHERE id = ?", (target_id,)).fetchone()
        if not target or target["seller_id"] == reporter["id"]:
            abort(400)
    else:
        abort(400)

    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            """
            INSERT INTO reports
                (reporter_id, target_type, target_id, reason_category, reason)
            VALUES (?, ?, ?, ?, ?)
            """,
            (reporter["id"], target_type, target_id, reason_category, reason),
        )
        if target_type == "product":
            db.execute(
                "UPDATE products SET report_count = report_count + 1 WHERE id = ?",
                (target_id,),
            )
            count = db.execute(
                "SELECT report_count FROM products WHERE id = ?", (target_id,)
            ).fetchone()["report_count"]
            if count >= REPORT_THRESHOLD:
                db.execute("UPDATE products SET status = 'hidden' WHERE id = ?", (target_id,))
        else:
            db.execute(
                "UPDATE users SET report_count = report_count + 1 WHERE id = ?",
                (target_id,),
            )
            count = db.execute(
                "SELECT report_count FROM users WHERE id = ?", (target_id,)
            ).fetchone()["report_count"]
            if count >= REPORT_THRESHOLD:
                db.execute(
                    """
                    UPDATE users
                    SET is_suspended = 1, session_version = session_version + 1
                    WHERE id = ? AND is_suspended = 0
                    """,
                    (target_id,),
                )
        write_audit_log(
            db,
            "report.created",
            actor_id=reporter["id"],
            target_type=target_type,
            target_id=target_id,
            details={"reason_category": reason_category},
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return "같은 대상을 중복 신고할 수 없습니다."
    return None



def issue_product_submission_token() -> str:
    token = secrets.token_urlsafe(32)
    session["product_submission_token"] = token
    return token


def validate_product_submission_token(token: str) -> bool:
    expected = session.get("product_submission_token")
    return bool(expected and token and secrets.compare_digest(expected, token))


def issue_transfer_submission_token() -> str:
    token = secrets.token_urlsafe(32)
    session["transfer_submission_token"] = token
    return token


def validate_transfer_submission_token(token: str) -> bool:
    expected = session.get("transfer_submission_token")
    return bool(expected and token and secrets.compare_digest(expected, token))


def can_send_product_message(
    db: sqlite3.Connection,
    *,
    product: sqlite3.Row,
    sender_id: int,
    receiver_id: int,
) -> bool:
    seller_id = product["seller_id"]
    if sender_id != seller_id:
        return receiver_id == seller_id
    if receiver_id == seller_id:
        return False
    return (
        db.execute(
            """
            SELECT 1 FROM messages
            WHERE product_id = ?
              AND ((sender_id = ? AND receiver_id = ?)
                   OR (sender_id = ? AND receiver_id = ?))
            LIMIT 1
            """,
            (product["id"], receiver_id, seller_id, seller_id, receiver_id),
        ).fetchone()
        is not None
    )


def is_recent_duplicate_product(
    db: sqlite3.Connection,
    seller_id: int,
    name: str,
    description: str,
    price: int,
    category: str,
) -> bool:
    return db.execute(
        """
        SELECT 1
        FROM products
        WHERE seller_id = ? AND name = ? AND description = ?
          AND price = ? AND category = ?
          AND created_at >= datetime('now', '-60 seconds')
        LIMIT 1
        """,
        (seller_id, name, description, price, category),
    ).fetchone() is not None

def register_routes(app: Flask) -> None:
    @app.get("/media/products/<filename>")
    def product_media(filename: str):
        if not UPLOAD_FILENAME_RE.fullmatch(filename):
            abort(404)
        return send_from_directory(
            current_app.config["UPLOAD_FOLDER"],
            filename,
            mimetype="image/webp",
            as_attachment=False,
            max_age=7 * 24 * 60 * 60,
        )

    @app.route("/")
    def index():
        query = request.args.get("q", "").strip()[:50]
        if not validate_user_text(query):
            abort(400)
        selected_category = request.args.get("category", "").strip()
        if selected_category and selected_category not in PRODUCT_CATEGORIES:
            abort(400)
        db = get_db()
        sql = """
            SELECT p.*, u.username AS seller_name, COALESCE(NULLIF(u.nickname, ''), u.username) AS seller_nickname
            FROM products p JOIN users u ON p.seller_id = u.id
            WHERE p.status != 'hidden' AND u.is_suspended = 0
        """
        params: list[str] = []
        if query:
            sql += (
                " AND (p.name LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\' "
                "OR p.category LIKE ? ESCAPE '\\')"
            )
            like = f"%{escape_like(query)}%"
            params.extend((like, like, like))
        if selected_category:
            sql += " AND p.category = ?"
            params.append(selected_category)
        sql += " ORDER BY p.id DESC"
        products = db.execute(sql, tuple(params)).fetchall()
        return render_template(
            "index.html",
            products=products,
            query=query,
            categories=PRODUCT_CATEGORIES,
            selected_category=selected_category,
        )

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            real_name = request.form.get("real_name", "").strip()
            nickname = request.form.get("nickname", "").strip()
            password = request.form.get("password", "")
            password_confirm = request.form.get("password_confirm", "")
            phone = request.form.get("phone", "").strip()
            postal_code = request.form.get("postal_code", "").strip()
            address_city = request.form.get("address_city", "").strip()
            address_district = request.form.get("address_district", "").strip()
            address_neighborhood = request.form.get("address_neighborhood", "").strip()
            address_detail = request.form.get("address_detail", "").strip()
            privacy_consent = request.form.get("privacy_consent") == "on"

            error = None
            normalized_phone = None
            if not USERNAME_RE.fullmatch(username):
                error = "아이디는 영문, 숫자, 밑줄로 3~20자만 사용할 수 있습니다."
            elif not REAL_NAME_RE.fullmatch(real_name):
                error = "이름은 한글 또는 영문과 공백으로 2~30자 입력하세요."
            elif not NICKNAME_RE.fullmatch(nickname):
                error = "닉네임은 한글, 영문, 숫자, 밑줄로 2~20자 입력하세요."
            elif password != password_confirm:
                error = "비밀번호 확인이 일치하지 않습니다."
            else:
                error = validate_password(password)
            if not error:
                normalized_phone, error = validate_contact_fields(
                    phone, postal_code, address_city, address_district, address_neighborhood, address_detail
                )
            if not error and not privacy_consent:
                error = "개인정보 수집·이용에 동의해야 가입할 수 있습니다."

            if error:
                flash(error, "error")
            else:
                try:
                    db = get_db()
                    combined_address = f"{address_city} {address_district} {address_neighborhood}"
                    db.execute(
                        """
                        INSERT INTO users
                            (username, real_name, nickname, password_hash, phone, postal_code,
                             address, address_city, address_district, address_neighborhood,
                             address_detail, privacy_consent, third_party_consent, consent_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, CURRENT_TIMESTAMP)
                        """,
                        (
                            username, real_name, nickname, generate_password_hash(password),
                            normalized_phone, postal_code, combined_address, address_city, address_district,
                            address_neighborhood, address_detail,
                        ),
                    )
                    new_user = db.execute(
                        "SELECT id FROM users WHERE username = ?", (username,)
                    ).fetchone()
                    write_audit_log(
                        db,
                        "auth.signup",
                        actor_id=new_user["id"] if new_user else None,
                        target_type="user",
                        target_id=new_user["id"] if new_user else None,
                    )
                    db.commit()
                    flash("회원가입이 완료되었습니다. 로그인해 주세요.", "success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    flash("이미 사용 중인 아이디 또는 닉네임입니다.", "error")
        return render_template("signup.html")

    @app.get("/policies/privacy")
    def privacy_policy():
        return render_template("privacy_policy.html")

    @app.get("/policies/third-party")
    def third_party_policy():
        return redirect(url_for("privacy_policy"), code=301)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        next_page = request.args.get("next") or request.form.get("next")
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            password = request.form.get("password", "")
            rate_keys = login_rate_keys(username)
            if login_is_rate_limited(rate_keys):
                flash("로그인 시도가 너무 많습니다. 5분 후 다시 시도하세요.", "error")
                return render_template("login.html", next=next_page), 429

            user = get_db().execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            password_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
            password_matches = check_password_hash(password_hash, password)

            if not user or not password_matches:
                record_failed_login(rate_keys, username)
                flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
            elif user["is_suspended"]:
                record_failed_login(rate_keys, username)
                flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
            else:
                clear_login_failures(rate_keys)
                session.clear()
                session["user_id"] = user["id"]
                session["session_version"] = user["session_version"]
                session["_csrf_token"] = secrets.token_urlsafe(32)
                session.permanent = True
                db = get_db()
                write_audit_log(
                    db,
                    "auth.login_success",
                    actor_id=user["id"],
                    target_type="user",
                    target_id=user["id"],
                )
                db.commit()
                flash(f"{user['nickname'] or user['username']}님, 환영합니다!", "success")
                if is_safe_next_url(next_page):
                    return redirect(next_page)
                return redirect(url_for("index"))
        return render_template("login.html", next=next_page)

    @app.post("/logout")
    def logout():
        user = get_current_user()
        if user:
            db = get_db()
            write_audit_log(
                db,
                "auth.logout",
                actor_id=user["id"],
                target_type="user",
                target_id=user["id"],
            )
            db.commit()
        session.clear()
        flash("로그아웃되었습니다.", "info")
        return redirect(url_for("index"))

    @app.get("/profile")
    @login_required
    def profile():
        user = get_current_user()
        products = get_db().execute(
            "SELECT * FROM products WHERE seller_id = ? ORDER BY id DESC", (user["id"],)
        ).fetchall()
        return render_template("profile.html", user=user, products=products)

    @app.post("/profile/bio")
    @login_required
    def update_bio():
        user = get_current_user()
        bio = request.form.get("bio", "").strip()
        if not validate_user_text(bio, multiline=True):
            flash("소개글에 허용되지 않은 제어 문자가 포함되어 있습니다.", "error")
        elif len(bio) > 300:
            flash("소개글은 300자 이하여야 합니다.", "error")
        else:
            db = get_db()
            db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user["id"]))
            write_audit_log(
                db,
                "profile.bio_updated",
                actor_id=user["id"],
                target_type="user",
                target_id=user["id"],
            )
            db.commit()
            flash("소개글을 수정했습니다.", "success")
        return redirect(url_for("profile"))

    @app.post("/profile/contact")
    @login_required
    def update_contact():
        user = get_current_user()
        phone = request.form.get("phone", "").strip()
        postal_code = request.form.get("postal_code", "").strip()
        address_city = request.form.get("address_city", "").strip()
        address_district = request.form.get("address_district", "").strip()
        address_neighborhood = request.form.get("address_neighborhood", "").strip()
        address_detail = request.form.get("address_detail", "").strip()
        normalized_phone, error = validate_contact_fields(
            phone, postal_code, address_city, address_district, address_neighborhood, address_detail
        )
        if error:
            flash(error, "error")
        else:
            db = get_db()
            combined_address = f"{address_city} {address_district} {address_neighborhood}"
            db.execute(
                """
                UPDATE users
                SET phone = ?, postal_code = ?, address = ?, address_city = ?,
                    address_district = ?, address_neighborhood = ?, address_detail = ?
                WHERE id = ?
                """,
                (normalized_phone, postal_code, combined_address, address_city, address_district,
                 address_neighborhood, address_detail, user["id"]),
            )
            write_audit_log(
                db, "profile.contact_updated", actor_id=user["id"],
                target_type="user", target_id=user["id"]
            )
            db.commit()
            flash("연락처와 주소를 수정했습니다.", "success")
        return redirect(url_for("profile"))

    @app.route("/profile/password", methods=["GET", "POST"])
    @login_required
    def update_password():
        user = get_current_user()
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            new_password_confirm = request.form.get("new_password_confirm", "")
            if not check_password_hash(user["password_hash"], current_password):
                flash("현재 비밀번호가 올바르지 않습니다.", "error")
            elif new_password != new_password_confirm:
                flash("새 비밀번호 확인이 일치하지 않습니다.", "error")
            elif error := validate_password(new_password):
                flash(error, "error")
            elif check_password_hash(user["password_hash"], new_password):
                flash("기존 비밀번호와 다른 비밀번호를 사용하세요.", "error")
            else:
                db = get_db()
                db.execute(
                    """
                    UPDATE users
                    SET password_hash = ?, session_version = session_version + 1
                    WHERE id = ?
                    """,
                    (generate_password_hash(new_password), user["id"]),
                )
                write_audit_log(
                    db,
                    "auth.password_changed",
                    actor_id=user["id"],
                    target_type="user",
                    target_id=user["id"],
                )
                db.commit()
                session.clear()
                flash("비밀번호를 변경했습니다. 다시 로그인해 주세요.", "success")
                return redirect(url_for("login"))
        return render_template("password_change.html")

    @app.get("/users/<username>")
    def public_profile(username: str):
        profile_user = fetch_public_user_or_404(username)
        viewer = get_current_user()
        db = get_db()
        if viewer and viewer["is_admin"]:
            products = db.execute(
                "SELECT * FROM products WHERE seller_id = ? ORDER BY id DESC",
                (profile_user["id"],),
            ).fetchall()
            user_reports = db.execute(
                """
                SELECT rp.*, reporter.username AS reporter_name, COALESCE(NULLIF(reporter.nickname, ''), reporter.username) AS reporter_nickname
                FROM reports rp
                JOIN users reporter ON rp.reporter_id = reporter.id
                WHERE rp.target_type = 'user' AND rp.target_id = ?
                ORDER BY rp.id DESC
                """,
                (profile_user["id"],),
            ).fetchall()
            product_report_total = db.execute(
                """
                SELECT COUNT(*) AS count
                FROM reports rp
                JOIN products p ON rp.target_type = 'product' AND rp.target_id = p.id
                WHERE p.seller_id = ?
                """,
                (profile_user["id"],),
            ).fetchone()["count"]
        else:
            products = db.execute(
                """
                SELECT * FROM products
                WHERE seller_id = ? AND status != 'hidden'
                ORDER BY id DESC
                """,
                (profile_user["id"],),
            ).fetchall()
            user_reports = []
            product_report_total = 0
        return render_template(
            "public_profile.html",
            profile_user=profile_user,
            products=products,
            user_reports=user_reports,
            product_report_total=product_report_total,
        )

    @app.route("/products/new", methods=["GET", "POST"])
    @login_required
    def add_product():
        user = get_current_user()
        if user["is_admin"]:
            abort(403)
        form_token = session.get("product_submission_token") or issue_product_submission_token()
        if request.method == "POST":
            submitted_token = request.form.get("submission_token", "")
            if not validate_product_submission_token(submitted_token):
                flash("이미 처리되었거나 만료된 상품 등록 요청입니다. 새 등록 화면에서 다시 시도하세요.", "error")
                return redirect(url_for("add_product"))

            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            price_text = request.form.get("price", "").strip()
            category = request.form.get("category", "").strip()
            image = request.files.get("image")
            price, error = validate_product_fields(name, description, price_text, category)
            image_filename = None
            if not error:
                try:
                    image_filename = save_uploaded_image(image, required=True)
                except ValueError as exc:
                    error = str(exc)

            if error:
                flash(error, "error")
            else:
                db = get_db()
                try:
                    db.execute("BEGIN IMMEDIATE")
                    # 동일 폼 토큰은 DB에서도 한 번만 사용할 수 있다.
                    db.execute(
                        "INSERT INTO product_submission_tokens (token, user_id) VALUES (?, ?)",
                        (submitted_token, user["id"]),
                    )
                    if is_recent_duplicate_product(
                        db, user["id"], name, description, price, category
                    ):
                        raise ValueError("같은 상품이 방금 등록되었습니다. 중복 등록을 확인해 주세요.")
                    cursor = db.execute(
                        """
                        INSERT INTO products
                            (seller_id, name, description, price, image_filename,
                             category, trade_status, status)
                        VALUES (?, ?, ?, ?, ?, ?, 'active', 'active')
                        """,
                        (user["id"], name, description, price, image_filename, category),
                    )
                    write_audit_log(
                        db,
                        "product.created",
                        actor_id=user["id"],
                        target_type="product",
                        target_id=cursor.lastrowid,
                    )
                    db.execute(
                        "DELETE FROM product_submission_tokens WHERE created_at < datetime('now', '-1 day')"
                    )
                    db.commit()
                except ValueError as exc:
                    db.rollback()
                    remove_uploaded_image(image_filename)
                    flash(str(exc), "error")
                except sqlite3.IntegrityError:
                    db.rollback()
                    remove_uploaded_image(image_filename)
                    flash("상품 등록 요청이 이미 처리되었습니다. 중복 등록하지 않았습니다.", "info")
                    return redirect(url_for("profile"))
                except sqlite3.Error:
                    db.rollback()
                    remove_uploaded_image(image_filename)
                    raise
                else:
                    session.pop("product_submission_token", None)
                    flash("상품이 등록되었습니다.", "success")
                    return redirect(url_for("product_detail", product_id=cursor.lastrowid))
        return render_template(
            "product_form.html",
            product=None,
            categories=PRODUCT_CATEGORIES,
            submission_token=form_token,
        )

    @app.route("/product/<int:product_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_product(product_id: int):
        product = fetch_product_or_404(product_id, include_hidden=True)
        user = get_current_user()
        if product["seller_id"] != user["id"] and not user["is_admin"]:
            abort(403)
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            price_text = request.form.get("price", "").strip()
            category = request.form.get("category", "").strip()
            image = request.files.get("image")
            price, error = validate_product_fields(name, description, price_text, category)
            new_image_filename = None
            if not error and image and image.filename:
                try:
                    new_image_filename = save_uploaded_image(image)
                except ValueError as exc:
                    error = str(exc)
            if not error and not product["image_filename"] and not new_image_filename:
                error = "상품 이미지는 반드시 등록해야 합니다."

            if error:
                flash(error, "error")
            else:
                image_filename = new_image_filename or product["image_filename"]
                db = get_db()
                db.execute(
                    """
                    UPDATE products
                    SET name = ?, description = ?, price = ?, category = ?, image_filename = ?
                    WHERE id = ?
                    """,
                    (name, description, price, category, image_filename, product_id),
                )
                write_audit_log(
                    db,
                    "product.updated",
                    actor_id=user["id"],
                    target_type="product",
                    target_id=product_id,
                )
                db.commit()
                if new_image_filename:
                    remove_uploaded_image(product["image_filename"])
                flash("상품 정보를 수정했습니다.", "success")
                return redirect(url_for("product_detail", product_id=product_id))
        return render_template(
            "product_form.html", product=product, categories=PRODUCT_CATEGORIES, submission_token=None
        )

    @app.route("/product/<int:product_id>")
    def product_detail(product_id: int):
        product = fetch_product_or_404(product_id, include_hidden=True)
        viewer = get_current_user()
        if product["status"] == "hidden" and not (
            viewer and (viewer["id"] == product["seller_id"] or viewer["is_admin"])
        ):
            abort(404)
        db = get_db()
        qna_count = db.execute(
            "SELECT COUNT(*) AS count FROM qna WHERE product_id = ?", (product_id,)
        ).fetchone()["count"]
        product_reports = []
        seller_reports = []
        if viewer and viewer["is_admin"]:
            product_reports = db.execute(
                """
                SELECT rp.*, u.username AS reporter_name, COALESCE(NULLIF(u.nickname, ''), u.username) AS reporter_nickname
                FROM reports rp JOIN users u ON rp.reporter_id = u.id
                WHERE rp.target_type = 'product' AND rp.target_id = ?
                ORDER BY rp.id DESC
                """,
                (product_id,),
            ).fetchall()
            seller_reports = db.execute(
                """
                SELECT rp.*, u.username AS reporter_name, COALESCE(NULLIF(u.nickname, ''), u.username) AS reporter_nickname
                FROM reports rp JOIN users u ON rp.reporter_id = u.id
                WHERE rp.target_type = 'user' AND rp.target_id = ?
                ORDER BY rp.id DESC
                """,
                (product["seller_id"],),
            ).fetchall()
        return render_template(
            "product_detail.html",
            product=product,
            qna_count=qna_count,
            product_reports=product_reports,
            seller_reports=seller_reports,
        )

    @app.post("/product/<int:product_id>/status")
    @login_required
    def product_status(product_id: int):
        product = fetch_product_or_404(product_id, include_hidden=True)
        user = get_current_user()
        if product["seller_id"] != user["id"] and not user["is_admin"]:
            abort(403)
        trade_status = request.form.get("trade_status")
        if trade_status not in TRADE_STATUS_LABELS:
            abort(400)
        db = get_db()
        db.execute(
            "UPDATE products SET trade_status = ? WHERE id = ?",
            (trade_status, product_id),
        )
        write_audit_log(
            db,
            "product.trade_status_changed",
            actor_id=user["id"],
            target_type="product",
            target_id=product_id,
            details={"trade_status": trade_status},
        )
        db.commit()
        flash("거래 상태를 변경했습니다.", "success")
        return redirect(safe_back_url(url_for("profile")))

    @app.post("/product/<int:product_id>/delete")
    @login_required
    def delete_product(product_id: int):
        product = fetch_product_or_404(product_id, include_hidden=True)
        user = get_current_user()
        if product["seller_id"] != user["id"] and not user["is_admin"]:
            abort(403)
        db = get_db()
        write_audit_log(
            db,
            "product.deleted",
            actor_id=user["id"],
            target_type="product",
            target_id=product_id,
        )
        db.execute("DELETE FROM products WHERE id = ?", (product_id,))
        db.commit()
        remove_uploaded_image(product["image_filename"])
        flash("상품을 삭제했습니다.", "info")
        if user["is_admin"]:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("profile"))

    @app.route("/qna/<int:product_id>")
    @login_required
    def qna_page(product_id: int):
        product = fetch_product_or_404(product_id)
        posts = get_db().execute(
            """
            SELECT q.*, u.username AS author_name, COALESCE(NULLIF(u.nickname, ''), u.username) AS author_nickname
            FROM qna q JOIN users u ON q.author_id = u.id
            WHERE q.product_id = ?
            ORDER BY q.id DESC
            """,
            (product_id,),
        ).fetchall()
        return render_template("qna.html", product=product, posts=posts)

    @app.post("/qna/<int:product_id>/add")
    @login_required
    def add_question(product_id: int):
        fetch_product_or_404(product_id)
        user = get_current_user()
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not validate_user_text(title) or not validate_user_text(body, multiline=True):
            flash("질문에 허용되지 않은 제어 문자가 포함되어 있습니다.", "error")
        elif not 2 <= len(title) <= 100 or not 2 <= len(body) <= 1000:
            flash("제목 2~100자, 내용 2~1000자로 입력하세요.", "error")
        elif not consume_action_quota("qna.create", user["id"], limit=20, window_seconds=600):
            flash("질문 등록 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", "error")
        else:
            db = get_db()
            cursor = db.execute(
                "INSERT INTO qna (product_id, author_id, title, body) VALUES (?, ?, ?, ?)",
                (product_id, user["id"], title, body),
            )
            write_audit_log(
                db,
                "qna.created",
                actor_id=user["id"],
                target_type="qna",
                target_id=cursor.lastrowid,
                details={"product_id": product_id},
            )
            db.commit()
            flash("질문을 등록했습니다.", "success")
        return redirect(url_for("qna_page", product_id=product_id))

    @app.post("/qna/<int:product_id>/delete/<int:post_id>")
    @login_required
    def delete_question(product_id: int, post_id: int):
        post = get_db().execute(
            "SELECT * FROM qna WHERE id = ? AND product_id = ?", (post_id, product_id)
        ).fetchone()
        if not post:
            abort(404)
        user = get_current_user()
        if post["author_id"] != user["id"] and not user["is_admin"]:
            abort(403)
        db = get_db()
        write_audit_log(
            db,
            "qna.deleted",
            actor_id=user["id"],
            target_type="qna",
            target_id=post_id,
            details={"product_id": product_id},
        )
        db.execute("DELETE FROM qna WHERE id = ?", (post_id,))
        db.commit()
        flash("질문을 삭제했습니다.", "info")
        return redirect(url_for("qna_page", product_id=product_id))

    @app.post("/messages/send/<int:product_id>")
    @login_required
    def send_message(product_id: int):
        product = fetch_product_or_404(product_id)
        sender = get_current_user()
        if sender["is_admin"]:
            abort(403)
        receiver_id_text = request.form.get("receiver_id", "").strip()
        body = request.form.get("body", "").strip()
        receiver_id = (
            parse_bounded_int(receiver_id_text, minimum=1, maximum=2_147_483_647)
            if receiver_id_text
            else product["seller_id"]
        )
        if receiver_id is None:
            abort(400)

        db = get_db()
        receiver = db.execute(
            "SELECT * FROM users WHERE id = ? AND is_suspended = 0", (receiver_id,)
        ).fetchone()
        if not receiver or receiver_id == sender["id"]:
            flash("메시지 수신자를 확인하세요.", "error")
        elif receiver["is_admin"]:
            flash("관리자 계정에는 거래 메시지를 보낼 수 없습니다.", "error")
        elif not can_send_product_message(
            db, product=product, sender_id=sender["id"], receiver_id=receiver_id
        ):
            abort(403)
        elif not validate_user_text(body, multiline=True):
            flash("메시지에 허용되지 않은 제어 문자가 포함되어 있습니다.", "error")
        elif not 1 <= len(body) <= 500:
            flash("메시지는 1~500자로 입력하세요.", "error")
        elif not consume_action_quota("message.send", sender["id"], limit=20, window_seconds=60):
            flash("메시지를 너무 빠르게 보내고 있습니다. 잠시 후 다시 시도하세요.", "error")
        else:
            cursor = db.execute(
                """
                INSERT INTO messages (product_id, sender_id, receiver_id, body, is_read)
                VALUES (?, ?, ?, ?, 0)
                """,
                (product_id, sender["id"], receiver_id, body),
            )
            write_audit_log(
                db, "message.sent", actor_id=sender["id"], target_type="message",
                target_id=cursor.lastrowid,
                details={"product_id": product_id, "receiver_id": receiver_id},
            )
            db.commit()
        return redirect(url_for("message_thread", product_id=product_id, other_user_id=receiver_id))

    @app.get("/messages")
    @login_required
    def messages():
        user = get_current_user()
        if user["is_admin"]:
            abort(403)
        product_id_text = request.args.get("product_id", "").strip()
        if product_id_text:
            product_id = parse_bounded_int(product_id_text, minimum=1, maximum=2_147_483_647)
            if product_id is None:
                abort(400)
            product = fetch_product_or_404(product_id)
            if product["seller_id"] == user["id"]:
                flash("판매자는 대화 목록에서 구매 희망자를 선택하세요.", "info")
            else:
                return redirect(
                    url_for("message_thread", product_id=product_id, other_user_id=product["seller_id"])
                )

        db = get_db()
        conversations = db.execute(
            """
            WITH involved AS (
                SELECT m.*,
                       CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END AS other_user_id
                FROM messages m
                WHERE m.sender_id = ? OR m.receiver_id = ?
            ), grouped AS (
                SELECT product_id, other_user_id, MAX(id) AS latest_id,
                       SUM(CASE WHEN receiver_id = ? AND is_read = 0 THEN 1 ELSE 0 END) AS unread_count
                FROM involved
                GROUP BY product_id, other_user_id
            )
            SELECT g.product_id, g.other_user_id, g.unread_count,
                   m.body AS latest_body, m.created_at AS latest_at,
                   p.name AS product_name, p.image_filename,
                   u.username AS other_username,
                   COALESCE(NULLIF(u.nickname, ''), u.username) AS other_nickname
            FROM grouped g
            JOIN messages m ON m.id = g.latest_id
            JOIN products p ON p.id = g.product_id
            JOIN users u ON u.id = g.other_user_id
            WHERE u.is_suspended = 0
            ORDER BY g.latest_id DESC
            LIMIT 100
            """,
            (user["id"], user["id"], user["id"], user["id"]),
        ).fetchall()
        return render_template("messages.html", conversations=conversations, user=user)

    @app.get("/messages/<int:product_id>/<int:other_user_id>")
    @login_required
    def message_thread(product_id: int, other_user_id: int):
        user = get_current_user()
        if user["is_admin"] or other_user_id == user["id"]:
            abort(403)
        product = fetch_product_or_404(product_id)
        db = get_db()
        other_user = db.execute(
            "SELECT * FROM users WHERE id = ? AND is_admin = 0 AND is_suspended = 0",
            (other_user_id,),
        ).fetchone()
        if not other_user:
            abort(404)
        # 구매자는 해당 상품 판매자와만 대화를 시작할 수 있고,
        # 판매자는 실제로 문의를 받은 상대와만 대화방을 열 수 있다.
        if not can_send_product_message(
            db, product=product, sender_id=user["id"], receiver_id=other_user_id
        ):
            abort(403)

        db.execute(
            """
            UPDATE messages SET is_read = 1, read_at = CURRENT_TIMESTAMP
            WHERE product_id = ? AND sender_id = ? AND receiver_id = ? AND is_read = 0
            """,
            (product_id, other_user_id, user["id"]),
        )
        db.commit()
        thread_messages = db.execute(
            """
            SELECT m.*,
                   COALESCE(NULLIF(s.nickname, ''), s.username) AS sender_nickname
            FROM messages m JOIN users s ON s.id = m.sender_id
            WHERE m.product_id = ?
              AND ((m.sender_id = ? AND m.receiver_id = ?)
                   OR (m.sender_id = ? AND m.receiver_id = ?))
            ORDER BY m.id ASC
            LIMIT 500
            """,
            (product_id, user["id"], other_user_id, other_user_id, user["id"]),
        ).fetchall()
        return render_template(
            "message_thread.html", product=product, other_user=other_user,
            thread_messages=thread_messages, user=user
        )

    @app.get("/chat")
    def legacy_chat_redirect():
        return redirect(url_for("board_list"), code=301)

    @app.get("/board")
    def board_list():
        selected_category = request.args.get("category", "").strip()
        query = request.args.get("q", "").strip()[:50]
        if not validate_user_text(query):
            abort(400)
        if selected_category and selected_category not in BOARD_CATEGORIES:
            abort(400)
        sql = """
            SELECT bp.*, u.username AS author_name,
                   COALESCE(NULLIF(u.nickname, ''), u.username) AS author_nickname,
                   (SELECT COUNT(*) FROM board_comments bc WHERE bc.post_id = bp.id) AS comment_count
            FROM board_posts bp JOIN users u ON bp.author_id = u.id
            WHERE u.is_suspended = 0
        """
        params: list[str] = []
        if selected_category:
            sql += " AND bp.category = ?"
            params.append(selected_category)
        if query:
            sql += (
                " AND (bp.title LIKE ? ESCAPE '\\' OR bp.body LIKE ? ESCAPE '\\' "
                "OR u.username LIKE ? ESCAPE '\\' OR u.nickname LIKE ? ESCAPE '\\')"
            )
            like = f"%{escape_like(query)}%"
            params.extend((like, like, like, like))
        sql += " ORDER BY bp.id DESC LIMIT 200"
        posts = get_db().execute(sql, tuple(params)).fetchall()
        return render_template(
            "board_list.html",
            posts=posts,
            categories=BOARD_CATEGORIES,
            selected_category=selected_category,
            query=query,
        )

    @app.route("/board/new", methods=["GET", "POST"])
    @login_required
    def board_new():
        user = get_current_user()
        if request.method == "POST":
            category = request.form.get("category", "").strip()
            title = request.form.get("title", "").strip()
            body = request.form.get("body", "").strip()
            if not validate_user_text(title) or not validate_user_text(body, multiline=True):
                flash("게시글에 허용되지 않은 제어 문자가 포함되어 있습니다.", "error")
            elif category not in BOARD_CATEGORIES:
                flash("게시판 카테고리를 선택하세요.", "error")
            elif not 2 <= len(title) <= 100:
                flash("제목은 2~100자로 입력하세요.", "error")
            elif not 2 <= len(body) <= 3000:
                flash("내용은 2~3000자로 입력하세요.", "error")
            elif not consume_action_quota("board.post", user["id"], limit=5, window_seconds=600):
                flash("게시글 등록 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", "error")
            else:
                db = get_db()
                cursor = db.execute(
                    "INSERT INTO board_posts (author_id, category, title, body) VALUES (?, ?, ?, ?)",
                    (user["id"], category, title, body),
                )
                write_audit_log(
                    db,
                    "board.post_created",
                    actor_id=user["id"],
                    target_type="board_post",
                    target_id=cursor.lastrowid,
                )
                db.commit()
                flash("게시글을 등록했습니다.", "success")
                return redirect(url_for("board_detail", post_id=cursor.lastrowid))
        return render_template("board_form.html", categories=BOARD_CATEGORIES)

    @app.get("/board/<int:post_id>")
    def board_detail(post_id: int):
        db = get_db()
        post = db.execute(
            """
            SELECT bp.*, u.username AS author_name, COALESCE(NULLIF(u.nickname, ''), u.username) AS author_nickname
            FROM board_posts bp JOIN users u ON bp.author_id = u.id
            WHERE bp.id = ? AND u.is_suspended = 0
            """,
            (post_id,),
        ).fetchone()
        if not post:
            abort(404)
        comments = db.execute(
            """
            SELECT bc.*, u.username AS author_name, COALESCE(NULLIF(u.nickname, ''), u.username) AS author_nickname
            FROM board_comments bc JOIN users u ON bc.author_id = u.id
            WHERE bc.post_id = ? AND u.is_suspended = 0
            ORDER BY bc.id ASC
            """,
            (post_id,),
        ).fetchall()
        return render_template("board_detail.html", post=post, comments=comments)

    @app.post("/board/<int:post_id>/view")
    def board_record_view(post_id: int):
        post = get_db().execute(
            """
            SELECT bp.id FROM board_posts bp
            JOIN users u ON bp.author_id = u.id
            WHERE bp.id = ? AND u.is_suspended = 0
            """,
            (post_id,),
        ).fetchone()
        if not post:
            abort(404)
        viewed_posts = session.get("viewed_board_posts", [])
        if not isinstance(viewed_posts, list):
            viewed_posts = []
        if post_id not in viewed_posts:
            db = get_db()
            db.execute(
                "UPDATE board_posts SET view_count = view_count + 1 WHERE id = ?",
                (post_id,),
            )
            db.commit()
            viewed_posts.append(post_id)
            session["viewed_board_posts"] = viewed_posts[-100:]
        count = get_db().execute(
            "SELECT view_count FROM board_posts WHERE id = ?", (post_id,)
        ).fetchone()["view_count"]
        return jsonify({"view_count": count})

    @app.post("/board/<int:post_id>/comments")
    @login_required
    def board_add_comment(post_id: int):
        post = get_db().execute("SELECT id FROM board_posts WHERE id = ?", (post_id,)).fetchone()
        if not post:
            abort(404)
        body = request.form.get("body", "").strip()
        user = get_current_user()
        if not validate_user_text(body, multiline=True):
            flash("댓글에 허용되지 않은 제어 문자가 포함되어 있습니다.", "error")
        elif not 1 <= len(body) <= 1000:
            flash("댓글은 1~1000자로 입력하세요.", "error")
        elif not consume_action_quota("board.comment", user["id"], limit=20, window_seconds=600):
            flash("댓글 등록 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", "error")
        else:
            db = get_db()
            cursor = db.execute(
                "INSERT INTO board_comments (post_id, author_id, body) VALUES (?, ?, ?)",
                (post_id, user["id"], body),
            )
            write_audit_log(
                db,
                "board.comment_created",
                actor_id=user["id"],
                target_type="board_comment",
                target_id=cursor.lastrowid,
                details={"post_id": post_id},
            )
            db.commit()
            flash("댓글을 등록했습니다.", "success")
        return redirect(url_for("board_detail", post_id=post_id))

    @app.post("/board/<int:post_id>/delete")
    @login_required
    def board_delete(post_id: int):
        post = get_db().execute("SELECT * FROM board_posts WHERE id = ?", (post_id,)).fetchone()
        if not post:
            abort(404)
        user = get_current_user()
        if post["author_id"] != user["id"] and not user["is_admin"]:
            abort(403)
        db = get_db()
        write_audit_log(
            db,
            "board.post_deleted",
            actor_id=user["id"],
            target_type="board_post",
            target_id=post_id,
        )
        db.execute("DELETE FROM board_posts WHERE id = ?", (post_id,))
        db.commit()
        flash("게시글을 삭제했습니다.", "info")
        return redirect(url_for("board_list"))

    @app.post("/board/<int:post_id>/comments/<int:comment_id>/delete")
    @login_required
    def board_delete_comment(post_id: int, comment_id: int):
        comment = get_db().execute(
            "SELECT * FROM board_comments WHERE id = ? AND post_id = ?",
            (comment_id, post_id),
        ).fetchone()
        if not comment:
            abort(404)
        user = get_current_user()
        if comment["author_id"] != user["id"] and not user["is_admin"]:
            abort(403)
        db = get_db()
        write_audit_log(
            db,
            "board.comment_deleted",
            actor_id=user["id"],
            target_type="board_comment",
            target_id=comment_id,
            details={"post_id": post_id},
        )
        db.execute("DELETE FROM board_comments WHERE id = ?", (comment_id,))
        db.commit()
        flash("댓글을 삭제했습니다.", "info")
        return redirect(url_for("board_detail", post_id=post_id))

    @app.route("/wallet", methods=["GET", "POST"])
    @login_required
    def wallet():
        user = get_current_user()
        if user["is_admin"]:
            flash("관리자 계정은 가상 송금 기능을 사용하지 않습니다.", "info")
            return redirect(url_for("admin_dashboard"))

        transfer_token = session.get("transfer_submission_token") or issue_transfer_submission_token()
        db = get_db()
        if request.method == "POST":
            submitted_token = request.form.get("submission_token", "")
            if not validate_transfer_submission_token(submitted_token):
                flash("이미 처리되었거나 만료된 송금 요청입니다.", "error")
                return redirect(url_for("wallet"))

            recipient_name = request.form.get("recipient", "").strip().lower()
            amount_text = request.form.get("amount", "").strip()
            amount = parse_bounded_int(amount_text, minimum=1, maximum=1_000_000)

            if not USERNAME_RE.fullmatch(recipient_name):
                flash("받는 사용자 아이디를 확인하세요.", "error")
            elif amount is None:
                flash("송금액은 1원 이상 100만 원 이하로 입력하세요.", "error")
            elif not consume_action_quota("wallet.transfer", user["id"], limit=10, window_seconds=60):
                flash("송금 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", "error")
            else:
                try:
                    db.execute("BEGIN IMMEDIATE")
                    sender = db.execute(
                        """
                        SELECT id, username, balance, is_admin, is_suspended
                        FROM users WHERE id = ?
                        """,
                        (user["id"],),
                    ).fetchone()
                    recipient = db.execute(
                        """
                        SELECT id, username, balance, is_admin, is_suspended
                        FROM users WHERE username = ? COLLATE NOCASE
                        """,
                        (recipient_name,),
                    ).fetchone()

                    if not sender or sender["is_admin"] or sender["is_suspended"]:
                        db.rollback()
                        session.clear()
                        flash("현재 계정으로 송금할 수 없습니다.", "error")
                        return redirect(url_for("login"))
                    if not recipient or recipient["is_suspended"]:
                        db.rollback()
                        flash("받는 사용자를 찾을 수 없습니다.", "error")
                    elif recipient["is_admin"]:
                        db.rollback()
                        flash("관리자 계정에는 송금할 수 없습니다.", "error")
                    elif recipient["id"] == sender["id"]:
                        db.rollback()
                        flash("자기 자신에게 송금할 수 없습니다.", "error")
                    else:
                        debit = db.execute(
                            """
                            UPDATE users
                            SET balance = balance - ?
                            WHERE id = ? AND balance >= ?
                              AND is_admin = 0 AND is_suspended = 0
                            """,
                            (amount, sender["id"], amount),
                        )
                        if debit.rowcount != 1:
                            db.rollback()
                            flash("잔액이 부족합니다.", "error")
                        else:
                            credit = db.execute(
                                """
                                UPDATE users
                                SET balance = balance + ?
                                WHERE id = ? AND is_admin = 0 AND is_suspended = 0
                                """,
                                (amount, recipient["id"]),
                            )
                            if credit.rowcount != 1:
                                db.rollback()
                                flash("받는 사용자의 상태가 변경되어 송금할 수 없습니다.", "error")
                            else:
                                cursor = db.execute(
                                    """
                                    INSERT INTO transfers
                                        (sender_id, receiver_id, amount, request_token)
                                    VALUES (?, ?, ?, ?)
                                    """,
                                    (sender["id"], recipient["id"], amount, submitted_token),
                                )
                                write_audit_log(
                                    db,
                                    "wallet.transfer",
                                    actor_id=sender["id"],
                                    target_type="transfer",
                                    target_id=cursor.lastrowid,
                                    details={"receiver_id": recipient["id"], "amount": amount},
                                )
                                db.commit()
                                session.pop("transfer_submission_token", None)
                                flash(
                                    f"{recipient['username']}님에게 {amount:,}원을 송금했습니다.",
                                    "success",
                                )
                                return redirect(url_for("wallet"))
                except sqlite3.IntegrityError:
                    db.rollback()
                    session.pop("transfer_submission_token", None)
                    flash("이미 처리된 송금 요청입니다. 중복 송금하지 않았습니다.", "info")
                    return redirect(url_for("wallet"))
                except sqlite3.Error:
                    db.rollback()
                    raise

        user = get_current_user()
        transfers = db.execute(
            """
            SELECT t.*, s.username AS sender_name, r.username AS receiver_name,
                   COALESCE(NULLIF(s.nickname, ''), s.username) AS sender_nickname,
                   COALESCE(NULLIF(r.nickname, ''), r.username) AS receiver_nickname
            FROM transfers t
            JOIN users s ON t.sender_id = s.id
            JOIN users r ON t.receiver_id = r.id
            WHERE t.sender_id = ? OR t.receiver_id = ?
            ORDER BY t.id DESC LIMIT 30
            """,
            (user["id"], user["id"]),
        ).fetchall()
        return render_template(
            "wallet.html",
            user=user,
            transfers=transfers,
            submission_token=transfer_token,
        )

    @app.route("/report/product/<int:product_id>", methods=["GET", "POST"])
    @login_required
    def report_product(product_id: int):
        product = fetch_product_or_404(product_id)
        user = get_current_user()
        if user["is_admin"]:
            abort(403)
        if product["seller_id"] == user["id"]:
            abort(400)
        if request.method == "POST":
            report_target = request.form.get("report_target", "")
            if report_target == "product":
                target_type, target_id = "product", product_id
            elif report_target == "seller":
                target_type, target_id = "user", product["seller_id"]
            else:
                flash("신고 대상을 선택하세요.", "error")
                return render_template(
                    "report_form.html",
                    target_type="product",
                    target=product,
                    reason_categories=REPORT_REASON_CATEGORIES,
                    combined_report=True,
                )
            error = apply_report(
                user,
                target_type,
                target_id,
                request.form.get("reason_category", ""),
                request.form.get("reason", "").strip(),
            )
            if error:
                flash(error, "error")
            else:
                label = "상품" if report_target == "product" else "판매자"
                flash(f"{label} 신고가 접수되었습니다.", "success")
                return redirect(url_for("product_detail", product_id=product_id))
        return render_template(
            "report_form.html",
            target_type="product",
            target=product,
            reason_categories=REPORT_REASON_CATEGORIES,
            combined_report=True,
        )

    @app.route("/report/user/<int:user_id>", methods=["GET", "POST"])
    @login_required
    def report_user(user_id: int):
        target = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        user = get_current_user()
        if user["is_admin"]:
            abort(403)
        if not target or target["id"] == user["id"] or target["is_admin"]:
            abort(400)
        if request.method == "POST":
            error = apply_report(
                user,
                "user",
                user_id,
                request.form.get("reason_category", ""),
                request.form.get("reason", "").strip(),
            )
            if error:
                flash(error, "error")
            else:
                flash("사용자 신고가 접수되었습니다.", "success")
                return redirect(url_for("index"))
        return render_template(
            "report_form.html",
            target_type="user",
            target=target,
            reason_categories=REPORT_REASON_CATEGORIES,
        )

    @app.route("/admin")
    @admin_required
    def admin_dashboard():
        db = get_db()
        users = db.execute("SELECT * FROM users ORDER BY id DESC LIMIT 500").fetchall()
        products = db.execute(
            """
            SELECT p.*, u.username AS seller_name,
                   COALESCE(NULLIF(u.nickname, ''), u.username) AS seller_nickname
            FROM products p JOIN users u ON p.seller_id = u.id
            ORDER BY p.id DESC LIMIT 500
            """
        ).fetchall()
        reports = db.execute(
            """
            SELECT rp.*, reporter.username AS reporter_name,
                   COALESCE(NULLIF(reporter.nickname, ''), reporter.username) AS reporter_nickname,
                   target_user.username AS target_user_name,
                   COALESCE(NULLIF(target_user.nickname, ''), target_user.username) AS target_user_nickname,
                   target_product.name AS target_product_name
            FROM reports rp
            JOIN users reporter ON rp.reporter_id = reporter.id
            LEFT JOIN users target_user
              ON rp.target_type = 'user' AND rp.target_id = target_user.id
            LEFT JOIN products target_product
              ON rp.target_type = 'product' AND rp.target_id = target_product.id
            ORDER BY rp.id DESC LIMIT 100
            """
        ).fetchall()
        summary = {
            "user_count": db.execute("SELECT COUNT(*) AS count FROM users WHERE is_admin = 0").fetchone()["count"],
            "suspended_count": db.execute("SELECT COUNT(*) AS count FROM users WHERE is_suspended = 1").fetchone()["count"],
            "product_count": db.execute("SELECT COUNT(*) AS count FROM products").fetchone()["count"],
            "hidden_count": db.execute("SELECT COUNT(*) AS count FROM products WHERE status = 'hidden'").fetchone()["count"],
            "report_count": db.execute("SELECT COUNT(*) AS count FROM reports").fetchone()["count"],
        }
        return render_template(
            "admin.html", users=users, products=products, reports=reports, summary=summary
        )

    @app.post("/admin/user/<int:user_id>/toggle")
    @admin_required
    def admin_toggle_user(user_id: int):
        admin = get_current_user()
        target = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target or target["id"] == admin["id"] or target["is_admin"]:
            abort(400)
        requested_state = request.form.get("state", "")
        if requested_state not in {"active", "suspended"}:
            abort(400)
        new_value = 1 if requested_state == "suspended" else 0
        db = get_db()
        db.execute(
            """
            UPDATE users
            SET is_suspended = ?, session_version = session_version + 1
            WHERE id = ?
            """,
            (new_value, user_id),
        )
        write_audit_log(
            db,
            "admin.user_state_changed",
            actor_id=admin["id"],
            target_type="user",
            target_id=user_id,
            details={"state": requested_state},
        )
        db.commit()
        flash("사용자 계정 상태를 변경했습니다.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/product/<int:product_id>/visibility")
    @admin_required
    def admin_product_visibility(product_id: int):
        fetch_product_or_404(product_id, include_hidden=True)
        visibility = request.form.get("visibility")
        if visibility not in {"active", "hidden"}:
            abort(400)
        db = get_db()
        db.execute("UPDATE products SET status = ? WHERE id = ?", (visibility, product_id))
        write_audit_log(
            db,
            "admin.product_visibility_changed",
            actor_id=get_current_user()["id"],
            target_type="product",
            target_id=product_id,
            details={"visibility": visibility},
        )
        db.commit()
        flash("상품 공개 상태를 변경했습니다.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/product/<int:product_id>/trade-status")
    @admin_required
    def admin_product_trade_status(product_id: int):
        fetch_product_or_404(product_id, include_hidden=True)
        trade_status = request.form.get("trade_status")
        if trade_status not in TRADE_STATUS_LABELS:
            abort(400)
        db = get_db()
        db.execute(
            "UPDATE products SET trade_status = ? WHERE id = ?",
            (trade_status, product_id),
        )
        write_audit_log(
            db,
            "admin.product_trade_status_changed",
            actor_id=get_current_user()["id"],
            target_type="product",
            target_id=product_id,
            details={"trade_status": trade_status},
        )
        db.commit()
        flash("상품 거래 상태를 변경했습니다.", "success")
        return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    # 모듈 import 시 DB/키 파일을 만들지 않고, 직접 실행할 때만 앱을 생성한다.
    # 공개 터널에서 Werkzeug 디버거가 노출되지 않도록 안전한 기본값을 강제한다.
    create_app().run(host="127.0.0.1", port=5000, debug=False)
