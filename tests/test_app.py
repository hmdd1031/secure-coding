from io import BytesIO
import sqlite3

from PIL import Image

from app import create_app, get_db


def csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as sess:
        return sess["_csrf_token"]


def signup(client, username="alice", password="AlicePass123!"):
    nickname = f"{username[:14]}_nick"
    return client.post(
        "/signup",
        data={
            "csrf_token": csrf(client),
            "username": username,
            "real_name": "테스트사용자",
            "nickname": nickname,
            "password": password,
            "password_confirm": password,
            "phone": "010-1234-5678",
            "postal_code": "06236",
            "address_city": "서울특별시",
            "address_district": "강남구",
            "address_neighborhood": "역삼동",
            "address_detail": "테헤란로 1 101호",
            "privacy_consent": "on",
        },
        follow_redirects=True,
    )


def login(client, username="alice", password="AlicePass123!"):
    return client.post(
        "/login",
        data={"csrf_token": csrf(client), "username": username, "password": password},
        follow_redirects=True,
    )


def logout(client):
    return client.post(
        "/logout",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )


def image_file(name="product.png"):
    buffer = BytesIO()
    Image.new("RGB", (32, 32), (255, 255, 255)).save(buffer, format="PNG")
    buffer.seek(0)
    return buffer, name


def product_submission_token(client) -> str:
    client.get("/products/new")
    with client.session_transaction() as sess:
        return sess["product_submission_token"]


def transfer_submission_token(client) -> str:
    client.get("/wallet")
    with client.session_transaction() as sess:
        return sess["transfer_submission_token"]


def login_session_as(app, client, username: str) -> None:
    with app.app_context():
        user = get_db().execute(
            "SELECT id, session_version FROM users WHERE username = ?", (username,)
        ).fetchone()
    with client.session_transaction() as sess:
        sess["user_id"] = user["id"]
        sess["session_version"] = user["session_version"]
        sess["_csrf_token"] = "test-session-token"


def test_csrf_required(client):
    response = client.post("/signup", data={"username": "alice"})
    assert response.status_code == 400


def test_signup_requires_contact_and_consents(client):
    response = client.post(
        "/signup",
        data={
            "csrf_token": csrf(client),
            "username": "alice",
            "real_name": "테스트사용자",
            "nickname": "앨리스",
            "password": "AlicePass123!",
            "password_confirm": "AlicePass123!",
        },
        follow_redirects=True,
    )
    assert "휴대전화" in response.get_data(as_text=True)


def test_signup_login_and_hashed_password(app, client):
    response = signup(client)
    assert "회원가입이 완료" in response.get_data(as_text=True)
    response = login(client)
    assert "alice_nick님, 환영합니다" in response.get_data(as_text=True)
    with app.app_context():
        row = get_db().execute(
            "SELECT password_hash, phone, privacy_consent FROM users WHERE username = ?",
            ("alice",),
        ).fetchone()
        assert row is not None
        assert row["password_hash"] != "AlicePass123!"
        assert row["phone"] == "010-1234-5678"
        assert row["privacy_consent"] == 1


def test_xss_is_escaped(client):
    signup(client)
    login(client)
    response = client.post(
        "/qna/1/add",
        data={
            "csrf_token": csrf(client),
            "title": "문의",
            "body": "<script>alert(1)</script>",
        },
        follow_redirects=True,
    )
    text = response.get_data(as_text=True)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "<script>alert(1)</script>" not in text


def test_search_treats_sql_injection_as_text(client):
    response = client.get("/?q=%27%20OR%201%3D1%20--")
    assert response.status_code == 200
    assert "상품명, 설명, 카테고리 검색" in response.get_data(as_text=True)


def test_product_image_is_required(client):
    signup(client)
    login(client)
    response = client.post(
        "/products/new",
        data={
            "csrf_token": csrf(client),
            "submission_token": product_submission_token(client),
            "name": "깨끗한 키보드",
            "category": "디지털기기",
            "description": "사용감이 적은 키보드입니다.",
            "price": "10000",
        },
        follow_redirects=True,
    )
    assert "상품 이미지는 반드시" in response.get_data(as_text=True)


def test_prohibited_product_keyword_is_blocked(client):
    signup(client)
    login(client)
    response = client.post(
        "/products/new",
        data={
            "csrf_token": csrf(client),
            "submission_token": product_submission_token(client),
            "name": "전자 담배 판매",
            "category": "기타",
            "description": "새 상품입니다.",
            "price": "10000",
            "image": image_file(),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert "금지 품목" in response.get_data(as_text=True)


def test_product_creation_and_public_seller_profile(client):
    signup(client)
    login(client)
    response = client.post(
        "/products/new",
        data={
            "csrf_token": csrf(client),
            "submission_token": product_submission_token(client),
            "name": "화이트 키보드",
            "category": "디지털기기",
            "description": "깨끗하게 사용한 화이트 키보드입니다.",
            "price": "10000",
            "image": image_file(),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    text = response.get_data(as_text=True)
    assert "화이트 키보드" in text
    assert "/users/alice" in text
    profile = client.get("/users/alice")
    assert "화이트 키보드" in profile.get_data(as_text=True)


def test_unauthorized_product_delete_is_forbidden(client):
    signup(client)
    login(client)
    response = client.post(
        "/product/1/delete",
        data={"csrf_token": csrf(client)},
    )
    assert response.status_code == 403


def test_report_uses_separate_page_and_hides_count(client):
    signup(client)
    login(client)
    detail = client.get("/product/1")
    text = detail.get_data(as_text=True)
    assert "신고 수" not in text
    assert "/report/product/1" in text
    report_page = client.get("/report/product/1")
    assert "상품·판매자 신고" in report_page.get_data(as_text=True)


def test_unread_private_message_badge(app, client):
    signup(client, "alice", "AlicePass123!")
    signup(client, "bob", "BobPass1234!")
    login(client, "bob", "BobPass1234!")
    client.post(
        "/products/new",
        data={
            "csrf_token": csrf(client),
            "submission_token": product_submission_token(client),
            "name": "밥의 거래 상품",
            "category": "생활용품",
            "description": "메시지 권한 테스트용 상품입니다.",
            "price": "12000",
            "image": image_file("bob-product.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    logout(client)
    login(client, "alice", "AlicePass123!")
    client.post(
        "/messages/send/2",
        data={
            "csrf_token": csrf(client),
            "body": "안녕하세요",
        },
        follow_redirects=True,
    )
    logout(client)
    login(client, "bob", "BobPass1234!")
    home = client.get("/").get_data(as_text=True)
    assert "읽지 않은 메시지 1개" in home
    with app.app_context():
        alice = get_db().execute("SELECT id FROM users WHERE username = 'alice'").fetchone()
    client.get(f"/messages/2/{alice['id']}")
    home_after = client.get("/").get_data(as_text=True)
    assert "읽지 않은 메시지 1개" not in home_after


def test_board_escapes_post_and_comment(client):
    signup(client)
    login(client)
    response = client.post(
        "/board/new",
        data={
            "csrf_token": csrf(client),
            "category": "자유",
            "title": "안전한 게시판",
            "body": "<img src=x onerror=alert(1)>",
        },
        follow_redirects=True,
    )
    text = response.get_data(as_text=True)
    assert "&lt;img src=x onerror=alert(1)&gt;" in text
    assert "<img src=x onerror=alert(1)>" not in text
    response = client.post(
        "/board/1/comments",
        data={"csrf_token": csrf(client), "body": "<script>alert(1)</script>"},
        follow_redirects=True,
    )
    text = response.get_data(as_text=True)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "<script>alert(1)</script>" not in text


def test_password_change_requires_current_password(client):
    signup(client)
    login(client)
    response = client.post(
        "/profile/password",
        data={
            "csrf_token": csrf(client),
            "current_password": "wrong-password",
            "new_password": "NewAlicePass456!",
            "new_password_confirm": "NewAlicePass456!",
        },
        follow_redirects=True,
    )
    assert "현재 비밀번호가 올바르지" in response.get_data(as_text=True)


def test_transfer_rejects_insufficient_balance(app, client):
    signup(client, "alice", "AlicePass123!")
    signup(client, "bob", "BobPass1234!")
    login(client, "alice", "AlicePass123!")
    response = client.post(
        "/wallet",
        data={
            "csrf_token": csrf(client),
            "submission_token": transfer_submission_token(client),
            "recipient": "bob",
            "amount": "200000",
        },
        follow_redirects=True,
    )
    assert "잔액이 부족" in response.get_data(as_text=True)
    with app.app_context():
        alice = get_db().execute("SELECT balance FROM users WHERE username='alice'").fetchone()
        bob = get_db().execute("SELECT balance FROM users WHERE username='bob'").fetchone()
        assert alice["balance"] == 100000
        assert bob["balance"] == 100000


def test_category_filter_and_policy_pages(client):
    response = client.get("/?category=취미/굿즈")
    assert response.status_code == 200
    assert "가나디 나 안아 티셔츠" in response.get_data(as_text=True)
    assert client.get("/policies/privacy").status_code == 200
    assert "개인정보 수집·이용 안내" in client.get("/policies/privacy").get_data(as_text=True)
    third_party = client.get("/policies/third-party", follow_redirects=True)
    assert "외부 주소 검색 API를 사용하지 않습니다" in third_party.get_data(as_text=True)


def test_password_change_has_separate_page(client):
    signup(client)
    login(client)
    page = client.get("/profile/password")
    text = page.get_data(as_text=True)
    assert page.status_code == 200
    assert "ACCOUNT SECURITY" in text
    profile = client.get("/profile").get_data(as_text=True)
    assert "비밀번호 변경" in profile
    assert "current_password" not in profile


def test_admin_can_see_report_details_on_product_and_profile(app, client):
    signup(client, "alice", "AlicePass123!")
    login(client, "alice", "AlicePass123!")
    client.post(
        "/report/product/1",
        data={
            "csrf_token": csrf(client),
            "report_target": "product",
            "reason_category": "사기 의심",
            "reason": "상품 설명과 실제 상태가 달라 확인이 필요합니다.",
        },
        follow_redirects=True,
    )
    logout(client)
    login_session_as(app, client, "admin")
    detail = client.get("/product/1").get_data(as_text=True)
    assert "ADMIN REPORT VIEW" in detail
    assert "상품 설명과 실제 상태가 달라" in detail
    profile = client.get("/users/ganadi").get_data(as_text=True)
    assert "ADMIN USER VIEW" in profile
    assert "사용자 신고 횟수" in profile



def test_product_submission_token_prevents_double_post(app, client):
    signup(client)
    login(client)
    token = product_submission_token(client)
    first = client.post(
        "/products/new",
        data={
            "csrf_token": csrf(client),
            "submission_token": token,
            "name": "중복 방지 마우스",
            "category": "디지털기기",
            "description": "중복 등록 방지 테스트용 상품입니다.",
            "price": "15000",
            "image": image_file("mouse.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert "상품이 등록되었습니다" in first.get_data(as_text=True)
    second = client.post(
        "/products/new",
        data={
            "csrf_token": csrf(client),
            "submission_token": token,
            "name": "중복 방지 마우스",
            "category": "디지털기기",
            "description": "중복 등록 방지 테스트용 상품입니다.",
            "price": "15000",
            "image": image_file("mouse2.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert "이미 처리되었거나 만료된" in second.get_data(as_text=True)
    with app.app_context():
        count = get_db().execute(
            "SELECT COUNT(*) AS count FROM products WHERE name = ?",
            ("중복 방지 마우스",),
        ).fetchone()["count"]
        assert count == 1


def test_combined_product_report_can_target_seller(app, client):
    signup(client)
    login(client)
    response = client.post(
        "/report/product/1",
        data={
            "csrf_token": csrf(client),
            "report_target": "seller",
            "reason_category": "욕설·괴롭힘",
            "reason": "판매자가 거래 대화에서 반복적으로 욕설을 사용했습니다.",
        },
        follow_redirects=True,
    )
    assert "판매자 신고가 접수" in response.get_data(as_text=True)
    with app.app_context():
        seller = get_db().execute("SELECT id FROM users WHERE username='ganadi'").fetchone()
        row = get_db().execute(
            "SELECT * FROM reports WHERE target_type='user' AND target_id=?",
            (seller["id"],),
        ).fetchone()
        assert row is not None

def test_message_compose_is_on_messages_page_not_product_detail(client):
    signup(client)
    login(client)

    detail = client.get("/product/1").get_data(as_text=True)

    assert "판매자에게 1:1 메시지" not in detail
    assert "/messages?product_id=1" in detail

    response = client.get(
        "/messages?product_id=1",
        follow_redirects=True,
    )
    messages_page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "가나디상점" in messages_page
    assert 'id="message-body"' in messages_page    

def test_product_management_controls_are_on_profile(client):
    signup(client)
    login(client)
    token = product_submission_token(client)
    client.post(
        "/products/new",
        data={
            "csrf_token": csrf(client),
            "submission_token": token,
            "name": "관리 화면 테스트 상품",
            "category": "생활용품",
            "description": "마이페이지 관리 위치를 확인하는 상품입니다.",
            "price": "7000",
            "image": image_file("manage.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    profile = client.get("/profile").get_data(as_text=True)
    assert "segmented-status" in profile
    assert "상품 수정" in profile
    assert "상품 삭제" in profile
    detail = client.get("/product/2").get_data(as_text=True)
    assert "owner-panel" not in detail
    assert "내 상품 관리에서 수정" in detail


def test_admin_has_direct_state_controls_and_no_wallet(app, client):
    with app.app_context():
        admin = get_db().execute("SELECT * FROM users WHERE username='admin'").fetchone()
        assert admin["balance"] == 0
    login_session_as(app, client, "admin")
    dashboard = client.get("/admin").get_data(as_text=True)
    assert "거래 상태와 공개 상태를 각각의 열에서 직접 변경" in dashboard
    assert "/admin/product/1/trade-status" in dashboard
    assert "/admin/product/1/visibility" in dashboard
    assert "휴면 전환" in dashboard
    home = client.get("/").get_data(as_text=True)
    assert ">WALLET<" not in home
    wallet = client.get("/wallet", follow_redirects=True).get_data(as_text=True)
    assert "관리자 계정은 가상 송금 기능을 사용하지 않습니다" in wallet


def test_regular_user_cannot_transfer_to_admin(app, client):
    signup(client)
    login(client)
    response = client.post(
        "/wallet",
        data={
            "csrf_token": csrf(client),
            "submission_token": transfer_submission_token(client),
            "recipient": "admin",
            "amount": "1000",
        },
        follow_redirects=True,
    )
    assert "관리자 계정에는 송금할 수 없습니다" in response.get_data(as_text=True)
    with app.app_context():
        admin = get_db().execute("SELECT balance FROM users WHERE username='admin'").fetchone()
        assert admin["balance"] == 0


def test_message_receiver_tampering_is_forbidden(app, client):
    signup(client, "alice", "AlicePass123!")
    signup(client, "bob", "BobPass1234!")
    login(client, "alice", "AlicePass123!")
    with app.app_context():
        bob = get_db().execute("SELECT id FROM users WHERE username = 'bob'").fetchone()
    response = client.post(
        "/messages/send/1",
        data={
            "csrf_token": csrf(client),
            "receiver_id": str(bob["id"]),
            "body": "판매자가 아닌 사용자에게 보내기",
        },
    )
    assert response.status_code == 403
    with app.app_context():
        count = get_db().execute(
            "SELECT COUNT(*) AS count FROM messages WHERE receiver_id = ?", (bob["id"],)
        ).fetchone()["count"]
        assert count == 0


def test_transfer_submission_token_prevents_double_transfer(app, client):
    signup(client, "alice", "AlicePass123!")
    signup(client, "bob", "BobPass1234!")
    login(client, "alice", "AlicePass123!")
    token = transfer_submission_token(client)
    payload = {
        "csrf_token": csrf(client),
        "submission_token": token,
        "recipient": "bob",
        "amount": "1000",
    }
    first = client.post("/wallet", data=payload, follow_redirects=True)
    assert "1,000원을 송금했습니다" in first.get_data(as_text=True)
    second = client.post("/wallet", data=payload, follow_redirects=True)
    assert "이미 처리되었거나 만료된" in second.get_data(as_text=True)
    with app.app_context():
        alice = get_db().execute("SELECT balance FROM users WHERE username='alice'").fetchone()
        bob = get_db().execute("SELECT balance FROM users WHERE username='bob'").fetchone()
        transfer_count = get_db().execute("SELECT COUNT(*) AS count FROM transfers").fetchone()["count"]
        assert alice["balance"] == 99000
        assert bob["balance"] == 101000
        assert transfer_count == 1


def test_password_change_revokes_other_sessions(app, client):
    signup(client, "alice", "AlicePass123!")
    first_client = client
    second_client = app.test_client()
    login(first_client, "alice", "AlicePass123!")
    login(second_client, "alice", "AlicePass123!")

    response = first_client.post(
        "/profile/password",
        data={
            "csrf_token": csrf(first_client),
            "current_password": "AlicePass123!",
            "new_password": "NewAlicePass456!",
            "new_password_confirm": "NewAlicePass456!",
        },
        follow_redirects=True,
    )
    assert "비밀번호를 변경했습니다" in response.get_data(as_text=True)
    revoked = second_client.get("/profile", follow_redirects=True)
    assert "로그인" in revoked.get_data(as_text=True)
    assert revoked.request.path == "/login"


def test_board_view_count_changes_only_on_csrf_post(app, client):
    signup(client)
    login(client)
    client.post(
        "/board/new",
        data={
            "csrf_token": csrf(client),
            "category": "자유",
            "title": "조회 수 테스트",
            "body": "GET 요청은 상태를 바꾸지 않습니다.",
        },
        follow_redirects=True,
    )
    with app.app_context():
        before = get_db().execute("SELECT view_count FROM board_posts WHERE id = 1").fetchone()["view_count"]
    client.get("/board/1")
    with app.app_context():
        after_get = get_db().execute("SELECT view_count FROM board_posts WHERE id = 1").fetchone()["view_count"]
    assert after_get == before
    response = client.post("/board/1/view", data={"csrf_token": csrf(client)})
    assert response.status_code == 200
    assert response.get_json()["view_count"] == before + 1
    second = client.post("/board/1/view", data={"csrf_token": csrf(client)})
    assert second.get_json()["view_count"] == before + 1


def test_uploaded_image_is_served_from_restricted_media_route(app, client):
    signup(client)
    login(client)
    client.post(
        "/products/new",
        data={
            "csrf_token": csrf(client),
            "submission_token": product_submission_token(client),
            "name": "미디어 경로 테스트",
            "category": "기타",
            "description": "업로드 파일은 static 폴더 밖에서 제공합니다.",
            "price": "1000",
            "image": image_file("media.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    with app.app_context():
        filename = get_db().execute(
            "SELECT image_filename FROM products WHERE name = ?", ("미디어 경로 테스트",)
        ).fetchone()["image_filename"]
    media = client.get(f"/media/products/{filename}")
    assert media.status_code == 200
    assert media.mimetype == "image/webp"
    assert client.get("/media/products/../../app.py").status_code == 404


def test_security_headers_are_set(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "object-src 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"


def test_login_rate_limit_is_persisted(client):
    signup(client)
    for _ in range(5):
        response = login(client, "alice", "wrong-password")
        assert response.status_code == 200
    blocked = login(client, "alice", "wrong-password")
    assert blocked.status_code == 429
    assert "로그인 시도가 너무 많습니다" in blocked.get_data(as_text=True)


def test_v4_database_schema_is_migrated(tmp_path):
    database = tmp_path / "legacy.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            bio TEXT NOT NULL DEFAULT '',
            balance INTEGER NOT NULL DEFAULT 100000,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_suspended INTEGER NOT NULL DEFAULT 0,
            report_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price INTEGER NOT NULL,
            image_filename TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            report_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE qna (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER NOT NULL,
            target_type TEXT NOT NULL,
            target_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    connection.commit()
    connection.close()

    migrated_app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "migration-test-secret-key-32-characters",
            "DATABASE": str(database),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        }
    )
    with migrated_app.app_context():
        db = get_db()
        user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        transfer_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(transfers)")
        }
        tables = {
            row["name"]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {"session_version", "real_name", "nickname", "postal_code", "address_city", "address_district", "address_neighborhood"} <= user_columns
        assert "request_token" in transfer_columns
        assert {"auth_attempts", "action_events", "audit_logs"} <= tables


def test_untrusted_host_is_rejected(client):
    response = client.get("/", headers={"Host": "evil.example"})
    assert response.status_code == 400


def test_security_events_are_audited_without_password(app, client):
    signup(client, "audituser", "AuditPass123!")
    login(client, "audituser", "AuditPass123!")
    with app.app_context():
        rows = get_db().execute(
            "SELECT event_type, details FROM audit_logs ORDER BY id"
        ).fetchall()
        event_types = {row["event_type"] for row in rows}
        combined_details = " ".join(row["details"] for row in rows)
        assert "auth.signup" in event_types
        assert "auth.login_success" in event_types
        assert "AuditPass123!" not in combined_details


def test_signup_requires_strong_password_and_separate_identity_fields(client):
    response = client.post(
        "/signup",
        data={
            "csrf_token": csrf(client),
            "username": "weakuser",
            "real_name": "약한비밀번호",
            "nickname": "약한계정",
            "password": "Weakpass123",
            "password_confirm": "Weakpass123",
            "phone": "010-1234-5678",
            "postal_code": "06236",
            "address_city": "서울특별시",
            "address_district": "강남구",
            "address_neighborhood": "역삼동",
            "address_detail": "테헤란로 1 101호",
            "privacy_consent": "on",
        },
        follow_redirects=True,
    )
    text = response.get_data(as_text=True)
    assert "특수문자" in text


def test_signup_uses_manual_address_fields_without_postcode_api(client):
    page = client.get("/signup").get_data(as_text=True)
    assert 'name="address_city"' in page
    assert 'name="address_district"' in page
    assert 'name="postal_code"' in page
    assert 'name="address_neighborhood"' in page
    assert "Kakao" not in page and "Daum" not in page
    assert "주소 검색" not in page


def test_nickname_is_unique(app, client):
    signup(client, "alice", "AlicePass123!")
    response = client.post(
        "/signup",
        data={
            "csrf_token": csrf(client),
            "username": "alice2",
            "real_name": "두번째사용자",
            "nickname": "alice_nick",
            "password": "AlicePass123!",
            "password_confirm": "AlicePass123!",
            "phone": "010-9999-8888",
            "postal_code": "06236",
            "address_city": "서울특별시",
            "address_district": "마포구",
            "address_neighborhood": "서교동",
            "address_detail": "와우산로 1 202호",
            "privacy_consent": "on",
        },
        follow_redirects=True,
    )
    assert "이미 사용 중인 아이디 또는 닉네임" in response.get_data(as_text=True)


def test_messages_are_grouped_into_product_conversation(app, client):
    signup(client, "alice", "AlicePass123!")
    signup(client, "bob", "BobPass1234!")
    login(client, "bob", "BobPass1234!")
    client.post(
        "/products/new",
        data={
            "csrf_token": csrf(client),
            "submission_token": product_submission_token(client),
            "name": "대화형 상품",
            "category": "생활용품",
            "description": "상품별 대화 테스트에 사용하는 상품입니다.",
            "price": "15000",
            "image": image_file("thread.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    logout(client)
    login(client, "alice", "AlicePass123!")
    with app.app_context():
        bob = get_db().execute("SELECT id FROM users WHERE username='bob'").fetchone()
    client.post(
        "/messages/send/2",
        data={"csrf_token": csrf(client), "receiver_id": str(bob["id"]), "body": "첫 문의입니다."},
        follow_redirects=True,
    )
    thread = client.get(f"/messages/2/{bob['id']}").get_data(as_text=True)
    assert "첫 문의입니다." in thread
    assert "private-chat-bubble" in thread
    listing = client.get("/messages").get_data(as_text=True)
    assert listing.count("대화형 상품") == 1


def test_kst_filter_is_applied_to_rendered_timestamps(client):
    signup(client)
    profile = client.get("/users/alice").get_data(as_text=True)
    assert "KST" in profile


def test_seller_cannot_open_thread_before_buyer_inquiry(app, client):
    signup(client, "alice", "AlicePass123!")
    signup(client, "bob", "BobPass1234!")
    login(client, "bob", "BobPass1234!")
    client.post(
        "/products/new",
        data={
            "csrf_token": csrf(client),
            "submission_token": product_submission_token(client),
            "name": "문의 전 접근 검사 상품",
            "category": "생활용품",
            "description": "구매 문의 전 판매자의 임의 대화방 접근을 검사합니다.",
            "price": "20000",
            "image": image_file("thread-access.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    with app.app_context():
        alice = get_db().execute("SELECT id FROM users WHERE username='alice'").fetchone()
        product = get_db().execute(
            "SELECT id FROM products WHERE seller_id = (SELECT id FROM users WHERE username='bob') "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    response = client.get(f"/messages/{product['id']}/{alice['id']}")
    assert response.status_code == 403


def test_v6_ui_consistency_and_forbidden_item_tooltip(client):
    signup(client)
    login(client)

    board_form = client.get("/board/new").get_data(as_text=True)
    assert "board-form-actions" in board_form
    assert "board-submit-button" in board_form

    board_list = client.get("/board").get_data(as_text=True)
    assert "board-write-button" in board_list

    wallet = client.get("/wallet").get_data(as_text=True)
    assert "wallet-stack" in wallet
    assert wallet.count("wallet-section") >= 3

    product_form = client.get("/products/new").get_data(as_text=True)
    assert "prohibited-tooltip" in product_form
    assert "금지 품목" in product_form
    assert "마약류" in product_form
