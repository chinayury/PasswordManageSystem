"""两步验证回归：跨入口、并发和旧备份均保留动态码防重用。"""

import secrets
import sqlite3
from base64 import b32encode
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Barrier
from types import SimpleNamespace
from urllib.parse import urlsplit

import bcrypt
import pyotp
import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.db import get_db, init_db
from app.services import totp
from app.services.backup import restore_backup


@pytest.fixture()
def account(tmp_path, monkeypatch):
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": secrets.token_hex(32),
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "DATABASE": str(tmp_path / "test.db"),
        "BACKUP_FOLDER": str(tmp_path / "backups"),
    })
    init_db(app)
    username = "totp-test-user"
    password = secrets.token_urlsafe(24)
    digest = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode()
    with app.app_context():
        conn = get_db()
        user_id = conn.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, "totp-test@example.invalid", digest),
        ).lastrowid
        conn.commit()

    secret = b32encode(bytes(range(20))).decode("ascii")
    clock = SimpleNamespace(now=1_700_000_010)
    monkeypatch.setattr(totp, "generate_secret", lambda: secret)
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: clock.now))
    return app, user_id, {"username": username, "password": password}, clock, pyotp.TOTP(secret)


def _redirected_to(response):
    assert response.status_code == 302
    return urlsplit(response.location).path


def _user_row(user_id):
    return get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def _enroll(user_id, code):
    assert totp.set_pending_secret(user_id)[0]
    ok, _, recovery_codes = totp.enable(user_id, code)
    assert ok
    return recovery_codes


def test_totp_step_is_shared_across_account_actions(account):
    app, user_id, login, clock, authenticator = account
    setup_client = app.test_client()
    assert _redirected_to(setup_client.post("/login", data=login)) == "/"
    assert setup_client.post("/account/totp/setup").status_code == 200
    enrollment_code = authenticator.at(clock.now)
    assert setup_client.post("/account/totp/enable", data={"code": enrollment_code}).status_code == 200

    client = app.test_client()
    assert _redirected_to(client.post("/login", data=login)) == "/login/2fa"
    assert client.post("/login/2fa", data={"code": enrollment_code}).status_code == 200
    with client.session_transaction() as session:
        assert "_user_id" not in session

    clock.now += authenticator.interval
    login_code = authenticator.at(clock.now)
    assert _redirected_to(client.post("/login/2fa", data={"code": login_code})) == "/"
    disable_form = {"current_password": login["password"], "code": login_code}
    assert _redirected_to(client.post("/account/totp/disable", data=disable_form)) == "/account/security"
    with app.app_context():
        assert _user_row(user_id)["totp_enabled"] == 1

    clock.now += authenticator.interval
    disable_form["code"] = authenticator.at(clock.now)
    assert _redirected_to(client.post("/account/totp/disable", data=disable_form)) == "/account/security"
    with app.app_context():
        row = _user_row(user_id)
        assert row["totp_enabled"] == 0
        assert row["totp_last_step"] is None


def test_totp_step_only_one_concurrent_verification(account):
    app, user_id, _, clock, authenticator = account
    with app.app_context():
        _enroll(user_id, authenticator.at(clock.now))
    clock.now += authenticator.interval
    code = authenticator.at(clock.now)
    barrier = Barrier(2, timeout=10)

    def verify():
        with app.app_context():
            row = _user_row(user_id)
            barrier.wait()
            return totp.verify_login_code(row, code)

    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = [pool.submit(verify) for _ in range(2)]
        assert sorted(attempt.result() for attempt in attempts) == [(False, False), (True, False)]


def test_restore_legacy_backup_preserves_totp_and_recovery_codes(account, tmp_path):
    app, user_id, _, clock, authenticator = account
    old_db = tmp_path / "previous.db"
    with app.app_context():
        recovery_code = _enroll(user_id, authenticator.at(clock.now))[0]
        with closing(sqlite3.connect(old_db)) as backup:
            get_db().backup(backup)
            backup.execute("ALTER TABLE users DROP COLUMN totp_last_step")
        assert restore_backup(str(old_db), user_id)[0]
        row = _user_row(user_id)
        assert row["totp_enabled"] == 1 and row["totp_last_step"] is None
        assert totp.verify_login_code(row, recovery_code) == (True, True)
        assert totp.verify_login_code(_user_row(user_id), recovery_code) == (False, False)
        assert totp.verify_login_code(_user_row(user_id), authenticator.at(clock.now)) == (True, False)
