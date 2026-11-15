"""v0.2.0 回归：用户名冲突防御（GB-53）+ 记录分词搜索（GB-54）。

- 注册/管理员改名拒绝保留名与既有用户名的大小写变体；
- 记录搜索：多关键词逐词 AND（任一搜索字段命中）、单关键词保持所选字段、
  % 与 _ 按字面量处理。
"""
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.db import get_db, init_db
from app.services.auth import admin_update_user, register_user
from app.services.records import list_records
from app.utils.timefmt import to_db_time, utcnow


@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "unit-test-secret",
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "DATABASE": str(tmp_path / "test.db"),
    })
    init_db(app)
    return app


def _insert_code(app, email: str, code: str = "123456"):
    with app.app_context():
        conn = get_db()
        conn.execute(
            "INSERT INTO email_verification_codes (email, code, purpose, expires_at, used)"
            " VALUES (?,?,?,?,0)",
            (email, code, "register", to_db_time(utcnow() + timedelta(minutes=10)))
        )
        conn.commit()


def _insert_user(app, username: str, email: str):
    with app.app_context():
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, email, password, is_admin, email_verified,"
            " is_active) VALUES (?,?,'x',0,1,1)", (username, email))
        conn.commit()


def _insert_record(app, user_id: int, **cols):
    with app.app_context():
        conn = get_db()
        fields = {"device_model": "", "ip_address": "", "username": "",
                  "serial_number": "", "port": "22"}
        fields.update(cols)
        conn.execute(
            "INSERT INTO passwords (user_id, device_model, ip_address, username,"
            " serial_number, port) VALUES (?,?,?,?,?,?)",
            (user_id, fields["device_model"], fields["ip_address"],
             fields["username"], fields["serial_number"], fields["port"]))
        conn.commit()


def test_register_rejects_reserved_names(app):
    for name in ("Admin", "ADMIN", "system", "API", "root", "administrator"):
        ok, err = register_user(name, f"{name.lower()}@x.com", "Str0ng-Pass!",
                                "Str0ng-Pass!", "000000")
        assert ok is None, name
        assert "保留名" in err, (name, err)


def test_register_rejects_case_variant_of_existing_user(app):
    _insert_user(app, "operator", "op@x.com")
    _insert_code(app, "new@x.com")
    with app.app_context():
        ok, err = register_user("OPERATOR", "new@x.com", "Str0ng-Pass!",
                                "Str0ng-Pass!", "123456")
    assert ok is None
    assert "已被注册" in err


def test_register_allows_plain_name_with_valid_code(app):
    _insert_code(app, "plain@x.com")
    with app.app_context():
        user, err = register_user("plainuser", "plain@x.com", "Str0ng-Pass!",
                                  "Str0ng-Pass!", "123456")
    assert err is None
    assert user is not None and user["username"] == "plainuser"


def test_admin_rename_rejects_case_variant_and_reserved(app):
    _insert_user(app, "operator", "op@x.com")
    _insert_user(app, "helper", "helper@x.com")
    with app.app_context():
        conn = get_db()
        target = conn.execute(
            "SELECT id FROM users WHERE username='helper'").fetchone()["id"]
        admin = conn.execute(
            "SELECT id FROM users WHERE username='admin'").fetchone()["id"]
        # 把 helper 改名为既有用户 operator 的大小写变体 → 拒绝
        ok, err = admin_update_user(admin, target, "OPERATOR", "helper@x.com", "")
        assert ok is False and "已被其他用户使用" in err
        ok, err = admin_update_user(admin, target, "API", "helper@x.com", "")
        assert ok is False and "保留名" in err
        # 改回自己名字的大小写变体 → 合法（排除自身后无冲突）
        ok, err = admin_update_user(admin, target, "HELPER", "helper@x.com", "")
        assert ok is True


def test_multi_term_and_single_term_search(app):
    _insert_record(app, 1, device_model="webserver", ip_address="10.0.0.5",
                   username="root", serial_number="SN-A1")
    _insert_record(app, 1, device_model="dbserver", ip_address="10.0.0.6",
                   username="root", serial_number="SN-B1")
    _insert_record(app, 1, device_model="db_server_01", ip_address="10.0.1.9",
                   username="svc", serial_number="SN-C1")

    with app.app_context():
        # 多关键词：逐词 AND、任一搜索字段命中即算（默认字段 device_model
        # 不含 "10.0.0"，但 IP 字段命中，仍应返回 webserver）
        rows, total = list_records(1, "web 10.0.0")
        assert total == 1 and rows[0]["device_model"] == "webserver"
        # 多关键词 AND：两词分别命中不同记录 → 交集为空
        _, total2 = list_records(1, "webserver 10.0.1")
        assert total2 == 0
        # 单关键词保持原行为：仅所选字段
        _, total3 = list_records(1, "10.0.0", field="device_model")
        assert total3 == 0
        _, total4 = list_records(1, "10.0.0", field="ip_address")
        assert total4 == 2
        # 下划线按字面量匹配（ESCAPE）：db_server_01 命中，dbserver 不命中
        _, total5 = list_records(1, "b_s", field="device_model")
        assert total5 == 1
