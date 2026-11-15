"""v0.2.1 回归：登录/登出会话重生成（GB-55）+ 回收站保留期清理（GB-56）。

- _establish_session 前清空 session：预置的旧会话内容不带入已认证会话；
- purge_expired_recycled：仅清理超过保留期的软删除记录，0=关闭；
- 启动任务挂接由 config 默认值 0 保证行为兼容。
"""
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet
from flask import session

from app import create_app
from app.db import get_db, init_db
from app.routes.auth import _establish_session
from app.services.records import purge_expired_recycled
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


def _insert_record(app, user_id: int, device_model: str):
    with app.app_context():
        conn = get_db()
        cur = conn.execute(
            "INSERT INTO passwords (user_id, device_model, port) VALUES (?,?,?)",
            (user_id, device_model, "22"))
        conn.commit()
        return cur.lastrowid


def _soft_delete(app, record_id: int, days_ago: int):
    with app.app_context():
        conn = get_db()
        conn.execute("UPDATE passwords SET deleted_at=? WHERE id=?",
                     (to_db_time(utcnow() - timedelta(days=days_ago)), record_id))
        conn.commit()


def _get_row(app, record_id: int):
    with app.app_context():
        return get_db().execute(
            "SELECT * FROM passwords WHERE id=?", (record_id,)).fetchone()


def test_establish_session_clears_pre_auth_state(app):
    with app.test_request_context("/login"):
        session["pending_2fa"] = {"uid": 999, "remember": False}
        session["attacker_controlled"] = "x"
        row = get_db().execute(
            "SELECT * FROM users WHERE username='admin'").fetchone()
        _establish_session(row, remember=False)
        # 旧内容（含半登录状态）不得带入已认证会话
        assert "attacker_controlled" not in session
        assert "pending_2fa" not in session
        # 登录态正常建立
        assert session["_user_id"] == str(row["id"])
        assert session.permanent is True
        assert "_epoch" in session


def test_purge_expired_recycled_disabled_by_default(app):
    rid = _insert_record(app, 1, "keep-me")
    _soft_delete(app, rid, days_ago=400)
    with app.app_context():
        assert purge_expired_recycled(0) == 0
        assert purge_expired_recycled(-1) == 0
    assert _get_row(app, rid) is not None


def test_purge_expired_recycled_removes_only_stale(app):
    stale_id = _insert_record(app, 1, "stale-record")
    fresh_id = _insert_record(app, 1, "fresh-record")
    _soft_delete(app, stale_id, days_ago=40)
    _soft_delete(app, fresh_id, days_ago=2)
    with app.app_context():
        purged = purge_expired_recycled(30)
    assert purged == 1
    assert _get_row(app, stale_id) is None      # 超期：彻底删除
    assert _get_row(app, fresh_id) is not None  # 未超期：保留


def test_purge_expired_recycled_keeps_live_records(app):
    live_id = _insert_record(app, 1, "never-deleted")
    with app.app_context():
        assert purge_expired_recycled(30) == 0
    assert _get_row(app, live_id) is not None
