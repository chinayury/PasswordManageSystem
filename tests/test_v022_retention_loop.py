"""v0.2.2 回归：回收站保留期周期执行的线程挂接（GB-56 补强）。"""
import threading

import pytest
from cryptography.fernet import Fernet

from app import _start_recycle_retention_loop, create_app
from app.db import init_db


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


def test_retention_loop_thread_starts_as_daemon(app):
    before = {t.name for t in threading.enumerate()}
    _start_recycle_retention_loop(app)
    after = {t.name for t in threading.enumerate()}
    assert "recycle-retention" not in before
    assert "recycle-retention" in after
    t = next(t for t in threading.enumerate() if t.name == "recycle-retention")
    assert t.daemon is True
    # （TESTING 下启动任务整体跳过、不会调到本函数——该跳过由
    # _register_startup_tasks 的 if not TESTING 守卫结构性保证。）
