"""v0.1.1 回归：/healthz 就绪探针 + 版本单一来源守护。

- /healthz 无鉴权 200、JSON status=ok、version 与包入口一致；
- config.VERSION 与 pyproject.toml [project].version 与包入口三方一致
  （版本声明收敛后不允许任何位置再散落硬编码）。
"""
import tomllib
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app import __version__, create_app
from app.config import BaseConfig
from app.db import init_db


@pytest.fixture()
def client(tmp_path):
    """最小可用应用：隔离临时库，TESTING 跳过启动期任务。"""
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "unit-test-secret",
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "DATABASE": str(tmp_path / "test.db"),
    })
    init_db(app)
    return app.test_client()


def test_healthz_ok(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["version"] == __version__


def test_version_single_source():
    root = Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__
    assert BaseConfig.VERSION == __version__
