"""v0.2.5 回归：导入口令逐字保留（GB-58）+ 恢复校验应用标识（GB-59）。

- _zip_columns 对 password 列不再剥首尾空格，其余列维持原行为；
- import_rows 端到端：带首尾空格的口令入库后解密往返逐字一致；
- validate_backup_file：本系统库（魔数 0x50444D31）与存量库（0）放行，
  其它应用标识的 SQLite 被拒绝。
"""
import sqlite3

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.db import get_db, init_db
from app.services.backup import validate_backup_file
from app.services.crypto import crypto
from app.services.excelio import _zip_columns, import_rows


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


def test_zip_columns_preserves_password_spaces():
    values = ("web  ", "", "", "", "", "root", "  p@ss word  ", "22", "", "", "", "")
    row = _zip_columns(values)
    assert row["device_model"] == "web"          # 其余列照常剥首尾空白
    assert row["password"] == "  p@ss word  "    # 口令逐字保留（GB-58）


def test_import_rows_preserves_password_verbatim(app):
    rows = [_zip_columns(("dev", "", "", "", "", "root",
                          " p@ss with spaces ", "22", "", "", "", ""))]
    with app.app_context():
        result = import_rows(1, rows)
        assert result["imported"] == 1 and not result["errors"]
        stored = get_db().execute(
            "SELECT password FROM passwords WHERE device_model='dev'").fetchone()["password"]
        assert crypto().decrypt(stored) == " p@ss with spaces "


def _write_db(path, application_id):
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TABLE passwords (id INTEGER PRIMARY KEY)")
    if application_id is not None:
        conn.execute(f"PRAGMA application_id = {application_id}")
    conn.commit()
    conn.close()


def test_validate_backup_accepts_pdm_and_legacy(tmp_path):
    good = tmp_path / "pdm.db"
    legacy = tmp_path / "legacy.db"
    _write_db(good, 0x50444D31)
    _write_db(legacy, 0)
    ok, msg = validate_backup_file(str(good))
    assert ok, msg
    ok2, msg2 = validate_backup_file(str(legacy))
    assert ok2, msg2


def test_validate_backup_rejects_foreign_instance(tmp_path):
    foreign = tmp_path / "foreign.db"
    # 注意：PRAGMA application_id 静默忽略 ≥2^31 的值（读回 0），
    # 外来标识须落在带符号 32 位正数范围内才能被持久化
    _write_db(foreign, 0x12345678)  # 其它应用的标识
    ok, msg = validate_backup_file(str(foreign))
    assert not ok
    assert "应用标识" in msg
