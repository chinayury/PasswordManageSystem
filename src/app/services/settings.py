"""业务层：应用运行时设置（数据库键值存储，可热更新）。"""
from ..db import get_db


def get_setting(key: str, default: str = "") -> str:
    row = get_db().execute(
        "SELECT value FROM app_settings WHERE key=?", (key,)
    ).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    conn = get_db()
    conn.execute(
        "INSERT INTO app_settings (key, value) VALUES (?,?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    conn.commit()


def allow_register() -> bool:
    """是否开放自注册：数据库设置优先，缺省回退环境变量。"""
    from flask import current_app

    val = get_setting("allow_register", "")
    if val in ("0", "1"):
        return val == "1"
    return bool(current_app.config.get("ALLOW_REGISTER", True))
