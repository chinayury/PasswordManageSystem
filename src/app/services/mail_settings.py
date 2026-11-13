"""业务层：邮件服务在线配置（数据库键值存储，可热更新）。

优先级：数据库配置 > 环境变量(.env)。
- 管理员在「系统设置」保存后即刻生效，无需重启容器；
- 数据库无记录时回退 .env（兼容旧部署）；
- 密码用应用 ENCRYPTION_KEY（Fernet）加密后存库，页面永不回显明文。
"""
from flask import current_app

from .crypto import crypto
from .settings import get_setting, set_setting

# app_settings 键前缀（与 allow_register 等业务键区分）
_PREFIX = "mail."
_KEYS = ("server", "port", "use_tls", "username", "password_enc", "sender")


def _get(key: str, default: str = "") -> str:
    return get_setting(_PREFIX + key, default)


def has_db_config() -> bool:
    """数据库里是否存过邮件配置（任一关键字段存在即视为已配置）。"""
    return bool(_get("server") or _get("username"))


def _port_of(raw: str) -> int:
    """解析端口值；库内值损坏（非数字）时回退 465，不让设置页/发信 500。"""
    try:
        return int(raw or 465)
    except (TypeError, ValueError):
        return 465


def get_mail_config() -> dict:
    """返回生效的邮件配置 dict：server/port/use_tls/username/password/sender/source。

    source: 'db'（在线配置）| 'env'（.env 回退）| 'none'
    """
    if has_db_config():
        pwd_enc = _get("password_enc")
        password = crypto().decrypt_or_none(pwd_enc) if pwd_enc else ""
        return {
            "server": _get("server"),
            "port": _port_of(_get("port", "465")),
            "use_tls": _get("use_tls", "1") == "1",
            "username": _get("username"),
            "password": password,
            "sender": _get("sender") or _get("username"),
            "source": "db",
        }
    cfg = current_app.config
    env = {
        "server": cfg.get("MAIL_SERVER", ""),
        "port": int(cfg.get("MAIL_PORT", 465) or 465),
        "use_tls": bool(cfg.get("MAIL_USE_TLS", True)),
        "username": cfg.get("MAIL_USERNAME", ""),
        "password": cfg.get("MAIL_PASSWORD", ""),
        "sender": cfg.get("MAIL_DEFAULT_SENDER", "") or cfg.get("MAIL_USERNAME", ""),
        "source": "env" if cfg.get("MAIL_SERVER") else "none",
    }
    return env


def mail_configured() -> bool:
    c = get_mail_config()
    return bool(c["server"] and c["username"] and c["password"])


def masked_view() -> dict:
    """给设置页展示的配置（不含密码明文，只给是否已设置）。"""
    c = get_mail_config()
    return {
        "server": c["server"],
        "port": c["port"],
        "use_tls": c["use_tls"],
        "username": c["username"],
        "sender": c["sender"],
        "password_set": bool(c["password"]),
        "source": c["source"],
        "configured": mail_configured(),
    }


def save_mail_config(server: str, port: int, use_tls: bool, username: str,
                     password: str, sender: str) -> None:
    """保存在线配置。password 传空串表示保留已存密码。"""
    conn_set = set_setting
    conn_set(_PREFIX + "server", server)
    conn_set(_PREFIX + "port", str(port))
    conn_set(_PREFIX + "use_tls", "1" if use_tls else "0")
    conn_set(_PREFIX + "username", username)
    if password:
        conn_set(_PREFIX + "password_enc", crypto().encrypt(password))
    conn_set(_PREFIX + "sender", sender or username)


def clear_mail_config() -> None:
    """清除在线配置，回退 .env。"""
    from ..db import get_db

    conn = get_db()
    for key in _KEYS:
        conn.execute("DELETE FROM app_settings WHERE key=?", (_PREFIX + key,))
    conn.commit()
