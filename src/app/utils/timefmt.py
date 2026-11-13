"""工具层：时间处理。

约定：数据库内所有时间戳均为 UTC，字符串格式 '%Y-%m-%d %H:%M:%S'
（与 SQLite CURRENT_TIMESTAMP 完全一致），从根本上修复旧版
"Python 本地时间 vs SQLite UTC 混用导致验证码/共享过期检查失效"的缺陷。
展示时统一通过 localtime 过滤器转换为本地时间。
"""
from datetime import datetime, timedelta, timezone

DB_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def utcnow() -> datetime:
    """当前 UTC 时间（naive，便于与库内字符串直接比较）。"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utcnow_str() -> str:
    return utcnow().strftime(DB_TIME_FORMAT)


def to_db_time(dt: datetime) -> str:
    return dt.strftime(DB_TIME_FORMAT)


def parse_db_time(value) -> datetime | None:
    """把库内时间字符串解析为 naive UTC datetime；无法解析返回 None。"""
    if not value:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo is None else value.astimezone(
            timezone.utc
        ).replace(tzinfo=None)
    s = str(value).strip().replace("T", " ")
    for fmt in (DB_TIME_FORMAT, "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[: len(fmt) + 6] if "%f" in fmt else s[:19], fmt)
        except ValueError:
            continue
    return None


def hours_from_now(hours: float) -> str:
    return to_db_time(utcnow() + timedelta(hours=hours))


def localtime_filter(value) -> str:
    """模板过滤器：UTC 库内时间 -> 本地时间展示。"""
    dt = parse_db_time(value)
    if dt is None:
        return "-" if not value else str(value)
    local = dt.replace(tzinfo=timezone.utc).astimezone()
    return local.strftime("%Y-%m-%d %H:%M")


def date_only_filter(value) -> str:
    dt = parse_db_time(value)
    if dt is None:
        return "-"
    return dt.replace(tzinfo=timezone.utc).astimezone().strftime("%Y-%m-%d")


def is_expired(value) -> bool:
    """库内 UTC 时间字符串是否已经早于当前时刻。None 视为永不过期。

    v0.1.0 修复 B-06：解析失败时改为**fail-closed**（视为已过期）。
    旧实现对脏数据返回 False，等于"过期共享继续可访问"——共享一旦
    带上了 expires_at，就绝不该因为数据格式问题而 silently 放行。
    调用方若需要区分"未设置"与"已过期"，请先判空再调本函数。
    """
    if not value:
        return False  # 未设置过期时间 = 永不过期（显式语义）
    dt = parse_db_time(value)
    if dt is None:
        return True  # 设了却解析不了 → 按已过期处理，宁可多拒不可放过
    return dt <= utcnow()
