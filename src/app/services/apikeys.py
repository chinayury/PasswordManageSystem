"""业务层：API 密钥（摘要存储、认证、管理、来源 IP 白名单）。"""
import ipaddress
import logging
import re

from ..db import get_db
from ..utils.timefmt import parse_db_time, utcnow, utcnow_str
from ..utils.validators import ValidationError, clean_str
from .crypto import generate_api_key, hash_api_key

logger = logging.getLogger(__name__)


def list_keys(user_id: int):
    return get_db().execute(
        "SELECT * FROM api_keys WHERE user_id=? ORDER BY id DESC", (user_id,)
    ).fetchall()


def create_key(user_id: int, key_name: str, allowed_ips: str = "") -> str:
    """创建密钥：库里只存摘要，明文仅本次返回（刷新后不可再见）。

    v0.1.0 第六轮（借鉴 GB-30）：新增 allowed_ips 参数，可绑定来源
    IP / CIDR 白名单（逗号分隔）。空字符串 = 不限制（与旧行为一致）。
    """
    from .audit import log_operation

    key_name = clean_str(key_name, "密钥名称", 100, required=True)
    allowed_ips = normalize_ip_list(allowed_ips)
    plaintext = generate_api_key()
    conn = get_db()
    conn.execute(
        "INSERT INTO api_keys (user_id, key_name, api_key, is_active, allowed_ips)"
        " VALUES (?,?,?,1,?)",
        (user_id, key_name, hash_api_key(plaintext), allowed_ips),
    )
    conn.commit()
    log_operation(user_id, "create", "api_key", None,
                  f"生成 API 密钥: {key_name}"
                  + (f"（IP 白名单: {allowed_ips}）" if allowed_ips else ""))
    return plaintext


def delete_key(user_id: int, key_id: int) -> None:
    from .audit import log_operation

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM api_keys WHERE id=? AND user_id=?", (key_id, user_id)
    ).fetchone()
    if row is None:
        raise ValidationError("密钥不存在或无权限删除")
    conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
    conn.commit()
    log_operation(user_id, "delete", "api_key", key_id, f"删除 API 密钥: {row['key_name']}")


def toggle_key(user_id: int, key_id: int) -> None:
    from .audit import log_operation

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM api_keys WHERE id=? AND user_id=?", (key_id, user_id)
    ).fetchone()
    if row is None:
        raise ValidationError("密钥不存在")
    conn.execute(
        "UPDATE api_keys SET is_active=? WHERE id=?",
        (0 if row["is_active"] else 1, key_id),
    )
    conn.commit()
    log_operation(user_id, "update", "api_key", key_id,
                  f"{'禁用' if row['is_active'] else '启用'} API 密钥: {row['key_name']}")


def set_key_ip_list(user_id: int, key_id: int, allowed_ips: str) -> None:
    """更新密钥的来源 IP / CIDR 白名单（GB-30）。

    传入空字符串表示清除限制。非法条目直接抛 ValidationError，
    不会写坏库里的既有配置。
    """
    from .audit import log_operation

    allowed_ips = normalize_ip_list(allowed_ips)
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM api_keys WHERE id=? AND user_id=?", (key_id, user_id)
    ).fetchone()
    if row is None:
        raise ValidationError("密钥不存在")
    conn.execute("UPDATE api_keys SET allowed_ips=? WHERE id=?",
                 (allowed_ips, key_id))
    conn.commit()
    log_operation(user_id, "update", "api_key", key_id,
                  f"更新 API 密钥 {row['key_name']} 的 IP 白名单: "
                  f"{allowed_ips or '（不限制）'}")


# ---------- 来源 IP / CIDR 白名单（GB-30） ----------

def normalize_ip_list(raw: str) -> str:
    """规范化 IP / CIDR 白名单字符串。

    接受逗号/分号/空白分隔的若干条目，每条必须是合法 IPv4/IPv6 地址或
    CIDR 网段（含裸 IP，按 /32 归一）。去重后按字典序输出；
    条目数超过 50 或总长度超过 500 字符时拒绝（防配置滥用）。
    """
    if not raw or not raw.strip():
        return ""
    parts = re.split(r"[,;\s]+", raw.strip())
    seen: list[str] = []
    for part in parts:
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError as exc:
            raise ValidationError(
                f"IP 白名单条目 {part!r} 不是合法的 IP 或 CIDR 网段") from exc
        canonical = str(net)
        if canonical not in seen:
            seen.append(canonical)
    if not seen:
        return ""
    if len(seen) > 50:
        raise ValidationError("IP 白名单条目过多（上限 50 条）")
    result = ", ".join(sorted(seen))
    if len(result) > 500:
        raise ValidationError("IP 白名单配置过长（上限 500 字符）")
    return result


def ip_allowed(allowed_ips: str, client_ip: str) -> bool:
    """判断来源 IP 是否命中白名单。

    - 白名单为空 = 不限制（与旧行为一致）；
    - 反代场景下 client_ip 可能带端口（如 1.2.3.4:56789），先剥离；
    - IPv4-mapped IPv6（::ffff:1.2.3.4）先解包，避免反代环境误判。
    """
    if not allowed_ips or not allowed_ips.strip():
        return True
    if not client_ip:
        return False
    candidate = client_ip.strip()
    if candidate.startswith("[") and "]" in candidate:   # [::1]:8080
        candidate = candidate[1:candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate:  # 1.2.3.4:8080
        candidate = candidate.rsplit(":", 1)[0]
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        logger.warning("IP 白名单校验：来源 %r 不是合法 IP，按不匹配处理", client_ip)
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    for entry in re.split(r"[,;\s]+", allowed_ips.strip()):
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


def authenticate_api_key(request) -> tuple[int | None, str]:
    """从请求头解析 Bearer 密钥 -> (user_id|None, 错误信息)。

    v0.1.0 第六轮修复 BU-13：旧实现每次认证都 `UPDATE api_keys SET
    last_used=?` + commit，纯读的 API 请求也开启并提交一个写事务——
    WAL 文件持续增长、并发请求被写锁序列化（busy_timeout 用尽即
    database is locked）。现改为节流写：距上次更新不足
    LAST_USED_THROTTLE_SECONDS 时跳过写库。
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, "缺少 Bearer 认证头"
    plaintext = auth[7:].strip()
    if not plaintext.startswith("pmk_"):
        return None, "密钥格式不正确"
    conn = get_db()
    row = conn.execute(
        "SELECT ak.id, ak.user_id, ak.is_active, ak.allowed_ips,"
        " u.is_active AS user_active"
        " FROM api_keys ak JOIN users u ON ak.user_id = u.id"
        " WHERE ak.api_key = ?",
        (hash_api_key(plaintext),),
    ).fetchone()
    if row is None:
        return None, "密钥无效"
    if not row["is_active"]:
        return None, "密钥已被禁用"
    if not row["user_active"]:
        return None, "密钥所属账户已被禁用"
    # v0.1.0 第六轮（借鉴 GB-30）：来源 IP / CIDR 白名单校验。
    # 反代部署必须把 TRUST_PROXY 置 true，否则 client_ip 恒为代理地址、
    # 白名单会全拒——这一点在文档与页面提示里都写明了。
    from ..security.ratelimit import client_ip

    if not ip_allowed(row["allowed_ips"], client_ip()):
        logger.warning("API 密钥 %s 来源 IP 不在白名单内，已拒绝", row["id"])
        return None, "来源 IP 不在该密钥的白名单内"
    _touch_last_used(conn, row["id"])
    return row["user_id"], ""


# BU-13：last_used 的最小更新间隔（秒）。轮询脚本以秒级频率调用时，
# 每秒最多一次写事务，其余请求零写入。
LAST_USED_THROTTLE_SECONDS = 60


def _touch_last_used(conn, key_id: int) -> None:
    """节流更新 api_keys.last_used（BU-13）。"""
    now = utcnow_str()
    row = conn.execute("SELECT last_used FROM api_keys WHERE id=?",
                       (key_id,)).fetchone()
    if row is not None and row["last_used"]:
        last = parse_db_time(row["last_used"])
        if last is not None:
            elapsed = (utcnow() - last).total_seconds()
            if elapsed < LAST_USED_THROTTLE_SECONDS:
                return
    conn.execute("UPDATE api_keys SET last_used=? WHERE id=?", (now, key_id))
    conn.commit()
