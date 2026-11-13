"""业务层：TOTP 两步验证（v2.3）。

安全设计：
- TOTP 密钥使用应用层 Fernet 加密落库（与密码记录密文同一密钥体系），
  仅在开启流程向用户展示一次明文，之后不再回显；
- 一次性恢复码：开启时生成 10 个（secrets 模块），只存摘要，明文不落库，
  登录时验证成功一次即从库中删除（用过即废）；
  v0.1.0 摘要算法升级为 HMAC-SHA256（以 SECRET_KEY 为 pepper），
  替代逐条 bcrypt 比对——单次失败尝试从约 1 秒降到微秒级，
  彻底消除攻击者故意提交恢复码格式耗尽 CPU 的面；存量 bcrypt 哈希
  仍可验证（向后兼容），下次重新开启两步验证即切换为新格式；
- 验证容差 valid_window=1（容忍前后各 1 个 30 秒周期的时钟偏差）；
- 未开启两步验证的用户完全不受影响（登录/接口流程不变）。
"""
import hashlib
import hmac as _hmac
import json
import logging
import re

import bcrypt
import pyotp
from flask import current_app

from ..db import get_db
from .crypto import constant_time_equal, crypto

logger = logging.getLogger(__name__)

RECOVERY_CODE_COUNT = 10  # 开启时一次性生成的恢复码数量
_TOTP_ISSUER = "PasswordManageSystem"  # 认证器 App 内显示的发行方名
_RECOVERY_RE = re.compile(r"^[0-9A-F]{8}$")  # 恢复码格式：8 位十六进制


def _normalize(code: str) -> str:
    """去掉空格/短横线并统一大写（兼容用户粘贴 'xxxx-xxxx' 格式）。"""
    return (code or "").strip().replace(" ", "").replace("-", "").upper()


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    """生成 otpauth:// URI（本项目不引入二维码库，由用户手动录入或用
    支持 otpauth 链接的认证器导入）。"""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=_TOTP_ISSUER)


def _decrypt_secret(enc_secret: str | None) -> str | None:
    """解密库内 TOTP 密钥；未设置或密钥变更导致解不开时返回 None。"""
    if not enc_secret:
        return None
    try:
        return crypto().decrypt(enc_secret)
    except Exception:  # noqa: BLE001
        return None


def get_user_totp_row(user_id: int):
    """取用户 TOTP 相关字段（totp_secret/totp_enabled/recovery_codes）。"""
    return get_db().execute(
        "SELECT username, totp_secret, totp_enabled, recovery_codes"
        " FROM users WHERE id=?", (user_id,)
    ).fetchone()


def set_pending_secret(user_id: int) -> tuple[bool, str, str]:
    """开启流程第一步：生成新密钥（覆盖旧的未启用密钥），加密落库。
    返回 (是否成功, 明文密钥, otpauth URI)，明文仅此一次展示。

    v0.1.0 修复 S-01：两步验证已开启时拒绝重新生成密钥。此前该函数
    无条件执行 `totp_enabled=0`，等于让已开启 2FA 的用户在一次
    「生成密钥」点击后两步验证被静默关闭，且无需密码或动态码确认。
    """
    try:
        row = get_user_totp_row(user_id)
        if row is None:
            return False, "", ""
        if row["totp_enabled"]:
            logger.warning(
                "用户 %s 已开启两步验证，拒绝重新生成密钥（防止无声关闭 2FA）", user_id)
            return False, "", ""
        secret = generate_secret()
        get_db().execute(
            "UPDATE users SET totp_secret=?, totp_enabled=0 WHERE id=?",
            (crypto().encrypt(secret), user_id),
        )
        get_db().commit()
        return True, secret, provisioning_uri(secret, row["username"])
    except Exception:  # noqa: BLE001
        logger.exception("生成 TOTP 密钥失败 user_id=%s", user_id)
        return False, "", ""


def _verify_totp(secret: str, code: str) -> bool:
    """校验 6 位动态码，容差 1 个周期。"""
    if not re.fullmatch(r"\d{6}", code):
        return False
    try:
        return bool(pyotp.TOTP(secret).verify(code, valid_window=1))
    except Exception:  # noqa: BLE001
        return False


def _load_recovery_hashes(row) -> list[str]:
    try:
        hashes = json.loads(row["recovery_codes"] or "[]")
    except (ValueError, TypeError):
        hashes = []
    return [h for h in hashes if h]


def _recovery_digest(code: str) -> str:
    """恢复码摘要（v0.1.0）：HMAC-SHA256(code, SECRET_KEY)。

    恢复码本身为 8 位十六进制（32 bit 熵）的密码学随机值，摘要引入
    服务端 pepper 后，离线爆破必须同时拿到数据库与 SECRET_KEY——
    而两者皆失守时攻击者已可直接伪造会话，安全性等价于 bcrypt 方案。
    """
    pepper = str(current_app.config.get("SECRET_KEY", ""))
    return "hmac:" + _hmac.new(pepper.encode(), code.encode(),
                               hashlib.sha256).hexdigest()


def _check_recovery_code(hashes: list[str], code: str) -> int | None:
    """恢复码是否命中某个摘要。返回命中的下标，未命中返回 None。

    v0.1.0 新格式（hmac: 前缀）走常数时间快路径；存量 bcrypt 哈希
    （旧格式）逐条回退比对，保证升级后旧恢复码仍然有效。
    """
    if not _RECOVERY_RE.fullmatch(code):
        return None
    digest = _recovery_digest(code)
    for i, h in enumerate(hashes):
        if h.startswith("hmac:"):
            if constant_time_equal(h, digest):
                return i
        else:  # v2.3 存量 bcrypt 哈希
            try:
                if bcrypt.checkpw(code.encode(), h.encode()):
                    return i
            except ValueError:
                continue
    return None


def enable(user_id: int, code: str) -> tuple[bool, str, list[str]]:
    """开启流程第二步：用一次有效动态码确认开启，并生成一次性恢复码。

    返回 (是否成功, 提示, 恢复码明文列表)——明文仅随本次响应展示一次，
    库中只保留 bcrypt 哈希。
    """
    from .audit import log_operation

    row = get_user_totp_row(user_id)
    if row is None:
        return False, "用户不存在", []
    secret = _decrypt_secret(row["totp_secret"])
    if secret is None:
        return False, "请先点击「生成密钥」开始设置", []
    if not _verify_totp(secret, _normalize(code)):
        return False, "验证码错误，请输入认证器当前的 6 位动态码", []

    codes = _generate_recovery_codes(RECOVERY_CODE_COUNT)
    # v0.1.0：恢复码摘要改用 HMAC-SHA256（秒级完成 10 个摘要的计算，
    # 旧 bcrypt 方案此处需约 1.5 秒且每次登录失败校验逐条重算）
    hashes = [_recovery_digest(c) for c in codes]
    get_db().execute(
        "UPDATE users SET totp_enabled=1, recovery_codes=? WHERE id=?",
        (json.dumps(hashes), user_id),
    )
    get_db().commit()
    log_operation(user_id, "totp_enabled", "user", user_id,
                  "用户开启两步验证（TOTP），已生成一次性恢复码")
    return True, "两步验证已开启", codes


def _generate_recovery_codes(count: int) -> list[str]:
    """生成恢复码：8 位十六进制（secrets 模块，密码学安全）。"""
    import secrets

    return [secrets.token_hex(4).upper() for _ in range(count)]


def disable(user_id: int, current_password: str, code: str) -> tuple[bool, str]:
    """关闭两步验证：需当前密码 + 当前有效动态码双重确认。"""
    from .audit import log_operation

    conn = get_db()
    row = conn.execute(
        "SELECT username, password, totp_secret FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if row is None:
        return False, "用户不存在"
    try:
        pw_ok = bcrypt.checkpw(
            (current_password or "").encode(), row["password"].encode())
    except ValueError:
        pw_ok = False
    if not pw_ok:
        return False, "当前密码错误"
    secret = _decrypt_secret(row["totp_secret"])
    if secret is None or not _verify_totp(secret, _normalize(code)):
        return False, "验证码错误，请输入认证器当前的 6 位动态码"

    conn.execute(
        "UPDATE users SET totp_secret=NULL, totp_enabled=0, recovery_codes=NULL"
        " WHERE id=?", (user_id,))
    conn.commit()
    log_operation(user_id, "totp_disabled", "user", user_id, "用户关闭两步验证")
    return True, "两步验证已关闭"


def verify_login_code(row, code: str) -> tuple[bool, bool]:
    """登录第二因子校验：动态码或一次性恢复码均可。

    参数 row 为 users 整行。返回 (是否通过, 是否使用了恢复码)；
    恢复码命中后立即从库中删除（用过即废）。失败由调用方计入防爆破计数。
    """
    code = _normalize(code)
    secret = _decrypt_secret(row["totp_secret"])
    if secret is None:
        # 开关开着但密钥缺失/解不开：宁可拒绝也不能放行
        logger.error("用户 %s(TOTP) 密钥缺失或解密失败，已拒绝登录", row["id"])
        return False, False

    if _verify_totp(secret, code):
        return True, False

    # 动态码未命中，尝试恢复码（格式 8 位十六进制；6 位纯数字必然不匹配，直接跳过）
    hashes = _load_recovery_hashes(row)
    if hashes:
        idx = _check_recovery_code(hashes, code)
        if idx is not None:
            from .audit import log_operation

            hashes.pop(idx)
            get_db().execute(
                "UPDATE users SET recovery_codes=? WHERE id=?",
                (json.dumps(hashes), row["id"]),
            )
            get_db().commit()
            log_operation(row["id"], "recovery_used", "user", row["id"],
                          f"使用一次性恢复码登录（剩余 {len(hashes)} 个）")
            return True, True
    return False, False
