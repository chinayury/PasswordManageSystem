"""业务层：认证（登录/注册/验证码/密码重置）。

安全设计：
- 登录失败计数 + 账户锁定（5 次失败锁 15 分钟），成功登录即清零；
- 验证码：secrets 生成、10 分钟有效、一次性、新码作废旧码，
  过期比较全部在 Python 侧用统一 UTC 时钟完成（修复旧版时区混用缺陷）；
- 密码哈希使用 bcrypt（带盐、不可逆）。
"""
import logging
import secrets
from datetime import timedelta

import bcrypt

from ..db import get_db
from ..utils.timefmt import is_expired, parse_db_time, to_db_time, utcnow, utcnow_str
from ..utils.validators import (
    BCRYPT_MAX_BYTES,
    ValidationError,
    check_account_password,
    password_byte_len,
    valid_email,
    valid_username,
)
from . import mailer
from .crypto import constant_time_equal, generate_numeric_code

logger = logging.getLogger(__name__)

MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
CODE_TTL_MINUTES = 10
PASSWORD_HISTORY_KEEP = 5   # v2.2 最近 N 个口令不得重复 (借鉴用户中心设计)

# v2.3 同 用户名+IP 维度的持久化防爆破（与上面的单账户锁定互为补充：
# 单账户锁定防"盯着一个账号试"，本维度防"同一来源对同一用户名持续撞库"，
# 且对不存在的用户名同样生效；持久化到 SQLite，应用重启不会清零）
PAIR_MAX_FAILED = 10
PAIR_LOCK_MINUTES = 15

# v0.1.0 login_lockouts 过期行保留期：超过该时长的行在清理时删除，
# 防止表被撞库流量无限撑大（锁定本身只有 15 分钟，计数过期后无保留价值）
LOCKOUT_RETENTION_HOURS = 24
# v0.1.0 第六轮 BU-05：节流从 3600s 降到 300s，并新增行数硬上限
# （见 _LOCKOUT_MAX_ROWS / _enforce_lockout_row_cap）
_LOCKOUT_CLEANUP_INTERVAL = 300  # 两次清理之间的最小间隔（秒）
_LOCKOUT_MAX_ROWS = 50_000
_LOCKOUT_CLEANUP_ROW_TRIGGER = 20_000
# 同一 IP 每 5 分钟允许落库的"幽灵用户名"（不存在的用户名）失败条数上限
_GHOST_DB_BUDGET_PER_IP = 50
_last_lockout_cleanup = 0.0  # monotonic 时间戳（进程级）


def _hash_password(plain: str) -> str:
    """bcrypt 哈希。超长口令在策略层已被拦截，此处兜底再防一次
    （v0.1.0 修复 B-01：避免未捕获 ValueError 变成 HTTP 500）。"""
    if password_byte_len(plain) > BCRYPT_MAX_BYTES:
        raise ValidationError(
            f"密码长度不能超过 {BCRYPT_MAX_BYTES} 字节"
            "（中文等字符按多字节计算，请适当缩短）")
    try:
        return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()
    except ValueError as exc:  # noqa: BLE001 理论不可达，兜底不泄露堆栈
        logger.warning("口令哈希失败: %s", exc)
        raise ValidationError("密码格式不受支持，请更换后重试") from exc


def _check_password(hashed: str, plain: str) -> bool:
    if not hashed or password_byte_len(plain) > BCRYPT_MAX_BYTES:
        # 超长口令必然不匹配（bcrypt 上限 72 字节），直接判否而不调库
        return False
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except (ValueError, TypeError):
        return False


def generate_temp_password() -> str:
    """v2.2 一次性随机临时口令 (12 位, 去易混字符, 保证大小写+数字)。"""
    import secrets as _secrets
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    lower = "abcdefghjkmnpqrstuvwxyz"
    digit = "23456789"
    pool = upper + lower + digit
    chars = [_secrets.choice(upper), _secrets.choice(lower), _secrets.choice(digit)]
    chars += [_secrets.choice(pool) for _ in range(9)]
    _secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _password_in_history(row, plain: str) -> bool:
    """新口令是否命中最近 PASSWORD_HISTORY_KEEP 个历史 (含当前口令)。"""
    import json
    try:
        hist = json.loads(row["password_history"] or "[]") if "password_history" in row.keys() else []
    except (ValueError, TypeError):
        hist = []
    hashes = [row["password"]] + [h for h in hist if h]
    for h in hashes[:PASSWORD_HISTORY_KEEP]:
        if h and _check_password(h, plain):
            return True
    return False


def _push_history(row, old_hash: str) -> str:
    """返回把旧哈希压入后的历史 JSON 字符串 (保留最近 N 个)。"""
    import json
    try:
        hist = json.loads(row["password_history"] or "[]") if "password_history" in row.keys() else []
    except (ValueError, TypeError):
        hist = []
    hist = ([old_hash] + [h for h in hist if h])[:PASSWORD_HISTORY_KEEP]
    return json.dumps(hist)


class AuthResult:
    def __init__(self, ok: bool, user=None, message: str = ""):
        self.ok = ok
        self.user = user
        self.message = message


def is_locked(row) -> bool:
    locked_until = parse_db_time(row["locked_until"]) if "locked_until" in row.keys() else None
    return locked_until is not None and locked_until > utcnow()


# v0.1.0 修复 S-06：预置一个真 bcrypt 哈希作为"影子账户"，
# 用户不存在时也完整跑一遍 checkpw，使两条路径耗时一致。
_DUMMY_HASH = bcrypt.hashpw(
    secrets.token_bytes(24).hex().encode(), bcrypt.gensalt()).decode()


def _dummy_password_check(password: str = "not-a-real-password") -> None:
    """等效耗时的空转校验（结果丢弃），仅用于抹平时序差。"""
    try:
        bcrypt.checkpw(password.encode(), _DUMMY_HASH.encode())
    except (ValueError, TypeError):
        pass


# --- v2.3 用户名+IP 维度防爆破（持久化到 login_lockouts 表） ---

def _norm_pair_username(username: str) -> str:
    """锁定表用户名规范化：去空白 + 截断到表列宽，防止超长输入撑大存储。"""
    return (username or "").strip()[:50]


def _enforce_lockout_row_cap(conn) -> int:
    """把 login_lockouts 行数压回上限内，返回删除行数。

    淘汰策略：按 last_attempt_at 升序删除最旧的行（最旧的既不在锁定期内，
    计数也早已过期，删除不影响任何在效锁定）。
    """
    total = conn.execute("SELECT COUNT(*) FROM login_lockouts").fetchone()[0]
    if total <= _LOCKOUT_MAX_ROWS:
        return 0
    excess = total - _LOCKOUT_MAX_ROWS
    cur = conn.execute(
        "DELETE FROM login_lockouts WHERE rowid IN ("
        "  SELECT rowid FROM login_lockouts ORDER BY last_attempt_at ASC LIMIT ?"
        ")", (excess,))
    conn.commit()
    logger.warning("login_lockouts 行数 %d 超过上限 %d，已淘汰最旧 %d 行",
                   total, _LOCKOUT_MAX_ROWS, cur.rowcount)
    return cur.rowcount


def cleanup_expired_lockouts(force: bool = False) -> int:
    """清理 login_lockouts 过期行（v0.1.0 新增，第六轮加固）。

    删除 last_attempt_at 早于保留期（默认 24 小时）的行——该类行既不在
    锁定期内，计数也早已过期重置，没有保留价值。带进程级节流（默认
    至少间隔 5 分钟才真正执行一次 DELETE），避免每次登录都写库；
    行数超过触发阈值时无视节流强制执行。force=True 供启动任务/测试强制执行。
    返回删除行数。
    """
    global _last_lockout_cleanup
    import time as _time

    conn = get_db()
    # 行数超限时立即执行，不等节流窗口
    row_count = conn.execute("SELECT COUNT(*) FROM login_lockouts").fetchone()[0]
    now = _time.monotonic()
    if (not force
            and row_count <= _LOCKOUT_CLEANUP_ROW_TRIGGER
            and now - _last_lockout_cleanup < _LOCKOUT_CLEANUP_INTERVAL):
        return 0
    _last_lockout_cleanup = now

    cutoff = to_db_time(utcnow() - timedelta(hours=LOCKOUT_RETENTION_HOURS))
    cur = conn.execute(
        "DELETE FROM login_lockouts WHERE last_attempt_at < ?", (cutoff,))
    conn.commit()
    removed = cur.rowcount
    # 过期行删完仍超上限（24 小时内的海量随机用户名），再按行数淘汰
    removed += _enforce_lockout_row_cap(conn)
    if removed:
        logger.info("已清理 %d 条登录锁定记录（保留 %d 小时，当前表行数阈值 %d）",
                    removed, LOCKOUT_RETENTION_HOURS, _LOCKOUT_MAX_ROWS)
    return removed


def pair_lock_remaining_minutes(username: str, ip: str) -> int | None:
    """该 用户名+IP 组合是否处于锁定中。返回剩余锁定分钟数，未锁定返回 None。"""
    conn = get_db()
    row = conn.execute(
        "SELECT locked_until FROM login_lockouts WHERE username=? AND ip=?",
        (_norm_pair_username(username), ip),
    ).fetchone()
    if row is None or not row["locked_until"]:
        return None
    locked_until = parse_db_time(row["locked_until"])
    if locked_until is None or locked_until <= utcnow():
        return None
    # 向上取整，保证提示"还剩 N 分钟"不会提前放行
    return max(1, -(-(locked_until - utcnow()).total_seconds() // 60))


def record_pair_failure(username: str, ip: str) -> None:
    """记一次该 用户名+IP 的登录失败；连续达到阈值即锁定 15 分钟。

    已处于锁定期时不累加（避免无限顺延）；锁定过期后的首次失败重新计数
    （体现"连续失败"语义）。
    """
    from .audit import log_operation

    username = _norm_pair_username(username)
    if not username or not ip:
        return
    conn = get_db()
    row = conn.execute(
        "SELECT failed_count, locked_until FROM login_lockouts WHERE username=? AND ip=?",
        (username, ip),
    ).fetchone()
    if row is not None and row["locked_until"]:
        locked_until = parse_db_time(row["locked_until"])
        if locked_until is not None and locked_until > utcnow():
            return  # 锁定中：不再累加
        # 锁定已过期：重新计数
        conn.execute(
            "UPDATE login_lockouts SET failed_count=1, locked_until=NULL,"
            " last_attempt_at=? WHERE username=? AND ip=?",
            (utcnow_str(), username, ip),
        )
        conn.commit()
        return

    failed = int(row["failed_count"]) + 1 if row is not None else 1
    if failed >= PAIR_MAX_FAILED:
        locked_until = to_db_time(utcnow() + timedelta(minutes=PAIR_LOCK_MINUTES))
        conn.execute(
            "INSERT INTO login_lockouts (username, ip, failed_count, locked_until,"
            " last_attempt_at) VALUES (?,?,?,?,?)"
            " ON CONFLICT(username, ip) DO UPDATE SET failed_count=excluded.failed_count,"
            " locked_until=excluded.locked_until, last_attempt_at=excluded.last_attempt_at",
            (username, ip, failed, locked_until, utcnow_str()),
        )
        conn.commit()
        log_operation(None, "account_locked", "user", None,
                      f"用户名 {username} 来自 {ip} 连续 {failed} 次登录失败，"
                      f"锁定 {PAIR_LOCK_MINUTES} 分钟")
    else:
        conn.execute(
            "INSERT INTO login_lockouts (username, ip, failed_count, last_attempt_at)"
            " VALUES (?,?,?,?)"
            " ON CONFLICT(username, ip) DO UPDATE SET failed_count=excluded.failed_count,"
            " last_attempt_at=excluded.last_attempt_at",
            (username, ip, failed, utcnow_str()),
        )
        conn.commit()


def clear_pair_failures(username: str) -> None:
    """登录成功后清除该用户名所有来源的失败计数（与单账户计数清零对齐）。"""
    conn = get_db()
    conn.execute("DELETE FROM login_lockouts WHERE username=?",
                 (_norm_pair_username(username),))
    conn.commit()


def is_bootstrap_password(row) -> bool:
    """该用户行是否仍在使用引导阶段的默认口令 admin123（仅用于警示展示）。"""
    try:
        return bcrypt.checkpw(b"admin123", (row["password"] or "").encode())
    except (ValueError, TypeError):
        return False


def authenticate(username: str, password: str, ip: str) -> AuthResult:
    """用户名密码校验 + 失败锁定。统一返回模糊的错误信息防止用户名枚举。"""
    username = (username or "").strip()
    # 顺手清理过期锁定行（带节流，绝大多数请求直接跳过）
    cleanup_expired_lockouts()
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", ((username or "").strip(),)
    ).fetchone()

    # v2.3 用户名+IP 维度锁定（对不存在的用户名同样生效，提示不区分账户是否存在）
    if pair_lock_remaining_minutes(username, ip) is not None:
        return AuthResult(False, message="登录失败次数过多，请 15 分钟后再试。")

    if row is None:
        # v0.1.0 修复 S-06：用户不存在时也跑一次等价的 bcrypt 运算，
        # 消除"有账户 200ms / 无账户 1ms"的响应时间差（用户名枚举侧信道）。
        _dummy_password_check()
        # v0.1.0 第六轮修复 BU-05：随机用户名撞库流量会把 login_lockouts
        # 无限撑大。对"不存在的用户名"增设内存预算——同一 IP 每窗口只允许
        # 少量幽灵用户名落库，超出后仅走内存限流（该用户名下没有真实账户
        # 需要保护，IP 维度限流已由路由层承担），不再产生新的持久化行。
        from ..security.ratelimit import limiter
        ghost_ok, _ = limiter.hit(f"login:ghost:{ip}",
                                  _GHOST_DB_BUDGET_PER_IP, 300)
        if ghost_ok:
            record_pair_failure(username, ip)
        else:
            logger.info("幽灵用户名落库预算已用尽，改为纯内存限流 (ip=%s)", ip)
        return AuthResult(False, message="用户名或密码错误！")

    # v0.1.0 第六轮修复 BU-04：禁用/系统账户/已锁定三个分支此前在 bcrypt
    # 之前就 return，响应耗时比"用户不存在"（跑一次 dummy bcrypt）快约 780 倍，
    # 攻击者可稳定枚举"账户存在但被禁用/锁定"。现统一先跑等价的 dummy bcrypt
    # 再返回，把三类分支的时序特征拉平到同一条曲线上。
    if not row["is_active"]:
        logger.warning("禁用账户尝试登录: %s (ip=%s)", row["username"], ip)
        _dummy_password_check()
        return AuthResult(False, message="该账户已被禁用，请联系管理员。")

    # v0.1.0 兜底：内置系统账户（id=0）即便因历史数据被置为可用也一律拒绝
    if row["id"] == SYSTEM_USER_ID:
        logger.error("内置系统账户被尝试登录，已拒绝 (ip=%s)", ip)
        _dummy_password_check()
        return AuthResult(False, message="该账户不可用于登录。")

    if is_locked(row):
        _dummy_password_check()
        return AuthResult(False, message="失败次数过多，账户已临时锁定，请 15 分钟后重试。")

    if not _check_password(row["password"], password):
        record_pair_failure(username, ip)
        failed = int(row["failed_attempts"] or 0) + 1
        if failed >= MAX_FAILED_ATTEMPTS:
            conn.execute(
                "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                (failed, to_db_time(utcnow() + timedelta(minutes=LOCK_MINUTES)), row["id"]),
            )
            conn.commit()
            from .audit import log_operation

            log_operation(row["id"], "account_locked", "user", row["id"],
                          f"连续 {failed} 次登录失败，账户锁定 {LOCK_MINUTES} 分钟")
        else:
            conn.execute(
                "UPDATE users SET failed_attempts=? WHERE id=?", (failed, row["id"])
            )
            conn.commit()
        return AuthResult(False, message="用户名或密码错误！")

    # 登录成功：清零计数
    conn.execute(
        "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (row["id"],)
    )
    conn.commit()
    clear_pair_failures(row["username"])
    return AuthResult(True, user=row)


def get_user_by_email(email: str):
    return get_db().execute(
        "SELECT * FROM users WHERE email = ?", ((email or "").strip().lower(),)
    ).fetchone()


def create_verification_code(email: str, purpose: str) -> tuple[bool, str]:
    """生成并下发验证码。返回 (是否成功, 提示信息)。

    v0.1.0 修复 B-05：SMTP 未配置/不可用时**先不入库**再发送。
    旧实现先落库再发信，发信失败留下一条"有码收不到"的悬空记录，
    且路由层把发送失败当 500 返回（实为服务不可用，应为 503）。

    v0.1.0 第六轮修复 BU-08：B-05 只覆盖了"未配置"分支；"已配置但发送失败"
    （网络抖动、授权码过期、服务商限流）仍走"先落库后发信"的旧顺序，
    库里留下 10 分钟内有效的悬空验证码。现改为**先发信、成功后再落库**，
    与 docstring 声称的行为一致；发信失败时库里不留任何记录。
    """
    if not mailer.mail_configured():
        logger.warning("验证码下发被拒绝：SMTP 未配置（purpose=%s）", purpose)
        return False, ("邮件服务未配置：管理员尚未设置 SMTP，"
                       "暂无法发送验证码，请联系管理员")

    code = generate_numeric_code(6)
    # 先发信：失败则直接返回，库里不产生任何记录
    if not mailer.send_verification_email(email, code, purpose):
        logger.warning("验证码下发失败：SMTP 发送未成功（purpose=%s）", purpose)
        return False, "邮件发送失败：服务端 SMTP 不可用，请稍后重试或联系管理员"

    conn = get_db()
    # 作废同邮箱同用途的旧验证码，防止多码并存被爆破
    conn.execute(
        "UPDATE email_verification_codes SET used=1"
        " WHERE email=? AND purpose=? AND used=0",
        (email, purpose),
    )
    conn.execute(
        "INSERT INTO email_verification_codes (email, code, purpose, expires_at, used)"
        " VALUES (?,?,?,?,0)",
        (email, code, purpose, to_db_time(utcnow() + timedelta(minutes=CODE_TTL_MINUTES))),
    )
    conn.commit()
    return True, "验证码已发送，请查收邮箱（注意垃圾箱）"


def verify_code(email: str, code: str, purpose: str) -> bool:
    """核销验证码：一次性、过期作废、常数时间比较。"""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM email_verification_codes"
        " WHERE email=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 5",
        (email, purpose),
    ).fetchall()
    for row in rows:
        if not is_expired(row["expires_at"]) and constant_time_equal(
            str(row["code"]), str(code or "")
        ):
            conn.execute(
                "UPDATE email_verification_codes SET used=1 WHERE id=?", (row["id"],)
            )
            conn.commit()
            return True
    return False


def register_user(username: str, email: str, password: str, confirm: str, code: str):
    """注册新用户。返回 (user_row|None, error_message|None)。"""
    from .audit import log_operation

    username = (username or "").strip()
    email = (email or "").strip().lower()
    if not valid_username(username):
        return None, "用户名需为 3-50 位字母、数字、下划线或短横线"
    if not valid_email(email):
        return None, "邮箱格式不正确"
    if password != confirm:
        return None, "两次输入的密码不一致"
    try:
        check_account_password(password)
    except ValidationError as exc:
        return None, str(exc)
    if not verify_code(email, code, "register"):
        return None, "验证码错误、已过期或邮箱不匹配"

    conn = get_db()
    dup = conn.execute(
        "SELECT id FROM users WHERE username=? OR email=?", (username, email)
    ).fetchone()
    if dup:
        return None, "用户名或邮箱已被注册"
    try:
        cur = conn.execute(
            "INSERT INTO users (username, email, password, is_admin, email_verified, is_active)"
            " VALUES (?,?,?,0,1,1)",
            (username, email, _hash_password(password)),
        )
        conn.commit()
    except Exception:  # noqa: BLE001
        conn.rollback()
        return None, "注册失败：用户名或邮箱可能已被占用"
    log_operation(cur.lastrowid, "register", "user", cur.lastrowid, f"用户注册: {username}")
    return conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone(), None


def revoke_user_sessions(user_id: int, revoke_api_keys: bool = True) -> int:
    """把该用户的全部既有登录态踢下线（v0.1.0 修复 S-11）。

    做法：users.session_epoch + 1，并在请求前置校验中发现会话里记录的
    纪元落后于库内值时强制登出。因为 Flask 会话是客户端 Cookie，
    服务端无法枚举"这个用户当前有哪些会话"，纪元递增是唯一可靠的
    全量失效手段；同时按需吊销该用户的 API 密钥（Bearer 密钥不依赖
    Cookie，只能靠删库实现即时失效）。返回被吊销的 API 密钥数量。
    """
    from .audit import log_operation

    conn = get_db()
    cur = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if cur is None:
        return 0
    revoked = 0
    if revoke_api_keys:
        c = conn.execute("DELETE FROM api_keys WHERE user_id=?", (user_id,))
        revoked = c.rowcount or 0
    conn.execute(
        "UPDATE users SET session_epoch = COALESCE(session_epoch, 0) + 1 WHERE id=?",
        (user_id,))
    conn.commit()
    if revoked:
        logger.info("用户 %s 的 %d 个 API 密钥已随口令变更吊销", user_id, revoked)
    log_operation(user_id, "sessions_revoked", "user", user_id,
                  f"口令变更后全部登录态已失效（吊销 API 密钥 {revoked} 个）")
    return revoked


def reset_password_by_email(email: str, code: str, new_password: str) -> tuple[bool, str]:
    """通过邮箱验证码重置密码（忘记密码流程）。"""
    from .audit import log_operation

    email = (email or "").strip().lower()
    try:
        check_account_password(new_password)
    except ValidationError as exc:
        return False, str(exc)
    row = get_user_by_email(email)
    if row is None:
        # 不暴露邮箱是否注册（防枚举）；验证码同样校验以保持响应一致
        verify_code(email, code, "reset_password")
        return True, "如果该邮箱已注册，密码已被重置，请使用新密码登录。"
    if not verify_code(email, code, "reset_password"):
        return False, "验证码错误或已过期"
    if _password_in_history(row, new_password):
        return False, f"新密码不能与最近 {PASSWORD_HISTORY_KEEP} 次使用过的密码相同"
    conn = get_db()
    conn.execute(
        "UPDATE users SET password=?, password_history=?, must_change_password=0, "
        "failed_attempts=0, locked_until=NULL,"
        " session_epoch = COALESCE(session_epoch, 0) + 1 WHERE id=?",
        (_hash_password(new_password), _push_history(row, row["password"]), row["id"]),
    )
    conn.commit()
    # 改密即失效：清掉该用户其它设备上的登录态与 API 密钥（S-11）
    revoke_user_sessions(row["id"])
    log_operation(row["id"], "reset_password", "user", row["id"], "用户通过邮箱验证码重置密码")
    return True, "如果该邮箱已注册，密码已被重置，请使用新密码登录。"


def change_password(user_id: int, current_pw: str, new_pw: str, confirm_pw: str,
                    force: bool = False) -> tuple[bool, str]:
    """登录状态下修改自己的密码。

    v2.2: force=True 为"强制改密模式" (管理员重置/新建后), 跳过旧密码校验
    (用户手上是管理员给的临时口令), 但仍受强度策略与历史不重复约束。
    """
    from .audit import log_operation

    if new_pw != confirm_pw:
        return False, "新密码与确认密码不匹配"
    try:
        check_account_password(new_pw)
    except ValidationError as exc:
        return False, str(exc)
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        return False, "用户不存在"
    if not force and not _check_password(row["password"], current_pw):
        return False, "当前密码错误"
    if _password_in_history(row, new_pw):
        return False, f"新密码不能与最近 {PASSWORD_HISTORY_KEEP} 次使用过的密码相同"
    conn.execute(
        "UPDATE users SET password=?, password_history=?, must_change_password=0, "
        "failed_attempts=0, locked_until=NULL,"
        " session_epoch = COALESCE(session_epoch, 0) + 1 WHERE id=?",
        (_hash_password(new_pw), _push_history(row, row["password"]), user_id),
    )
    conn.commit()
    # 改密即失效：清掉该用户其它设备上的登录态与 API 密钥（S-11）
    revoke_user_sessions(user_id)
    log_operation(user_id, "change_password", "user", user_id,
                  "用户强制修改初始密码" if force else "用户修改登录密码")
    return True, "密码修改成功，请使用新密码重新登录"


# --- 管理员用户管理服务 ---

def admin_update_user(admin_id: int, target_id: int, username: str, email: str,
                      new_password: str) -> tuple[bool, str]:
    from .audit import log_operation

    if _is_system_account(target_id):
        return False, "内置系统账户不可修改"
    username = (username or "").strip()
    email = (email or "").strip().lower()
    if not valid_username(username):
        return False, "用户名需为 3-50 位字母、数字、下划线或短横线"
    if not valid_email(email):
        return False, "邮箱格式不正确"
    if new_password:
        try:
            check_account_password(new_password)
        except ValidationError as exc:
            return False, str(exc)

    conn = get_db()
    dup = conn.execute(
        "SELECT id FROM users WHERE (username=? OR email=?) AND id != ?",
        (username, email, target_id),
    ).fetchone()
    if dup:
        return False, "用户名或邮箱已被其他用户使用"
    cur = conn.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
    if cur is None:
        return False, "用户不存在"
    if new_password:
        # v2.2: 管理员代设口令 → 旧口令入历史 + 置强制改密 (让用户换成私人口令)
        # v0.1.0: 同时递增会话纪元，把该用户其它设备上的登录态踢下线
        conn.execute(
            "UPDATE users SET username=?, email=?, password=?, password_history=?, "
            "must_change_password=1,"
            " session_epoch = COALESCE(session_epoch, 0) + 1 WHERE id=?",
            (username, email, _hash_password(new_password),
             _push_history(cur, cur["password"]), target_id),
        )
    else:
        conn.execute(
            "UPDATE users SET username=?, email=? WHERE id=?",
            (username, email, target_id),
        )
    conn.commit()
    log_operation(admin_id, "update", "user", target_id,
                  f"管理员修改用户信息: {username}" + ("，重置密码" if new_password else ""))
    return True, "用户信息更新成功" + ("，密码已重置（该用户下次登录须改密）" if new_password else "")


def admin_reset_password(admin_id: int, target_id: int) -> tuple[bool, str, str]:
    """v2.2 管理员重置口令: 生成一次性随机临时口令 + 强制改密 + 清除锁定。

    返回 (是否成功, 提示, 临时口令)。临时口令仅随响应展示一次, 不落日志。
    """
    from .audit import log_operation

    conn = get_db()
    cur = conn.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
    if cur is None:
        return False, "用户不存在", ""
    if _is_system_account(target_id):
        return False, "内置系统账户不可重置", ""
    temp = generate_temp_password()
    conn.execute(
        "UPDATE users SET password=?, password_history=?, must_change_password=1, "
        "failed_attempts=0, locked_until=NULL,"
        " session_epoch = COALESCE(session_epoch, 0) + 1 WHERE id=?",
        (_hash_password(temp), _push_history(cur, cur["password"]), target_id),
    )
    conn.commit()
    log_operation(admin_id, "reset_password", "user", target_id,
                  f"管理员重置口令 (一次性临时口令): {cur['username']}")
    return True, "口令已重置，临时口令仅显示一次", temp


def admin_unlock(admin_id: int, target_id: int) -> tuple[bool, str]:
    """v2.2 管理员手动解锁: 清除失败计数与锁定时间。"""
    from .audit import log_operation

    conn = get_db()
    cur = conn.execute("SELECT username FROM users WHERE id=?", (target_id,)).fetchone()
    if cur is None:
        return False, "用户不存在"
    conn.execute(
        "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?",
        (target_id,),
    )
    conn.commit()
    log_operation(admin_id, "unlock", "user", target_id, f"管理员解锁账户: {cur['username']}")
    return True, "账户已解锁，可立即重新登录"


# 内置系统账户 id：承接"登录失败"等无明确操作者的审计日志，满足外键约束。
# 该账户永久禁用、口令随机不可登录，任何管理操作都不得触碰它，
# 否则会出现冒用"system"身份登录并污染审计归因的风险（S-10）。
SYSTEM_USER_ID = 0


def _is_system_account(target_id: int) -> bool:
    return target_id == SYSTEM_USER_ID


def admin_set_admin(admin_id: int, target_id: int, make_admin: bool) -> tuple[bool, str]:
    from .audit import log_operation

    if _is_system_account(target_id):
        return False, "内置系统账户不可修改"
    conn = get_db()
    exists = conn.execute("SELECT 1 FROM users WHERE id=?", (target_id,)).fetchone()
    if exists is None:
        return False, "用户不存在"
    conn.execute("UPDATE users SET is_admin=? WHERE id=?",
                 (1 if make_admin else 0, target_id))
    conn.commit()
    log_operation(admin_id, "update", "user", target_id,
                  f"{'授予' if make_admin else '撤销'}管理员权限")
    return True, "权限已更新"


def admin_set_active(admin_id: int, target_id: int, active: bool) -> tuple[bool, str]:
    from .audit import log_operation

    if _is_system_account(target_id):
        return False, "内置系统账户不可修改"
    conn = get_db()
    exists = conn.execute("SELECT 1 FROM users WHERE id=?", (target_id,)).fetchone()
    if exists is None:
        return False, "用户不存在"
    conn.execute(
        "UPDATE users SET is_active=?, failed_attempts=0, locked_until=NULL WHERE id=?",
        (1 if active else 0, target_id),
    )
    conn.commit()
    log_operation(admin_id, "update", "user", target_id,
                  f"{'启用' if active else '禁用'}账户")
    return True, "账户状态已更新"


def admin_anonymize_user(admin_id: int, target_id: int) -> tuple[bool, str]:
    """注销用户：匿名化账户（保留行以满足审计外键），其密码记录转入回收站。

    说明：物理删除 users 行会被 operation_logs 的外键阻止；且从审计角度
    保留用户标识更安全，故采用"匿名化 + 禁用"而非物理删除。
    """
    import secrets

    from .audit import log_operation
    from ..utils.timefmt import utcnow_str

    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
    if target is None:
        return False, "用户不存在"
    if _is_system_account(target_id):
        return False, "内置系统账户不可注销"
    anon_name = f"deleted_{target_id}_{secrets.token_hex(3)}"
    conn.execute(
        "UPDATE users SET username=?, email=?, password=?, is_active=0, is_admin=0,"
        " failed_attempts=0, locked_until=NULL,"
        " session_epoch = COALESCE(session_epoch, 0) + 1 WHERE id=?",
        (anon_name, f"{anon_name}@deleted.invalid",
         _hash_password(secrets.token_hex(16)), target_id),
    )
    conn.execute(
        "UPDATE passwords SET deleted_at=? WHERE user_id=? AND deleted_at IS NULL",
        (utcnow_str(), target_id),
    )
    conn.execute("DELETE FROM api_keys WHERE user_id=?", (target_id,))
    conn.execute("DELETE FROM shared_records WHERE owner_id=? OR shared_with_id=?",
                 (target_id, target_id))
    conn.commit()
    log_operation(admin_id, "delete", "user", target_id,
                  f"注销并匿名化用户（原用户名 {target['username']}），其记录已转入回收站")
    return True, "用户已注销，其名下记录已转入回收站"
