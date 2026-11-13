"""业务层：操作审计日志。记录失败绝不影响主流程。"""
import logging

from flask import has_request_context, request

from ..db import get_db

logger = logging.getLogger(__name__)

# 系统级操作者（登录失败等待确认场景），对应 users 表内置 id=0 账户
SYSTEM_USER_ID = 0

# 可读化操作类型（模板也引用此映射）
OP_LABELS = {
    "login": "登录",
    "logout": "登出",
    "register": "注册",
    "reset_password": "重置密码",
    "change_password": "修改密码",
    "create": "创建",
    "update": "更新",
    "delete": "删除",
    "restore": "恢复",
    "purge": "彻底删除",
    "share": "共享",
    "unshare": "取消共享",
    "import": "批量导入",
    "export": "批量导出",
    "reveal": "查看密码",
    "backup": "备份",
    "restore_db": "恢复数据库",
    "download": "下载",
    "login_failed": "登录失败",
    "account_locked": "账户锁定",
    # v2.3 TOTP 两步验证
    "totp_enabled": "开启两步验证",
    "totp_disabled": "关闭两步验证",
    "totp_failed": "两步验证失败",
    "recovery_used": "使用恢复码登录",
    # P4 密码健康审计
    "health_report_run": "密码健康审计",
    "health_export": "健康报告导出",
}


def log_operation(user_id, operation_type: str, target_type: str,
                  target_id=None, details: str = "") -> None:
    """写审计日志；任何异常只记录到应用日志，不阻断业务。

    user_id 允许传 None（如登录失败时尚未确定用户），落库为 0
    （系统内置 system 账户，满足外键约束）。
    """
    try:
        if has_request_context():
            from ..security.ratelimit import client_ip

            ip = client_ip()  # 与限流/锁定同一来源（受 TRUST_PROXY 统一控制）
            ua = (request.headers.get("User-Agent") or "")[:500]
        else:
            ip, ua = "system", ""
        conn = get_db()
        conn.execute(
            "INSERT INTO operation_logs"
            " (user_id, operation_type, target_type, target_id, details, ip_address, user_agent)"
            " VALUES (?,?,?,?,?,?,?)",
            (user_id if user_id is not None else SYSTEM_USER_ID,
             operation_type, target_type, target_id,
             (details or "")[:1000], ip, ua),
        )
        conn.commit()
    except Exception:  # noqa: BLE001
        # 失败必须回滚：残留的失败事务会持有写锁，阻塞后续请求
        try:
            get_db().rollback()
        except Exception:  # noqa: BLE001
            pass
        logger.exception("审计日志写入失败 op=%s", operation_type)


def query_logs(page: int = 1, per_page: int = 50, user_id: int | None = None,
               op_type: str = "", keyword: str = "", date_from: str = "", date_to: str = "",
               filter_user_id: int | None = None):
    """分页查询日志。user_id 不为空时只查该用户（普通用户场景）；
    filter_user_id 为管理员在日志页显式选择的"按操作人筛选"（v2.3）。"""
    where, params = [], []
    if user_id is not None:
        where.append("ol.user_id = ?")
        params.append(user_id)
    if filter_user_id is not None:
        where.append("ol.user_id = ?")
        params.append(filter_user_id)
    if op_type:
        where.append("ol.operation_type = ?")
        params.append(op_type)
    if keyword:
        # v0.1.0 第六轮（审计观察项 2）：LIKE 通配符未转义时，用户搜 "%" 或
        # "_" 会命中全部/大片日志，排查体验被破坏（不影响安全，属可用性缺陷）。
        # 这里对 %/_/转义符做 ESCAPE 转义，语义恢复为"按字面匹配"。
        where.append("(ol.details LIKE ? ESCAPE '\\' OR u.username LIKE ? ESCAPE '\\')")
        escaped = (keyword.replace("\\", "\\\\")
                          .replace("%", "\\%")
                          .replace("_", "\\_"))
        params.extend([f"%{escaped}%", f"%{escaped}%"])
    if date_from:
        where.append("substr(ol.created_at,1,10) >= ?")
        params.append(date_from)
    if date_to:
        where.append("substr(ol.created_at,1,10) <= ?")
        params.append(date_to)

    cond = (" WHERE " + " AND ".join(where)) if where else ""
    conn = get_db()
    total = conn.execute(
        "SELECT COUNT(*) AS c FROM operation_logs ol LEFT JOIN users u ON ol.user_id=u.id" + cond,
        params,
    ).fetchone()["c"]
    rows = conn.execute(
        "SELECT ol.*, u.username FROM operation_logs ol"
        " LEFT JOIN users u ON ol.user_id = u.id" + cond +
        " ORDER BY ol.id DESC LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page],
    ).fetchall()
    return rows, total
