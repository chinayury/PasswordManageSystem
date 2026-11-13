"""业务层：记录共享（支持有效期、可编辑权限、撤销、过期清理）。"""
import logging

from ..db import get_db
from ..utils.timefmt import hours_from_now, utcnow_str
from ..utils.validators import ValidationError, clean_str

logger = logging.getLogger(__name__)


def share_record(record_id: int, owner_id: int, shared_username: str,
                 can_edit: bool, expires_hours: int) -> None:
    """把记录共享给指定用户。

    v0.1.0 第六轮修复 BU-17：旧实现只校验"目标用户是否存在"和"不能共享
    给自己"，未校验 is_active。已被管理员禁用、或被 admin_anonymize_user
    匿名化后的 deleted_xxx 账户仍可被选为共享对象——对方虽登不进来，
    但记录里留下指向不可用账户的幽灵共享关系，账户被重新启用时共享
    silently 复活。现增加可用性校验。
    """
    from .audit import log_operation

    shared_username = clean_str(shared_username, "用户名", 50, required=True)
    conn = get_db()
    target = conn.execute(
        "SELECT * FROM users WHERE username = ?", (shared_username,)
    ).fetchone()
    if target is None:
        raise ValidationError("目标用户不存在")
    if not target["is_active"]:
        logger.warning("拒绝向不可用账户共享: record=%s target=%s",
                       record_id, shared_username)
        raise ValidationError("目标账户已被禁用或已注销，无法共享")
    if target["id"] == owner_id:
        raise ValidationError("不能共享给自己")
    exists = conn.execute(
        "SELECT id FROM shared_records WHERE record_id=? AND shared_with_id=?",
        (record_id, target["id"]),
    ).fetchone()
    if exists:
        raise ValidationError("已向该用户共享过此记录")
    expires = hours_from_now(expires_hours) if expires_hours and expires_hours > 0 else None
    conn.execute(
        "INSERT INTO shared_records (record_id, owner_id, shared_with_id, can_edit,"
        " expires_at, created_at) VALUES (?,?,?,?,?,?)",
        (record_id, owner_id, target["id"], 1 if can_edit else 0, expires, utcnow_str()),
    )
    conn.commit()
    log_operation(owner_id, "share", "password", record_id,
                  f"共享记录给 {shared_username}（{'可编辑' if can_edit else '只读'}，"
                  f"有效期 {expires_hours} 小时）" if expires_hours else
                  f"共享记录给 {shared_username}（{'可编辑' if can_edit else '只读'}，永久）")


def list_shares_for_record(record_id: int):
    return get_db().execute(
        "SELECT sr.*, u.username FROM shared_records sr"
        " JOIN users u ON sr.shared_with_id = u.id"
        " WHERE sr.record_id = ? ORDER BY sr.id DESC",
        (record_id,),
    ).fetchall()


def revoke_share(share_id: int, record_id: int, owner_id: int) -> None:
    """撤销共享（仅记录所有者）。"""
    from .audit import log_operation

    conn = get_db()
    row = conn.execute(
        "SELECT sr.*, u.username FROM shared_records sr"
        " JOIN users u ON sr.shared_with_id = u.id"
        " WHERE sr.id=? AND sr.record_id=? AND sr.owner_id=?",
        (share_id, record_id, owner_id),
    ).fetchone()
    if row is None:
        raise ValidationError("共享记录不存在或无权限撤销")
    conn.execute("DELETE FROM shared_records WHERE id=?", (share_id,))
    conn.commit()
    log_operation(owner_id, "unshare", "password", record_id,
                  f"取消共享给 {row['username']}")


def shared_with_me(user_id: int):
    """共享给我的有效记录（过期自动隐藏；UTC 统一比较）。"""
    return get_db().execute(
        "SELECT p.*, u.username AS owner_name, sr.can_edit, sr.id AS share_id,"
        "       sr.expires_at AS share_expires_at"
        " FROM shared_records sr"
        " JOIN passwords p ON sr.record_id = p.id"
        " JOIN users u ON sr.owner_id = u.id"
        " WHERE sr.shared_with_id = ? AND p.deleted_at IS NULL"
        "   AND (sr.expires_at IS NULL OR sr.expires_at > datetime('now'))"
        " ORDER BY sr.id DESC",
        (user_id,),
    ).fetchall()


def cleanup_expired_shares() -> int:
    """清理过期共享（后台/启动时调用），返回清理条数。"""
    conn = get_db()
    cur = conn.execute(
        "DELETE FROM shared_records WHERE expires_at IS NOT NULL"
        " AND expires_at <= datetime('now')"
    )
    conn.commit()
    return cur.rowcount
