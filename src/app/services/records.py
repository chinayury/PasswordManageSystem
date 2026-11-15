"""业务层：密码记录（CRUD/搜索/分页/回收站/附件）。"""
import logging
import os
import uuid

from flask import current_app
from werkzeug.utils import secure_filename

from ..db import get_db
from ..utils.timefmt import hours_from_now, utcnow_str
from ..utils.validators import RECORD_SEARCH_FIELDS, ValidationError
from .crypto import CryptoError, crypto

logger = logging.getLogger(__name__)

RECORD_FIELDS = (
    "device_model", "serial_number", "location", "node_name", "ip_address",
    "username", "port", "access_method", "remark1", "remark2",
)


# ---------- 查询 ----------

def list_records(user_id: int, search: str = "", field: str = "device_model",
                 project_id: int | None = None, page: int = 1, per_page: int = 20,
                 include_deleted: bool = False, expiring: bool = False):
    """分页查询当前用户的记录。搜索字段走白名单，杜绝对 SQL 的拼接注入。

    expiring=True 时仅返回"到期关注"记录：expires_at 已过期或在
    30 天内到期（与密码健康审计共用同一 expires_at 字段语义）。
    """
    field = field if field in RECORD_SEARCH_FIELDS else "device_model"
    page = max(1, page)
    per_page = max(1, min(per_page, 100))

    where = ["p.user_id = ?"]
    params: list = [user_id]
    if not include_deleted:
        where.append("p.deleted_at IS NULL")
    else:
        where.append("p.deleted_at IS NOT NULL")
    if search:
        # 借鉴 GB-54 · Padloc 多关键词检索：空格分隔的多个关键词逐词匹配
        # （任一搜索字段命中即算该词命中），词与词之间取 AND；单关键词保持
        # 原行为（仅所选字段）。% 与 _ 一律按字面量处理（ESCAPE '\'），
        # 型号/序列号里常见的下划线不再被当作通配符。
        terms = search.split()[:5]  # 最多取 5 个词，防止超长条件膨胀
        def _like(value: str) -> str:
            return "%" + value.replace("\\", "\\\\").replace("%", "\\%") \
                              .replace("_", "\\_") + "%"
        if len(terms) == 1:
            where.append(f"p.{field} LIKE ? ESCAPE '\\'")
            params.append(_like(terms[0]))
        else:
            term_groups = []
            for t in terms:
                term_groups.append(
                    "(" + " OR ".join(
                        f"p.{f} LIKE ? ESCAPE '\\'" for f in RECORD_SEARCH_FIELDS
                    ) + ")")
                params.extend([_like(t)] * len(RECORD_SEARCH_FIELDS))
            where.append("(" + " AND ".join(term_groups) + ")")
    if project_id:
        where.append("p.project_id = ?")
        params.append(project_id)
    if expiring:
        where.append("p.expires_at IS NOT NULL AND p.expires_at <= ?")
        params.append(hours_from_now(30 * 24))
    cond = " WHERE " + " AND ".join(where)

    conn = get_db()
    total = conn.execute(
        "SELECT COUNT(*) AS c FROM passwords p" + cond, params
    ).fetchone()["c"]
    rows = conn.execute(
        "SELECT p.*, pr.name AS project_name, pr.type AS project_type"
        " FROM passwords p LEFT JOIN projects pr ON p.project_id = pr.id"
        + cond + " ORDER BY p.id DESC LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page],
    ).fetchall()
    return rows, total


def get_record(record_id: int):
    return get_db().execute(
        "SELECT * FROM passwords WHERE id = ?", (record_id,)
    ).fetchone()


def get_record_permission(record, user_id: int) -> str | None:
    """返回 'owner' / 'shared_edit' / 'shared_view' / None（无权限）。"""
    if record is None:
        return None
    if record["user_id"] == user_id:
        return "owner"
    row = get_db().execute(
        "SELECT can_edit, expires_at FROM shared_records"
        " WHERE record_id=? AND shared_with_id=?",
        (record["id"], user_id),
    ).fetchone()
    if row is None:
        return None
    from ..utils.timefmt import is_expired

    if is_expired(row["expires_at"]):
        return None
    return "shared_edit" if row["can_edit"] else "shared_view"


def decrypt_record_password(record) -> str:
    """解密记录密码；密钥变更等导致解不开时抛 CryptoError。"""
    return crypto().decrypt(record["password"])


def _pw_changed_at_of(record) -> str | None:
    """取记录的口令变更时间；旧库行缺列（Row 无该键）时返回 None。

    update_record 传给本函数的 record 是编辑前查询的整行，键是否存在
    取决于库结构是否已完成迁移；防御式读取避免 KeyError。
    """
    try:
        return record["password_changed_at"]
    except (IndexError, KeyError):
        return None


def mask_record_list(rows):
    """列表数据脱敏：不把明文密码带进页面（点击查看时按需解密）。"""
    out = []
    for row in rows:
        item = dict(row)
        item["has_password"] = bool(item.get("password"))
        item.pop("password", None)
        out.append(item)
    return out


# ---------- 附件 ----------

def allowed_file(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    return ext in current_app.config["ALLOWED_UPLOAD_EXTENSIONS"]


# v0.1.0 第六轮（借鉴 GB-32 · Passwordcockpit）：附件上传加**内容类型
# 交叉校验**。旧实现只校验扩展名白名单——把 .php/.exe 改名成 .png 即可
# 绕过；并且没有大小上限。现按扩展名核对浏览器声明的 MIME 与文件头
# 魔术字节，并强制单附件大小上限。
_EXT_MIME_MAP = {
    "png": ("image/png",),
    "jpg": ("image/jpeg",),
    "jpeg": ("image/jpeg",),
    "gif": ("image/gif",),
    "bmp": ("image/bmp",),
    "tiff": ("image/tiff",),
    "tif": ("image/tiff",),
    "pdf": ("application/pdf",),
    "txt": ("text/plain",),
    "docx": ("application/vnd.openxmlformats-officedocument."
             "wordprocessingml.document",),
    "xlsx": ("application/vnd.openxmlformats-officedocument."
             "spreadsheetml.sheet",),
}

# 文件头魔术字节（前若干字节）→ 扩展名；与浏览器声明的 MIME 无关，
# 直接读落盘前的流，防"扩展名+MIME 双伪造"
_MAGIC = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
    "gif": (b"GIF87a", b"GIF89a"),
    "bmp": (b"BM",),
    "tiff": (b"II*\x00", b"MM\x00*"),
    "tif": (b"II*\x00", b"MM\x00*"),
    "pdf": (b"%PDF-",),
    "docx": (b"PK\x03\x04",),   # OOXML 实为 zip 容器
    "xlsx": (b"PK\x03\x04",),
}

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024  # 单附件 10MB


def _validate_upload_content(file_storage, ext: str) -> None:
    """按扩展名核对声明 MIME、文件头魔术字节与大小（GB-32）。

    txt 无魔术字节、浏览器 MIME 也可能缺失，这类"文本类"只做大小与
    二进制嗅探（含 NUL 字节视为可疑）；其余类型必须魔术字节命中。
    """
    size = 0
    stream = file_storage.stream
    try:
        pos = stream.tell()
    except (AttributeError, OSError):
        pos = 0
    try:
        head = stream.read(16)
        stream.seek(pos)
    except (AttributeError, OSError, ValueError):
        head = b""

    declared = (file_storage.mimetype or "").split(";")[0].strip().lower()
    allowed_mimes = _EXT_MIME_MAP.get(ext)
    if allowed_mimes and declared and declared not in allowed_mimes:
        # 某些浏览器对 docx/xlsx 会报 application/octet-stream 或 zip，
        # 这类"通用二进制"声明放行，交给魔术字节裁决
        if declared not in ("application/octet-stream", "application/zip"):
            raise ValidationError(
                f"附件内容类型与扩展名不符（.{ext} 但声明 {declared}）")

    magic = _MAGIC.get(ext)
    if magic:
        if not any(head.startswith(m) for m in magic):
            raise ValidationError("附件文件头与扩展名不符，已拒绝上传")
    elif ext == "txt":
        if b"\x00" in head:
            raise ValidationError("文本附件含有二进制内容，已拒绝上传")


def save_uploaded_file(file_storage) -> str | None:
    """保存附件，返回 uploads 内的相对文件名。安全性：
    扩展名白名单 + 内容类型交叉校验 + 大小上限 + uuid 随机名
    （杜绝路径穿越/可执行文件/原始中文名乱码问题，v0.1.0 第六轮加固）。"""
    if file_storage is None or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        raise ValidationError("附件格式不允许，支持：png/jpg/jpeg/gif/bmp/tiff/pdf/txt/docx/xlsx")
    ext = file_storage.filename.rsplit(".", 1)[1].lower()

    # 大小校验：先 seek 到末尾取长度，再复位（不消耗流）
    stream = file_storage.stream
    try:
        pos = stream.tell()
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(pos)
    except (AttributeError, OSError, ValueError):
        size = 0
    if size > MAX_ATTACHMENT_BYTES:
        raise ValidationError(
            f"附件超过 {MAX_ATTACHMENT_BYTES // (1024 * 1024)}MB 上限，请压缩后上传")

    _validate_upload_content(file_storage, ext)

    safe_name = secure_filename(file_storage.filename) or "file"
    unique = f"{uuid.uuid4().hex}_{safe_name[:80]}.{ext}"
    os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
    file_storage.save(os.path.join(current_app.config["UPLOAD_FOLDER"], unique))
    return unique


def attachment_disk_path(record, which: int) -> str | None:
    """把库内附件路径解析为磁盘路径。
    新版存 uploads 相对名；旧版存绝对路径（含分隔符），取其文件名兜底。"""
    stored = record[f"file{which}_path"]
    if not stored:
        return None
    if os.path.sep in stored or "/" in stored:  # 旧版绝对路径
        name = os.path.basename(stored)
    else:
        name = stored
    if not name or ".." in name:
        return None
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], name)
    return path if os.path.isfile(path) else None


def _remove_attachment_files(record) -> None:
    for which in (1, 2):
        path = attachment_disk_path(record, which)
        if path:
            try:
                os.remove(path)
            except OSError as exc:
                logger.warning("附件删除失败 %s: %s", path, exc)


# ---------- 写操作 ----------

def _validated_project_id(conn, owner_id: int, project_id) -> int | None:
    """项目归属校验（v0.1.0 修复 IDOR）：project_id 只能是该项目所有者
    自己创建的项目，或 None。否则抛 ValidationError，杜绝把记录挂到
    他人项目上、借列表 JOIN 泄露他人项目名称。"""
    if project_id in (None, "", 0):
        return None
    try:
        pid = int(project_id)
    except (TypeError, ValueError):
        return None
    row = conn.execute(
        "SELECT id FROM projects WHERE id=? AND owner_id=?", (pid, owner_id)
    ).fetchone()
    if row is None:
        raise ValidationError("所选项目不存在或无权限")
    return pid


def create_record(user_id: int, data: dict, file1, file2) -> int:
    from .audit import log_operation

    conn = get_db()
    project_id = _validated_project_id(conn, user_id, data.get("project_id"))
    has_password = bool(data.get("password"))
    encrypted = crypto().encrypt(data["password"]) if has_password else ""
    now = utcnow_str()
    cur = conn.execute(
        "INSERT INTO passwords"
        " (user_id, project_id, device_model, serial_number, location, node_name,"
        "  ip_address, username, password, port, access_method, remark1, remark2,"
        "  file1_path, file2_path, created_at, updated_at, password_changed_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            user_id, project_id, data["device_model"], data["serial_number"],
            data["location"], data["node_name"], data["ip_address"], data["username"],
            encrypted, data["port"], data["access_method"], data["remark1"], data["remark2"],
            save_uploaded_file(file1), save_uploaded_file(file2),
            now, now, now if has_password else None,
        ),
    )
    conn.commit()
    log_operation(user_id, "create", "password", cur.lastrowid,
                  f"添加设备: {data['device_model']}")
    return cur.lastrowid


def update_record(record, data: dict, file1, file2, editor_id: int,
                  keep_old_password: bool = False) -> None:
    """更新记录。密码留空时保留原密文（避免误清空/密钥异常时二次加密损坏数据）。

    v0.1.0：project_id 只有记录所有者本人名下的项目合法（共享编辑者
    的 project_id 在路由/API 层已强制沿用原值）。
    """
    from .audit import log_operation

    conn = get_db()
    if keep_old_password or not data.get("password"):
        new_password = record["password"]  # 原样保留密文
        password_changed_at = _pw_changed_at_of(record)  # 口令未变，沿用原时间
    else:
        new_password = crypto().encrypt(data["password"])
        password_changed_at = utcnow_str()  # 口令实际变更，刷新变更时间

    try:
        cand = int(data.get("project_id") or 0)
    except (TypeError, ValueError):
        cand = 0
    cand = cand or None
    if cand == record["project_id"]:
        # 未变更（含存量历史值）：原样保留，避免旧数据编辑被卡死
        new_project_id = cand
    else:
        new_project_id = _validated_project_id(
            conn, record["user_id"], cand)

    file1_path = record["file1_path"]
    file2_path = record["file2_path"]
    if file1 is not None and file1.filename:
        _safe_remove(file1_path)
        file1_path = save_uploaded_file(file1)
    if file2 is not None and file2.filename:
        _safe_remove(file2_path)
        file2_path = save_uploaded_file(file2)

    conn.execute(
        "UPDATE passwords SET project_id=?, device_model=?, serial_number=?, location=?,"
        " node_name=?, ip_address=?, username=?, password=?, port=?, access_method=?,"
        " remark1=?, remark2=?, file1_path=?, file2_path=?, updated_at=?,"
        " password_changed_at=?"
        " WHERE id=?",
        (
            new_project_id, data["device_model"], data["serial_number"],
            data["location"], data["node_name"], data["ip_address"], data["username"],
            new_password, data["port"], data["access_method"], data["remark1"],
            data["remark2"], file1_path, file2_path, utcnow_str(),
            password_changed_at, record["id"],
        ),
    )
    conn.commit()
    log_operation(editor_id, "update", "password", record["id"],
                  f"更新记录: {data['device_model']}")


def _safe_remove(stored_path) -> None:
    if not stored_path:
        return
    if os.path.sep in stored_path or "/" in stored_path:  # 旧版绝对路径
        target = stored_path if os.path.isabs(stored_path) else os.path.join(
            current_app.config["UPLOAD_FOLDER"], stored_path)
    else:
        target = os.path.join(current_app.config["UPLOAD_FOLDER"], stored_path)
    try:
        if os.path.isfile(target):
            os.remove(target)
    except OSError as exc:
        logger.warning("旧附件删除失败 %s: %s", target, exc)


def soft_delete_record(record, operator_id: int) -> None:
    """移入回收站（软删除）。同时作废对该记录的活跃共享。"""
    from .audit import log_operation

    conn = get_db()
    conn.execute("UPDATE passwords SET deleted_at=? WHERE id=?",
                 (utcnow_str(), record["id"]))
    conn.execute("DELETE FROM shared_records WHERE record_id=?", (record["id"],))
    conn.commit()
    log_operation(operator_id, "delete", "password", record["id"],
                  f"移入回收站: {record['device_model']}")


def restore_record(record, operator_id: int) -> None:
    from .audit import log_operation

    conn = get_db()
    conn.execute("UPDATE passwords SET deleted_at=NULL WHERE id=?", (record["id"],))
    conn.commit()
    log_operation(operator_id, "restore", "password", record["id"],
                  f"从回收站恢复: {record['device_model']}")


def purge_record(record, operator_id: int) -> None:
    """彻底删除：物理删除记录行、附件与其余关联（共享已随软删除清理）。"""
    from .audit import log_operation

    conn = get_db()
    _remove_attachment_files(record)
    conn.execute("DELETE FROM shared_records WHERE record_id=?", (record["id"],))
    conn.execute("DELETE FROM custom_field_values WHERE record_id=?", (record["id"],))
    conn.execute("DELETE FROM passwords WHERE id=?", (record["id"],))
    conn.commit()
    log_operation(operator_id, "purge", "password", record["id"],
                  f"彻底删除: {record['device_model']}")


def record_to_api_dict(record, include_password: str | None = None) -> dict:
    """记录 -> API/模板通用 dict；密码仅在明确要求时附带明文。"""
    item = {
        "id": record["id"],
        "project_id": record["project_id"],
        "device_model": record["device_model"],
        "serial_number": record["serial_number"],
        "location": record["location"],
        "node_name": record["node_name"],
        "ip_address": record["ip_address"],
        "username": record["username"],
        "port": record["port"],
        "access_method": record["access_method"],
        "remark1": record["remark1"],
        "remark2": record["remark2"],
        "has_file1": bool(record["file1_path"]),
        "has_file2": bool(record["file2_path"]),
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
        "deleted_at": record["deleted_at"] if "deleted_at" in record.keys() else None,
    }
    if include_password is not None:
        item["password"] = include_password
    return item
