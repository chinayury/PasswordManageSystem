"""业务层：SQLite 备份与恢复（真正可用的备份能力，替代旧版"仅提示"的占位实现）。"""
import logging
import os
import re
import shutil
import sqlite3
import threading
from datetime import datetime, timezone

from flask import current_app

from .audit import log_operation

logger = logging.getLogger(__name__)

_restore_lock = threading.Lock()
_BACKUP_NAME_RE = re.compile(r"^backup_\d{8}_\d{6}\.db$")
PRE_RESTORE_PREFIX = "pre_restore_"


def _backup_folder() -> str:
    """备份目录：优先取应用配置（测试可覆盖），回退项目默认。"""
    from flask import current_app

    return current_app.config.get("BACKUP_FOLDER") or _default_backup_folder()


def _default_backup_folder() -> str:
    from .. import paths

    return paths.BACKUP_FOLDER


def create_backup(user_id: int | None = None) -> str:
    """使用 SQLite 在线备份 API 生成一致性备份，返回文件名。"""
    os.makedirs(_backup_folder(), exist_ok=True)
    filename = f"backup_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.db"
    dest_path = os.path.join(_backup_folder(), filename)

    src = sqlite3.connect(current_app.config["DATABASE"])
    dst = sqlite3.connect(dest_path)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()

    _prune_old_backups()
    if user_id:
        log_operation(user_id, "backup", "system", None, f"创建数据库备份: {filename}")
    logger.info("数据库备份完成: %s", filename)
    return filename


def list_backups() -> list[dict]:
    folder = _backup_folder()
    items = []
    if os.path.isdir(folder):
        for name in os.listdir(folder):
            path = os.path.join(folder, name)
            if _BACKUP_NAME_RE.match(name) and os.path.isfile(path):
                stat = os.stat(path)
                items.append({
                    "name": name,
                    "size_kb": stat.st_size / 1024,
                    "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                })
    items.sort(key=lambda x: x["name"], reverse=True)
    return items


def _prune_old_backups() -> None:
    keep = current_app.config.get("BACKUP_MAX_KEEP", 10)
    names = sorted(
        (n for n in os.listdir(_backup_folder()) if _BACKUP_NAME_RE.match(n)),
        reverse=True,
    )
    for name in names[keep:]:
        try:
            os.remove(os.path.join(_backup_folder(), name))
            logger.info("已清理超出保留数量的旧备份: %s", name)
        except OSError as exc:
            logger.warning("清理旧备份失败 %s: %s", name, exc)


def backup_path(filename: str) -> str | None:
    """校验备份文件名合法性后返回其绝对路径（防目录穿越）。"""
    if not _BACKUP_NAME_RE.match(filename or ""):
        return None
    path = os.path.join(_backup_folder(), filename)
    return path if os.path.isfile(path) else None


def validate_backup_file(path: str) -> tuple[bool, str]:
    """校验上传文件确为本系统的 SQLite 备份。"""
    if not os.path.isfile(path) or os.path.getsize(path) < 1024:
        return False, "文件不存在或过小，不是有效的备份文件"
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            tables = {
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")
            }
            if not {"users", "passwords"} <= tables:
                return False, "备份文件缺少核心数据表，可能不是本系统的备份"
            # 借鉴 GB-59 · TeamPass 3.2.4.4：拒绝其它实例的库。application_id
            # 魔数（GB-38，0x50444D31="PDM1"）为本系统标识；0 为魔数引入前的
            # 存量库，保持放行（兼容旧备份），非本系统的非零标识一律拒绝。
            app_id = conn.execute("PRAGMA application_id").fetchone()[0]
            if app_id not in (0, 0x50444D31):
                return False, ("备份文件的应用标识不属于本系统"
                               "（可能是其它 SQLite 应用或另一系统的库），已拒绝恢复")
            conn.execute("SELECT COUNT(*) FROM users")
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return False, f"无法读取备份文件: {exc}"
    return True, ""


def _release_app_connections() -> int:
    """释放当前应用上下文的数据库连接（Windows 换库前置条件）。"""
    try:
        from ..db import release_app_connections
        return release_app_connections()
    except Exception:  # noqa: BLE001 释放失败不阻断，后续重试仍可能成功
        logger.debug("释放应用数据库连接失败", exc_info=True)
        return 0


def _same_volume(path_a: str, path_b: str) -> bool:
    """判断两个路径是否位于同一卷（Windows 上 os.replace 不支持跨卷）。

    ntpath.splitdrive 在 POSIX 下返回空盘符，此时恒为同卷（replace 本就跨目录可用）。
    """
    try:
        import ntpath

        drive_a = ntpath.splitdrive(os.path.abspath(path_a))[0].lower()
        drive_b = ntpath.splitdrive(os.path.abspath(path_b))[0].lower()
        if drive_a and drive_b:
            return drive_a == drive_b
    except Exception:  # noqa: BLE001 取盘符失败时不阻断，按同卷处理
        logger.debug("判断卷失败，按同卷处理", exc_info=True)
    return True


def _stage_next_to_target(src: str, db_path: str) -> str:
    """把上传的备份暂存到目标数据库**同目录**，保证 os.replace 原子语义。

    v0.1.0 第六轮修复 BU-01：此前直接把上传文件（落在 %TEMP%）os.replace
    到数据库路径，Windows 下二者常不在同一卷（项目在 D:\，%TEMP% 在 C:\），
    os.replace 抛 OSError(WinError 17)「系统无法将文件移到不同的磁盘驱动器」，
    而旧代码对非 PermissionError 的 OSError 直接 break 放弃重试——
    恢复功能在该类部署下 100% 不可用。
    """
    staged = db_path + ".restore_staged"
    shutil.copy2(src, staged)
    return staged


def _replace_database(uploaded_path: str, db_path: str, attempts: int = 5) -> None:
    """把上传的备份原子替换到目标路径。

    Windows 专项处理（两层）：
    1. **跨卷**（BU-01，v0.1.0 第六轮新增）：先把上传文件复制到数据库同目录
       的 `.restore_staged` 临时文件，再 os.replace——同卷才有原子替换语义。
    2. **目标被占用**（B-02，v0.1.0 第五轮）：先释放本进程连接，再以递增退避
       重试若干次，全部失败才报错。
    另外：任何 OSError 都不再静默 break，WinError 17（跨卷）会转成明确中文提示。
    """
    import time as _time

    last_exc: OSError | None = None
    staged_path = uploaded_path
    staged_by_us = False
    try:
        if not _same_volume(uploaded_path, db_path):
            staged_path = _stage_next_to_target(uploaded_path, db_path)
            staged_by_us = True
            logger.info("恢复：上传文件与数据库不同卷，已暂存到 %s", staged_path)

        for i in range(max(1, attempts)):
            if i == 0:
                _release_app_connections()
            try:
                os.replace(staged_path, db_path)
                return
            except PermissionError as exc:
                last_exc = exc
                if i < attempts - 1:
                    _time.sleep(0.4 * (i + 1))  # 0.4/0.8/1.2/1.6s
            except OSError as exc:
                # WinError 17 = ERROR_NOT_SAME_DEVICE（跨卷）。errno 与 winerror
                # 在不同平台/构造方式下只有一个被设置，两个都查。
                err_no = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
                if err_no == 17:
                    raise OSError(
                        "上传文件与数据库不在同一磁盘卷，无法直接替换；"
                        "请将备份文件放到数据库所在磁盘后重试"
                    ) from exc
                last_exc = exc
                if i < attempts - 1:
                    _time.sleep(0.4 * (i + 1))
    finally:
        # 暂存文件替换失败时清理，避免在数据库目录留下垃圾
        if staged_by_us and os.path.exists(staged_path):
            try:
                os.remove(staged_path)
            except OSError:
                logger.debug("清理恢复暂存文件失败: %s", staged_path)
    raise last_exc if last_exc else OSError("替换数据库文件失败")


def _snapshot_current_database(db_path: str, dest: str) -> None:
    """把当前库完整快照到 dest。

    v0.1.0 第六轮修复 BU-02：此前用 shutil.copy2 只复制主库文件，而 WAL 模式下
    最近一次 checkpoint 之后提交的数据只存在于 `-wal` 文件中——实测刚建表插入
    行的库，copy2 出来的快照连表结构都没有，恢复后若回滚到该快照即静默丢数据。
    现改用 SQLite 在线备份 API（与 create_backup 一致），从机制上保证完整。
    """
    src = sqlite3.connect(db_path)
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()


def restore_backup(uploaded_path: str, user_id: int) -> tuple[bool, str]:
    """校验 -> 现库另存预恢复副本 -> 原子替换。全程持锁防并发。"""
    with _restore_lock:
        ok, msg = validate_backup_file(uploaded_path)
        if not ok:
            return False, msg
        db_path = current_app.config["DATABASE"]
        os.makedirs(_backup_folder(), exist_ok=True)
        pre = os.path.join(
            _backup_folder(),
            f"{PRE_RESTORE_PREFIX}{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.db",
        )
        # v0.1.0 第六轮修复 BU-02：先落快照再 checkpoint 的旧顺序会导致
        # WAL 内已提交数据不进快照；且快照生成后不再清理（prune 只在启动时跑）。
        # 现改为：在线备份 API 生成完整快照 -> 恢复 -> 成功后再清理历史快照。
        try:
            _snapshot_current_database(db_path, pre)
        except (OSError, sqlite3.Error) as exc:
            logger.exception("创建预恢复快照失败")
            return False, f"恢复失败：无法备份当前数据库（{exc}）"
        try:
            # WAL 模式下库由 -wal/-shm 文件，替换前先检查点确保数据完整
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()
            _replace_database(uploaded_path, db_path)
            # 清理换库后遗留的旧 wal/shm，避免与新库不匹配
            for suffix in ("-wal", "-shm"):
                stale = db_path + suffix
                if os.path.exists(stale):
                    try:
                        os.remove(stale)
                    except OSError as exc:
                        logger.warning("清理残留 %s 失败: %s", stale, exc)
        except OSError as exc:
            logger.exception("恢复数据库失败")
            return False, (f"恢复失败: {exc}。若为 Windows，请确认没有其它程序"
                           "（含其它浏览器标签页触发的请求）正在占用数据库文件，"
                           "稍后重试；当前数据库已保留未改动。")
        # v0.1.0 修复 F-01：换库后释放本进程连接，后续请求重新打开新库，
        # 避免"恢复成功但进程仍连着旧库、重启前写入易丢失"
        _release_app_connections()
        # BU-02 连带：单次运维窗口内多次恢复会持续堆积与数据库等大的快照，
        # 这里补一次即时清理（原来只在进程启动时清理）。
        try:
            prune_pre_restore_snapshots(keep=3)
        except Exception:  # noqa: BLE001 清理失败不影响恢复结果
            logger.debug("清理历史预恢复快照失败", exc_info=True)
        log_operation(user_id, "restore_db", "system", None,
                      f"从备份恢复数据库（恢复前快照: {os.path.basename(pre)}）")
        logger.warning("数据库已从备份恢复，预恢复快照: %s", pre)
        return True, "数据库恢复成功，已切换到新库；建议重启服务以确保全部连接生效"


def prune_pre_restore_snapshots(keep: int = 3) -> int:
    """清理历史预恢复快照，只保留最近 keep 份。返回实际删除的文件数
    （目录不存在/无可删项返回 0），供启动日志输出计数。"""
    folder = _backup_folder()
    if not os.path.isdir(folder):
        return 0
    names = sorted(
        (n for n in os.listdir(folder) if n.startswith(PRE_RESTORE_PREFIX)),
        reverse=True,
    )
    removed = 0
    for name in names[keep:]:
        try:
            os.remove(os.path.join(folder, name))
            removed += 1
        except OSError:
            pass
    return removed
