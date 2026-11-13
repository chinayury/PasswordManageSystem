"""业务层：密码健康审计（P4 安全审计核心编排）。

架构（吸收 Bitwarden 服务端报告思路后按本系统服务端持密钥的现实自实现）：
  触发 -> 同 scope 单飞行锁（running 拒绝重复） -> 分页取条目（按权限过滤）
  -> 内存解密（明文仅存活于本次请求局部变量，用后即弃）
  -> 强度评分（password_strength，(password,username) 缓存）
  -> 跨条目复用检测（按解密后 SHA-256 分组，明文不参与持久化）
  -> 年龄/到期分析 -> HIBP（可选，默认关） -> 单事务原子写 findings 快照
  -> 渲染/Excel。

持久化安全：findings 只存派生量（评分/原因/次数/天数），严禁明文与哈希；
审计日志只记统计摘要。异常时 status=partial 保留已得结果，HIBP 失败
不阻塞其它类别。
"""
import hashlib
import json
import logging
import sqlite3
from datetime import timedelta

from ..db import get_db
from ..utils.timefmt import parse_db_time, to_db_time, utcnow, utcnow_str
from . import records as record_svc
from .audit import log_operation
from .crypto import CryptoError
from .hibp import client_from_config, count_bucket
from .password_strength import base_score, final_score, reason_text

logger = logging.getLogger(__name__)

# 分批处理：每批解密条数（资源保护，避免大库一次性解密的内存峰值）
BATCH_SIZE = 500
# 单次审计条目数硬上限（超出记 partial，防止同步请求被超大库拖垮）
MAX_ITEMS = 200000
# 快照保留：全局最多保留最近 N 轮审计（超出连同 findings 级联清理）
KEEP_RUNS = 100
# 30 天内到期视为"即将到期"（KeePassXC 文案分层：≤2 天"即将到期"）
EXPIRE_WARN_DAYS = 30
# 口令最大使用天数（超过记 old）
DEFAULT_MAX_AGE_DAYS = 365

# 态势评分五项告警（维度照 KeePassXC DatabaseStats 实测阈值语义落地）
POSTURE_WEIGHTS = {
    "reuse_ratio": 15,   # 复用口令条数 > 唯一口令数/10
    "max_reuse": 15,     # 单一口令最大复用次数 > 3
    "avg_length": 10,    # 平均口令长度 < 10
    "expired": 20,       # 存在已到期口令
    "weak_ratio": 25,    # 弱口令占比 > 10%
}

CATEGORIES = ("weak", "reused", "old", "hibp")


def thresholds() -> dict:
    """当前阈值配置（写进每轮 runs.thresholds_json 快照，保证结果可复现）。"""
    from flask import current_app

    return {
        "batch_size": BATCH_SIZE,
        "max_items": MAX_ITEMS,
        "expire_warn_days": EXPIRE_WARN_DAYS,
        "max_age_days": current_app.config.get(
            "HEALTH_MAX_AGE_DAYS", DEFAULT_MAX_AGE_DAYS),
        "weak_threshold": 75,          # <Good（KeePassXC Healthcheck 只收 quality<Good）
        "reuse_penalty": 15,
        "reuse_score_cap": 74,
        "posture_weights": dict(POSTURE_WEIGHTS),
        "hibp_enabled": bool(current_app.config.get("HIBP_ENABLED")),
    }


# ---------- 发起与并发控制 ----------

# v0.1.0 第六轮修复 BU-06：单飞行锁此前只有获取没有释放的超时机制，
# 把"进行中"等同于"活着"。进程被 kill -9 / 容器重启 / OOM 后，running 行
# 永久残留，该 scope（本人或全库）从此无法发起审计，只能手工改库。
# 现规定：超过该时长的 running 行视为僵尸，新 run 发起时顺手收敛为 failed。
# 取 60 分钟：覆盖 MAX_ITEMS=200000 且开启 HIBP（逐前缀节流 100ms）的
# 最慢合法执行时长，同时不至于让正常长任务被误判。
RUN_STALE_MINUTES = 60


def _has_active_run(conn: sqlite3.Connection, scope_type: str,
                    scope_id: int | None) -> bool:
    """该 scope 是否存在**存活中**的 running 行。

    v0.1.0 第六轮 BU-06：增加 started_at 时效判定，超时的僵尸行在这里
    顺手收敛为 failed（连同 error 说明），避免永久锁死该 scope。
    """
    cutoff = to_db_time(utcnow() - timedelta(minutes=RUN_STALE_MINUTES))
    conn.execute(
        "UPDATE password_health_runs SET status='failed',"
        " finished_at=?, error=? WHERE status='running' AND started_at < ?",
        (utcnow_str(),
         f"系统检测到该轮审计超过 {RUN_STALE_MINUTES} 分钟未完成"
         "（可能为进程中断），已自动标记为失败", cutoff),
    )
    conn.commit()
    row = conn.execute(
        "SELECT 1 FROM password_health_runs WHERE scope_type=?"
        " AND scope_id IS ? AND status='running' LIMIT 1",
        (scope_type, scope_id),
    ).fetchone()
    return row is not None


def reap_stale_running_runs() -> int:
    """收敛全部僵尸 running 行（供启动任务调用，与清理过期锁定并列）。

    返回被收敛的行数；表不存在/无僵尸行返回 0。
    """
    conn = get_db()
    try:
        cutoff = to_db_time(utcnow() - timedelta(minutes=RUN_STALE_MINUTES))
        cur = conn.execute(
            "UPDATE password_health_runs SET status='failed',"
            " finished_at=?, error=? WHERE status='running' AND started_at < ?",
            (utcnow_str(),
             f"系统检测到该轮审计超过 {RUN_STALE_MINUTES} 分钟未完成"
             "（可能为进程中断），已自动标记为失败", cutoff),
        )
        conn.commit()
        if cur.rowcount:
            logger.warning("启动时收敛 %d 条僵尸健康审计 running 行", cur.rowcount)
        return cur.rowcount
    except sqlite3.Error:
        logger.debug("收敛僵尸健康审计行失败", exc_info=True)
        return 0


def start_run(operator_id: int, scope_all: bool) -> tuple[int | None, str]:
    """发起一轮审计（同步执行）。返回 (run_id|None, 错误信息|'')。

    - scope_all=True（仅管理员路由允许）：全库所有未删除记录；
    - 否则：仅操作者本人的记录。
    并发防护：BEGIN IMMEDIATE 下检查"同 scope 是否已有 running"，杜绝
    两请求同时通过检查造成重复跑（SQLite 单写锁串行化）。
    """
    conn = get_db()
    scope_type = "all" if scope_all else "user"
    scope_id = None if scope_all else operator_id

    try:
        conn.execute("BEGIN IMMEDIATE")  # 立即取写锁，检查与插入原子化
    except sqlite3.OperationalError:
        return None, "数据库繁忙，请稍后重试"
    try:
        if _has_active_run(conn, scope_type, scope_id):
            conn.rollback()
            return None, "已有同范围的审计正在进行中，请等待完成后再发起"
        snapshot = thresholds()
        cur = conn.execute(
            "INSERT INTO password_health_runs (scope_type, scope_id, status,"
            " hibp_enabled, created_by, started_at, thresholds_json)"
            " VALUES (?,?,'running',?,?,?,?)",
            (scope_type, scope_id, 1 if snapshot["hibp_enabled"] else 0,
             operator_id, utcnow_str(),
             json.dumps(snapshot, ensure_ascii=False)),
        )
        run_id = cur.lastrowid
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    # v0.1.0 第六轮 BU-06：兜底除 Exception 外再覆盖 BaseException
    # （KeyboardInterrupt / SystemExit），并用 finally 保证 running 行
    # 在任何退出路径下都不会残留。
    finalized = False

    def _mark_failed(exc: BaseException) -> None:
        nonlocal finalized
        if finalized:
            return
        finalized = True
        logger.exception("健康审计异常 run_id=%s", run_id)
        try:
            _finalize_failed(run_id, str(exc))
        except Exception:  # noqa: BLE001 收敛自身失败不能吞掉原始异常
            logger.exception("收敛失败的健康审计 run 失败 run_id=%s", run_id)

    try:
        _execute_run(run_id, scope_type, scope_id, operator_id)
    except Exception as exc:  # noqa: BLE001
        _mark_failed(exc)
        return run_id, ""
    except BaseException as exc:  # noqa: BLE001 KeyboardInterrupt/SystemExit
        _mark_failed(exc)
        raise
    finally:
        if not finalized:
            # 正常完成路径：_execute_run 内部应已置 done；若因故仍为
            # running（例如 _execute_run 提前返回），这里兜底收敛，
            # 绝不留下僵尸行。
            try:
                row = conn.execute(
                    "SELECT status FROM password_health_runs WHERE id=?",
                    (run_id,)).fetchone()
                if row is not None and row["status"] == "running":
                    _finalize_failed(run_id, "审计未正常收尾，已自动标记为失败")
            except sqlite3.Error:
                logger.debug("健康审计收尾校验失败 run_id=%s", run_id)
    return run_id, ""


def _finalize_failed(run_id: int, error: str) -> None:
    conn = get_db()
    conn.execute(
        "UPDATE password_health_runs SET status='failed', finished_at=?,"
        " error=? WHERE id=?",
        (utcnow_str(), error[:500], run_id),
    )
    conn.commit()
    log_operation(None, "health_report_run", "system", run_id,
                  f"密码健康审计 #{run_id} 执行失败：{error[:200]}")


# ---------- 分析主流程 ----------

def _scope_where(scope_type: str, scope_id: int | None) -> tuple[str, list]:
    """条目范围过滤（权限沿用现有机制：普通用户只分析自己名下记录）。"""
    if scope_type == "all":
        return "user_id IS NOT NULL", []
    return "user_id = ?", [scope_id]


def _age_days(row, now) -> tuple[int | None, bool]:
    """口令使用天数。来源优先级 password_changed_at > updated_at > created_at；
    非首选来源标记 estimated（估算）。"""
    for col, estimated in (("password_changed_at", False),
                           ("updated_at", True), ("created_at", True)):
        try:
            value = row[col]
        except (IndexError, KeyError):
            continue
        dt = parse_db_time(value)
        if dt is None:
            continue
        return max((now - dt).days, 0), estimated
    return None, True


def _expiry_state(row, now) -> tuple[bool, int | None]:
    """返回 (是否已到期, 距到期天数|None)。未设置到期时间返回 (False, None)。"""
    try:
        value = row["expires_at"]
    except (IndexError, KeyError):
        return False, None
    dt = parse_db_time(value)
    if dt is None:
        return False, None
    if dt <= now:
        return True, None
    return False, max((dt - now).days, 0)


def _severity_by_score(score: int) -> int:
    """弱口令严重度三档：Bad=3 必须修改 / Poor=2 应尽快修改 / Weak=1 建议修改。"""
    if score <= 0:
        return 3
    if score < 40:
        return 2
    return 1


def _old_finding_detail(expired: bool, expire_in: int | None, age_days: int | None,
                        age_estimated: bool, max_age_days: int):
    """old 类发现（过期 / 即将到期 / 使用超龄）。返回 (details|None, severity)。"""
    detail: dict = {}
    severity = 0
    if expired:
        detail["reasons"] = ["口令已到期，必须立即更换"]
        detail["expired"] = True
        severity = 3
    elif expire_in is not None and expire_in <= EXPIRE_WARN_DAYS:
        text = ("即将到期（不足 2 天）" if expire_in <= 2
                else f"{expire_in} 天后到期")
        detail["reasons"] = [f"口令{text}，建议提前更换"]
        detail["expire_in_days"] = expire_in
        severity = 1
    if age_days is not None and age_days > max_age_days:
        detail.setdefault("reasons", []).append(
            f"口令已使用 {age_days} 天，超过阈值 {max_age_days} 天")
        if age_estimated:
            detail["age_estimated"] = True
        detail["age_days"] = age_days
        severity = max(severity, 1)
    return (detail, severity) if detail else (None, 0)


def _add_finding(findings: dict, item_id: int, category: str, severity: int,
                 score: float, details: dict) -> None:
    findings[(item_id, category)] = {
        "item_id": item_id, "category": category,
        "severity": severity, "score": float(score), "details": details,
    }


def _merge_finding(findings: dict, item_id: int, category: str, severity: int,
                   score: float, details: dict) -> None:
    """同条目同类别合并（严重度取大、原因合并、明细补充）。"""
    key = (item_id, category)
    exist = findings.get(key)
    if exist is None:
        _add_finding(findings, item_id, category, severity, score, details)
        return
    exist["severity"] = max(exist["severity"], severity)
    exist["score"] = min(exist["score"], float(score))
    merged = exist["details"]
    for reason in details.get("reasons", []):
        if reason not in merged.setdefault("reasons", []):
            merged["reasons"].append(reason)
    for k, v in details.items():
        if k != "reasons":
            merged[k] = v


def _posture_score(*, weak_ratio: float, reuse_count: int, unique_hashes: int,
                   max_reuse: int, avg_length: float, expired: bool) -> int:
    """态势评分：满分 100，五项告警加权扣分（照 KeePassXC DatabaseStats
    阈值语义）。返回 0-100。"""
    penalty = 0
    if unique_hashes and reuse_count > unique_hashes / 10:
        penalty += POSTURE_WEIGHTS["reuse_ratio"]
    if max_reuse > 3:
        penalty += POSTURE_WEIGHTS["max_reuse"]
    if avg_length < 10:
        penalty += POSTURE_WEIGHTS["avg_length"]
    if expired:
        penalty += POSTURE_WEIGHTS["expired"]
    if weak_ratio > 0.10:
        penalty += POSTURE_WEIGHTS["weak_ratio"]
    return max(0, 100 - penalty)


def _posture_alerts(*, weak_ratio: float, reuse_count: int, unique_hashes: int,
                    max_reuse: int, avg_length: float, expired: bool) -> list[str]:
    """五项态势告警清单（照 KeePassXC DatabaseStats 阈值语义），供报告页展示。"""
    alerts = []
    if unique_hashes and reuse_count > unique_hashes / 10:
        alerts.append(f"复用口令条数（{reuse_count}）超过唯一口令数的 1/10")
    if max_reuse > 3:
        alerts.append(f"存在单条口令被 {max_reuse} 条记录复用（阈值 3）")
    if avg_length < 10:
        alerts.append(f"平均口令长度 {avg_length:.1f}，低于 10 位")
    if expired:
        alerts.append("存在已到期口令")
    if weak_ratio > 0.10:
        alerts.append(f"弱口令占比 {weak_ratio * 100:.1f}%，超过 10%")
    return alerts


def _prune_old_runs(conn: sqlite3.Connection) -> None:
    """快照保留上限：只留最近 KEEP_RUNS 轮（findings 随 ON DELETE CASCADE 清理）。"""
    rows = conn.execute(
        "SELECT id FROM password_health_runs ORDER BY id DESC LIMIT ? OFFSET ?",
        (KEEP_RUNS, KEEP_RUNS),
    ).fetchall()
    stale = [r["id"] for r in rows]
    if stale:
        marks = ",".join("?" * len(stale))
        conn.execute(
            f"DELETE FROM password_health_runs WHERE id IN ({marks})", stale)


def _execute_run(run_id: int, scope_type: str, scope_id: int | None,
                 operator_id: int) -> None:
    """执行分析并落快照。明文只在批处理循环内存活，函数返回前全部丢弃。"""
    conn = get_db()
    where, params = _scope_where(scope_type, scope_id)
    now = utcnow()
    max_age_days = thresholds()["max_age_days"]

    findings: dict[tuple[int, str], dict] = {}
    # 复用分组：sha256(明文) -> [{id, title}]；sha256(明文) -> sha1(明文)
    reuse_groups: dict[str, list[dict]] = {}
    sha1_of_hash: dict[str, str] = {}
    # 每条目状态（复用惩罚需在全部分组确定后统一应用）
    item_state: dict[int, dict] = {}
    sha1_set: set[str] = set()  # HIBP 去重集合（仅 hex，不含明文）

    hibp_client = client_from_config()  # 未启用返回 None（零外联）
    hibp_available = None

    item_total = 0
    length_sum = 0
    distinct_hashes = 0
    last_id = 0
    error = ""

    try:
        while True:
            rows = conn.execute(
                "SELECT id, user_id, device_model, ip_address, username,"
                " password, password_changed_at, expires_at, created_at, updated_at"
                " FROM passwords WHERE deleted_at IS NULL AND id > ? AND " + where
                + " ORDER BY id LIMIT ?",
                [last_id] + params + [BATCH_SIZE],
            ).fetchall()
            if not rows:
                break
            stop = False
            for row in rows:
                last_id = row["id"]
                if item_total >= MAX_ITEMS:
                    error = f"条目数超过上限 {MAX_ITEMS}，仅分析前 {item_total} 条"
                    stop = True
                    break
                if not row["password"]:
                    continue  # 空口令条目跳过（Bitwarden 三组件统一 skip 语义）
                item_total += 1

                # --- 内存解密：明文只在本循环体内存活 ---
                try:
                    plain = record_svc.decrypt_record_password(row)
                except CryptoError:
                    # 存量密文解不开（密钥变更）：记 old 类提示，不中断
                    _add_finding(findings, row["id"], "old", 1, 0, {
                        "reasons": ["密文无法解密（加密密钥可能已变更），请重设口令"],
                    })
                    continue

                pw_hash = hashlib.sha256(plain.encode("utf-8")).hexdigest()
                sha1_hex = hashlib.sha1(plain.encode("utf-8")).hexdigest().upper()
                sha1_set.add(sha1_hex)

                # --- 强度评分 ---
                base, reasons = base_score(plain, row["username"] or "")
                length_sum += len(plain)

                # --- 年龄/到期 ---
                age_days, age_estimated = _age_days(row, now)
                expired, expire_in = _expiry_state(row, now)

                # --- 复用分组（按哈希；明文不再参与任何持久化） ---
                group = reuse_groups.setdefault(pw_hash, [])
                if not group:
                    distinct_hashes += 1
                group.append({"id": row["id"], "title": row["device_model"]})
                sha1_of_hash.setdefault(pw_hash, sha1_hex)
                item_state[row["id"]] = {
                    "base": base, "expired": expired,
                    "expire_in": expire_in, "group": pw_hash,
                    "age_days": age_days, "age_estimated": age_estimated,
                }

                # --- 弱口令 finding（<Good 即 <75） ---
                if base < thresholds()["weak_threshold"]:
                    detail = {"reasons": [reason_text(r) for r in reasons] or
                              ["强度不足（熵基准低于阈值）"]}
                    if age_days is not None:
                        detail["age_days"] = age_days
                        if age_estimated:
                            detail["age_estimated"] = True
                    if expired:
                        detail["expired"] = True
                    if expire_in is not None:
                        detail["expire_in_days"] = expire_in
                    _add_finding(findings, row["id"], "weak",
                                 _severity_by_score(base), float(base), detail)

                # --- old 类 finding（过期 / 即将到期 / 使用超龄） ---
                old_detail, old_sev = _old_finding_detail(
                    expired, expire_in, age_days, age_estimated, max_age_days)
                if old_detail:
                    _merge_finding(findings, row["id"], "old", old_sev,
                                   float(base), old_detail)

                del plain  # 明文用后即弃
            if stop:
                break

        # --- 复用 findings（count>1 组内全部条目入快照；Bitwarden
        #     passwordUseMap 语义），并统一各类别最终展示分 ---
        reused_group_sizes: dict[int, int] = {}
        for group in reuse_groups.values():
            if len(group) < 2:
                continue
            peers = [g["title"][:50] for g in group]
            for item in group:
                reused_group_sizes[item["id"]] = len(group)
                others = [t for g, t in zip(group, peers) if g["id"] != item["id"]]
                detail = {
                    "reuse_count": len(group),
                    "reuse_peers": others[:20] + (["…"] if len(others) > 20 else []),
                    "reasons": [f"与另外 {len(group) - 1} 条记录使用相同口令"],
                }
                st = item_state[item["id"]]
                score = final_score(
                    st["base"], reuse_count=len(group),
                    expired=st["expired"], expire_in_days=st["expire_in"])
                _merge_finding(findings, item["id"], "reused", 2, score, detail)

        # 把复用惩罚并入所有类别的展示分（同一条目各页签分值一致）
        for (item_id, _cat), f in findings.items():
            st = item_state.get(item_id)
            if st is None:
                continue
            f["score"] = float(final_score(
                st["base"], reuse_count=reused_group_sizes.get(item_id, 1),
                expired=st["expired"], expire_in_days=st["expire_in"]))

        # --- HIBP（可选）：对去重后的 SHA-1 批量 k-匿名查询 ---
        if hibp_client is not None:
            hibp_counts, hibp_available = hibp_client.query_counts_sha1(sha1_set)
            del sha1_set
            if hibp_available:
                for pw_hash, group in reuse_groups.items():
                    count = hibp_counts.get(sha1_of_hash.get(pw_hash, ""), 0)
                    if not count:
                        continue
                    for item in group:
                        st = item_state[item["id"]]
                        score = final_score(
                            st["base"], reuse_count=reused_group_sizes.get(
                                item["id"], 1),
                            expired=st["expired"],
                            expire_in_days=st["expire_in"])
                        _merge_finding(findings, item["id"], "hibp", 3, score, {
                            "hibp_count": count,
                            "hibp_bucket": count_bucket(count),
                            "reasons": [f"该口令出现在公开泄露数据中"
                                        f"（{count_bucket(count)}）"],
                        })

    except Exception as exc:  # noqa: BLE001
        error = error or f"分析中断：{exc}"
        logger.exception("健康审计部分失败 run_id=%s", run_id)

    # 汇总计数与态势评分（leaked 等计数在 try 块外统一由 findings 汇总，
    # 保证异常/部分完成时快照计数与 findings 一致）
    weak = sum(1 for f in findings.values() if f["category"] == "weak")
    reused = sum(1 for f in findings.values() if f["category"] == "reused")
    old = sum(1 for f in findings.values() if f["category"] == "old")
    leaked = sum(1 for f in findings.values() if f["category"] == "hibp")
    avg_len = (length_sum / item_total) if item_total else 0
    max_reuse = max((len(g) for g in reuse_groups.values()), default=0)
    expired_any = any(f["category"] == "old" and f["severity"] == 3
                      for f in findings.values())
    posture = _posture_score(
        weak_ratio=(weak / item_total) if item_total else 0,
        reuse_count=reused, unique_hashes=distinct_hashes,
        max_reuse=max_reuse, avg_length=avg_len, expired=expired_any,
    )
    # 结果聚合（派生量，无敏感数据）：报告页还原"五项态势告警"用
    result_json = json.dumps({
        "avg_length": round(avg_len, 1),
        "max_reuse": max_reuse,
        "unique_hashes": distinct_hashes,
        "weak_ratio": round(weak / item_total, 4) if item_total else 0,
        "expired_any": expired_any,
        "alerts": _posture_alerts(
            weak_ratio=(weak / item_total) if item_total else 0,
            reuse_count=reused, unique_hashes=distinct_hashes,
            max_reuse=max_reuse, avg_length=avg_len, expired=expired_any),
    }, ensure_ascii=False)

    # 单事务原子写 findings + run 收尾
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.executemany(
            "INSERT INTO password_health_findings"
            " (run_id, item_id, category, severity, score, details_json)"
            " VALUES (?,?,?,?,?,?)",
            [(run_id, item_id, f["category"], f["severity"], f["score"],
              json.dumps(f["details"], ensure_ascii=False))
             for (item_id, _), f in findings.items()],
        )
        conn.execute(
            "UPDATE password_health_runs SET status=?, finished_at=?,"
            " hibp_available=?, item_total=?, weak_count=?, reused_count=?,"
            " old_count=?, hibp_count=?, posture_score=?, result_json=?,"
            " error=? WHERE id=?",
            ("partial" if error else "done", utcnow_str(), hibp_available,
             item_total, weak, reused, old, leaked, posture, result_json,
             error[:500] or None, run_id),
        )
        _prune_old_runs(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    scope_desc = "全库" if scope_type == "all" else "本人记录"
    log_operation(
        operator_id, "health_report_run", "system", run_id,
        f"密码健康审计 #{run_id}（范围={scope_desc}）：分析 {item_total} 条，"
        f"弱 {weak} / 复用 {reused} / 逾期 {old} / 泄露 {leaked}，"
        f"态势评分 {posture}" + ("（部分失败）" if error else ""))
    logger.info("健康审计完成 run_id=%s items=%d weak=%d reused=%d old=%d hibp=%d",
                run_id, item_total, weak, reused, old, leaked)


# ---------- 查询（报告页/Excel） ----------

def visible_run(run_id: int, is_admin: bool, user_id: int):
    """取一轮审计（权限：管理员任意；普通用户仅本人 user 范围）。

    LEFT JOIN users 附带 creator 用户名：报告页/Excel 导出展示"发起人"
    用（导出路由直接以本函数结果传 build_health_report_xlsx）。
    """
    run = get_db().execute(
        "SELECT r.*, u.username AS creator"
        " FROM password_health_runs r LEFT JOIN users u ON r.created_by = u.id"
        " WHERE r.id=?", (run_id,)
    ).fetchone()
    if run is None:
        return None
    if is_admin:
        return run
    if run["scope_type"] == "user" and run["scope_id"] == user_id:
        return run
    return None


def list_runs(is_admin: bool, user_id: int, limit: int = 30):
    """审计轮次列表（普通用户只见本人 user 范围的轮次）。"""
    conn = get_db()
    if is_admin:
        return conn.execute(
            "SELECT r.*, u.username AS creator"
            " FROM password_health_runs r LEFT JOIN users u ON r.created_by=u.id"
            " ORDER BY r.id DESC LIMIT ?", (limit,)).fetchall()
    return conn.execute(
        "SELECT r.*, u.username AS creator"
        " FROM password_health_runs r LEFT JOIN users u ON r.created_by=u.id"
        " WHERE r.scope_type='user' AND r.scope_id=?"
        " ORDER BY r.id DESC LIMIT ?", (user_id, limit)).fetchall()


def run_findings(run_id: int, category: str, limit: int = 500):
    """取某一类发现明细（默认最差在前：严重度降序 + 评分数值升序）。

    limit 为展示上限（完整清单走 Excel 导出），防止超大快照撑爆页面。
    排序在 SQL 数值列上完成（score 为 REAL，天然数值排序，杜绝字符串排序）。
    """
    if category not in CATEGORIES:
        return []
    return get_db().execute(
        "SELECT f.*, p.device_model, p.username, p.ip_address, p.deleted_at,"
        " pr.name AS project_name"
        " FROM password_health_findings f"
        " JOIN passwords p ON f.item_id = p.id"
        " LEFT JOIN projects pr ON p.project_id = pr.id"
        " WHERE f.run_id=? AND f.category=?"
        " ORDER BY f.severity DESC, f.score ASC, f.id ASC LIMIT ?",
        (run_id, category, int(limit)),
    ).fetchall()


def run_all_findings(run_id: int):
    """Excel 导出用：全部发现（含被展示上限截断的部分）。"""
    return get_db().execute(
        "SELECT f.*, p.device_model, p.username, p.ip_address, p.deleted_at,"
        " pr.name AS project_name"
        " FROM password_health_findings f"
        " JOIN passwords p ON f.item_id = p.id"
        " LEFT JOIN projects pr ON p.project_id = pr.id"
        " WHERE f.run_id=?"
        " ORDER BY f.category, f.severity DESC, f.score ASC",
        (run_id,),
    ).fetchall()


def findings_of_item(run_id: int, item_id: int) -> dict[str, dict]:
    """把指定条目在本次 run 内的全部发现归并为 {category: details}。"""
    rows = get_db().execute(
        "SELECT category, details_json FROM password_health_findings"
        " WHERE run_id=? AND item_id=?", (run_id, item_id)).fetchall()
    out = {}
    for row in rows:
        try:
            out[row["category"]] = json.loads(row["details_json"] or "{}")
        except ValueError:
            out[row["category"]] = {}
    return out
