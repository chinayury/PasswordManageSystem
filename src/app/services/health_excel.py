"""业务层：密码健康报告 Excel 导出（复用 openpyxl，BytesIO 直传不落盘）。

导出内容绝对不含密码列（明文/密文/哈希一概不出），仅含派生统计与明细：
  概览 Sheet（run 元信息 + 态势评分 + 分类计数 + 阈值快照）
  + 每类一 Sheet（标题/分组/用户名/站点/评分/等级/严重度/复用次数/HIBP桶/
    天数/到期日/原因）。
格式：冻结首行 + AutoFilter + 严重度条件填充；单元格统一走 excelio 的
公式注入防护（与既有导出同一套处置）。
"""
import io
import json
from datetime import datetime, timezone

from openpyxl import Workbook
from openpyxl.styles import PatternFill

from .excelio import _sanitize_xlsx_row  # 复用既有公式注入防护（私有名共享在包内白名单）

_CATEGORY_TITLES = {
    "weak": "弱口令",
    "reused": "重复口令",
    "old": "年龄与到期",
    "hibp": "泄露查询(HIBP)",
}

# 严重度 -> 行填充色（3 红 / 2 橙 / 1 黄）
_SEVERITY_FILLS = {
    3: PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid"),
    2: PatternFill(start_color="FFE0B2", end_color="FFE0B2", fill_type="solid"),
    1: PatternFill(start_color="FFF6BF", end_color="FFF6BF", fill_type="solid"),
}

_GRADE_CN = {"Bad": "Bad（必须修改）", "Poor": "Poor（应尽快修改）",
             "Weak": "Weak（建议修改）", "Good": "Good", "Excellent": "Excellent"}


def _grade_of(score: float) -> str:
    if score <= 0:
        return "Bad"
    if score < 40:
        return "Poor"
    if score < 75:
        return "Weak"
    if score < 100:
        return "Good"
    return "Excellent"


def report_filename(run_id: int) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"密码健康报告_{run_id}_{stamp}.xlsx"


def build_health_report_xlsx(run, findings) -> io.BytesIO:
    """构建健康报告工作簿。run 为 runs 行，findings 为 run_all_findings 结果。

    返回 BytesIO（游标复位），由路由 send_file 直传，服务端不落盘。
    """
    wb = Workbook()

    # ---- 概览 Sheet ----
    ws = wb.active
    ws.title = "概览"
    try:
        snapshot = json.loads(run["thresholds_json"] or "{}")
    except ValueError:
        snapshot = {}
    # 发起人展示用户名（visible_run 已 LEFT JOIN users 提供 creator 列；
    # 用户被注销匿名化等导致 JOIN 不到时回退数字 ID，保证行不缺数据）
    creator = (run["creator"] if "creator" in run.keys() else None) \
        or run["created_by"]
    overview: list[list] = [
        ["项", "值"],
        ["报告编号", run["id"]],
        ["范围", "全库" if run["scope_type"] == "all" else "本人记录"],
        ["状态", {"done": "完成", "partial": "部分完成",
                  "failed": "失败", "running": "进行中"}.get(
                      run["status"], run["status"])],
        ["开始时间", run["started_at"]],
        ["结束时间", run["finished_at"] or "-"],
        ["发起人", creator],
        ["分析条目数", run["item_total"]],
        ["弱口令", run["weak_count"]],
        ["重复口令", run["reused_count"]],
        ["年龄/到期", run["old_count"]],
        ["泄露(HIBP)", run["hibp_count"]],
        ["态势评分", run["posture_score"]],
        ["HIBP 启用", "是" if run["hibp_enabled"] else "否"],
        ["HIBP 可用", {1: "是", 0: "否（查询失败已降级）"}.get(
            run["hibp_available"], "未启用")],
        ["错误信息", run["error"] or "-"],
        ["阈值快照", json.dumps(snapshot, ensure_ascii=False)],
    ]
    for row in overview:
        _sanitize_xlsx_row(ws, row)
    ws.column_dimensions["A"].width = 18
    ws.column_dimensions["B"].width = 80

    # ---- 分类明细 Sheet ----
    headers = ["标题", "分组", "用户名", "站点(IP)", "评分", "等级", "严重度",
               "复用次数", "HIBP 泄露次数", "HIBP 分桶", "口令年龄(天)",
               "到期日", "原因", "明细"]
    by_category: dict[str, list] = {c: [] for c in _CATEGORY_TITLES}
    for f in findings:
        by_category.setdefault(f["category"], []).append(f)

    for category, rows in by_category.items():
        sheet = wb.create_sheet(_CATEGORY_TITLES[category][:28])
        _sanitize_xlsx_row(sheet, headers)
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = (
            f"A1:{chr(ord('A') + len(headers) - 1)}{len(rows) + 1}")
        for f in rows:
            try:
                detail = json.loads(f["details_json"] or "{}")
            except ValueError:
                detail = {}
            reasons = "；".join(detail.get("reasons", []))
            expire = ""
            if detail.get("expired"):
                expire = "已到期"
            elif detail.get("expire_in_days") is not None:
                expire = f"{detail['expire_in_days']} 天后到期"
            values = [
                (f["device_model"] or "") + ("（已删除）" if f["deleted_at"] else ""),
                f["project_name"] or "未分组",
                f["username"] or "",
                f["ip_address"] or "",
                round(f["score"]),
                _GRADE_CN.get(_grade_of(f["score"]), _grade_of(f["score"])),
                f["severity"],
                detail.get("reuse_count", ""),
                detail.get("hibp_count", ""),
                detail.get("hibp_bucket", ""),
                detail.get("age_days", ""),
                expire,
                reasons,
                json.dumps(detail, ensure_ascii=False)[:500],
            ]
            _sanitize_xlsx_row(sheet, values)
            fill = _SEVERITY_FILLS.get(f["severity"])
            if fill:
                for cell in sheet[sheet.max_row]:
                    cell.fill = fill

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf
