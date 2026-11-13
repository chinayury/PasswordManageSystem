"""表现层：密码健康审计路由（发起/报告页/Excel 导出）。

权限模型（沿用现有角色机制）：
- 管理员：可发起全库（scope=all）或本人范围审计，可查看/导出任意轮次报告；
- 普通用户：可发起并查看/导出本人范围（scope=user）的审计。
防滥用：发起与导出均走内存滑动窗口限流；run 视图越权一律 404（不泄露
他人审计的存在性）。
"""
import logging

from flask import (Blueprint, abort, current_app, flash, redirect,
                   render_template, request, send_file, url_for)
from flask_login import current_user, login_required

from ..security.ratelimit import limiter
from ..services import health as health_svc
from ..services.audit import log_operation
from ..services.health_excel import build_health_report_xlsx, report_filename

bp = Blueprint("health", __name__)
logger = logging.getLogger(__name__)

# 报告页每类最多展示的行数（完整清单走 Excel 导出）
DISPLAY_LIMIT = 500


def _perm_or_404(run_id: int):
    run = health_svc.visible_run(run_id, current_user.is_admin, current_user.id)
    if run is None:
        abort(404)
    return run


@bp.get("/health")
@login_required
def index():
    """审计中心：轮次列表 + 发起入口 + HIBP 开关状态。"""
    runs = health_svc.list_runs(current_user.is_admin, current_user.id)
    from ..utils.timefmt import parse_db_time, utcnow

    progress = []
    for r in runs:
        started = parse_db_time(r["started_at"])
        progress.append({"row": r, "age_s": (
            int((utcnow() - started).total_seconds()) if started else None)})
    return render_template(
        "health/index.html", runs=progress,
        hibp_enabled=bool(current_app.config.get("HIBP_ENABLED")),
        thresholds=health_svc.thresholds(),
    )


@bp.post("/health/run")
@login_required
def run():
    """发起一轮审计。普通用户固定本人范围；scope=all 仅管理员生效。"""
    ok, wait = limiter.hit(f"healthrun:u{current_user.id}", 3, 600)
    if not ok:
        flash(f"发起过于频繁，请 {wait} 秒后再试", "danger")
        return redirect(url_for("health.index"))

    scope_all = (request.form.get("scope") == "all"
                 and bool(current_user.is_admin))
    run_id, err = health_svc.start_run(current_user.id, scope_all)
    if run_id is None:
        flash(err, "warning")
        return redirect(url_for("health.index"))
    if err:
        # run 已创建但执行失败（failed/partial），提示后仍可查看报告
        flash(f"审计执行失败：{err}", "danger")
        return redirect(url_for("health.report", run_id=run_id))
    flash("审计完成，报告已生成", "success")
    return redirect(url_for("health.report", run_id=run_id))


@bp.get("/health/report/<int:run_id>")
@login_required
def report(run_id):
    """报告页：概览头（态势评分/五项告警/阈值快照）+ 四类页签明细。"""
    run = _perm_or_404(run_id)
    tab = request.args.get("tab", "weak")
    if tab not in health_svc.CATEGORIES:
        tab = "weak"
    findings = health_svc.run_findings(run_id, tab, DISPLAY_LIMIT)
    findings = [_finding_view(f) for f in findings]
    total_in_tab = _count_category(run_id, tab)
    alerts = _posture_alerts(run)
    return render_template(
        "health/report.html", run=run, tab=tab, findings=findings,
        display_limit=DISPLAY_LIMIT, total_in_tab=total_in_tab,
        alerts=alerts, thresholds=_thresholds_of(run),
        hibp_enabled=bool(run["hibp_enabled"]),
        grade=_grade_fn,
    )


def _count_category(run_id: int, category: str) -> int:
    from ..db import get_db

    return get_db().execute(
        "SELECT COUNT(*) c FROM password_health_findings"
        " WHERE run_id=? AND category=?", (run_id, category)).fetchone()["c"]


def _finding_view(f) -> dict:
    """finding 行 -> 模板视图 dict（details_json 解析为 details dict）。"""
    import json

    view = dict(f)
    try:
        view["details"] = json.loads(f["details_json"] or "{}")
    except ValueError:
        view["details"] = {}
    return view


def _thresholds_of(run) -> dict:
    import json

    try:
        return json.loads(run["thresholds_json"] or "{}")
    except ValueError:
        return {}


def _posture_alerts(run) -> list[str]:
    """五项态势告警（本轮运行时由服务层计算并随快照落库）。"""
    import json

    try:
        result = json.loads(run["result_json"] or "{}")
    except ValueError:
        result = {}
    return result.get("alerts") or ["未命中态势告警阈值"]


def _grade_fn(score: float) -> str:
    from ..services.password_strength import grade

    return grade(int(score))


@bp.get("/health/report/<int:run_id>/export")
@login_required
def export(run_id):
    """导出健康报告 Excel（服务端 BytesIO 直传，绝不落盘、绝不含密码列）。"""
    run = _perm_or_404(run_id)
    ok, wait = limiter.hit(f"healthexp:u{current_user.id}", 10, 600)
    if not ok:
        flash(f"导出过于频繁，请 {wait} 秒后再试", "danger")
        return redirect(url_for("health.report", run_id=run_id))

    findings = health_svc.run_all_findings(run_id)
    buf = build_health_report_xlsx(run, findings)
    log_operation(
        current_user.id, "health_export", "system", run_id,
        f"导出密码健康报告 #{run_id}（{len(findings)} 条发现，不含密码列）")
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument."
                 "spreadsheetml.sheet",
        as_attachment=True, download_name=report_filename(run_id))
