"""表现层：管理员路由（用户管理/操作日志/系统设置/备份恢复）。"""
import logging
import os
import platform
import sqlite3
import uuid

import flask
from flask import (Blueprint, abort, current_app, flash, redirect,
                   render_template, request, send_file, session, url_for)
from flask_login import current_user, login_required

from .. import __version__
from ..db import get_db
from ..security.permissions import admin_required
from ..services import audit, backup as backup_svc
from ..services import auth as auth_svc
from ..services import onetime
from ..services import settings as settings_svc
from ..services import mail_settings, mailer
from ..utils.validators import valid_email, valid_port

bp = Blueprint("admin", __name__)
logger = logging.getLogger(__name__)


@bp.route("/manage-users")
@admin_required
def manage_users():
    page = max(1, _int_arg("page", 1))
    per_page = current_app.config["USERS_PER_PAGE"]
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    users = conn.execute(
        "SELECT id, username, email, is_admin, is_active, created_at,"
        " must_change_password, locked_until,"
        " (SELECT COUNT(*) FROM passwords p WHERE p.user_id=users.id"
        "   AND p.deleted_at IS NULL) AS record_count"
        " FROM users ORDER BY id DESC LIMIT ? OFFSET ?",
        (per_page, (page - 1) * per_page),
    ).fetchall()
    # v2.2 计算锁定状态 (locked_until 存 UTC 字符串)
    from ..utils.timefmt import is_expired
    rows = []
    for u in users:
        d = dict(u)
        d["is_locked"] = bool(d.get("locked_until")) and not is_expired(d["locked_until"])
        rows.append(d)
    pages = max(1, -(-total // per_page))
    # v0.1.0：管理员重置口令产生的临时口令从一次性仓取出后立即销毁
    reset_pw = None
    token = session.pop("reset_pw_token", None)
    if token:
        reset_pw = onetime.store.pop(token)
    return render_template("admin/users.html", users=rows, total=total,
                           page=page, pages=pages, reset_pw=reset_pw)


def _int_arg(name, default=1):
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


@bp.route("/manage-users/edit/<int:user_id>", methods=["GET", "POST"])
@admin_required
def edit_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if user is None:
        flash("用户不存在", "danger")
        return redirect(url_for("admin.manage_users"))

    if request.method == "POST":
        ok, msg = auth_svc.admin_update_user(
            current_user.id, user_id,
            request.form.get("username", ""),
            request.form.get("email", ""),
            request.form.get("password", ""),
        )
        flash(msg, "success" if ok else "danger")
        if ok:
            return redirect(url_for("admin.manage_users"))
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    return render_template("admin/user_edit.html", user=user)


@bp.route("/manage-users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    if user_id == current_user.id:
        flash("不能修改自己的管理员权限！", "danger")
        return redirect(url_for("admin.manage_users"))
    conn = get_db()
    target = conn.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        flash("用户不存在", "danger")
        return redirect(url_for("admin.manage_users"))
    _, msg = auth_svc.admin_set_admin(current_user.id, user_id,
                                      not target["is_admin"])
    flash(msg, "success")
    return redirect(url_for("admin.manage_users"))


@bp.route("/manage-users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_active(user_id):
    if user_id == current_user.id:
        flash("不能禁用自己的账户！", "danger")
        return redirect(url_for("admin.manage_users"))
    conn = get_db()
    target = conn.execute("SELECT is_active FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        flash("用户不存在", "danger")
        return redirect(url_for("admin.manage_users"))
    _, msg = auth_svc.admin_set_active(current_user.id, user_id,
                                       not target["is_active"])
    flash(msg, "success")
    return redirect(url_for("admin.manage_users"))


@bp.route("/manage-users/<int:user_id>/unlock", methods=["POST"])
@admin_required
def unlock_user(user_id):
    """v2.2 管理员手动解锁 (清除失败计数与锁定)"""
    ok, msg = auth_svc.admin_unlock(current_user.id, user_id)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("admin.manage_users"))


@bp.route("/manage-users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def reset_password(user_id):
    """v2.2 重置口令: 生成一次性随机临时口令 + 强制改密 + 清除锁定。

    临时口令经服务端一次性仓传递（v0.1.0 修复 S-02）：此前直接进 flash，
    而 flash 内容存放在 session cookie 里——cookie 只签名不加密，
    客户端 Base64 解码即可读到临时口令。现只在 session 里放不透明 token。
    """
    if user_id == current_user.id:
        flash("不能重置自己的密码（请在修改密码页自助改密）！", "danger")
        return redirect(url_for("admin.manage_users"))
    ok, msg, temp = auth_svc.admin_reset_password(current_user.id, user_id)
    if not ok:
        flash(msg, "danger")
        return redirect(url_for("admin.manage_users"))
    token = onetime.store.put(temp)
    session["reset_pw_token"] = token
    flash(msg + "（临时口令见下方提示，仅显示这一次，请通过安全渠道转交本人）",
          "success")
    return redirect(url_for("admin.manage_users"))


@bp.route("/manage-users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    """注销用户（匿名化 + 名下记录转回收站），替代旧版直接 DELETE
    因外键约束必然抛 500 的问题。"""
    if user_id == current_user.id:
        flash("不能注销自己！", "danger")
        return redirect(url_for("admin.manage_users"))
    confirm = (request.form.get("confirm") or "").strip()
    if confirm != "DELETE":
        flash("请输入 DELETE 确认注销操作", "danger")
        return redirect(url_for("admin.manage_users"))
    ok, msg = auth_svc.admin_anonymize_user(current_user.id, user_id)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("admin.manage_users"))


@bp.route("/operation-logs")
@login_required
def operation_logs():
    page = max(1, _int_arg("page", 1))
    per_page = current_app.config["LOGS_PER_PAGE"]
    # v2.3 管理员可按操作人筛选；普通用户始终只能看本人日志
    filter_user_id = _int_arg("user_id", 0) if current_user.is_admin else 0
    log_users = []
    if current_user.is_admin:
        log_users = get_db().execute(
            "SELECT id, username FROM users ORDER BY username").fetchall()
    logs, total = audit.query_logs(
        page=page, per_page=per_page,
        user_id=None if current_user.is_admin else current_user.id,
        filter_user_id=filter_user_id or None,
        op_type=(request.args.get("op_type") or "").strip(),
        keyword=(request.args.get("keyword") or "").strip()[:50],
        date_from=(request.args.get("date_from") or "").strip(),
        date_to=(request.args.get("date_to") or "").strip(),
    )
    pages = max(1, -(-total // per_page))
    return render_template("admin/logs.html", logs=logs, total=total,
                           page=page, pages=pages,
                           op_labels=audit.OP_LABELS,
                           log_users=log_users,
                           filters={
                               "op_type": request.args.get("op_type", ""),
                               "keyword": request.args.get("keyword", ""),
                               "date_from": request.args.get("date_from", ""),
                               "date_to": request.args.get("date_to", ""),
                               "user_id": filter_user_id,
                           })


@bp.route("/admin/security-overview")
@admin_required
def security_overview():
    """v0.1.0 管理员安全概览：失败登录 / 锁定现状 / 默认口令 / TOTP 覆盖率。

    数据全部实时聚合自既有表（operation_logs / users / login_lockouts /
    api_keys），只读页面，不提供任何写操作。
    """
    conn = get_db()
    from ..utils.timefmt import utcnow_str

    now = utcnow_str()
    stats = {
        "login_failed_24h": conn.execute(
            "SELECT COUNT(*) c FROM operation_logs"
            " WHERE operation_type='login_failed'"
            "   AND created_at >= datetime('now', '-1 day')").fetchone()["c"],
        "login_failed_7d": conn.execute(
            "SELECT COUNT(*) c FROM operation_logs"
            " WHERE operation_type='login_failed'"
            "   AND created_at >= datetime('now', '-7 day')").fetchone()["c"],
        "totp_failed_7d": conn.execute(
            "SELECT COUNT(*) c FROM operation_logs"
            " WHERE operation_type='totp_failed'"
            "   AND created_at >= datetime('now', '-7 day')").fetchone()["c"],
        "locked_accounts": conn.execute(
            "SELECT COUNT(*) c FROM users"
            " WHERE locked_until IS NOT NULL AND locked_until > ?",
            (now,)).fetchone()["c"],
        "pair_locks": conn.execute(
            "SELECT COUNT(*) c FROM login_lockouts"
            " WHERE locked_until IS NOT NULL AND locked_until > ?",
            (now,)).fetchone()["c"],
        "users_total": conn.execute(
            "SELECT COUNT(*) c FROM users WHERE id > 0").fetchone()["c"],
        "users_totp": conn.execute(
            "SELECT COUNT(*) c FROM users WHERE totp_enabled=1").fetchone()["c"],
        "users_must_change": conn.execute(
            "SELECT COUNT(*) c FROM users WHERE must_change_password=1"
            " AND is_active=1").fetchone()["c"],
        "api_keys_active": conn.execute(
            "SELECT COUNT(*) c FROM api_keys WHERE is_active=1").fetchone()["c"],
        "reveal_7d": conn.execute(
            "SELECT COUNT(*) c FROM operation_logs"
            " WHERE operation_type='reveal'"
            "   AND created_at >= datetime('now', '-7 day')").fetchone()["c"],
        "export_7d": conn.execute(
            "SELECT COUNT(*) c FROM operation_logs"
            " WHERE operation_type='export'"
            "   AND created_at >= datetime('now', '-7 day')").fetchone()["c"],
    }

    # 当前处于锁定中的账户明细（单账户锁定）
    locked_users = conn.execute(
        "SELECT id, username, locked_until, failed_attempts FROM users"
        " WHERE locked_until IS NOT NULL AND locked_until > ?"
        " ORDER BY locked_until DESC LIMIT 50", (now,)).fetchall()

    # 用户名+IP 维度锁定明细（v2.3 持久化锁定层）
    pair_rows = conn.execute(
        "SELECT username, ip, failed_count, locked_until FROM login_lockouts"
        " WHERE locked_until IS NOT NULL AND locked_until > ?"
        " ORDER BY locked_until DESC LIMIT 50", (now,)).fetchall()

    # 近 7 天失败登录最多的目标用户名（撞库热点）
    # v0.1.0 第六轮（审计观察项 3）：旧实现按 details 整串分组，而 details
    # 形如「登录失败: 用户名 (ip=x.x.x.x)」内含 IP，同一用户名不同 IP 不会
    # 聚合，"热点榜"实际退化成逐条失败记录。现从 details 中切出目标用户名
    # 再分组；切不出来时回退整串，保证不丢数据。
    hot_targets = conn.execute(
        "SELECT COALESCE(NULLIF(target, ''), details) AS target, COUNT(*) c"
        " FROM (SELECT substr(details, instr(details, ': ') + 2,"
        "               max(instr(details, ' (ip=') - instr(details, ': ') - 2, 0)"
        "              ) AS target, details"
        "       FROM operation_logs"
        "       WHERE operation_type='login_failed'"
        "         AND created_at >= datetime('now', '-7 day'))"
        " GROUP BY target ORDER BY c DESC LIMIT 10").fetchall()

    # 默认口令检测：管理员 admin 是否仍使用初始口令 admin123
    admin_row = conn.execute(
        "SELECT * FROM users WHERE username='admin' ORDER BY id LIMIT 1"
    ).fetchone()
    default_pw_active = bool(
        admin_row is not None and auth_svc.is_bootstrap_password(admin_row))

    return render_template(
        "admin/security_overview.html",
        stats=stats, locked_users=locked_users, pair_locks=pair_rows,
        hot_targets=hot_targets, default_pw_active=default_pw_active)


@bp.route("/system-settings")
@admin_required
def system_settings():
    conn = get_db()
    stats = {
        "users": conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
        "records": conn.execute(
            "SELECT COUNT(*) c FROM passwords WHERE deleted_at IS NULL").fetchone()["c"],
        "recycled": conn.execute(
            "SELECT COUNT(*) c FROM passwords WHERE deleted_at IS NOT NULL").fetchone()["c"],
        "projects": conn.execute("SELECT COUNT(*) c FROM projects").fetchone()["c"],
        "logs": conn.execute("SELECT COUNT(*) c FROM operation_logs").fetchone()["c"],
    }
    db_size_kb = os.path.getsize(current_app.config["DATABASE"]) / 1024
    return render_template(
        "admin/settings.html",
        stats=stats, db_size_kb=db_size_kb,
        backups=backup_svc.list_backups(),
        allow_register=settings_svc.allow_register(),
        mail=mail_settings.masked_view(),
        info={
            "version": __version__,
            "python": platform.python_version(),
            "flask": flask.__version__,
            "sqlite": sqlite3.sqlite_version,
            "db_path": current_app.config["DATABASE"],
        },
    )


@bp.route("/system-settings/mail", methods=["POST"])
@admin_required
def save_mail_settings():
    """保存在线邮件配置（密码留空 = 保留已存密码）。保存即生效，无需重启。"""
    from ..services.audit import log_operation

    server = (request.form.get("server") or "").strip()
    port = (request.form.get("port") or "465").strip()
    use_tls = request.form.get("use_tls") == "1"
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    sender = (request.form.get("sender") or "").strip()

    if not server:
        flash("SMTP 服务器不能为空", "error")
        return redirect(url_for("admin.system_settings"))
    if not valid_port(port):
        flash("端口必须是 1-65535 的数字", "error")
        return redirect(url_for("admin.system_settings"))
    if not username:
        flash("SMTP 账号不能为空", "error")
        return redirect(url_for("admin.system_settings"))
    # 首次保存（库里没有已存密码）时密码必填；再次保存留空表示不改
    if not password and not mail_settings.masked_view()["password_set"]:
        flash("首次配置必须填写 SMTP 密码（授权码）", "error")
        return redirect(url_for("admin.system_settings"))
    if sender and not valid_email(sender):
        flash("发件人地址格式不正确", "error")
        return redirect(url_for("admin.system_settings"))

    mail_settings.save_mail_config(
        server=server, port=int(port), use_tls=use_tls,
        username=username, password=password, sender=sender)
    log_operation(current_user.id, "update", "system", None,
                  f"更新邮件服务配置（{server}:{port}，账号 {username}）")
    flash("邮件服务配置已保存并立即生效，可点击「测试发送」验证", "success")
    return redirect(url_for("admin.system_settings"))


@bp.route("/system-settings/mail/clear", methods=["POST"])
@admin_required
def clear_mail_settings():
    """清除在线配置，回退 .env（若 .env 也没配则邮件功能停用）。"""
    from ..services.audit import log_operation

    mail_settings.clear_mail_config()
    log_operation(current_user.id, "update", "system", None, "清除邮件服务在线配置")
    flash("已清除在线邮件配置（回退 .env）", "success")
    return redirect(url_for("admin.system_settings"))


@bp.route("/system-settings/mail/test", methods=["POST"])
@admin_required
def test_mail_settings():
    """向指定邮箱发测试邮件，验证当前生效的 SMTP 配置。"""
    from ..security.ratelimit import limiter

    to_email = (request.form.get("test_email") or "").strip().lower()
    if not to_email or not valid_email(to_email):
        flash("请填写正确的收件邮箱", "error")
        return redirect(url_for("admin.system_settings"))
    # 防滥用: 同一 IP 10 分钟内最多 5 次测试发送
    from ..security.ratelimit import client_ip
    ok, wait = limiter.hit(f"mailtest:ip:{client_ip()}", 5, 600)
    if not ok:
        flash(f"测试过于频繁，请 {wait} 秒后再试", "error")
        return redirect(url_for("admin.system_settings"))

    success, msg = mailer.send_test_email(to_email)
    flash(msg, "success" if success else "error")
    return redirect(url_for("admin.system_settings"))


@bp.route("/system-settings/allow-register", methods=["POST"])
@admin_required
def toggle_allow_register():
    from ..services.audit import log_operation

    enable = request.form.get("enable") == "1"
    settings_svc.set_setting("allow_register", "1" if enable else "0")
    log_operation(current_user.id, "update", "system", None,
                  f"{'开启' if enable else '关闭'}自注册")
    flash(f"已{'开启' if enable else '关闭'}自注册", "success")
    return redirect(url_for("admin.system_settings"))


@bp.route("/backup", methods=["POST"])
@admin_required
def create_backup():
    try:
        name = backup_svc.create_backup(current_user.id)
        flash(f"备份成功：{name}", "success")
    except Exception as exc:  # noqa: BLE001
        logger.exception("备份失败")
        flash(f"备份失败: {exc}", "danger")
    return redirect(url_for("admin.system_settings"))


@bp.route("/backups/<path:filename>")
@admin_required
def download_backup(filename):
    path = backup_svc.backup_path(filename)
    if path is None:
        abort(404)
    from ..services.audit import log_operation

    log_operation(current_user.id, "download", "backup", None, f"下载备份: {filename}")
    return send_file(path, as_attachment=True, download_name=filename)


@bp.route("/restore", methods=["GET", "POST"])
@admin_required
def restore_data():
    if request.method == "POST":
        file = request.files.get("backup_file")
        confirm = (request.form.get("confirm") or "").strip()
        if file is None or not file.filename:
            flash("请选择备份文件", "danger")
            return redirect(url_for("admin.restore_data"))
        if not file.filename.lower().endswith(".db"):
            flash("仅支持 .db 备份文件", "danger")
            return redirect(url_for("admin.restore_data"))
        if confirm != "RESTORE":
            flash("请输入 RESTORE 进行二次确认", "danger")
            return redirect(url_for("admin.restore_data"))

        import tempfile

        tmp_path = os.path.join(tempfile.gettempdir(),
                                f"pm_restore_{uuid.uuid4().hex}.db")
        file.save(tmp_path)
        ok, msg = backup_svc.restore_backup(tmp_path, current_user.id)
        if not ok:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        flash(msg, "success" if ok else "danger")
        if ok:
            flash("强烈建议立即重启服务使恢复完全生效", "warning")
        return redirect(url_for("admin.system_settings"))

    return render_template("admin/restore.html", backups=backup_svc.list_backups())
