"""表现层：认证路由（登录/两步验证/注册/找回密码/验证码/登出）。"""
import logging
import time

from flask import (Blueprint, current_app, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from ..models.user import User
from ..security.ratelimit import client_ip, limiter
from ..services import auth as auth_svc
from ..services import settings as settings_svc
from ..services import totp as totp_svc
from ..services.audit import log_operation

bp = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)

# v0.1.0 pending_2fa（密码已过、等待第二因子）的有效期：10 分钟内未完成
# 二次验证则作废，需重新走完整登录流程
PENDING_2FA_TTL_MINUTES = 10


def _totp_enabled(row) -> bool:
    """该用户行是否已开启两步验证（旧库缺列时视为未开启）。"""
    return bool(row["totp_enabled"]) if "totp_enabled" in row.keys() else False


def _mark_bootstrap_pw_if_needed(session, row) -> None:
    """v0.1.0：管理员仍使用初始默认口令 admin123 时置会话警示标记。"""
    try:
        if row["username"] == "admin" and auth_svc.is_bootstrap_password(row):
            session["bootstrap_pw_warn"] = True
    except Exception:  # noqa: BLE001
        pass  # 警示缺失不影响登录主流程


def _establish_session(row, remember: bool):
    """建立登录会话（v0.1.0：统一入口，确保会话纪元被记录）。

    同时把会话标记为 permanent，使 config.PERMANENT_SESSION_LIFETIME
    真正生效（此前该配置从未被使用，S-09）。
    """
    from flask import session

    # 会话固定防护（借鉴 GB-55 · OWASP Session Management Cheat Sheet）：
    # 登录时必须重生成会话（OWASP 定级 mandatory）。Flask 默认为签名
    # Cookie 会话、无服务端会话 ID（见 pallets/flask#1600），等价实现即
    # 登录前清空整个 session——攻击者预置/残留的旧 Cookie 内容
    # （半登录 pending_2fa、bootstrap 警示位等）不会带进已认证会话。
    # 密码直登与 2FA 二次校验两条路径都经由本函数，一处覆盖全部入口。
    session.clear()
    session.permanent = True
    session["_epoch"] = int(row["session_epoch"]) if "session_epoch" in row.keys() else 0
    login_user(User(row), remember=remember)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("records.index"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()[:50]
        password = request.form.get("password") or ""
        remember = bool(request.form.get("remember"))
        ip = client_ip()

        # 会话过期后跳回登录页时给出明确提示（而非笼统的"请先登录"）
        if request.args.get("expired"):
            flash("登录已过期，请重新登录。", "warning")

        # 双维度限流：IP 维度（防批量撞库）+ 用户名维度（防单账户爆破）。
        # 用户名键统一小写，防止大小写变体（Admin/admin）绕开账户维度限流
        ok, wait = limiter.hit(f"login:ip:{ip}", 20, 300)
        if not ok:
            flash(f"尝试过于频繁，请 {wait} 秒后再试", "danger")
            return render_template("auth/login.html")
        ok, wait = limiter.hit(f"login:user:{username.lower()}", 10, 300)
        if not ok:
            flash(f"该账户尝试过于频繁，请 {wait} 秒后再试", "danger")
            return render_template("auth/login.html")

        result = auth_svc.authenticate(username, password, ip)
        if result.ok:
            # v2.3 已开启两步验证：密码通过后先进入第二因子校验，不建立登录会话
            if _totp_enabled(result.user):
                session["pending_2fa"] = {
                    "uid": result.user["id"], "remember": remember,
                    "ts": time.time(),
                }
                return redirect(url_for("auth.totp_login"))
            _establish_session(result.user, remember)
            _mark_bootstrap_pw_if_needed(session, result.user)
            log_operation(result.user["id"], "login", "user", result.user["id"], "用户登录")
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("records.index"))
        log_operation(None, "login_failed", "user", None,
                      f"登录失败: {username} (ip={ip})")
        flash(result.message, "danger")

    elif request.args.get("expired"):
        flash("登录已过期，请重新登录。", "warning")

    return render_template("auth/login.html",
                           allow_register=settings_svc.allow_register())


@bp.route("/login/2fa", methods=["GET", "POST"])
def totp_login():
    """v2.3 两步验证第二因子页：仅限密码刚校验通过的会话（pending_2fa）。

    v0.1.0：pending_2fa 超过 10 分钟自动作废，防止半登录状态长期悬置。
    """
    if current_user.is_authenticated:
        return redirect(url_for("records.index"))
    pending = session.get("pending_2fa")
    if not pending:
        return redirect(url_for("auth.login"))

    from ..db import get_db

    # 半登录状态有效期校验（向后兼容旧结构：无 ts 字段视为过期）
    try:
        issued_at = float(pending.get("ts") or 0)
    except (TypeError, ValueError):
        issued_at = 0.0
    if time.time() - issued_at > PENDING_2FA_TTL_MINUTES * 60:
        session.pop("pending_2fa", None)
        flash("登录已超时，请重新登录。", "warning")
        return redirect(url_for("auth.login"))

    row = get_db().execute(
        "SELECT * FROM users WHERE id=?", (pending.get("uid"),)).fetchone()
    if row is None or not row["is_active"] or not _totp_enabled(row):
        session.pop("pending_2fa", None)
        return redirect(url_for("auth.login"))

    ip = client_ip()
    if auth_svc.pair_lock_remaining_minutes(row["username"], ip) is not None:
        session.pop("pending_2fa", None)
        flash("登录失败次数过多，请 15 分钟后再试。", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        ok, wait = limiter.hit(f"login:ip:{ip}", 20, 300)
        if not ok:
            flash(f"尝试过于频繁，请 {wait} 秒后再试", "danger")
            return render_template("auth/totp.html")

        code = request.form.get("code") or ""
        verified, used_recovery = totp_svc.verify_login_code(row, code)
        if verified:
            remember = bool(pending.get("remember"))
            session.pop("pending_2fa", None)
            _establish_session(row, remember)
            _mark_bootstrap_pw_if_needed(session, row)
            log_operation(row["id"], "login", "user", row["id"],
                          "两步验证登录（恢复码）" if used_recovery else "两步验证登录")
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("records.index"))

        # 失败计入防爆破计数（用户名+IP 维度，持久化）
        log_operation(row["id"], "totp_failed", "user", row["id"],
                      f"两步验证校验失败 (ip={ip})")
        auth_svc.record_pair_failure(row["username"], ip)
        if auth_svc.pair_lock_remaining_minutes(row["username"], ip) is not None:
            session.pop("pending_2fa", None)
            flash("验证失败次数过多，请 15 分钟后重新登录。", "danger")
            return redirect(url_for("auth.login"))
        flash("验证码错误，请输入认证器当前的 6 位动态码，或改用一次性恢复码", "danger")

    return render_template("auth/totp.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("records.index"))
    if not settings_svc.allow_register():
        flash("系统已关闭自注册，请联系管理员开通账号。", "warning")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        # v0.1.0：注册提交限流（验证码爆破面——注册接口内含 6 位验证码
        # 校验，原先可无限次尝试暴力猜码）
        ok, wait = limiter.hit(f"register:ip:{client_ip()}", 10, 3600)
        if not ok:
            flash(f"尝试过于频繁，请 {wait} 秒后再试", "danger")
            return render_template("auth/register.html")
        user, error = auth_svc.register_user(
            request.form.get("username", ""),
            request.form.get("email", ""),
            request.form.get("password", ""),
            request.form.get("confirm_password", ""),
            request.form.get("code", ""),
        )
        if user is None:
            flash(error, "danger")
        else:
            flash("注册成功！请登录", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html")


@bp.route("/send-code", methods=["POST"])
def send_code():
    """发送邮箱验证码（JSON 接口，受频率限制）。"""
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()
    purpose = data.get("purpose", "register")

    from ..utils.validators import valid_email

    if not valid_email(email):
        return jsonify(success=False, message="邮箱格式不正确"), 400
    if purpose not in ("register", "reset_password"):
        return jsonify(success=False, message="用途参数不合法"), 400

    ip = client_ip()
    ok, wait = limiter.hit(f"code:ip:{ip}", 10, 3600)
    if not ok:
        return jsonify(success=False,
                       message=f"请求过于频繁，请 {wait} 秒后再试"), 429
    ok, wait = limiter.hit(f"code:email:{email}", 1, 60)
    if not ok:
        return jsonify(success=False,
                       message=f"发送太频繁，请 {wait} 秒后再试"), 429

    if purpose == "register":
        from ..db import get_db

        exists = get_db().execute(
            "SELECT 1 FROM users WHERE email=?", (email,)).fetchone()
        if exists:
            return jsonify(success=False, message="该邮箱已被注册"), 400
        if not settings_svc.allow_register():
            return jsonify(success=False, message="系统已关闭自注册"), 403
    # reset_password 场景不探测邮箱是否存在（防枚举），统一返回发送成功

    ok, msg = auth_svc.create_verification_code(email, purpose)
    if not ok:
        # v0.1.0 修复 B-05：SMTP 未配置/不可用属"服务不可用"（503），
        # 不再以 500 呈现；且此路径下验证码未入库，无悬空记录。
        status = 503 if "未配置" in msg or "不可用" in msg else 500
        return jsonify(success=False, message=msg), status
    return jsonify(success=True, message=msg)


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        # v0.1.0：找回密码提交限流（该接口内含 6 位验证码校验，原先可
        # 无限次尝试暴力猜码后直接重置任意账户口令）
        ok, wait = limiter.hit(f"forgot:ip:{client_ip()}", 10, 600)
        if not ok:
            flash(f"尝试过于频繁，请 {wait} 秒后再试", "danger")
            return render_template("auth/forgot_password.html")
        ok, msg = auth_svc.reset_password_by_email(
            request.form.get("email", ""),
            request.form.get("code", ""),
            request.form.get("new_password", ""),
        )
        flash(msg, "success" if ok else "danger")
        if ok:
            return redirect(url_for("auth.login"))
    return render_template("auth/forgot_password.html")


@bp.route("/logout")
@login_required
def logout():
    log_operation(current_user.id, "logout", "user", current_user.id, "用户登出")
    logout_user()
    # 登出同样重生成会话（OWASP Session Management Cheat Sheet）：
    # 清空残留的会话内容，防止半登出状态被复用
    from flask import session

    session.clear()
    flash("已成功退出登录！", "success")
    return redirect(url_for("auth.login"))
