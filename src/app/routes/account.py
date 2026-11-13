"""表现层：个人账户路由（修改密码/两步验证安全设置）。"""
import json

from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import current_user, login_required, logout_user

from ..services import auth as auth_svc
from ..services import totp as totp_svc

bp = Blueprint("account", __name__)


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    # v2.2 强制改密模式: 管理员重置/新建的账号手上是临时口令, 跳过旧密码校验
    force = bool(getattr(current_user, "must_change_password", False))
    if request.method == "POST":
        ok, msg = auth_svc.change_password(
            current_user.id,
            request.form.get("current_password", ""),
            request.form.get("new_password", ""),
            request.form.get("confirm_password", ""),
            force=force,
        )
        if ok:
            logout_user()
            # v0.1.0：口令已更换，清除"仍在使用初始默认口令"的警示标记
            session.pop("bootstrap_pw_warn", None)
            flash(msg + "，请使用新密码重新登录。", "success")
            return redirect(url_for("auth.login"))
        flash(msg, "danger")
    return render_template("auth/change_password.html", force_change=force)


# --- v2.3 两步验证（TOTP）自助管理 ---

def _totp_state() -> dict:
    """当前用户的 TOTP 状态：是否开启 / 是否有待确认密钥 / 剩余恢复码数。"""
    row = totp_svc.get_user_totp_row(current_user.id)
    if row is None:
        return {"enabled": False, "pending": False, "recovery_left": 0}
    enabled = bool(row["totp_enabled"]) if "totp_enabled" in row.keys() else False
    try:
        recovery_left = len(json.loads(row["recovery_codes"] or "[]"))
    except (ValueError, TypeError):
        recovery_left = 0
    return {"enabled": enabled,
            "pending": bool(row["totp_secret"]) and not enabled,
            "recovery_left": recovery_left}


@bp.route("/account/security", methods=["GET"])
@login_required
def security():
    return render_template("account/security.html", state=_totp_state())


@bp.route("/account/totp/setup", methods=["POST"])
@login_required
def totp_setup():
    """开启流程第一步：生成密钥并一次性展示（otpauth URI + 密钥文本）。

    v0.1.0 修复 S-01：已开启两步验证时直接拒绝，不再进入生成流程
    （服务端 totp.set_pending_secret 亦有一层守卫，双端拦截）。
    """
    if _totp_state()["enabled"]:
        flash("两步验证已开启，如需更换密钥请先关闭再重新开启", "warning")
        return redirect(url_for("account.security"))
    ok, secret, uri = totp_svc.set_pending_secret(current_user.id)
    if not ok:
        flash("生成密钥失败，请重试", "danger")
        return redirect(url_for("account.security"))
    return render_template("account/totp_setup.html", secret=secret, uri=uri)


@bp.route("/account/totp/enable", methods=["POST"])
@login_required
def totp_enable():
    """开启流程第二步：输入一次有效动态码确认；成功后一次性展示恢复码。"""
    if _totp_state()["enabled"]:
        flash("两步验证已开启，无需重复操作", "warning")
        return redirect(url_for("account.security"))
    ok, msg, codes = totp_svc.enable(current_user.id, request.form.get("code", ""))
    if not ok:
        flash(msg, "danger")
        return redirect(url_for("account.security"))
    return render_template("account/totp_recovery.html", codes=codes)


@bp.route("/account/totp/disable", methods=["POST"])
@login_required
def totp_disable():
    """关闭两步验证：当前密码 + 当前有效动态码双重确认。"""
    ok, msg = totp_svc.disable(
        current_user.id,
        request.form.get("current_password", ""),
        request.form.get("code", ""),
    )
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("account.security"))
