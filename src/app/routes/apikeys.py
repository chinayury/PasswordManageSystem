"""表现层：API 密钥管理（所有登录用户可管理自己的密钥）。"""
from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import current_user, login_required

from ..services import apikeys as apikey_svc
from ..services import onetime
from ..utils.validators import ValidationError

bp = Blueprint("apikeys", __name__)

# session 里只放不透明 token，明文密钥在服务端一次性仓内（S-02）
_KEY_TOKEN_SESSION = "created_api_key_token"


@bp.route("/api-keys")
@login_required
def manage():
    keys = apikey_svc.list_keys(current_user.id)
    # 新密钥明文经服务端一次性仓传递，展示后立即销毁
    # （避免明文进入 session cookie——cookie 只签名不加密，客户端可解码）
    token = session.pop(_KEY_TOKEN_SESSION, None)
    created_key = onetime.store.pop(token) if token else None
    return render_template("apikeys/manage.html", keys=keys, created_key=created_key)


@bp.route("/api-keys/create", methods=["POST"])
@login_required
def create():
    try:
        plaintext = apikey_svc.create_key(
            current_user.id, request.form.get("key_name", ""),
            request.form.get("allowed_ips", ""))
        session[_KEY_TOKEN_SESSION] = onetime.store.put(plaintext)
        return redirect(url_for("apikeys.manage"))
    except ValidationError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("apikeys.manage"))


@bp.route("/api-keys/<int:key_id>/delete", methods=["POST"])
@login_required
def delete(key_id):
    try:
        apikey_svc.delete_key(current_user.id, key_id)
        flash("API 密钥已删除", "success")
    except ValidationError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("apikeys.manage"))


@bp.route("/api-keys/<int:key_id>/toggle", methods=["POST"])
@login_required
def toggle(key_id):
    try:
        apikey_svc.toggle_key(current_user.id, key_id)
        flash("密钥状态已更新", "success")
    except ValidationError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("apikeys.manage"))


@bp.route("/api-keys/<int:key_id>/ip-list", methods=["POST"])
@login_required
def update_ip_list(key_id):
    """更新密钥的来源 IP / CIDR 白名单（v0.1.0 第六轮，借鉴 GB-30）。"""
    try:
        apikey_svc.set_key_ip_list(current_user.id, key_id,
                                   request.form.get("allowed_ips", ""))
        flash("IP 白名单已更新", "success")
    except ValidationError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("apikeys.manage"))
