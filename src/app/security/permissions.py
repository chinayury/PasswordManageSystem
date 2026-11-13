"""安全层：权限控制装饰器。"""
from functools import wraps

from flask import abort, flash, redirect, request, url_for
from flask_login import current_user, login_required


def admin_required(view):
    """管理员权限装饰器：未登录跳登录页，非管理员回主页并提示。"""

    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            if request.accept_mimetypes.best == "application/json":
                abort(403)
            flash("无管理员权限！", "danger")
            return redirect(url_for("records.index"))
        return view(*args, **kwargs)

    return wrapped


def json_or_form(name: str, default: str = ""):
    """从 JSON 体或表单中取参数（API 与表单复用同一处理逻辑）。"""
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data.get(name, default)
    return request.form.get(name, default)
