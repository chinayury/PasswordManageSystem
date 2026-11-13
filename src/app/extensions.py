"""扩展层：Flask 扩展统一实例化，避免循环导入。"""
from flask import jsonify, redirect, request, url_for
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

login_manager = LoginManager()
csrf = CSRFProtect()


def init_extensions(app):
    """初始化所有扩展并挂载到应用。"""
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "请先登录后再访问该页面。"
    login_manager.login_message_category = "warning"

    # v0.1.0 会话过期体验：AJAX/JSON/API 请求未认证时返回 401 JSON
    # （前端据此提示"登录已过期"并跳转登录页），页面请求仍走 302 跳转
    # 并带上 expired=1 标记，由登录页展示友好提示。
    @login_manager.unauthorized_handler
    def _unauthorized():
        if (request.headers.get("X-Requested-With") == "XMLHttpRequest"
                or (request.accept_mimetypes.best == "application/json")
                or request.path.startswith("/api/")):
            return jsonify(success=False, error={
                "code": 401, "message": "登录已过期，请重新登录"}), 401
        return redirect(url_for("auth.login", expired=1))

    csrf.init_app(app)
