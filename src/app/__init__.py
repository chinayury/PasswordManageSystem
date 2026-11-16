"""密码管理系统（PasswordManageSystem / PDM）应用工厂：创建并装配 Flask 应用。

调用链（分层职责）：
  routes(表现层) -> services(业务层) -> db(数据层)；
  security/utils(横切关注点) 由工厂统一挂载。
"""
import logging
import logging.handlers
import os

import click
from flask import Flask, jsonify, redirect, render_template, request, url_for

# 品牌命名（全站统一引用，禁止散落硬编码）
APP_NAME_CN = "密码管理系统"
APP_NAME_EN = "PasswordManageSystem"
APP_NAME_ABBR = "PDM"

from . import paths
from .version import __version__
from .config import load_config
from .extensions import init_extensions, login_manager
from .models.user import load_user_by_id
from .security.headers import init_security_headers
from .services.crypto import init_crypto
from .utils.timefmt import date_only_filter, localtime_filter

login_manager.user_loader(load_user_by_id)


def _setup_logging(app: Flask) -> None:
    """应用日志：控制台 + 滚动文件（logs/app.log，5MB x 3）。"""
    os.makedirs(paths.LOG_FOLDER, exist_ok=True)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s")

    root = logging.getLogger()
    root.setLevel(app.config.get("LOG_LEVEL", "INFO"))
    for handler in list(root.handlers):  # waitress/gunicorn 托管时避免重复
        root.removeHandler(handler)
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(paths.LOG_FOLDER, "app.log"),
        maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    if app.debug:
        logging.getLogger("werkzeug").setLevel(logging.INFO)


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(err):
        return _render_error(400, "请求参数错误", err)

    @app.errorhandler(403)
    def forbidden(err):
        return _render_error(403, "无权限访问该页面", err)

    @app.errorhandler(404)
    def not_found(err):
        return _render_error(404, "页面不存在", err)

    @app.errorhandler(413)
    def too_large(err):
        return _render_error(
            413, f"上传内容超过大小限制（{app.config['MAX_CONTENT_LENGTH'] // 1024 // 1024}MB）", err)

    @app.errorhandler(500)
    def server_error(err):
        app.logger.exception("服务器内部错误: %s", err)
        return _render_error(500, "服务器内部错误，请稍后重试", err)

    def _render_error(code: int, message: str, err):
        if (request.accept_mimetypes.best == "application/json"
                or request.path.startswith("/api/")):
            return jsonify(success=False,
                           error={"code": code, "message": message}), code
        return render_template("errors/error.html", code=code, message=message), code


def _register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def cli_init_db():
        """初始化/迁移数据库。"""
        from .db import init_db

        init_db(app)
        print("数据库初始化/迁移完成。")

    @app.cli.command("create-admin")
    def cli_create_admin():
        """交互式创建管理员账户。"""
        import getpass

        import bcrypt

        from .db import get_db
        from .services.auth import username_taken

        username = input("管理员用户名: ").strip()
        email = input("管理员邮箱: ").strip()
        password = getpass.getpass("管理员密码: ")
        if not username or not email or not password:
            print("所有字段都不能为空")
            raise SystemExit(1)
        with app.app_context():
            conn = get_db()
            # CLI 为可信操作者入口，仅做大小写归一查重（不套保留名黑名单，
            # 保证"admin 被删后重建管理员"等恢复场景可用）
            dup = conn.execute(
                "SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if dup or username_taken(conn, username):
                print("用户名或邮箱已存在")
                raise SystemExit(1)
            conn.execute(
                "INSERT INTO users (username, email, password, is_admin,"
                " email_verified, is_active) VALUES (?,?,?,1,1,1)",
                (username, email,
                 bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()),
            )
            conn.commit()
            print(f"管理员 {username} 创建成功。")

    @app.cli.command("purge-logs")
    @click.option("--days", default=90, show_default=True, help="保留最近 N 天")
    def cli_purge_logs(days):
        """清理 N 天前的操作日志。"""
        from datetime import timedelta

        from .db import get_db
        from .utils.timefmt import to_db_time, utcnow

        with app.app_context():
            cutoff = to_db_time(utcnow() - timedelta(days=days))
            conn = get_db()
            cur = conn.execute(
                "DELETE FROM operation_logs WHERE created_at < ?", (cutoff,))
            conn.commit()
            print(f"已清理 {cur.rowcount} 条 {days} 天前的操作日志。")

    @app.cli.command("cleanup-shares")
    def cli_cleanup_shares():
        """清理已过期的共享关系。"""
        from .services.shares import cleanup_expired_shares

        with app.app_context():
            print(f"已清理 {cleanup_expired_shares()} 条过期共享。")


def _register_startup_tasks(app: Flask) -> None:
    """启动时的轻量维护：过期共享清理 + 登录锁定表清理 + 预恢复快照清理
    + 僵尸健康审计行收敛 + 回收站保留期清理 + 数据库结构迁移。"""
    from .db import init_db
    from .services.auth import cleanup_expired_lockouts
    from .services.backup import prune_pre_restore_snapshots
    from .services.health import reap_stale_running_runs
    from .services.records import purge_expired_recycled
    from .services.shares import cleanup_expired_shares

    init_db(app)
    with app.app_context():
        cleaned = cleanup_expired_shares()
        if cleaned:
            app.logger.info("启动清理：%d 条过期共享已移除", cleaned)
        removed = cleanup_expired_lockouts(force=True)
        if removed:
            app.logger.info("启动清理：%d 条过期登录锁定记录已移除", removed)
        pruned = prune_pre_restore_snapshots()
        if pruned:
            app.logger.info("启动清理：%d 个历史预恢复快照已移除", pruned)
        # v0.1.0 第六轮 BU-06：进程中断留下的僵尸 running 行会让对应 scope
        # 永久无法发起审计，启动时统一收敛为 failed。
        stale_runs = reap_stale_running_runs()
        if stale_runs:
            app.logger.info("启动清理：%d 条僵尸健康审计轮次已标记为失败", stale_runs)
        # 回收站保留期清理（RECYCLE_RETENTION_DAYS>0 才启用，默认关闭）
        purged = purge_expired_recycled(
            app.config.get("RECYCLE_RETENTION_DAYS") or 0)
        if purged:
            app.logger.info("启动清理：%d 条回收站超期记录已彻底删除", purged)
    # 进程内周期执行（GB-56 补强）：启动任务只跑一次，长期不重启的实例
    # 此前不会再次清理；守护线程每日复用同一清理函数，保留期关闭时空转。
    _start_recycle_retention_loop(app)


def _start_recycle_retention_loop(app: Flask) -> None:
    """回收站保留期的 24 小时守护线程。

    RECYCLE_RETENTION_DAYS 为 0（默认关闭）时线程空转、零清理，行为与
    关闭状态一致；周期任务异常只记日志，不拖垮服务。
    """
    import threading
    import time as _time

    def _loop() -> None:
        while True:
            _time.sleep(24 * 3600)
            try:
                with app.app_context():
                    purged = purge_expired_recycled(
                        app.config.get("RECYCLE_RETENTION_DAYS") or 0)
                if purged:
                    app.logger.info("周期清理：%d 条回收站超期记录已彻底删除", purged)
            except Exception:  # noqa: BLE001
                app.logger.exception("回收站保留期周期清理失败")

    threading.Thread(target=_loop, name="recycle-retention", daemon=True).start()


def _warn_on_unsafe_binding(app: Flask) -> None:
    """对外暴露且未启用安全 Cookie 时给出醒目告警（借鉴 GB-37 · CipherMoth）。

    CipherMoth 的做法是"Docker 默认只听 127.0.0.1，对外暴露是显式开关"。
    本项目保持 HOST 可自由配置（不改变既有部署行为），但在
    "绑定 0.0.0.0/:: 且 SESSION_COOKIE_SECURE=false" 这个组合下，
    口令库会经明文 HTTP 暴露——启动时醒目告警，并在日志里给出两种修法。
    """
    host = str(app.config.get("HOST") or "").strip()
    exposed = host in ("0.0.0.0", "::", "*", "")
    secure_cookie = bool(app.config.get("SESSION_COOKIE_SECURE"))
    if exposed and not secure_cookie:
        app.logger.warning(
            "=" * 68 + "\n"
            "[安全告警] 服务正绑定 %s 且 SESSION_COOKIE_SECURE=false：\n"
            "  登录会话与密码明文可能经明文 HTTP 传输。二选一：\n"
            "  1) 仅本机使用：设 HOST=127.0.0.1（最稳，口令库不出本机）；\n"
            "  2) 需远程访问：前置 nginx/Caddy 终结 TLS，并把\n"
            "     SESSION_COOKIE_SECURE=true + TRUST_PROXY=true。\n"
            + "=" * 68, host or "0.0.0.0")


def create_app(config_object=None) -> Flask:
    app = Flask(__name__)
    if isinstance(config_object, dict):
        # 测试等场景传入部分配置：叠加在默认值之上，保证业务默认项齐全
        from .config import BaseConfig

        app.config.from_object(BaseConfig)
        app.config.update(config_object)
    else:
        config = config_object if config_object is not None else load_config()
        app.config.from_object(config)
    # UPLOAD_FOLDER 等运行期路径统一从 paths 模块注入
    app.config.setdefault("UPLOAD_FOLDER", paths.UPLOAD_FOLDER)
    app.config.setdefault("BACKUP_FOLDER", paths.BACKUP_FOLDER)

    _setup_logging(app)
    _warn_on_unsafe_binding(app)
    init_crypto(app.config["ENCRYPTION_KEY"])
    init_extensions(app)
    # v0.1.0 修复 Q-01：注册请求结束的数据库连接关闭钩子。
    # 此前 db.init_app() 从未被调用，teardown 实际未注册，连接随应用上下文
    # 一起泄漏——在 Windows 上直接表现为数据库文件长期被占用，
    # 进而导致"恢复数据库"必然失败（B-02 的上游根因）。
    from .db import init_app as init_db_app
    init_db_app(app)
    init_security_headers(app)
    _register_error_handlers(app)
    _register_cli(app)

    from .routes import (account, admin, api, apikeys, auth, health,
                         projects, records, shares)

    app.register_blueprint(auth.bp)
    app.register_blueprint(records.bp)
    app.register_blueprint(projects.bp)
    app.register_blueprint(shares.bp)
    app.register_blueprint(account.bp)
    app.register_blueprint(apikeys.bp)
    app.register_blueprint(health.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(api.bp)

    # v2.2 强制改密拦截: 管理员重置/新建的账号 (must_change_password=1) 登录后,
    # 除改密/登出/静态资源/健康检查外一律重定向到改密页。服务端强制 (双端拦截的后端半边)。
    # v0.1.0 修复 S-08：异常时 fail-closed（拒绝放行）而非 fail-open。
    _FORCE_CHANGE_ALLOW = {
        "account.change_password", "auth.logout", "auth.login", "auth.register",
        "auth.send_code", "auth.forgot_password", "static", "healthz",
    }

    @app.before_request
    def _enforce_password_change():
        from flask_login import current_user
        try:
            if current_user.is_authenticated and current_user.must_change_password:
                if request.endpoint not in _FORCE_CHANGE_ALLOW:
                    return redirect(url_for("account.change_password"))
        except Exception:  # noqa: BLE001
            # 拦截器自身故障时按"需要改密"处理：宁可多拦一次，不可放过一次
            app.logger.exception("强制改密拦截器异常，按需改密处理")
            return redirect(url_for("account.change_password"))
        return None

    # v0.1.0 会话纪元校验（S-11 的生效半边）：改密/重置/注销会递增
    # users.session_epoch，会话里记录的纪元一旦落后即强制登出，
    # 从而实现"改密后其它设备全部下线"。
    #
    # v0.1.0 第六轮修复 BU-07：旧实现把"会话里没有纪元"一律当作"首次访问"
    # 并静默采纳当前值。但"记住我"（remember cookie）重新认证的路径不携带
    # 纪元——设备空闲超过会话 cookie 寿命（12h）而 remember cookie 仍有效
    # （7 天）时，仅凭 remember cookie 即可重新入座，S-11 的踢下线被绕过。
    # 现区分两种"无纪元"：
    #   ① 从未在本会话登录过（无 _user_id、无 remember cookie）→ 正常放行；
    #   ② 由 remember cookie 重新认证而来 → 强制走一次完整登录，
    #      让用户在登录表单里重新证明身份，而不是静默继承新纪元。
    @app.before_request
    def _enforce_session_epoch():
        from flask import session
        from flask_login import current_user, logout_user
        try:
            if not current_user.is_authenticated:
                return None
            current = session.get("_epoch")
            if current is None:
                has_remember = "remember_token" in request.cookies
                if has_remember:
                    app.logger.info(
                        "remember cookie 重新认证未携带会话纪元，强制重新登录"
                        "（user_id=%s）", getattr(current_user, "id", None))
                    session.clear()
                    logout_user()
                    return redirect(url_for("auth.login", expired=1))
                session["_epoch"] = getattr(current_user, "session_epoch", 0)
                return None
            if int(current) != int(getattr(current_user, "session_epoch", 0) or 0):
                session.clear()
                logout_user()
                return redirect(url_for("auth.login", expired=1))
        except Exception:  # noqa: BLE001
            # 纪元无法判定时不放行：避免用故障绕过"改密踢下线"
            app.logger.exception("会话纪元校验异常，按失效处理")
            session.clear()
            logout_user()
            return redirect(url_for("auth.login", expired=1))
        return None

    # 空闲会话自动锁定（借鉴 Psono autolock）：SESSION_IDLE_MINUTES>0 时，
    # 认证会话连续空闲超过阈值强制重新登录。默认 0=关闭（行为与 v0.1.0
    # 完全一致）；静态资源不计入空闲计时，避免页面资源加载"续命"。
    # v0.1.0 修复 S-08：异常时按"已过期"处理（fail-closed）。
    @app.before_request
    def _enforce_session_idle():
        import time as _time

        from flask import current_app, session
        from flask_login import current_user, logout_user
        try:
            minutes = int(current_app.config.get("SESSION_IDLE_MINUTES") or 0)
            if minutes <= 0 or not current_user.is_authenticated:
                return None
            if request.endpoint == "static":
                return None
            now = _time.time()
            last = session.get("_idle_ts")
            if last is None:
                session["_idle_ts"] = now
                return None
            if now - float(last) > minutes * 60:
                session.clear()
                logout_user()
                return redirect(url_for("auth.login", expired=1))
            session["_idle_ts"] = now
        except Exception:  # noqa: BLE001
            # 空闲时间无法判定时不让会话无限续期，按过期处理
            app.logger.exception("空闲会话校验异常，按过期处理")
            session.clear()
            logout_user()
            return redirect(url_for("auth.login", expired=1))
        return None

    # 模板工具
    app.jinja_env.filters["localtime"] = localtime_filter
    app.jinja_env.filters["dateonly"] = date_only_filter
    app.jinja_env.globals["APP_VERSION"] = __version__
    app.jinja_env.globals["APP_NAME_CN"] = APP_NAME_CN
    app.jinja_env.globals["APP_NAME_ABBR"] = APP_NAME_ABBR

    def modify_query(**new_values):
        """在当前 URL 基础上替换查询参数（分页/筛选保留其余条件）。"""
        from urllib.parse import urlencode

        args = request.args.to_dict()
        args.update({k: v for k, v in new_values.items() if v is not None})
        return request.path + "?" + urlencode(args)

    app.jinja_env.globals["modify_query"] = modify_query

    # 健康检查（供负载均衡/监控探活）
    @app.route("/healthz")
    def healthz():
        from .db import get_db

        try:
            get_db().execute("SELECT 1")
            return jsonify(success=True, status="ok",
                           version=__version__)
        except Exception:  # noqa: BLE001
            return jsonify(success=False, status="db_error"), 503

    # 启动期迁移与清理（仅非测试环境自动执行）
    if not (app.config.get("TESTING") or os.getenv("PM_SKIP_AUTO_INIT")):
        try:
            _register_startup_tasks(app)
        except Exception:  # noqa: BLE001
            app.logger.exception("启动期数据库初始化失败，请检查配置后重试")
            raise

    return app
