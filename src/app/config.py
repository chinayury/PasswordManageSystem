"""配置层：所有配置集中管理，禁止硬编码散落在业务代码中。

安全默认值原则：
- SECRET_KEY / ENCRYPTION_KEY 无安全默认值，缺失时直接拒绝启动（生产），
  避免旧版"随机回退密钥导致存量密文不可解"的隐患。
- Cookie 安全属性默认加固；SESSION_COOKIE_SECURE 部署 HTTPS 后应置 true。
"""
import os
import sys

from dotenv import load_dotenv

from .paths import BASE_DIR, LOG_FOLDER, ensure_runtime_dirs
from .version import __version__

# 兼容旧版 run.py 的首次生成 .env 行为：仅当文件完全不存在时生成一份
_ENV_FILE = os.path.join(BASE_DIR, ".env")
if not os.path.exists(_ENV_FILE):
    from cryptography.fernet import Fernet

    with open(_ENV_FILE, "w", encoding="utf-8") as f:
        f.write(f"SECRET_KEY={os.urandom(32).hex()}\n")
        f.write(f"ENCRYPTION_KEY={Fernet.generate_key().decode()}\n")

load_dotenv(_ENV_FILE)


def _bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: str, minimum=None, maximum=None) -> int:
    """容错读取整数配置（v0.1.0 修复 B-10）。

    旧实现直接 `int(os.getenv(...))`：运维在 .env 里写错一个字符
    （如 MAIL_PORT=465#备注、HEALTH_MAX_AGE_DAYS=365天）就会让
    ValueError 冒到 import 期，表现为「服务起不来且没有任何提示」。
    此处解析失败时告警并回退默认值，同时做上下限钳制。
    """
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return int(default)
    try:
        value = int(raw)
    except ValueError:
        sys.stderr.write(
            f"[配置告警] {name}={raw!r} 不是合法整数，已回退为默认值 {default}\n")
        return int(default)
    if minimum is not None and value < minimum:
        sys.stderr.write(
            f"[配置告警] {name}={value} 小于下限 {minimum}，已钳制为 {minimum}\n")
        value = minimum
    if maximum is not None and value > maximum:
        sys.stderr.write(
            f"[配置告警] {name}={value} 大于上限 {maximum}，已钳制为 {maximum}\n")
        value = maximum
    return value


def _float(name: str, default: str, minimum=None, maximum=None) -> float:
    """容错读取浮点配置（与 _int 同思路，v0.1.0 修复 B-10）。"""
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return float(default)
    try:
        value = float(raw)
    except ValueError:
        sys.stderr.write(
            f"[配置告警] {name}={raw!r} 不是合法数字，已回退为默认值 {default}\n")
        return float(default)
    if minimum is not None and value < minimum:
        value = float(minimum)
    if maximum is not None and value > maximum:
        value = float(maximum)
    return value


# v0.1.0 第六轮修复 BU-09：合法的 logging 级别名白名单
_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def _log_level_env(default: str = "INFO") -> str:
    """容错读取日志级别（与 _int/_float 同思路，v0.1.0 修复 B-09）。

    旧实现 `os.getenv("LOG_LEVEL", "INFO").upper()` 后直接交给
    `logging.setLevel`：运维在 .env 里写错一个级别名（verbose、DEBUG2、
    带上空格/备注）就会让 ValueError 冒到 create_app()，表现为
    「服务起不来且报错栈指向 logging 模块」。此处白名单校验，
    非法值告警并回退 INFO，大小写不敏感。
    """
    raw = (os.getenv("LOG_LEVEL") or "").strip()
    if not raw:
        return default
    level = raw.upper()
    if level not in _VALID_LOG_LEVELS:
        sys.stderr.write(
            f"[配置告警] LOG_LEVEL={raw!r} 不是合法日志级别"
            f"（可选 {'/'.join(_VALID_LOG_LEVELS)}），已回退为 {default}\n")
        return default
    return level


def serve_port_env(default: str = "8000") -> int:
    """WSGI 监听端口（v0.1.0 第六轮修复 BU-11）。

    入口脚本（run.py / wsgi.py）原先对 PORT 裸 int(os.getenv(...))，
    手滑写成 8000t 就在启动期崩溃且没有任何"哪个配置项错了"的提示。
    现统一收口到 config 层，与 _int 同样容错 + 上下限钳制。
    """
    return _int("PORT", default, minimum=1, maximum=65535)


def serve_threads_env(default: str = "8") -> int:
    """WSGI 工作线程数（BU-11 同上，收口到 config 层）。"""
    return _int("THREADS", default, minimum=1, maximum=256)


class BaseConfig:
    """所有环境共享的配置。"""

    VERSION = __version__  # 版本单一来源（app/version.py），禁止在此硬编码

    # --- 会话与安全 ---
    SECRET_KEY = os.getenv("SECRET_KEY", "")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE")
    # v0.1.0：是否信任反向代理传递的 X-Forwarded-For 头。
    # 默认不信任（防伪造 XFF 绕过 IP 维度限流/锁定）；仅在应用部署于
    # 可信反向代理（nginx 等）之后时置 true，此时客户端 IP 取 XFF 末段
    # （XFF 由每跳代理追加，末段才是代理观察到的真实对端地址）。
    TRUST_PROXY = _bool("TRUST_PROXY")
    # 空闲会话自动锁定（借鉴 Psono autolock）：0=关闭（默认，行为与
    # v0.1.0 完全一致）；>0 时认证会话连续空闲超过 N 分钟强制重新登录。
    # 静态资源请求不计入空闲计时；配置为负数按 0 处理。
    SESSION_IDLE_MINUTES = _int("SESSION_IDLE_MINUTES", "0", minimum=0)
    PERMANENT_SESSION_LIFETIME = 12 * 60 * 60  # 12 小时（秒）
    REMEMBER_COOKIE_DURATION = 7 * 24 * 60 * 60  # "记住我" 7 天
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 单次请求体上限 20MB

    # --- 数据 ---
    from .paths import DATABASE_PATH as DATABASE  # noqa: E402 依赖已在顶部加载
    UPLOAD_FOLDER = None  # 由子类/工厂注入（避免循环路径计算）
    ALLOWED_UPLOAD_EXTENSIONS = {
        "png", "jpg", "jpeg", "gif", "bmp", "tiff", "pdf", "txt", "docx", "xlsx",
    }

    # --- 加密 ---
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")

    # --- 邮件（未配置时验证码功能自动降级为明确报错，而不是崩溃） ---
    MAIL_SERVER = os.getenv("MAIL_SERVER", "").strip()
    MAIL_PORT = _int("MAIL_PORT", "465", minimum=1, maximum=65535)
    MAIL_USE_TLS = _bool("MAIL_USE_TLS", "true")
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "").strip()
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "") or MAIL_USERNAME

    # --- 业务开关 ---
    ALLOW_REGISTER = _bool("ALLOW_REGISTER", "true")  # 是否开放自注册
    RECORDS_PER_PAGE = 20
    LOGS_PER_PAGE = 50
    USERS_PER_PAGE = 50
    IMPORT_MAX_ROWS = _int("IMPORT_MAX_ROWS", "5000", minimum=1)
    IMPORT_MAX_FILE_MB = _int("IMPORT_MAX_FILE_MB", "10", minimum=1)
    BACKUP_MAX_KEEP = _int("BACKUP_MAX_KEEP", "10", minimum=1)

    # --- P4 密码健康审计 ---
    # HIBP k-匿名泄露查询（默认关闭：关闭时零外联，报告页隐藏泄露页签）。
    # 开启后仅发送口令 SHA-1 前 5 位（k-匿名协议），明文与完整摘要不出服务端。
    HIBP_ENABLED = _bool("HIBP_ENABLED")
    HIBP_RANGE_URL = os.getenv("HIBP_RANGE_URL",
                               "https://api.pwnedpasswords.com/range/")
    HIBP_TIMEOUT_S = max(1.0, _float("HIBP_TIMEOUT_S", "10"))
    HIBP_MIN_INTERVAL_MS = _int("HIBP_MIN_INTERVAL_MS", "100", minimum=0)
    # HIBP 服务要求 UA；照 KeePassXC 不带版本号，减小指纹
    HIBP_USER_AGENT = os.getenv("HIBP_USER_AGENT", "PasswordManageSystem")
    # 口令最大使用天数（健康审计"使用超龄"阈值）
    HEALTH_MAX_AGE_DAYS = _int("HEALTH_MAX_AGE_DAYS", "365", minimum=1)

    # --- 日志 ---
    LOG_FOLDER = LOG_FOLDER
    # v0.1.0 第六轮修复 BU-09：旧实现 .upper() 后直接交给 logging.setLevel，
    # .env 手写非标准级别名（LOG_LEVEL=verbose）会在 create_app() 里抛
    # ValueError: Unknown level，服务起不来且报错栈指向 logging 模块而非配置项。
    # 现纳入与 _int/_float 同一套"非法值告警 + 回退"机制。
    LOG_LEVEL = _log_level_env()


class DevConfig(BaseConfig):
    DEBUG = True


class ProdConfig(BaseConfig):
    DEBUG = False


class TestConfig(BaseConfig):
    TESTING = True
    # 测试环境允许显式注入密钥；WTF_CSRF 保留开启以覆盖 CSRF 用例，
    # 需要绕过时在用例中显式设置 WTF_CSRF_ENABLED=False
    DATABASE = os.path.join(BASE_DIR, "tests", "_instance", "test.db")


CONFIG_MAP = {"development": DevConfig, "production": ProdConfig, "testing": TestConfig}


def load_config():
    """按 APP_ENV 选择配置，并完成启动前安全检查。"""
    env = os.getenv("APP_ENV", "production").strip().lower()
    cfg_cls = CONFIG_MAP.get(env, ProdConfig)
    cfg = cfg_cls()

    ensure_runtime_dirs()

    # 密钥缺失是致命问题：宁可拒绝启动也不静默回退随机密钥
    # （旧版回退随机密钥会导致重启后所有存量密文无法解密）
    if not cfg.SECRET_KEY or not cfg.ENCRYPTION_KEY:
        sys.stderr.write(
            "[启动失败] 缺少 SECRET_KEY 或 ENCRYPTION_KEY。\n"
            "请在项目根目录 .env 中配置（可参考 .env.example），\n"
            "首次生成命令：python -c \"import os;from cryptography.fernet import "
            "Fernet;print(f'SECRET_KEY={os.urandom(32).hex()}');"
            f"print(f'ENCRYPTION_KEY={{Fernet.generate_key().decode()}}')\" > .env\"\n"
        )
        raise RuntimeError("SECRET_KEY/ENCRYPTION_KEY not configured")

    from cryptography.fernet import Fernet

    try:
        Fernet(cfg.ENCRYPTION_KEY.encode())
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"[启动失败] ENCRYPTION_KEY 不是合法的 Fernet 密钥: {exc}\n")
        raise RuntimeError("invalid ENCRYPTION_KEY") from exc

    return cfg
