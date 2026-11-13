"""数据层：SQLite 连接管理、建库、增量迁移。

设计要点：
- 每个应用上下文一条连接（Flask g），请求结束自动关闭；
- 打开 WAL 与 busy_timeout，提升多线程/多请求下的并发稳定性；
- 建表脚本幂等（IF NOT EXISTS），存量旧库通过 run_migrations 增量补列，
  绝不 DROP、绝不破坏既有数据。
"""
import logging
import os
import sqlite3

from flask import current_app, g

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1  # v0.1.0 结构基线

# 旧库迁移：表 -> 需要补齐的列定义（列已存在则自动跳过）
_COLUMN_MIGRATIONS = {
    "users": {
        "is_active": "INTEGER DEFAULT 1",
        "failed_attempts": "INTEGER DEFAULT 0",
        "locked_until": "VARCHAR(30)",
        # v2.2 用户管理增强 (借鉴用户中心设计文档):
        #  口令历史 (JSON 数组, 存最近 N 个 bcrypt 哈希, 防重复使用)
        "password_history": "TEXT NOT NULL DEFAULT '[]'",
        #  管理员重置/新建后的强制改密标记
        "must_change_password": "INTEGER NOT NULL DEFAULT 0",
        # v2.3 TOTP 两步验证（secret 为 Fernet 密文；恢复码为 bcrypt 哈希 JSON）
        "totp_secret": "TEXT",
        "totp_enabled": "INTEGER NOT NULL DEFAULT 0",
        "recovery_codes": "TEXT",
        # v0.1.0 会话纪元（改密/重置踢下线，见 services.auth.revoke_user_sessions）
        "session_epoch": "INTEGER NOT NULL DEFAULT 0",
    },
    "passwords": {
        "deleted_at": "VARCHAR(30)",
        "updated_at": "VARCHAR(30)",
        # P4 密码健康审计：口令变更时间与到期时间（Passbolt v4.5.0
        # AddExpiredDateFieldToResources 的思路，列定义自拟）
        "password_changed_at": "VARCHAR(30)",
        "expires_at": "VARCHAR(30)",
    },
    # v0.1.0 第六轮（借鉴 GB-30 · eusonlito/Password-Manager）：
    # API 密钥可绑定来源 IP / CIDR 白名单，把长期 bearer token 的
    # 泄露影响面压回内网。空值 = 不限制（与旧行为一致）。
    "api_keys": {
        "allowed_ips": "TEXT NOT NULL DEFAULT ''",
    },
}


def get_db() -> sqlite3.Connection:
    """获取当前应用上下文的数据库连接（懒加载，单例）。"""
    if "db" not in g:
        conn = sqlite3.connect(
            current_app.config["DATABASE"],
            check_same_thread=False,
            timeout=10,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute("PRAGMA journal_mode = WAL")
        # WAL 模式标配 synchronous=NORMAL：事务提交不再逐次 fsync WAL，
        # 吞吐显著提升；断电最多丢最后一次提交，数据库不会损坏
        conn.execute("PRAGMA synchronous = NORMAL")
        g.db = conn
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        try:
            conn.close()
        except sqlite3.Error:  # noqa: BLE001 关闭失败不应掩盖原始异常
            logger.debug("关闭数据库连接时出现非致命错误", exc_info=True)


def release_app_connections() -> int:
    """释放当前应用上下文持有的数据库连接。

    用于"恢复数据库"这类需要替换数据库文件的场景：Windows 上目标文件
    被本进程打开时 os.replace 必然失败（v0.1.0 修复 B-02）。恢复请求本身
    跑在某个应用上下文里，该上下文的 g.db 就是持锁者；跨请求的连接由
    teardown 负责（见 init_app，此前未注册导致连接泄漏，是 B-02 的根因）。
    返回释放的连接数（0 或 1）。
    """
    from flask import has_app_context

    if not has_app_context():
        return 0
    conn = g.pop("db", None)
    if conn is None:
        return 0
    try:
        conn.close()
        return 1
    except sqlite3.Error:  # noqa: BLE001 关闭失败不应阻断恢复流程
        logger.debug("释放数据库连接时出现非致命错误", exc_info=True)
        return 0


def init_app(app) -> None:
    """注册到 Flask 应用（teardown 钩子）。

    v0.1.0 修复 Q-01：此前该方法从未被工厂调用，close_db teardown
    实际未注册，导致每个应用上下文退出时连接不关闭（Windows 上表现为
    数据库文件长期被占用）。现由 create_app 统一调用。
    """
    app.teardown_appcontext(close_db)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def _columns(conn: sqlite3.Connection, table: str):
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def init_db(app) -> None:
    """建库 + 增量迁移 + 初始管理员。可在应用上下文外调用。

    执行顺序（关键）：建表 -> 旧库补列迁移 -> 建索引。
    索引必须最后执行：旧库缺失的新列（如 deleted_at）需先由迁移补齐，
    否则 idx_passwords_deleted_at 之类的索引会因列不存在而失败。
    """
    import bcrypt

    with app.app_context():
        conn = get_db()
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, "r", encoding="utf-8") as f:
            script = f.read()

        marker = "-- 索引"
        table_part, _, index_part = script.partition(marker)

        # v0.1.0 第六轮（借鉴 GB-38 · CipherMoth）：给库打 application_id
        # 魔数（SQLite 标准 32 位应用标识，0x50444D31 = "PDM1"），
        # 误把别处拷来的 SQLite 文件当本系统库打开时可被快速识别。
        conn.execute("PRAGMA application_id = 0x50444D31")

        # 1) 建表（幂等）
        conn.executescript(table_part)
        # 2) 旧库增量迁移（补列/密钥摘要化）
        run_migrations(conn)
        # 3) 建索引（幂等）
        conn.executescript(index_part)

        # 首次使用且无任何真实用户时（id=0 为内置 system 账户，不算），
        # 创建默认管理员（admin / admin123）。
        # v0.1.0 修复 S-03：同时置 must_change_password=1，首次登录即被
        # 强制引导到改密页（服务端拦截，无法跳过），而不是仅靠横幅警示。
        has_user = conn.execute(
            "SELECT 1 FROM users WHERE id > 0 LIMIT 1").fetchone()
        if not has_user:
            hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8")
            conn.execute(
                "INSERT INTO users (username, email, password, is_admin,"
                " email_verified, is_active, must_change_password)"
                " VALUES ('admin', 'admin@example.com', ?, 1, 1, 1, 1)",
                (hashed,),
            )
            conn.commit()
            logger.warning(
                "已创建默认管理员 admin（初始密码 admin123，首次登录将强制修改，"
                "请尽快登录并设置私有口令）")


def run_migrations(conn: sqlite3.Connection) -> None:
    """对存量库执行幂等增量迁移（补列/补表/记录版本）。"""
    changed = False
    for table, columns in _COLUMN_MIGRATIONS.items():
        if not _table_exists(conn, table):
            continue  # 全新建库走 schema.sql，已包含全部列
        existing = _columns(conn, table)
        for col, ddl in columns.items():
            if col not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
                logger.info("迁移：为表 %s 补充列 %s", table, col)
                changed = True

    # 旧版 api_keys 表可能已存在且含明文密钥：迁移为摘要存储
    if _table_exists(conn, "api_keys"):
        import hashlib

        rows = conn.execute(
            "SELECT id, api_key FROM api_keys WHERE api_key NOT LIKE 'sha256:%'"
        ).fetchall()
        for row in rows:
            digest = "sha256:" + hashlib.sha256(row["api_key"].encode()).hexdigest()
            try:
                conn.execute(
                    "UPDATE api_keys SET api_key=? WHERE id=?", (digest, row["id"])
                )
                changed = True
            except sqlite3.IntegrityError:
                # 摘要重复（同一密钥存在多行）说明旧行冗余，直接删除旧行
                conn.execute("DELETE FROM api_keys WHERE id=?", (row["id"],))
                changed = True
        if rows:
            logger.info("迁移：%d 个存量 API 密钥已转换为摘要存储", len(rows))

    # P4 健康审计：存量库补列后回填 password_changed_at = updated_at
    # （无法追溯真实变更时刻，年龄分析按最后编辑时间估算）
    if _table_exists(conn, "passwords") and "password_changed_at" in _columns(
            conn, "passwords"):
        cur = conn.execute(
            "UPDATE passwords SET password_changed_at=updated_at"
            " WHERE password_changed_at IS NULL AND updated_at IS NOT NULL")
        if cur.rowcount:
            logger.info("迁移：%d 条存量记录口令变更时间回填为最后编辑时间（估算）",
                        cur.rowcount)
            changed = True

    conn.execute(
        "INSERT OR REPLACE INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,)
    )
    # 内置系统账户（id=0，禁用状态、随机口令哈希不可登录）：
    # 承接"登录失败"等无明确操作者的审计日志，满足外键约束。
    # 必须在列迁移之后执行：旧库 users 表起初没有 is_active 列。
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, email, password, is_admin,"
        " email_verified, is_active)"
        " VALUES (0, 'system', 'system@localhost.invalid', ?, 0, 0, 0)",
        (bcrypt_sys_password(),),
    )
    conn.commit()
    if changed:
        logger.info("数据库增量迁移完成，当前结构版本: %d", SCHEMA_VERSION)


def bcrypt_sys_password() -> str:
    """system 账户的口令哈希：真实 bcrypt 格式但对应随机口令，无法被登录。"""
    import bcrypt
    import secrets

    return bcrypt.hashpw(secrets.token_bytes(24), bcrypt.gensalt()).decode()

