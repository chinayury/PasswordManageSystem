-- 密码管理系统 v0.1.0 数据库结构（SQLite）
-- 特性：幂等（IF NOT EXISTS，可重复执行），不包含任何 DROP 语句，
--       与存量旧版数据库完全兼容（旧库启动时自动增量迁移补齐新列）。
-- 时间约定：所有时间戳统一使用 UTC（SQLite CURRENT_TIMESTAMP 即 UTC，
--       应用写入时也统一写 UTC 字符串，格式 '%Y-%m-%d %H:%M:%S'）。

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_admin INTEGER DEFAULT 0,
    email_verified INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,          -- 账户可用状态（禁用=0，禁止登录）
    failed_attempts INTEGER DEFAULT 0,    -- 连续登录失败次数（用于锁定）
    locked_until VARCHAR(30),             -- 账户锁定截止时间（UTC）
    password_history TEXT NOT NULL DEFAULT '[]',  -- 最近口令哈希JSON(v2.2 防重复)
    must_change_password INTEGER NOT NULL DEFAULT 0, -- 管理员重置后强制改密(v2.2)
    -- v2.3 TOTP 两步验证：secret 用应用层 Fernet 加密存储；恢复码存 bcrypt 哈希 JSON
    totp_secret TEXT,                     -- TOTP 密钥（Fernet 密文，NULL=未设置）
    totp_enabled INTEGER NOT NULL DEFAULT 0, -- 两步验证开关（1=登录需二次验证）
    totp_last_step INTEGER,               -- 当前密钥已使用的最大 TOTP 时间步
    recovery_codes TEXT,                  -- 恢复码 bcrypt 哈希 JSON 数组（用过即删）
    -- v0.1.0 会话纪元：改密/重置/注销时 +1，用于把该用户既有登录态
    -- （含"记住我"）全部踢下线，替代原先"改密不清场"的缺陷（S-11）
    session_epoch INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 项目表（先于 passwords 创建：被其外键引用）
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('集成项目','运维项目','日常办公','其它')),
    owner_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users (id)
);

-- 密码记录表
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INT NOT NULL,
    project_id INT NULL,
    device_model VARCHAR(100) NOT NULL,
    serial_number VARCHAR(100),
    location VARCHAR(100),
    node_name VARCHAR(100),
    ip_address VARCHAR(50),
    username VARCHAR(100),
    password TEXT,
    port VARCHAR(20),
    access_method VARCHAR(50),
    remark1 TEXT,
    remark2 TEXT,
    file1_path VARCHAR(255),
    file2_path VARCHAR(255),
    deleted_at VARCHAR(30),               -- 软删除时间（回收站）；NULL=正常
    -- P4 密码健康审计：口令变更时间与到期时间（存量旧库由启动迁移补列并回填）
    password_changed_at VARCHAR(30),      -- 口令最后变更时间（UTC）；迁移回填=updated_at
    expires_at VARCHAR(30),               -- 口令到期时间（UTC）；NULL=未设置到期
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at VARCHAR(30),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE SET NULL
);

-- 共享记录表
CREATE TABLE IF NOT EXISTS shared_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id INT NOT NULL,
    owner_id INT NOT NULL,
    shared_with_id INT NOT NULL,
    can_edit INTEGER DEFAULT 0,
    expires_at VARCHAR(30) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (record_id) REFERENCES passwords (id),
    FOREIGN KEY (owner_id) REFERENCES users (id),
    FOREIGN KEY (shared_with_id) REFERENCES users (id)
);

-- 操作日志表
CREATE TABLE IF NOT EXISTS operation_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INT NOT NULL,
    operation_type VARCHAR(50) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id INT,
    details TEXT,
    ip_address VARCHAR(50),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- 邮箱验证码表
CREATE TABLE IF NOT EXISTS email_verification_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(100) NOT NULL,
    code VARCHAR(10) NOT NULL,
    purpose VARCHAR(50) NOT NULL,
    expires_at VARCHAR(30) NOT NULL,
    used INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 自定义字段表（预留，v0.1.0 暂未开放界面）
CREATE TABLE IF NOT EXISTS custom_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INT NOT NULL,
    field_name VARCHAR(100) NOT NULL,
    field_type VARCHAR(20) NOT NULL,
    is_required INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- 自定义字段值表（预留，v0.1.0 暂未开放界面）
CREATE TABLE IF NOT EXISTS custom_field_values (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id INT NOT NULL,
    field_id INT NOT NULL,
    field_value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (record_id) REFERENCES passwords (id),
    FOREIGN KEY (field_id) REFERENCES custom_fields (id)
);

-- API 密钥表（v0.1.0：密钥只存 SHA-256 摘要，明文仅创建时展示一次）
-- v0.1.0 第六轮（借鉴 GB-30）：allowed_ips 为来源 IP / CIDR 白名单，
-- 逗号分隔；空字符串 = 不限制（与旧行为一致）
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INT NOT NULL,
    key_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(128) UNIQUE NOT NULL,
    is_active INTEGER DEFAULT 1,
    permissions TEXT,
    allowed_ips TEXT NOT NULL DEFAULT '',
    last_used VARCHAR(30),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- 登录防爆破锁定表（v2.3：同 用户名+IP 连续失败 10 次锁 15 分钟，持久化防重启失效）
CREATE TABLE IF NOT EXISTS login_lockouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL,
    ip VARCHAR(50) NOT NULL,
    failed_count INTEGER NOT NULL DEFAULT 0,  -- 连续失败次数（成功登录即清零）
    locked_until VARCHAR(30),                 -- 锁定截止时间（UTC），NULL=未锁定
    last_attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, ip)
);

-- 应用运行时设置表（键值对，如是否开放注册）
CREATE TABLE IF NOT EXISTS app_settings (
    key VARCHAR(50) PRIMARY KEY,
    value TEXT
);

-- 结构版本表（增量迁移依据）
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

-- P4 密码健康审计：审计轮次表（一次运行 = 一份只读快照）
-- status: running|done|partial|failed；同 scope 存在 running 时拒绝重复发起
CREATE TABLE IF NOT EXISTS password_health_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_type TEXT NOT NULL DEFAULT 'user',  -- user=单用户本人 | all=管理员全库
    scope_id INTEGER,                          -- scope_type='user' 时的用户 id；all 为 NULL
    status TEXT NOT NULL DEFAULT 'running',
    hibp_enabled INTEGER NOT NULL DEFAULT 0,   -- 本次运行是否启用 HIBP 查询
    hibp_available INTEGER,                    -- HIBP 是否成功（NULL=未启用）
    item_total INTEGER NOT NULL DEFAULT 0,     -- 参与分析条目数
    weak_count INTEGER NOT NULL DEFAULT 0,
    reused_count INTEGER NOT NULL DEFAULT 0,
    old_count INTEGER NOT NULL DEFAULT 0,
    hibp_count INTEGER NOT NULL DEFAULT 0,
    posture_score INTEGER,                     -- 0-100 态势评分
    thresholds_json TEXT,                      -- 本次运行的阈值快照（复现结果用）
    result_json TEXT,                          -- 结果聚合（均长/最大复用/告警清单），派生量无敏感数据
    error TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at VARCHAR(30),
    created_by INTEGER NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users (id)
);

-- P4 密码健康审计：发现明细快照表
-- category: weak|reused|old|hibp；UNIQUE(run_id,item_id,category) 幂等
-- details_json 只存派生量（reasons/复用次数/天数等），严禁存明文/哈希
CREATE TABLE IF NOT EXISTS password_health_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('weak','reused','old','hibp')),
    severity INTEGER NOT NULL DEFAULT 0,       -- 0 提示 / 1 建议修改 / 2 应尽快修改 / 3 必须修改
    score REAL NOT NULL DEFAULT 0,             -- 该条目最终评分（数值排序用）
    details_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(run_id, item_id, category),
    FOREIGN KEY (run_id) REFERENCES password_health_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES passwords (id) ON DELETE CASCADE
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON passwords(user_id);
CREATE INDEX IF NOT EXISTS idx_passwords_project_id ON passwords(project_id);
CREATE INDEX IF NOT EXISTS idx_passwords_device_model ON passwords(device_model);
CREATE INDEX IF NOT EXISTS idx_passwords_ip_address ON passwords(ip_address);
CREATE INDEX IF NOT EXISTS idx_passwords_deleted_at ON passwords(deleted_at);
CREATE INDEX IF NOT EXISTS idx_shared_records_shared_with ON shared_records(shared_with_id);
CREATE INDEX IF NOT EXISTS idx_operation_logs_user_id ON operation_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_operation_logs_created_at ON operation_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_email_codes_email ON email_verification_codes(email);
CREATE INDEX IF NOT EXISTS idx_custom_fields_user_id ON custom_fields(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_login_lockouts_username ON login_lockouts(username);
CREATE INDEX IF NOT EXISTS idx_health_runs_scope ON password_health_runs(scope_type, scope_id, status);
CREATE INDEX IF NOT EXISTS idx_health_findings_run ON password_health_findings(run_id);
