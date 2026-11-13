# 密码管理系统 PasswordManageSystem (PDM)

[![CI](https://github.com/chinayury/PasswordManageSystem/actions/workflows/ci.yml/badge.svg)](https://github.com/chinayury/PasswordManageSystem/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

团队密码管理 Web 系统：密码记录加密存储、受控共享、两步验证、API 密钥集成、
全链路审计。本仓库为对外唯一稳定基线，版本演进与变更明细见 `CHANGELOG.md`。

> **⚠️ 部署前提：必须经 HTTPS 或仅本机访问。** 本系统处理明文口令，
> Web Crypto / 安全 Cookie / CSP 都依赖安全上下文。请二选一：
> ① 仅本机使用设 `HOST=localhost`；② 远程访问前置 nginx/Caddy 终结 TLS，
> 并设 `SESSION_COOKIE_SECURE=true` + `TRUST_PROXY=true`。
> 详见 [02-环境部署教程](docs/02-环境部署教程.md)。

> **诚实免责**：本项目是自研的自托管工具，**不可替代经过第三方专业审计的
> 商用口令管理器**。它能显著改善团队口令的存储与协作现状，但不承诺对抗
> 已被攻陷的终端或恶意管理员。能力边界逐条列于
> [04-安全设计说明](docs/04-安全设计说明.md)。

## 功能全景

| 模块 | 功能 |
|---|---|
| 认证 | 用户名密码登录、邮箱验证码注册/找回密码、记住我（7 天）、强制改密（管理员重置后）、**改密/找回成功后全设备踢下线**、空闲自动锁定（`SESSION_IDLE_MINUTES` 可选） |
| 两步验证（TOTP） | 自助开启/关闭（当前密码+动态码双重确认）、10 个一次性恢复码、10 分钟半登录状态有效期 |
| 密码记录 | 设备台账式 12 字段、Fernet 应用层加密、按需解密查看（限流 60 次/分钟）、搜索分页、"到期关注"快捷筛选（30 天内/已过期）、回收站（软删除/恢复/彻底删除）、双附件上传 |
| 密码生成器 | 随机字符（长度/字符集开关/排除易混淆字符）与易记口令短语（内置词表、词数/大写/附加数字可选）双模式，字符池保底 |
| 泄露即检 | 记录表单一键对照 HIBP 公开泄露库（k-匿名，仅发送 SHA-1 前 5 位，限流 10 次/分钟；默认随 `HIBP_ENABLED` 关闭） |
| 批量导入导出 | xlsx/CSV 导入（表头严格校验+标准模板）、**导入模板动态生成下载**、xlsx/CSV 导出（明文密码、含公式注入防护）、单次上限 5000 行/10MB |
| 项目分组 | 记录按项目归组（仅本人名下项目可选，IDOR 已封堵）、**项目重命名** |
| 受控共享 | 按用户共享（只读/可编辑）、可设过期、随时撤销；共享者不可变更项目归属 |
| 密码健康审计 | 服务端批量强度评分（内置弱口令词典/序列/用户名 token 扣分）、跨条目重复检测、口令年龄与到期分析、态势评分五项告警；HIBP k-匿名泄露查询可选（默认关闭）；报告页四页签 + Excel 导出（永不含密码列）；管理员可审计全库，普通用户仅本人 |
| API 密钥 | Bearer `pmk_xxx` 密钥（仅存 SHA-256 摘要）、REST API v1 记录增删改查、**API 明文查询限流**（reveal 按条数计 60 条/分钟/用户，单页明文上限 20）、**来源 IP / CIDR 白名单**、启停管理 |
| 审计日志 | 登录成功/失败、查看密码、导出、共享、锁定、TOTP 动作等全量留痕（含 IP/UA）；管理员可按操作人筛选 |
| 管理端 | 成员管理（解锁/重置口令/禁用/注销匿名化）、安全态势页、系统控制台、SMTP 在线配置、备份/恢复 |
| 防爆破 | 三层：内存限流（IP 20/5min、用户名 10/5min）+ 单账户锁定（5 次锁 15 分钟）+ 用户名+IP 持久化锁定（10 次锁 15 分钟，重启不清零）；**锁定表行数硬上限 5 万 + 幽灵用户名内存预算**；找回/注册接口验证码爆破限流 |
| 安全响应头 | CSP / X-Frame-Options DENY / nosniff / Referrer-Policy；页面 no-store 防密码残留缓存 |
| 键盘快捷键 | `Alt+N` 新建、`Ctrl+F` 聚焦站内搜索、`/` 聚焦搜索框、`Alt+L` 口令轮换页、`Esc` 收起内联表单 |

## 技术栈

- **后端**：Python 3.11+ + Flask（分层架构：routes 表现层 → services 业务层 → db 数据层，security/utils 横切）
- **数据库**：SQLite（WAL 模式 + `synchronous=NORMAL`，幂等增量迁移，免单独装库）
- **加密**：cryptography（Fernet 对称加密记录密码与 TOTP 密钥）、bcrypt（登录口令与存量恢复码）、HMAC-SHA256（新版恢复码摘要）
- **表单/CSRF**：Flask-WTF + WTForms（全站 CSRF 保护，API 密钥接口豁免）
- **Excel**：openpyxl + defusedxml（XML 实体扩张防护，装后自动生效）
- **两步验证**：pyotp
- **WSGI 服务器**：waitress（Windows 友好）
- **配置**：python-dotenv（密钥缺失拒绝启动）
- **构建**：setuptools（`pyproject.toml`，标准 src 布局，包目录名 = 发行名 = `app`）
- **依赖纪律**：全周期**零新增第三方包**，全部依赖版本锁定于 `requirements.txt` 与 `pyproject.toml`

## 目录结构

```
PasswordManageSystem/
├── src/
│   └── app/                 # 业务源码（标准 src 布局，包目录名 = 发行名 = app）
│       ├── __init__.py      # 应用工厂（版本号、蓝图注册、错误处理、CLI、安全拦截器）
│       ├── __main__.py      # python -m app / password-manager 命令入口
│       ├── config.py        # 集中配置（容错读取、安全开关、启动前密钥校验）
│       ├── db.py            # SQLite 连接/建库/幂等迁移
│       ├── schema.sql       # 建表脚本
│       ├── extensions.py    # Flask-Login / CSRF
│       ├── paths.py         # 可写数据目录解析（源码/打包双形态）
│       ├── models/          # 用户模型
│       ├── routes/          # 表现层蓝图：auth/records/projects/shares/
│       │                    #   account/apikeys/health/admin/api
│       ├── services/        # 业务层：auth/totp/records/projects/shares/
│       │                    #   excelio/apikeys/audit/backup/crypto/
│       │                    #   mailer/mail_settings/settings/health/
│       │                    #   hibp/password_strength/onetime/wordlist
│       ├── security/        # 横切：headers(安全响应头)/permissions/ratelimit
│       ├── utils/           # validators/timefmt
│       ├── templates/       # Jinja2 模板
│       └── static/          # CSS + JS（含 pages/ 各页脚本与全局快捷键）
├── docs/                   # 项目文档（01~05 五篇）
├── .github/workflows/       # CI（构建+冒烟）与 Release（GHCR+发布+清理）
├── Dockerfile              # python:3.11-slim + gosu 降权运行
├── docker-compose.yml      # 镜像 password-manager:<version>，数据落 ./data
├── docker-entrypoint.sh    # 首启自动生成密钥并持久化
├── deploy.sh / deploy.bat  # 一键部署脚本
├── wsgi.py / run.py        # 生产(waitress)/开发启动入口
├── pyproject.toml          # 构建配置（发行名 app、入口点 password-manager）
├── requirements.txt        # 版本锁定依赖
├── .env.example            # 环境变量模板（无真实密钥）
├── .dockerignore           # Docker 构建上下文瘦身
├── LICENSE                 # AGPL-3.0-or-later
├── package_release.py      # 交付打包脚本（敏感文件双排除自检）
├── CHANGELOG.md            # 变更记录（只追加，不改历史）
└── README.md
```

## 快速开始

### Docker（推荐）

```bash
./deploy.sh        # Linux/macOS；Windows 用 deploy.bat
# 或手动
docker compose up -d --build
```

浏览器打开 `http://服务器IP:6084`，初始账号 `admin / admin123`
（登录后系统持续警示直至修改口令）。详细部署、升级与备份说明见
[02-环境部署教程](docs/02-环境部署教程.md)。

### 本地开发

```bash
pip install -r requirements.txt
python wsgi.py        # 生产入口（waitress，默认监听所有网卡的 8000 端口）
# 或 python run.py   # 开发入口（默认仅本机回环地址的 5000 端口）
```

`wsgi.py` / `run.py` 内置 src 路径注入，装依赖后可直接运行。若需模块入口或命令行入口，
先安装本包再使用：

```bash
pip install -e .
python -m app        # 模块入口（等价 wsgi.py 的 waitress 模式）
# 或 password-manager  # 命令行入口
```

首次启动在项目根目录自动生成 `.env`（含 `SECRET_KEY`/`ENCRYPTION_KEY`）。
**`ENCRYPTION_KEY` 一旦投入使用切勿更换/丢失**，否则已存密码永久无法解密。

## 文档索引

| 文档 | 内容 |
|---|---|
| [01-项目介绍与架构](docs/01-项目介绍与架构.md) | 项目概述、设计原则、模块结构、分层原则、技术选型 |
| [02-环境部署教程](docs/02-环境部署教程.md) | 环境要求、Docker/源码安装、目录与配置、启动方式、常见问题 |
| [03-功能使用说明](docs/03-功能使用说明.md) | 各功能入口用法、参数说明、已知限制 |
| [04-安全设计说明](docs/04-安全设计说明.md) | 安全架构、鉴权、输入校验、凭据管理、路径防护、降级策略 |
| [05-开发日志](docs/05-开发日志.md) | 缺陷修复（现象→根因→解决方案）、功能新增、架构改进 |

其他：`CHANGELOG.md`（版本变更记录，只追加不改历史）。

## 安全要点（速览）

- 密码记录、TOTP 密钥均为 Fernet 应用层加密；口令 bcrypt 哈希；API 密钥仅存 SHA-256 摘要
- **默认管理员首次登录强制改密**（`admin / admin123` 登录后持续警示直至修改，安全态势页标红告警）
- **两步验证已开启时禁止重新生成密钥**（杜绝一次点击静默关闭 2FA）
- **XFF 仅取末段**：`TRUST_PROXY=true` 时客户端 IP 取 `X-Forwarded-For` 最后一段，防伪造绕过限流
- **临时口令/API 密钥明文不经 session cookie**：进程内一次性机密仓（`src/app/services/onetime.py`）随机不透明 token 换取，阅后即焚
- 密钥缺失拒绝启动；调试模式严禁对外
- 对外暴露务必置于反向代理 + HTTPS 之后：设 `SESSION_COOKIE_SECURE=true`，
  且仅此时才设 `TRUST_PROXY=true`
- 密码健康审计：明文只在服务端内存中存活（用后即弃），快照/日志/导出
  只含评分与状态等派生量；HIBP 泄露查询默认关闭（开启也仅外发 SHA-1
  前 5 位，k-匿名协议）
- `./data/.secrets.env`（Docker 部署的密钥文件）必须单独备份

## 许可证

本项目采用 **GNU Affero General Public License v3.0 or later（AGPL-3.0-or-later）**，
完整条款见 [LICENSE](LICENSE)。

作为网络服务向他人提供时，AGPL 要求向使用者提供对应源码；修改后分发或对外提供
服务，须同样以 AGPL-3.0 开放源代码。
