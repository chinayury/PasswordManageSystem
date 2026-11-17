# Changelog

本文件记录 PasswordManageSystem 的显著变更（新增在前）。

## [2026-11-18] v0.2.3 · 安全依赖升级 + 加密层基线测试

### Changed（依赖升级 · 行为不变）

- **cryptography 44.0.1 → 50.0.2**（口令加密核心，Fernet API 稳定，
  升级后加解密往返与库内密文兼容——Fernet 令牌格式未变，存量密文
  无需迁移）
- pyotp 2.9.0 → 2.12.0（TOTP 校验行为一致）
- Werkzeug 3.1.8 → 3.1.9、WTForms 3.2.2 → 3.3.2、python-dotenv 1.2.3 → 1.2.4
- 升级范围经使用面核查：cryptography 仅用 `cryptography.fernet`
  （Fernet/InvalidToken），pyotp 仅 TOTP 校验与 provisioning URI。

### Fixed（修复）

- `decrypt_or_none(None)` 此前抛 AttributeError（与 `_or_none` 语义
  不符）；现空值统一返回 None。生产路径唯一调用方已自带守卫，
  本修为防御性收敛，合法输入行为不变。

### Tests（新增）

- `tests/test_v023_crypto_baseline.py`（4 例）：Fernet 加解密往返与
  IV 随机性、非法 token fail-closed、生成器输出形态（密码/短语/数字码/
  API 密钥）、TOTP 校验与 provisioning URI——加密层此前无直接测试，
  本轮补齐作为依赖升级基线。

### 兼容性说明

- 全量测试 16 passed；无数据库结构变更；存量密文直接可用；
  CI 三平台矩阵 + Docker 构建为跨平台兼容背书。

## [2026-11-16] v0.2.2 · 回收站保留期周期化执行

### Changed（改进）

- **回收站保留期清理周期化（GB-56 补强）**：v0.2.1 的保留期清理仅在
  服务启动时执行一次，长期不重启的实例不会再次清理。现以 24 小时
  间隔的守护线程（`recycle-retention`）每日复用同一清理函数；周期任务
  异常只记日志、不拖垮服务；RECYCLE_RETENTION_DAYS 为 0（默认关闭）
  时线程空转、行为与关闭状态一致。
- 新增 `tests/test_v022_retention_loop.py`（1 例）：守护线程挂接与
  daemon 属性断言。

### 兼容性说明

- 不新增/删除依赖；无数据库结构变更；未配置 RECYCLE_RETENTION_DAYS 时
  行为与 v0.2.1 完全一致（线程空转）；TESTING 环境启动任务整体跳过，
  测试环境零后台线程。

## [2026-11-15] v0.2.1 · 会话重生成加固 + 回收站保留期（可选）

### Security（安全加固）

- **登录/登出会话重生成（借鉴 GB-55 · OWASP Session Management Cheat
  Sheet，登录时会话 ID 重生成定级 mandatory；Flask 签名 Cookie 会话的
  等价实现为 `session.clear()`，见 pallets/flask#1600 与 Flask-Session
  官方文档）**：`_establish_session` 建立登录会话前先清空整个 session，
  攻击者预置/残留的旧 Cookie 内容（半登录 pending_2fa、bootstrap 警示位
  等）不再带入已认证会话；密码直登与 2FA 二次校验两条路径均经由该入口，
  一处覆盖。登出时同样清空（OWASP 同源建议）。
- 登录校验与会话纪元机制不变；既有用户会话不受影响。

### Added（新增）

- **回收站保留期（借鉴 GB-56 · Bitwarden/Vaultwarden 回收站 30 天自动
  清理策略）**：新增 `RECYCLE_RETENTION_DAYS` 环境变量，N>0 时服务启动期
  自动彻底删除在回收站停留超过 N 天的记录（含附件文件）；**默认 0=关闭**
  （与历史行为逐字节一致），30 为对齐 Bitwarden 默认策略的推荐取值。
  `.env.example` 同步文档。
- 新增 `tests/test_v021_session_recycle.py`（4 例）：会话固定防护（旧
  会话内容不带入）、保留期关闭/超期清理/未超期保留/存活记录不受影响。

### 兼容性说明

- 不新增/删除依赖；无数据库结构变更；`RECYCLE_RETENTION_DAYS` 未配置时
  行为与 v0.2.0 完全一致；登录/登出仅多一次会话内容清空，正常用户无感。

## [2026-11-15] v0.2.0 · 用户名冲突防御 + 记录多关键词搜索

### Added（新增）

- **记录多关键词搜索（借鉴 GB-54 · Padloc）**：检索框支持空格分隔多个
  关键词，逐词匹配（任一搜索字段命中即算该词命中），词间取 AND——
  例如 `web 10.0.0` 可同时按型号与 IP 定位记录；单关键词行为不变
  （仅所选字段）。搜索框占位提示同步更新。
- 新增 `tests/test_v02_username_search.py`（5 例）：保留名拒绝、大小写
  变体查重（注册/管理员改名）、合法注册路径、多关键词与单关键词搜索、
  通配符字面量化。

### Security（安全加固）

- **用户名冲突防御（借鉴 GB-53 · TeamPass 3.2.4.3）**：TeamPass 该版本
  修复的"与内部账户同名的用户可被创建"风险面在本项目同样存在——注册
  查重原为精确匹配，admin 存在时仍可注册 Admin/ADMIN。现注册与管理员
  改名均按 lower(username) 归一查重，并新增保留名黑名单
  （admin/administrator/system/api/root）。CLI create-admin 仅做归一查重、
  不套黑名单（可信操作者入口，保留 admin 重建等恢复场景）。
- 登录仍为精确匹配（行为不变）；历史库中已存在的同名大小写变体不受
  影响，新入口不再产生新的变体。

### Fixed（修复）

- 记录搜索中 `%` 与 `_` 一律按字面量处理（SQL LIKE ESCAPE）：
  型号/序列号里常见的下划线此前会被当作单字符通配符，产生似是而非的
  检索结果。

### 兼容性说明

- 不新增/删除依赖；无数据库结构变更；单关键词搜索与登录行为保持
  逐字节兼容；多关键词为新能力，不影响既有查询。

## [2026-11-14] v0.1.1 · 健康探针挂接 + 版本单一来源收敛

### Added（新增）

- Dockerfile 内置 `HEALTHCHECK`（每 30s 请求容器内 `/healthz`；slim 镜像无
  curl/wget，改用标准库 urllib。借鉴 GB-51 · Vaultwarden `/alive` 官方镜像
  探针实践与 GB-52 · Passbolt healthcheck 容器实践，含"exec 形式不展开环境
  变量须用 shell 形式"的坑位规避）。
- `docs/02` 部署教程补「健康检查」说明（`docker compose ps` healthy 判定与
  `curl /healthz` 手动验证）。
- 新增 `tests/test_v011_healthz.py`（2 例）：/healthz 200/JSON/版本一致 +
  pyproject / config / 包入口三方版本一致性守护。

### Changed（改进）

- **版本声明收敛为两处**（pyproject.toml + `app/version.py`）：新增
  `app/version.py` 作为运行时单一来源；`config.py` 的 `VERSION` 改为导入
  （原为第三处硬编码，存在发布漏改的漂移风险）。
- `docker-compose.yml` 镜像 tag 由 `v0.1.0` 改为 `latest`（本地构建 tag
  不再钉版本号，随重建自然跟随当前版本）。
- `docs/01~05` 头部去掉钉死的版本号（改为更新日期）；`requirements.txt`
  注释同步去版本。
- `/healthz` 为既有实现（调研去重：Vaultwarden `/alive` 已有等价实现，
  本轮仅补容器层挂接与文档）。

### 兼容性说明

- 不新增/删除依赖；不改任何请求处理行为；compose 镜像 tag 变更只影响本地
  构建镜像名，`docker compose up -d --build` 重建即生效，数据卷不受影响。

## [2026-11-14] README 许可信息排版调整

- 将 README 底部章节调整为 `## 许可与信息`，按最终文本直接列出开发者、版权、
  官网、许可证与 SPDX 标识，并保留四项声明；移除表格与重复说明段落。

## [2026-11-13] 许可与信息完善（AGPL-3.0-or-later）

> 许可证保持 AGPL-3.0-or-later；本次补齐「许可与信息」元数据、SPDX 标识与
> 网络服务（SaaS/Web/API）源码提供义务说明。版本号仍为 v0.1.0。

### Changed（许可与信息）

- `LICENSE`：文件头新增「许可与信息」块（开发者、版权、官网、许可证、SPDX 标识）
  与四项声明；AGPL v3 官方正文保持不变。
- `README.md`：新增「许可与信息」表与完整声明，「许可证」章节补充官方链接。
- `pyproject.toml`：作者改为「智维ITMSKY」，新增 `[project.urls]`
  （Homepage / Developer Website）。
- 页面页脚（主界面及登录/注册/找回密码/两步验证页）新增
  「Copyright © 2026 智维ITMSKY · itmsky.com」。

## [2026-11-13] v0.1.0 交付整理（标准 src 布局 · 文档对齐 · 冗余清理）

> 版本号保持 v0.1.0 不变。本次为交付前的基线固化整理，无功能变更、无第三方依赖增减。
> 按通用整理指令将项目重组为「纯代码 + 文档」的初始版本（非 Git 仓库）。

### Changed（结构调整）

- **源码迁移为标准 src 布局**：业务包由根目录 `app/` 迁移至 `src/app/`，包目录名 =
  发行名 = `app`，与 `pyproject.toml` 的 `name` 一致；包内模块间相对导入无需改动。
- **新增 `pyproject.toml`**：声明发行名 `app`、版本 `0.1.0`、依赖（与
  `requirements.txt` 一致）、入口点 `password-manager = app.__main__:main`、
  `package-dir = { "" = "src" }` 与 `package-data`（模板/静态/schema.sql）。
- **新增 `src/app/__main__.py`**：支持 `python -m app` 与 `password-manager` 命令，
  默认 waitress，`FLASK_DEBUG=1` 走开发服务器。
- **`run.py` / `wsgi.py` 增加 src 路径注入**：源码布局未安装时也能直接定位 `app` 包。
- **`src/app/paths.py` 重写项目根定位**：由"向上两级"改为"向上查找项目根标记文件
  （pyproject.toml / run.py / wsgi.py）"，适配 src 布局且未来布局调整不受影响。
- **`Dockerfile` COPY 路径调整**：`COPY app ./app` → `COPY src/app ./app`，容器内
  包位置与 `wsgi.py` 的 `from app import` 保持一致。

### Removed（冗余清理）

- 删除 **`.env`**（含真实 SECRET_KEY/ENCRYPTION_KEY，敏感文件，绝不保留）。
- 删除 **`.gitignore`**（非 Git 仓库，无 Git 元数据）。
- 删除 **`pytest.ini`** 与 **`tests/`**（本初始版本按项目方要求不含测试）。
- 删除 **`docs-archive/`**（历史归档素材，按初始版本策略移除）。
- 删除 **`password_manager.spec`**（PyInstaller 构建配置，路径已随 src 布局失效，
  非运行必需）。
- 删除 `docs/` 下 7 份旧文档（交付验收清单/使用说明/功能说明/安全审查报告/
  故障排查/环境变量说明/部署文档），由新的五篇结构化文档取代。

### Added（文档）

- 重写 `docs/` 五篇：`01-项目介绍与架构` / `02-环境部署教程` / `03-功能使用说明` /
  `04-安全设计说明` / `05-开发日志`，路径、模块名、命令均与磁盘一致。
- 重写 `README.md`：目录结构反映 src 布局，文档索引与 `docs/` 五篇对齐。

## [2026-11-12] v0.1.0 第七轮（GitHub/Gitee 同类项目实抓检索 · 钴湾视觉重构 · 19 项修复加固 · 借鉴落地）

> 版本号保持 v0.1.0 不变（镜像 tag / APP_VERSION / README 一律不升号）。
> 本轮四件事：① **GitHub 与 Gitee 双渠道同类项目实抓检索**（24+13 组检索式、
> 16 个入围项目深析，产出 GB/GE 两套借鉴要点清单并逐项落地取舍）；
> ② 「Cobalt Bay 钴湾」视觉体系 **30 模板全量重写**（零功能变更、可回滚）；
> ③ 前后端全量审计后完成 **19 项修复与加固**（BU-01~BU-17 + FU-01 + FU-09，
> 含 2 项 HIGH）；④ 从同类项目借鉴的能力落地（GB-15/26/30/32/35~48、
> GE-02/09/11）。
> 无第三方依赖增减；数据库仅**新增一列**（`api_keys.allowed_ips`，
> 幂等迁移，空值与旧行为完全一致），存量库直接重启即可。

### Added（新增）

- **GitHub 同类项目实抓检索**（2026-11-12）：GitHub Search API v3 + raw 接口 +
  releases 页面实抓；两阶段筛选（24 组检索式 → 89 个去重候选 → 6 类淘汰 →
  **12 个入围**：TeamPass 1890★、Vaultwarden 70594★、Passbolt 6230★、
  AliasVault 3510★、Padloc 2941★、Passman 829★、Rowel 965★、
  eusonlito/Password-Manager 332★、marius-wieschollek/passwords 251★、
  Passwordcockpit 137★、CipherMoth 26★、PassManagerWeb 24★，均为当日实抓核验）。
  - `docs/_调研_GitHub同类项目检索-v0.1.0.md`：检索式留痕（G01~G24）、候选池
    全表与淘汰理由、12 份 README 实抓证据、深析结论。
  - 如实记录：GitHub Search API 对中文检索式返回 422；CipherMoth 两个源文件
    raw 抓取连续 Connection reset（未虚构其 CSP/限流具体内容）。
- **Gitee 同类项目实抓检索**（2026-11-12）：Gitee API v5 被 WAF 限流
  （HTTP 403），改经**真实浏览器渲染** `search.gitee.com` SPA 取得一手数据
  （上一轮 2026-11-10 该渠道完全不可用）；13 组检索式 → **4 个入围**
  （`huanyp/password-xl` 63★、`hal-wang/Lavcode` 8★、
  `user_9679501/passwordManager` 0★、`flybird1015/passwordmanager` 0★）。
  - `docs/_调研_Gitee同类项目检索-v0.1.0.md`：检索式留痕、候选池与淘汰理由、
    4 个入围项目深析、Gitee 生态结论（不存在同构成熟同类）。
- **同类项目可借鉴要点清单**（`docs/同类项目借鉴要点清单-v0.1.0.md`）：
  GB-01~GB-50（GitHub）+ GE-01~GE-10（Gitee），逐项标注来源项目、价值判断、
  技术栈适配性与**本轮处置**（本轮已落地 14 / 既有能力已覆盖 4 /
  暂缓路线图 24 / 不采纳 6），并给出 P0~P3 下一步路线图。
- **API 密钥来源 IP / CIDR 白名单**（借鉴 GB-30 · eusonlito/Password-Manager）：
  `api_keys.allowed_ips` 列 + `normalize_ip_list()` / `ip_allowed()` /
  `set_key_ip_list()` + `POST /api-keys/<id>/ip-list` + 页面行内编辑。
  支持 IPv4/IPv6/CIDR、反代带端口、IPv4-mapped IPv6；空值 = 不限制（旧行为不变）。
- **附件上传内容类型交叉校验**（借鉴 GB-32 · Passwordcockpit）：
  按扩展名核对浏览器声明 MIME + 文件头魔术字节校验 + 10MB 大小上限。
  旧实现只校验扩展名——把 ELF 改名 `.pdf` 即可绕过。
- **不安全绑定的启动告警**（借鉴 GB-37 · CipherMoth）：
  `app/__init__.py::_warn_on_unsafe_binding`，绑定 0.0.0.0/:: 且
  `SESSION_COOKIE_SECURE=false` 时打印醒目告警并给出两种修法。
- **SQLite `application_id` 魔数**（借鉴 GB-38 · CipherMoth）：
  `PRAGMA application_id = 0x50444D31`（"PDM1"），误把别处拷来的 SQLite
  当本系统库打开时可被快速识别。
- **全局键盘快捷键**（借鉴 GE-02 · password-xl）：
  `app/static/js/pages/shortcuts.js`，`Alt+N` 新建、`Ctrl+F` 聚焦站内搜索、
  `/` 聚焦搜索框、`Alt+L` 口令轮换页、`Esc` 收起内联表单；输入态自动让位，
  CSP 合规（document 级委托，无内联事件属性）。

### Changed（视觉体系全面重构 · 30 模板）

- **设计语言重制（"Cobalt Bay 钴湾"）**：由 "Teal Ledger 青墨账台"
  （墨色 L 形外壳 + 深青 #0d6e63 + 琥珀 #a45c1a + 暖纸底）重构为——
  1. **结构**：彻底移除左侧墨色侧栏，改为**白色双层顶栏**（`.appbar` 品牌栏
     + `.navstrip` 横向导航带），内容区获全宽；新增 `.appfoot` 页脚收束阅读动线。
  2. **配色**：主色深青 #0d6e63 → **钴蓝 #2f49c8**，强调色琥珀 #a45c1a →
     **珊瑚 #dd4f26**，背景暖纸 #f5f4ef → **冷白 #f4f6fb**；色相/明度/冷暖
     三者同时改变，一眼可辨。
  3. **排版**：页头由「眉标文字 + 主标题 + 副标题」改为
     **左侧 4px 钴蓝竖轨 + 实心眉标胶囊 + 大号主标题 + 副标题**；
     区块标题改为「图标徽章 + 文字 + 尾翼分隔线」三件套。
  4. **组件**：圆角 10/6 → **14/9**；卡片取消顶部色带，改为
     **淡钴头部 + 左侧 3px 钴蓝竖条**；表头改实心淡钴底 + 钴蓝字；
     新增 `.danger-card`（红竖条）/`.card--accent`（珊瑚竖条）区分高危区。
  5. **图标**：全部重绘为**双色调（duotone）**——1.7 描边线性构形 +
     一枚 16% 不透明度填充的实心形状，与上一版纯描边一眼可辨。
  6. **认证页**：由「左右分屏 + 墨色品牌区」改为
     **居中单卡 + 钴蓝渐变头带**，页面骨架完全不同。
- **全量重写**：30 个业务模板 + `base/style/icons` 全部重写；
  **零功能变更、零数据模型变更、可回滚**（换回上一版镜像即恢复）。
- **1:1 保留**：全部 **318 项 DOM 挂钩**（id 132 + name 118 + data-* 29 +
  aria-* 24 + role 15）与 38 个 `<form>`、约 35 组 JS 选择器触点原样保留；
  CSP `script-src 'self'` 合规（零内联 script/事件属性；唯一内联样式是
  `health/report.html` 的 `score-ring` `--pct`，已列入白名单并加测试锁定）。
- **文案刷新**：26 个页面的眉标统一为「英文模块码 · 中文页名」格式
  （如 `ASSET LEDGER · 资产台账`、`MEMBERS · 成员管理`），
  副标题与区块标题同步改写，语义不变。
- **文档同步**：README（徽章、HTTPS 警示、诚实免责、钴湾视觉描述、
  测试基线 301、文档索引）、DOCKER.md（HTTPS 警示 + NAS 章节 + 端口 6082）、
  `docs/使用说明-v0.1.0.md`（快捷键、NIST SP 800-63B、资源基线、
  IP 白名单用法）同步更新。

### Fixed（本轮 19 项修复）

#### 后端 17 项（BU-01~BU-17，对应 `docs/_审计_后端问题清单-v0.1.0-第2轮.md`）

- **BU-01**（HIGH）：Windows 跨卷场景下「恢复数据库」仍 100% 失败——
  `os.replace` 抛 WinError 17（%TEMP% 在 C:、库在 D:），而旧代码对非
  `PermissionError` 的 `OSError` 直接 `break` 放弃重试。改为：上传文件先
  暂存到**数据库同目录**的 `.restore_staged` 再 `os.replace`（同卷才有原子
  替换语义）；`errno`/`winerror` 均为 17 时转中文可操作提示；暂存文件失败
  必清理。**实测覆盖**：`test_bu01_winerror17_becomes_friendly_message`。
- **BU-02**（HIGH）：预恢复快照在 checkpoint **之前**拷贝，WAL 内已提交数据
  全部丢失（实测快照连表结构都没有）→ 恢复的安全网失效。改为：用 SQLite
  在线备份 API（`src.backup(dst)`，与 `create_backup` 一致）生成完整快照，
  从机制上保证完整；恢复成功后补一次即时 `prune_pre_restore_snapshots()`
  （原来只在进程启动时清理，单次运维窗口内多次恢复会持续占盘）。
  **实测覆盖**：`test_bu02_snapshot_actually_contains_committed_wal_data`。
- **BU-03**（MEDIUM）：`/api/v1/records?reveal=true` 限流按"请求次数"计，
  单请求 `per_page` 最大 100 → 每分钟最多 **6000 条**明文外泄，是注释宣称
  值（60 条）的 100 倍。改为：① 单页明文条数压到 **20**；② 按本次实际返回
  **条数**扣减额度；③ 单次 ≥50 条明文补一条审计告警。
- **BU-04**（MEDIUM）：登录计时侧信道——禁用/锁定/内置系统账户三个分支在
  bcrypt 之前就 return，与"用户不存在"（跑一次 dummy bcrypt）耗时差约
  **783 倍**，可稳定枚举"账户存在但被禁用/锁定"。改为：三个分支同样先跑
  `_dummy_password_check()` 再返回。**实测覆盖**：
  `test_bu04_timing_flattened`（修后耗时比 < 3 倍）。
- **BU-05**（MEDIUM）：`login_lockouts` 可被随机用户名撞库流量无限撑大
  （实测 300 次随机用户名失败 → 表行数 2→302；清理节流 1 小时且只删 24 小时
  前的行）。三道防线：① "用户不存在"的失败增设**内存预算**
  （同 IP 每 5 分钟只允许 50 个幽灵用户名落库，超出仅走内存限流）；
  ② 表**行数硬上限 5 万**，超出按 `last_attempt_at` 淘汰最旧行；
  ③ 清理节流 1 小时 → **5 分钟**，且行数超 2 万即无视节流强制执行。
- **BU-06**（MEDIUM）：健康审计 `running` 行无超时回收，进程崩溃/被 kill 后
  该 scope **永久**无法发起审计（实测预置 2020 年 running 行即锁死）。
  改为：`_has_active_run` 增加 `started_at > now - 60 分钟` 时效判定并把
  僵尸行顺手收敛为 `failed`；`_execute_run` 兜底除 `Exception` 外再覆盖
  `BaseException` 并用 `finally` 保证任何退出路径都不留僵尸行；启动任务新增
  `reap_stale_running_runs()`。
- **BU-07**（MEDIUM）："记住我"重新认证可绕过 session_epoch 踢下线——
  设备空闲超过会话 cookie 寿命（12h）而 remember cookie 仍有效（7 天）时，
  仅凭 remember cookie 即可重新入座并静默采纳最新纪元。改为：区分两种
  "无纪元"——从未登录过的正常放行；**由 remember cookie 重新认证而来的强制
  走一次完整登录**。
- **BU-08**（MEDIUM）：SMTP 已配置但发送失败时，验证码仍落库形成 10 分钟
  悬空记录（B-05 只修了"未配置"分支与 503 状态码）。改为**先发信、成功后
  再落库**，与 docstring 声称的行为一致；发信失败时库里不留任何记录。
- **BU-09**（LOW）：`LOG_LEVEL` 非法值仍会在启动期崩溃
  （`ValueError: Unknown level`，B-10 的容错未覆盖）。新增 `_log_level_env()`
  白名单 `{DEBUG, INFO, WARNING, ERROR, CRITICAL}`，非法值告警并回退 INFO。
- **BU-10**（LOW）：`db.py` 中 `init_app` 被重复定义，带 Q-01 修复注释的
  版本成死代码。删除重复定义，只保留一份。
- **BU-11**（LOW）：入口脚本对 `PORT`/`THREADS` 裸 `int()`，坏环境变量直接崩
  且无提示。改为统一走 `config.serve_port_env()` / `serve_threads_env()`
  （与 `_int` 同套"非法值告警 + 回退 + 上下限钳制"）。
- **BU-12**（LOW）：`rename_project` 审计日志归因到项目 owner 而非操作者
  （同文件 `delete_project` 用的是 operator_id，两处口径不一致）。改为
  `rename_project(project, name, operator_id)`，管理员代操作时明细注明
  "代 owner（id=X）操作"；缺省时回退 owner，兼容旧调用方。
- **BU-13**（LOW）：API 认证每次请求都写库（`last_used` UPDATE + commit），
  纯读请求也开启写事务，WAL 持续增长、并发写锁竞争。改为**节流写**
  （距上次更新不足 60 秒跳过写库）。
- **BU-14**（LOW）：`.env.example` 的 XFF 注释仍写"取首段"，与 S-05 修复后
  的实现（取末段）相反，按注释"修正"代码会重新引入 IP 伪造面。已改为
  "取**末段**"并说明理由。
- **BU-15**（LOW）：`Dockerfile` 的 `EXPOSE 8000` 与 compose 实际端口 6082
  不一致，端口文档漂移。统一为 6082。
- **BU-16**（LOW）：HIBP 前缀响应缓存无大小上限，大库 + 开启 HIBP 时内存
  可到 GB 级。加 **64MB 字节预算 + FIFO 淘汰**；单条超预算直接不缓存。
- **BU-17**（LOW）：共享记录时不校验目标账户是否可用，可共享给已禁用/已注销
  匿名化账户，形成幽灵共享关系。增加 `is_active` 校验并拒绝。

#### 前端 2 项 + 无障碍 5 项

- **FU-01**（HIGH）：注销用户二次确认完全失效——`app.js` 把整句
  `data-confirm-input` 文案同时当作 prompt 提示语和期望答案，输入 `DELETE`
  被静默拦截、照抄整句又被后端 `confirm != "DELETE"` 打回，UI 上注销功能
  不可用（测试直接 POST 绕过 JS 故未暴露）。拆为两个属性：
  `data-confirm-input` = 提示文案、`data-confirm-token` = 期望令牌
  （缺省 `DELETE`，与后端一致，向后兼容）。
- **FU-09**（LOW）：`records.py` 下载导入模板的失败兜底分支
  `url_for("records.import_records")` 指向不存在的端点（实际为
  `records.import_data`），模板生成失败时先抛 BuildError 变 500。已修正。
- **FU-04**：`totp_setup.html` 的 `label for` 指向 `<div>`（无效关联）、
  `textarea` 无 label、`#pw-mode` select 仅 `title` 无可访问名。已全部补齐。
- **FU-05**：`records/index.html`、`admin/logs.html` 用空
  `<label>&nbsp;</label>` 占位对齐，向读屏软件暴露无意义标签。改为
  `aria-hidden` 的 `.form-spacer`。
- **FU-06**：`#pw-mismatch` 字段错误未用 `aria-describedby` 关联输入框。
  register / change_password 两页已补。
- **FU-07**：`health/report.html` 的 `<div><dd>` 脱离 `<dl>`，不是合法的
  描述列表结构。改为 `dl > div > dd`。
- **FU-08**：`--muted-light #98a0ae` 在白底对比度约 2.9:1，低于 WCAG AA。
  加深到 `#6f7787`（约 4.7:1）。

### 借鉴落地（GB / GE）

- **GB-15**（PSONO）：`DOCKER.md` 与 `docs/使用说明-v0.1.0.md` 明确"备份必须
  包含 `/app/data` 整个卷（含 `.secrets.env`）"，否则只备份 `backups/`
  会得到一份解不开的库。
- **GB-26**（Nextcloud Passman）：`docs/使用说明-v0.1.0.md` 口令生成器章节
  补写 NIST SP 800-63B 依据、易记短语优先的理由、"不建议无理由定期轮换"的结论。
- **GB-35**（Vaultwarden）：README 与 DOCKER.md 顶部加 HTTPS/反代警示框；
  启动告警（见 Added）给出同款提示。
- **GB-36**（AliasVault）：`docs/使用说明-v0.1.0.md` 补"资源基线（实测）"，
  数字为本项目实测观察值并明确标注，**未照搬其它项目数值**。
- **GB-39**（Passwordcockpit）：`.env.example` 与使用说明的环境变量章节逐项
  对齐，补 `HOST` / `SESSION_COOKIE_SECURE` 的安全约束说明。
- **GB-40**（Padloc）：`docs/安全审查报告-v0.1.0.md` 新增"密钥与密文对象图"，
  用 ASCII 图标明派生与持有关系，非密码学评审者可读。
- **GB-42**（CipherMoth）：`tests/test_v010_round6.py` 对 50 个图标分支与
  30 个模板 CSP 做**全量对拍**，防重构期静默漂移。
- **GB-43**（CipherMoth）：`app/services/crypto.py` 固化"口令生成必须走
  secrets（CSPRNG）、严禁改用 random"的注释，并加随机源正常性测试。
- **GB-45 / GB-46 / GB-47 / GB-48 / GB-50**（Passbolt / CipherMoth /
  Passman / PassManagerWeb / TeamPass）：`docs/安全审查报告-v0.1.0.md`
  新增「威胁模型四分类」「能力边界（明确不承诺）」「明确不做的事项」
  三节；README 顶部加诚实免责与工程质量徽章。
- **GE-09**（password-xl）：`DOCKER.md` 补"群晖/NAS 部署"章节。

### Tests（真实执行）

- 新增 `tests/test_v010_round6.py`（33 例）：视觉重构断言（新外壳类名在位 /
  旧体系类名清零 / 钴蓝珊瑚冷白令牌 / 双色调图标 / 页头新结构 / 全 30 模板
  CSP 合规 / 50 图标分支全量对拍 / 318 项 DOM 挂钩在位 / 旧色值清零）+
  FU-01 注销闭环 + FU-09 模板下载 + 全页面 200 回归。
- 新增 `tests/test_v010_round6_bugs.py`（32 例）：BU-01~BU-17 + 两个审计
  观察项（LIKE 通配符转义、撞库热点按用户名聚合）的回归，多数为**实机复现
  级**断言（跨卷 WinError 17、WAL 快照完整性、时序侧信道拉平、锁定表淘汰、
  僵尸 running 行收敛、发送失败不留悬空验证码等）。
- 新增 `tests/test_v010_round6_borrow.py`（18 例）：GB-30 IP 白名单矩阵、
  GB-32 附件魔术字节（含"ELF 改名 .pdf 必须被拒"）、GB-37 告警、
  GB-38 application_id、GB-43 随机源纪律。
- 更新 `tests/render_smoke.py`：新增第 3 步「内联样式白名单核查」
  （唯一允许 `health/report.html` 的 `score-ring` `--pct`），防止重构期把
  "临时调样式"的内联写法带回来。
- 全量测试：`python -m pytest tests/ -q` **301 passed**
  （0 failed / 0 error；基线 218 + 33 + 32 + 18 = 301）。

### 回滚说明

- 本轮**无第三方依赖增减**；数据库仅新增 `api_keys.allowed_ips` 一列
  （`schema.sql` + `db.py` 幂等迁移双保险，空值与旧行为完全一致）。
- 视觉重构为纯模板/CSS/JS 层改动，换回上一版镜像即恢复；
  DOM 挂钩 1:1 保留，回滚不丢任何功能。
- 19 项修复均为行为收紧（拒绝更多非法输入、补上失效的安全网），
  不含破坏性数据格式变更；除 BU-01/BU-02 属于"恢复功能从不可用到可用"外，
  其余修复在合法使用路径下与旧版无差异。

## [2026-11-10] v0.1.0 第六轮·定版（项目重命名前端接线 · 配置容错 · 218 项回归）

> 版本号保持 v0.1.0 不变（镜像 tag / APP_VERSION / README 一律不升号）。
> 本轮两件事：① 把第五轮如实留痕为「后端就绪、页面入口未接线」的
> **F-02 项目重命名前端半边补齐**，重命名自此为前后端完整可用功能；
> ② 修复《BUG修复清单》附二中留痕的 **B-10 配置裸转换**（`.env`
> 手写非数字导致 import 期崩溃）。
> 无数据库结构变更、无新增第三方依赖；存量库直接重启即可。

### Fixed（本轮 2 项）
- **F-02**（MEDIUM）：项目重命名此前仅有后端路由与服务，页面无入口
  （第五轮已如实留痕「未接线」，用户只能直接向路由 POST）。本轮补齐
  前端半边：`app/templates/projects/list.html` 每行操作列新增
  「重命名」按钮 + 折叠内联表单（`hidden` 属性控制显隐，CSP 合规、
  零内联脚本）；新增 `app/static/js/pages/project-rename.js`
  （点击按钮展开并聚焦/全选输入框，再次点击或按 Esc 收起，展开时
  自动收起其它行的表单避免表格撑乱，`aria-expanded` 同步）；
  `app/static/css/style.css` 新增 `.rename-form` 样式。
  **用户操作路径**：项目分组页 → 每行「重命名」按钮 → 展开输入框 →
  保存（仅创建者或管理员可操作，同创建者下名称不可重复，记审计日志）。
- **B-10**（LOW，附二留痕项转正修复）：`app/config.py` 原以裸
  `int(os.getenv(...))`/`float(...)` 读取 8 项数值配置
  （`MAIL_PORT`/`SESSION_IDLE_MINUTES`/`HIBP_TIMEOUT_S`/
  `HIBP_MIN_INTERVAL_MS`/`HEALTH_MAX_AGE_DAYS`/`IMPORT_MAX_ROWS`/
  `IMPORT_MAX_FILE_MB`/`BACKUP_MAX_KEEP`），`.env` 手写非数字会在
  import 期直接崩溃、服务无法启动。新增 `_int()`/`_float()` 容错
  读取函数并统一替换全部 8 处：非法值打印 `[配置告警]` 并回退默认值，
  超出上下限自动钳制（如 `MAIL_PORT` 钳制在 1~65535、
  `IMPORT_MAX_ROWS`/`BACKUP_MAX_KEEP` 下限 1），不再让坏配置值
  拖垮启动。已实测：写入非数字值后服务正常启动并按默认值运行。

### Tests（真实执行）
- 新增回归用例 `tests/test_v010_round5.py`（14 个）：覆盖 B-01 口令
  字节上限、B-03 非 ASCII 验证码、B-04 导入模板下载、B-05 SMTP
  未配置 503、B-06 过期 fail-closed、B-10 配置容错、F-02 项目重命名
  （3 个用例，含创建者/非创建者权限分支）、S-01 TOTP 重复生成守卫、
  S-02 临时口令不入 cookie、S-05 XFF 取末段、S-10 系统账户保护、
  S-11 改密踢下线。
- 全量测试：`python -m pytest tests/ -q --basetemp=./.ptz`
  **218 passed**（0 failed / 0 error，耗时约 245 秒；基线 204 +
  新增 14；`--collect-only` 分文件计数合计复核：
  13+18+18+10+38+15+1+15+8+24+7+24+14+13=218）。
- 渲染冒烟 `.smoke_render.py` 复跑通过：关键页面 HTTP 200、
  零内联 script/style、DOM 挂钩完整（项目分组页新增的重命名
  按钮/表单为外部 JS + CSS 类，未引入内联）。

### 回滚说明
- 本轮无数据库结构变更、无新增依赖。F-02 为纯前端增量（模板按钮/
  表单 + 外部 JS + 一条 CSS 规则），回滚后页面入口消失、后端路由
  不受影响，无用户数据影响；B-10 仅改配置读取容错，合法配置值
  行为与旧版完全一致（回滚无差异）。

## [2026-11-10] v0.1.0 第五轮（GitHub 同类项目检索 · 视觉体系全面重构 · 18 项修复与加固）

> 版本号保持 v0.1.0 不变（镜像 tag / APP_VERSION / README 一律不升号）。
> 本轮三件事：① **真正连网完成 GitHub 同类项目检索**（上一轮 2026-11-08
> 受网络限制只能用公知知识，已在文档如实标注；本轮 Gitee 渠道全程检索
> 受限，同样如实声明，未虚构任何 Gitee 数据）；② 「Teal Ledger 青墨账台」
> 视觉体系 30 模板全量重写（零功能变更、可回滚）；③ 前后端全量审计
> （68 条问题）后完成 **18 项修复与加固**（15 项 BUG/边界 + 3 项高危
> 安全漏洞）及一批同批安全加固。
> 无数据库结构变更、无新增第三方依赖（本轮零新增包）；存量库直接
> 重启/换镜像即可。

### Added（新增）
- **GitHub 同类项目实抓检索**（2026-11-10）：GitHub REST API v3 +
  raw 接口 + Bitwarden Help Center 实抓；两阶段筛选（第 1 轮 20 个候选
  → 第 2/3 轮初筛 → 9 个入围深析：Vaultwarden 70,508★、Bitwarden
  Server 20,610★、Passbolt 6,227★、Padloc 2,940★、TeamPass 1,890★、
  Passwordcockpit 137★、Psono 113★、Keyper 115★、CipherMoth 26★，
  均为当日实抓核验）。产出：
  - `docs/同类项目借鉴要点清单-v0.1.0.md`：L01~L51 借鉴要点总清单，
    按「已落地 11 / 本轮落地 3 / 暂缓路线图 37」分级，逐项对照代码
    核实，宁少写不虚报；
  - `docs/_调研_同类项目原始资料-v0.1.0.md`：检索式留痕（G1~G10、
    C1~C10）、候选池全表与淘汰理由、README 实抓证据（底料）。
- **服务端一次性机密仓**（`app/services/onetime.py`）：新建 API 密钥
  明文与管理员重置的临时口令改经进程内一次性仓传递，session 只放
  随机不透明 token，阅后即焚（修复 S-02，详见 Security）。
- **导入模板动态生成下载**（`app/services/excelio.py`
  `build_import_template`）：按当前表头规范服务端即时生成 xlsx，
  杜绝旧版「下载一个不存在的静态文件」500（修复 B-04）。
- **项目重命名**（`/projects/<id>/rename`）：项目分组支持改名，
  同步写审计日志（修复 F-02）。
- **前后端全量审计留档**：`docs/_审计_后端问题清单-v0.1.0.md`
  （68 条：BUG 15 + 安全 24 + 代码质量 11 + 功能缺失 12，另含 9 个
  疑点实机复现记录）与 `docs/_审计_前端问题清单-v0.1.0.md`
  （30 模板结构地图 + 功能交互 1:1 保留清单 + 重构风险点）。

### Changed（视觉体系全面重构 · 30 模板）
- **设计语言重制（"Teal Ledger 青墨账台"）**：从 "Indigo Console"
  （左侧栏工作台、靛蓝主色）重构为——顶部通栏墨色顶栏 + 左侧墨色
  侧栏连成 L 形导航外壳；深青 #0d6e63 主色 + 琥珀强调色；暖纸底色；
  「眉标 + 主标题 + 副标题」三层页头；卡片顶部主色带；重绘线性
  图标集；仅浅色主题（无暗色模式）。
- **全量重写**：30 个业务模板 + `base/style/icons` 全部重写；
  **零功能变更、零数据模型变更、可回滚**（换回上一版镜像即恢复）。
- **1:1 保留**：全部 DOM 挂钩（ID/class）、Jinja 条件分支、
  `csrf_token` 隐藏域、`data-confirm` 危险确认属性原样保留；
  CSP `script-src 'self'` 合规（零内联 script/事件属性/内联 style）。
- **文档同步**：README（视觉体系描述、功能全景、目录结构增补
  `onetime.py`、测试基线 218、安全要点四项补充、文档索引）、
  DOCKER.md（XFF 取末段表述与代码对齐）同步更新。

### Fixed（本轮 18 项修复之 15 项 BUG/边界，B-01~B-15）
- **B-01**（HIGH）：bcrypt 72 字节上限 vs 128 字符口令策略——长中文
  口令直接 500。改为按 UTF-8 字节校验（≤72 字节）+ `_hash_password`
  统一捕获转友好提示，并修正注册失败误导文案。
- **B-02**（HIGH）：Windows 下「恢复数据库」必然失败（os.replace
  WinError 5，恢复功能 100% 不可用）。改为恢复前释放本进程连接 +
  递增退避重试（0.4/0.8/1.2/1.6s）。
- **B-03**：验证码校验遇非 ASCII 输入抛 TypeError 变 500。统一转
  UTF-8 字节后常数时间比较（`constant_time_equal`）。
- **B-04**：「下载导入模板」500，导入业务闭环断裂。改服务端动态
  生成（见 Added）。
- **B-05**：`send-code` 在 SMTP 未配置时 500 且验证码已落库。改为
  先发送后入库 + 503 服务不可用语义。
- **B-06**：`is_expired` 对无法解析的时间返回 False（失效开放）。
  改 fail-closed（视为已过期）。
- **B-07**：`parse_db_time` 切片逻辑脆弱——加固解析容错。
- **B-10**：配置项 `int()/float()` 在 import 期崩溃——加安全转换
  与兜底默认值。（2026-11-10 第六轮落地，见顶部第六轮条目。）

> **勘误（2026-11-10 第六轮补记）**：本条目的 B-08、B-09、B-11、B-12、
> B-13、B-14 六项，经逐行核验代码后确认**当时并未实际实施修复**，
> 此处原表述与最终代码不符，现予如实验明而非删除——审计发现、
> 现状代码位置与建议处置详见 `docs/BUG修复清单-v0.1.0.md` 附二。
> B-15 仅为进程内/文档层面的重申说明，非代码修复。

### Security（本轮 18 项修复之 3 项高危漏洞 + 同批加固）
- **S-01**（HIGH）：「生成密钥」会静默关闭已开启的两步验证——已
  开启 TOTP 时直接拒绝重新生成（`app/services/totp.py`
  `set_pending_secret`），并不再无条件执行 `totp_enabled=0`。
- **S-02**（HIGH）：明文 API 密钥与临时管理员口令存入客户端可读的
  session cookie（Flask session 只签名不加密）——改为一次性机密仓
  传递，token 阅后即焚（见 Added）。
- **S-03**（HIGH）：默认管理员 `admin / admin123` 无强制改密——
  建号即置 `must_change_password=1`，首次登录强制改密，安全态势
  页默认口令检测标红告警。
- 同批安全加固：**S-04** `/api/v1` 明文批量导出限流（reveal 60
  次/分钟/用户，与 Web 端同口径，429 + `rate_limited`）；**S-05**
  采信 XFF 时取**末段**而非首段（防伪造 IP 绕过限流/锁定）；
  **S-06** 登录影子账户（用户不存在也跑等价 bcrypt，消除响应时间
  侧信道用户名枚举）；**S-07** 强度评分缓存键改口令 SHA-256 摘要
  （明文口令不再驻留进程内存）；**S-08** 安全拦截器异常时
  fail-closed（拒绝放行/按已过期处理）；**S-09**
  `PERMANENT_SESSION_LIFETIME=12h` 真正生效（登录链路接入）；
  **S-11** 改密/邮箱找回成功后递增会话纪元，**全设备踢下线**；
  **F-01** 换库后释放本进程连接（恢复后请求重开新库）；
  **Q-01** 注册请求结束的数据库连接关闭钩子接入工厂。

### Tests（真实执行）
- 全量测试：`python -m pytest tests/ -q --basetemp=./.ptx`
  **218 passed**（0 failed / 0 error；`--collect-only` 分文件计数
  合计复核：13+18+18+10+38+15+1+15+8+24+7+24+14+13=218）。
- 渲染冒烟脚本 `.smoke_render.py`：30 个模板逐页 HTTP 200；零内联
  script/style；DOM 挂钩（ID/class）逐项核验通过。
- 渗透与实机复现：审计阶段 9 个疑点一次性复现脚本全部复现成功
  （记录于 `docs/_审计_后端问题清单-v0.1.0.md` 附录 A）；修复后
  按现象→根因→解决方案逐项回归。

### 回滚说明
- 本轮无数据库结构变更、无新增依赖；视觉为纯前端层（CSS/模板），
  回滚换回上一版镜像即可。测试中断言的界面文案已按新视觉同步更新。
- 借鉴清单与调研底料为纯文档，不影响运行；18 项修复中涉及加解密
  与哈希的项（B-01/B-03/S-07）均保持存量数据兼容，无需迁移。

## [2026-11-10] v0.1.0 第四轮（Teal Ledger 视觉重构 · 剩余 7 模板落地）

> 版本号保持 v0.1.0。本轮将「Teal Ledger 青墨账台」视觉体系补齐到
> 剩余 7 个业务模板（base/style/icons/index/auth 已在前序完成）。
> 无数据库结构变更、无新增依赖、无功能逻辑变更；纯前端视觉层，
> 回滚换回上一版镜像即可。

### Changed（模板重写 · 7 个）
- `records/add.html`（新增记录）：眉标 `Vault · 密码资产`；分区标题
  「设备标识 / Device Identity」「连接与凭据 / Connection」
  「备注与附件 / Notes」；密码生成器按新版 pg-head/check-grid 重组，
  模式切换保留 `#pw-mode` 下拉（JS 按 ID 挂钩，零改动）。
- `records/edit.html`（编辑记录）：同一套眉标与分区标题；`password_broken`
  警示改为 notice-warning；共享编辑徽章移入页头副标区；`#fetch-password-btn`
  保留于生成器头部。
- `records/import.html`（批量导入）：眉标 `Vault · 密码资产`；导入说明
  改 notice-info；「下载标准模板」上移页头工具条。
- `records/recycle_bin.html`（回收站）：眉标 `Vault · 回收站`；空态补
  图标；操作列统一 cell-actions + 图标按钮，`data-confirm` 原样保留。
- `account/security.html`（安全中心）：眉标 `Account · 安全中心`；
  卡片头右侧增加开启状态徽章；关闭/开启表单字段名 `current_password`、
  `code` 原样保留。
- `account/totp_setup.html`（TOTP 密钥）：眉标 `Account · 安全中心`；
  密钥改用 `.code-block` 展示，otpauth 链接收进 details；移除
  `onclick="this.select()"` 内联事件（CSP 合规）。
- `account/totp_recovery.html`（恢复码）：眉标 `Account · 安全中心`；
  恢复码清单改用 `.code-block` 分组展示。

### Preserved（功能挂钩 · 1:1）
- add/edit 全部 DOM 挂钩：#password #pw-mode #pw-random-opts #pw-phrase-opts
  #pw-length #pw-upper #pw-lower #pw-digits #pw-symbols #pw-no-similar
  #pw-words #pw-caps #pw-digit #generate-password-btn #leak-check-btn
  #toggle-password-visibility #pw-hint #fetch-password-btn #remark1 #remark2
  #remark1-preview #remark2-preview .password-generator .file-hint。
- Jinja 条件分支：`record.permission == 'owner'/'shared_edit'`、
  `record.password_broken`、`record.file1_path/file2_path`、
  `state.enabled/pending/recovery_left`、`import_max_rows/import_max_mb`
  等原样保留；表单均含 `csrf_token` 隐藏域；`data-confirm` /
  `data-confirm-input` 危险操作确认属性未动。
- CSP `script-src 'self'` 合规：7 个模板零内联 `<script>`、零内联
  事件属性、零内联 `style=""`；JS 仍走 `{% block scripts %}` 外部文件。

### Verified（真实执行）
- `python -m pytest tests/ -q --basetemp=./.pytest_tmp`：204 passed
  （0 failed / 0 error；另以 JUnit XML 复核 tests=204 failures=0）。
- 渲染冒烟脚本 `.smoke_render.py`：7 个页面全部 HTTP 200；无内联
  script/style；21 个 ID 挂钩 + 2 个 class 挂钩逐项核验通过；
  index 页 .btn-reveal/.btn-copy/.pw-mask/.remark-image 回归通过。

## [2026-11-08] v0.1.0 第三轮补充（全维度渗透复核 + 安全审查追加）

> 版本号保持 v0.1.0。无代码逻辑变更：本次为上一轮落地项的安全复核
> 与文档补全，含真实渗透实测。

### Verified（渗透复核，真实执行）
- 隔离本地实例（临时密钥 + SQLite，127.0.0.1:6086）执行 12 组 curl
  探针：未授权访问（302/401）、安全响应头（CSP self + frame-ancestors
  none + nosniff + Referrer-Policy）、SQL 注入（LIKE 字面匹配，他人记录
  零泄露）、XSS 反射（Jinja 转义后无原始 script 标签）、CSRF 缺失（400）、
  API 越权与密钥范围（仅本人）、IDOR（/edit/1、reveal → 302/404）、
  管理页越权（302）、爆破防护（连续错误登录第 5 次起触发用户名+IP
  「尝试过于频繁」锁定）、生成器与泄露即检边界参数（400/钳制）。
- 结论：本轮新增攻击面未引入新高危/中危漏洞；既有遗留风险（单进程
  限流）按既定评估接受。
- 安全审查报告追加第三轮章节（新攻击面逐项审计 + 渗透实测记录 + 基线）。

### Changed（文档对齐）
- README / 借鉴要点清单：测试基线 185 → 203。
- 新增 `docs/交付验收清单-v0.1.0.md`（规范 §7.2 七项逐项验收 + 版本
  锁定/安全核验/交付物清单）；《BUG 修复清单》追加第三轮 2 项
  （认证页 flash 渲染区丢失、空闲锁定钩子 current_app 未导入静默失效）。
- 《功能优化与新增-v0.1.0.md》《版本迭代说明-v0.1.0.md》《使用说明-v0.1.0.md》
  上一轮已追加的第三轮条目保持不变。

## [2026-11-08] v0.1.0 第三轮迭代（同类项目借鉴落地 + 全站视觉重构）

> 版本号保持 v0.1.0 不变（镜像 tag / APP_VERSION / README 一律不升号）。
> 本轮无数据库结构变更，无新增依赖；存量库直接换镜像/重启即可。

### Added（新增功能 · 借鉴清单落地项）
- **同类项目借鉴研究**：对 GitHub/Gitee 同类自托管团队密码管理项目完成
  两阶段筛选（相关性→成熟度→参考价值初筛 + 入围深析），产出
  `docs/同类项目借鉴要点清单-v0.1.0.md`（入围：Vaultwarden、Passbolt、
  Psono、Padloc、Teampass；淘汰理由与暂缓路线图见文档）。
- **密码生成器升级**（借鉴 Vaultwarden/Bitwarden 生成器）：
  `/generate-password` 支持 random / passphrase 双模式——random 模式
  可调长度（8-64）与大写/小写/数字/符号字符集开关、新增"排除易混淆
  字符"（iIlOo01|）；passphrase 模式内置 457 词表（约 8.8 bit/词），
  3-10 词 + 可选首字母大写/附加数字；所有被选字符池保证至少贡献一位
  （旧版无此保证）。前端生成区随模式切换选项组，生成结果即时提示。
- **单条口令泄露即检**（借鉴 Bitwarden 健康报告即检场景）：记录表单新增
  "泄露检查"，复用既有 HIBP k-匿名服务——仅发送口令 SHA-1 前 5 位，
  明文只存在于请求内存，绝不落库、绝不写日志；限流 10 次/分钟/用户；
  HIBP 未开启（默认）或查询失败时给出明确降级提示，不影响保存。
- **空闲会话自动锁定**（借鉴 Psono autolock）：新增 `SESSION_IDLE_MINUTES`
  配置（默认 0=关闭，行为与基线完全一致）；开启后认证会话连续空闲超过
  N 分钟强制重新登录并跳转带 expired=1 提示的登录页；静态资源不计入
  空闲计时；配置为负按 0 处理（.env.example 已补充说明）。
- **记录列表"到期关注"快捷筛选**（借鉴 Padloc 快捷筛选 Chips）：复用
  密码健康审计的 expires_at 字段语义，一键筛选"已过期或 30 天内到期"
  的记录；筛选条件与分页/搜索/项目筛选叠加保留。

### Changed（视觉重构 · 全站）
- **设计语言重制（"Indigo Console"）**：全部页面从"顶部按钮排 + 蓝色
  卡片"重构为"左侧栏工作台"布局——品牌区/分组导航（工作台/账户/管理）/
  用户卡底栏；移动端侧边栏自动折行为横向导航。
- **配色体系**：靛蓝主色（#4f46e5）+ 石板灰阶 + 柔和色调徽章/按钮
  （success/danger/warning/info 均 soft 底色 + 边框），仅浅色主题，
  无暗色模式与深色背景。
- **图标体系**：新增统一线性 SVG 图标库（`partials/icons.html`，1.8
  描边、currentColor），替换全部 emoji 图标（🔐/👤/📥 等 18 类）。
- **标题文案更新**：页面与导航更名并保持语义——密码主页→密码资产、
  安全审计→健康体检、项目管理→项目分组、共享给我→共享中心、
  操作日志→审计日志、API密钥→API 接入、用户管理→成员管理、
  安全概览→安全态势、系统设置→系统控制台、安全设置→安全中心。
- **认证页分栏重排**：登录/注册/找回/两步验证改为"品牌叙事侧栏 +
  表单卡"分栏布局，功能字段与校验逻辑不变。
- **组件重制**：按钮（填充/色调/幽灵三系 + 三尺寸）、徽章（圆点式）、
  表格（大写表头 + 行悬停）、表单（聚焦光环）、分页/空态/Toast/图片
  模态框/强度条全部重新设计；新增生成器选项与筛选 chip 样式。
- `docs/宣传截图/` 11 张截图全部按新视觉重制（浏览器实测截图）。

### Fixed（本轮修复）
- 认证页（登录/注册/找回/两步验证）重排为独立 body 块后丢失闪现消息
  （flash）渲染区——登录过期提示等不显示。已抽出 `partials/flash.html`
  公共片段，base 与四个认证页统一渲染（回归测试覆盖）。
- 空闲锁定钩子初版 `current_app` 未导入导致钩子静默失效（被 except
  吞掉）——自查发现并修复，配专项测试。

### Verified（测试验证）
- 新增 `tests/test_borrow.py` 18 个用例：生成器（no_similar 排除/字符池
  保底/全关回退/口令短语钳制与词表来源/端点新旧参数兼容）、泄露即检
  （关闭 503/命中与未命中/降级/校验与限流计数/未登录拦截）、空闲锁定
  （默认关闭/超时登出/活跃通过）、到期筛选（默认不过滤/仅含已过期与
  30 天内）。
- 全量测试：`python -m pytest tests/ --basetemp=.pytest-tmp`
  **203/203 通过**（基线 185 + 本轮 18）。
- 浏览器实测冒烟（隔离实例 + 演示数据）：登录/资产列表/按需解密揭示/
  生成器双模式/泄露检查降级/到期筛选/共享页/回收站/审计日志/系统控制台/
  成员管理/安全态势共 12 项交互与页面全部通过，11 张截图按新视觉重制。

### 回滚说明
- 本轮无数据库结构与依赖变更；视觉为纯前端层（CSS/模板），回滚换回
  上一版镜像即可。测试中断言的界面文案按新视觉同步更新（导航更名、
  空态文案、安全概览更名）。

本文件记录 PasswordManageSystem 的显著变更（新增在前）。

## [2026-10-28] v0.1.0 第二轮迭代（密码健康审计 P4 + 全量排查修复）

> 版本号保持 v0.1.0 不变（镜像 tag / APP_VERSION / README 一律不升号）。
> 本轮含数据库增量迁移：passwords 补 password_changed_at/expires_at 两列，
> 新增 password_health_runs / password_health_findings 两表——均为幂等
> 增量，存量库升级只需重建镜像重启。

### Added（新增功能）
- **密码健康审计（P4 安全审计）**：导航栏「安全审计」入口
  （/health）。管理员可发起全库审计（scope=all，结果仅管理员可见），
  普通用户可发起并查看本人范围审计。服务端批量内存解密后分析：
  - 零依赖强度评分（app/services/password_strength.py）：对数熵基准
    （字符池 26+26+10+34+CJK 补 40）+ 规则扣分（纯数字 -20、字母/
    数字/键盘序列段每段 -10、同字符连打 -10、年份 -10、包含用户名
    token -25、内置约 500 条常见弱口令词典直接 Bad）；等级五档照
    KeePassXC quality() 分界（≤0 Bad / <40 Poor / <75 Weak / <100 Good
    / ≥100 Excellent），报告只列 <Good；复用每多一次 -15 封顶 74；
    30 天内到期封顶 70 再每天 -2；已过期 0 分。长口令（≥25）跳过
    重熵类规则，逐字符分析截断前 256 字符外推（均照 KeePassXC 思路，
    无任何第三方代码复制）；(password, username) 评分缓存。
  - 跨条目重复检测：解密后按 SHA-256 分组，count>1 组内全部条目入
    findings，reuse_peers 列同口令其它条目标题（上限 20 + 省略号）。
  - 年龄/到期分析：passwords 补 password_changed_at（存量回填
    =updated_at 并标 estimated）与 expires_at 列；过期=severity3+0 分，
    30 天内到期 severity1（≤2 天"即将到期"分层文案），使用超
    HEALTH_MAX_AGE_DAYS（默认 365 天）记 old。
  - 态势评分 posture_score（0-100）：五项告警加权扣分——复用条数>
    唯一口令数/10（-15）、最大复用>3（-15）、平均长度<10（-10）、
    存在过期（-20）、弱占比>10%（-25），告警清单随快照落库。
  - **HIBP k-匿名泄露查询（默认关闭，零外联）**：HIBP_ENABLED=false
    缺省；开启后仅发送 SHA-1 前 5 位（GET range_url+prefix，响应行
    SUFFIX:COUNT 精确等值匹配），先去重再查、同前缀响应 run 内缓存、
    100ms 节流、UA 固定 PasswordManageSystem（不带版本号）；失败降级
    保留已得结果并在报告页标注"暂不可用"，不阻塞其它类别；展示分桶
    1/≤10/≤100/≤1000/≤1万/≤10万/≤100万/百万+。配置项：
    HIBP_ENABLED/HIBP_RANGE_URL/HIBP_TIMEOUT_S/HIBP_MIN_INTERVAL_MS/
    HIBP_USER_AGENT（.env.example 与使用说明已补充）。
  - 报告页：概览头（态势评分/五项告警/分类计数/阈值快照）+ 弱口令/
    重复/年龄到期/泄露四页签；严重度三档着色（Bad=必须修改/Poor=应尽
    快修改/Weak=建议修改，同色前景保读屏器可达）、数字评分数值排序、
    行操作跳编辑页；HIBP 关闭时隐藏页签。
  - Excel 导出（health_excel.py）：概览 Sheet（run 元信息+态势评分+
    分类计数+阈值快照）+ 每类一 Sheet，冻结首行 + AutoFilter + 严重度
    条件填充 + 公式注入防护；BytesIO 直传服务端不落盘；**绝不含密码
    列**；文件名 密码健康报告_{run_id}_{ts}.xlsx。
  - 并发与资源保护：同 scope 有 running 时拒绝重复发起
    （BEGIN IMMEDIATE 原子检查）；分页批处理（每批 500 条）防内存
    峰值；单轮条目硬上限 200000；快照全局保留最近 100 轮自动清理；
    发起 3 次/10 分钟/用户、导出 10 次/10 分钟/用户 限流。
  - 审计日志：health_report_run（发起，含范围与结果统计摘要）与
    health_export（导出）全量入 operation_logs。
- 启动维护新增：预恢复快照（pre_restore_*.db）自动清理（保留 3 份，
  此前只在恢复时创建、永不清理）。

### Fixed（BUG 修复）
- 批量导入单行失败连带回滚已成功行（app/services/excelio.py）：旧实现
  对失败行直接 conn.rollback()，把本轮已 INSERT 的行全部回滚，而
  imported 计数照常累加——导入结果页提示"成功 N 条"但库里实际为空，
  造成静默数据丢失。现改用 SAVEPOINT 逐行隔离，失败行跳过、已成功行
  保留（新增回归测试断言）。
- HIBP 响应解析解包错误（app/services/hibp.py，本轮新代码自查发现）：
  str.partition 返回三元组被误写成四元组解包，任何响应行匹配都会抛
  ValueError。已修复并补前缀碰撞用例（AB1 不误匹配 AB12）。
- 内存限流器键无限增长（app/security/ratelimit.py）：任意可变输入
  （随机用户名/邮箱）都成为限流键且永不回收，长期运行缓慢吃掉进程
  内存（内存 DoS 面）。现键数达 2 万触发过期清扫（24 小时窗口）。
- 共享列表页无密码记录显示"查看/复制"按钮（routes/shares.py +
  templates/shares/shared_with_me.html）：has_password 此前硬编码
  True，点击后 reveal 接口返回空字符串，体验为"查看密码无反应"。
  现按记录实际是否有密码渲染"未设置"占位。
- 在线邮件配置端口值损坏导致 500（app/services/mail_settings.py）：
  库内 port 被手工改成非数字后，系统设置页与发信路径 int() 抛异常。
  现解析失败回退 465（新增 _port_of 防御）。
- 登录限流用户名键大小写绕过（app/routes/auth.py）：login:user:{name}
  键未归一化，Admin/admin 交替输入可绕开用户名维度 10 次/5 分钟限流
  （数据库层大小写不敏感，两者命中同一账户）。现统一小写。
- xlsx 导入空工作簿 AttributeError（app/services/excelio.py）：
  上传仅含图表/无工作表的 xlsx 时 wb.active 为 None，500。现校验后
  返回 ValidationError 引导信息。

### Verified（测试验证）
- 新增 tests/test_health.py 38 个用例：评分函数（词典/纯数字/序列/
  键盘/连打/年份/用户名 token/长口令跳过/复用到期封顶/等级分界）、
  HIBP（解析精确匹配与前缀碰撞/去重与前缀缓存/失败降级/分桶/关闭零
  外联/失败不阻塞其它类别）、审计编排（分类计数/快照不含明文与哈希/
  本人范围隔离/空库/过期与即将到期/超龄/并发拒绝/限流）、权限边界
  （越权 404/普通用户仅本人/scope=all 非管理员强制回本人）、审计日志
  落库、Excel 导出不含密码明文与密码列断言、关联 BUG 回归（导入
  SAVEPOINT/限流器清扫/共享 has_password）。
- 全量测试：`python -m pytest tests/ --basetemp=.pytest-tmp`
  **185/185 通过**（基线 147 + 本轮 38；约 197 秒）。
- 迁移兼容冒烟：全新库建表 + 存量库增量补列/回填验证通过（本地脚本
  实测 passwords 列清单含 password_changed_at/expires_at）。

## [v0.1.0] - 2026-10-12 · 正式稳定版（内部 2.x 线归一为 v0.1.0）

> 版本号说明：此前内部迭代的 2.0/2.2/2.3 线自本版起统一归一为
> **v0.1.0 正式稳定版**（对外唯一基线）。历史 2.x 条目见下方，仅作留痕。

### Fixed（BUG 修复）
- `login_lockouts` 表无限增长：撞库/不存在的用户名也会写入该表且永不
  清理。现于启动时与登录时（1 小时节流）自动删除超过 24 小时无活动的
  过期行；锁定表用户名统一截断到 50 字符，防超长输入撑大存储。
- Excel 导入表头校验形同虚设：旧实现对"映射后的 dict"检查列名，恒为
  真——乱序/中文/任意表头的文件都会按位置错误导入。现按首行真实单元
  格内容与标准模板逐列比对，不一致明确报错并引导下载标准模板。
- TOTP 恢复码验证性能：单次失败登录逐条试 10 个 bcrypt（约 1 秒 CPU），
  攻击者可借恢复码格式消耗服务端 CPU。现改存 HMAC-SHA256 摘要
  （以 SECRET_KEY 为 pepper），校验降为微秒级常数时间比较；
  存量 bcrypt 哈希仍可验证（向后兼容），重新开启两步验证即切换新格式；
  开启流程生成 10 个摘要从约 1.5 秒降为瞬时。
- pending_2fa 半登录状态永久有效：密码通过后若不完成第二因子，
  该状态此前一直挂到会话过期。现超过 10 分钟自动作废，需重新登录。
- 记录 project_id 越权（IDOR）：表单/API 提交任意 project_id 可把记录
  挂到他人项目下并借列表 JOIN 窥见他人项目名。现服务层强制校验项目
  归属（仅记录所有者本人名下项目合法）；API 共享编辑者的 project_id
  字段直接忽略。

### Security（安全加固）
- 找回密码 / 注册接口验证码爆破面封堵：两接口内含 6 位验证码校验，
  原先可无限次尝试暴力猜码。现限流——找回密码 10 次/10 分钟/IP，
  注册 10 次/小时/IP。
- 导出公式注入（CSV/Excel Injection）防护：以 `=` `+` `-` `@` 等开头
  的单元格在 Excel 打开时会被当公式执行。xlsx 导出强制按字符串类型
  写入（数据逐字保留、往返导入不失真）；CSV 导出按 OWASP 惯例加
  单引号前缀。
- X-Forwarded-For 伪造防护：新增 `TRUST_PROXY` 开关（默认 false），
  仅在可信反向代理之后才采信 XFF，防止伪造 XFF 轮换"IP"绕过 IP
  维度限流与 用户名+IP 锁定；审计日志 IP 记录与限流统一走同一策略。
- 默认口令引导强度：管理员仍使用 admin/admin123 时，登录后全站顶部
  持续显示安全警告横幅（直至修改口令），并在安全概览页标红提示。
- 依赖升级：`cryptography` 42.0.5 → 44.0.1（42.0.0–44.0.0 的官方
  wheel 捆绑的 OpenSSL 存在已披露漏洞，44.0.1 为最小安全修复版；
  详见 docs/安全审查报告-v0.1.0.md）。其余锁定版本经逐项 CVE 核查
  无已知高危问题（waitress 3.0.2 已含 CVE-2024-49768/49769 修复）。

### Added（新增功能）
- 管理员「安全概览」页（/admin/security-overview）：失败登录统计
  （24h/7d）、两步验证失败统计、两类锁定现状明细（单账户/用户名+IP）、
  撞库热点目标 TOP10、TOTP 覆盖率、待强制改密人数、默认口令检测、
  活跃 API 密钥数、近 7 天 reveal/export 次数——一页掌握攻击面。
- 会话过期友好提示：AJAX 请求会话过期时统一返回 401 JSON，前端弹出
  "登录已过期"提示并自动跳转登录页；页面请求跳转登录页时展示明确的
  "登录已过期，请重新登录"提示（替代原先笼统的"请先登录"）。

### Changed
- SQLite 连接新增 `PRAGMA synchronous=NORMAL`（WAL 标配）：写吞吐
  提升，断电最多丢最后一次提交、库文件不会损坏。
- 镜像标签统一为 `password-manager:v0.1.0`（docker-compose.yml）。
- 测试从 123 个增至 147 个（新增 tests/test_v010.py 24 个用例，
  覆盖上述全部修复与新增）。

### 回滚说明
- 数据结构无变更（无新增列/表），v0.1.0 与 2.3.0 数据库完全互通，
  直接换回旧镜像重启即可回滚。
- TOTP 恢复码新摘要格式仅在"重新开启两步验证"后生效，存量用户旧
  恢复码在 2.3.0 代码下依然有效。
- 若已将 `TRUST_PROXY=true`，回滚旧版本时该配置被忽略（旧版无此开关，
  行为退回为始终信任 XFF）。

## [2.3.0] - 2026-10-12 · 登录防爆破增强 + TOTP 两步验证

### Added
- 登录防爆破（用户名+IP 维度）：同 用户名+IP 连续失败 10 次锁定 15 分钟，
  计数持久化到新表 `login_lockouts`（应用重启不清零）；锁定期内统一返回
  友好提示，不区分"用户不存在/密码错误"，对不存在的用户名同样生效。
- TOTP 两步验证：登录密码校验通过后进入第二因子页（6 位动态码，
  pyotp 校验，容差 1 个周期）；用户可在「安全设置」页自助开启
  （生成密钥 + otpauth:// 链接一次性展示，输入一次有效动态码确认），
  关闭需当前密码 + 当前有效动态码双重确认。
- 一次性恢复码：开启时生成 10 个（secrets 模块），仅存 bcrypt 哈希、
  明文只展示一次；登录时可在验证码位置改用恢复码，用过即废。
- 审计日志动作新增：`totp_enabled` / `totp_disabled` / `totp_failed` /
  `recovery_used`；`account_locked` 同时覆盖单账户锁定与用户名+IP 锁定。
- 管理端「操作日志」页新增按操作人（用户）筛选；管理员可见全部，
  普通用户仍仅见本人。
- 新增测试 `tests/test_totp_v23.py`：锁定逻辑（阈值/清零/过期重计/
  持久化/审计）、TOTP 开启-验证-恢复码-关闭、登录全流程、2.2 旧库迁移。

### Changed
- `users` 表经增量迁移新增 3 列：`totp_secret`（Fernet 密文）、
  `totp_enabled`、`recovery_codes`（bcrypt 哈希 JSON）；新表
  `login_lockouts`（username+ip 唯一）。均为幂等迁移，旧数据无损。
- `requirements.txt` 新增 `pyotp==2.9.0`（版本锁定）。
- 镜像标签 `password-manager:2.2.0` → `2.3.0`；DOCKER.md 补充
  两步验证使用说明与审计日志说明。

### Security
- 登录现具备三层防护：内存限流（IP 20/5min、用户名 10/5min，v2.1 既有）+
  单账户锁定（5 次锁 15 分钟，v2.2 既有）+ 用户名+IP 持久化锁定
  （10 次锁 15 分钟，本次新增）。
- TOTP 密钥以应用层 Fernet 加密落库（与密码记录同一密钥体系）；
  恢复码只存 bcrypt 哈希；密钥与恢复码均仅在开启流程展示一次。

### 回滚说明
- 本版全部改动向前兼容：新列/新表经幂等迁移创建，未开启两步验证的
  用户登录流程与旧版完全一致；审计日志沿用既有 `operation_logs` 表。
- 如需回滚，直接改回 `2.2.0` 镜像重启即可：旧代码不读取新增列/新表，
  运行不受影响（已开启两步验证的用户回滚后将退化为仅密码登录）。
- 如需彻底清理结构（可选，非必需）：`DROP TABLE login_lockouts;` 并
  `ALTER TABLE users DROP COLUMN totp_secret;`（另两列同理，SQLite 3.35+）。

## [2.2.0] - 2026-10-11 · 拆分为独立 Docker 项目

### Added
- 新增 `deploy.sh` / `deploy.bat` 独立一键部署脚本（建数据目录并 `docker compose up -d --build`）。
- 新增本 CHANGELOG。

### Changed
- Dockerfile pip 依赖层增加 `PIP_INDEX_URL` 构建参数；compose 默认传清华镜像，
  保证国内网络可构建。
- DOCKER.md 重写为自包含部署文档：修正宿主端口为 6084（原文误写 8000），
  补齐初始账号（admin/admin123）、密钥备份警告与迁移指引。

### 影响
- 本目录自此可独立交付部署，不依赖上级目录的 deploy.sh / README.md。
