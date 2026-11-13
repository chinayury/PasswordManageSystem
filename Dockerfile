# ============================================================
# 密码管理系统 PDM 版 · Docker 版(Flask + waitress + SQLite)
# 注:不写 # syntax=docker/dockerfile:1 —— 该指令强制 BuildKit 联网拉前端镜像,
# 隔离网络/代理失效环境(群晖 NAS 等)构建必败;内建前端足够。
# 数据(数据库/上传/备份/日志/密钥)统一在 /app/data,一个卷搞定备份迁移
# ============================================================
FROM python:3.11-slim

# v0.1.0 第六轮修复 BU-15：容器内监听端口与 docker-compose.yml 统一为 6082
# （原 EXPOSE 8000 而 compose 映射 6084:6082，按 EXPOSE/DOCKER.md 排查端口会踩空）
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    HOST=0.0.0.0 \
    PORT=6082 \
    DATABASE_PATH=/app/data/password_manager.db \
    UPLOAD_FOLDER=/app/data/uploads \
    BACKUP_FOLDER=/app/data/backups \
    LOG_FOLDER=/app/data/logs

WORKDIR /app

# gosu: 入口脚本以 root 修好卷属主后,降权到 appuser 运行服务
RUN apt-get update \
 && apt-get install -y --no-install-recommends gosu \
 && rm -rf /var/lib/apt/lists/*

# pip 源: compose 默认传清华镜像 (国内网络); 海外服务器改回 https://pypi.org/simple
ARG PIP_INDEX_URL=https://pypi.org/simple
ENV PIP_INDEX_URL=${PIP_INDEX_URL}

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# src 布局：源码位于 src/app，拷入容器 /app/app，与 wsgi.py 的 `from app import` 一致
COPY src/app ./app
COPY wsgi.py run.py ./
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod +x /usr/local/bin/docker-entrypoint \
 && useradd -r -u 1000 appuser \
 && mkdir -p /app/data \
 && chown -R appuser:appuser /app

ENTRYPOINT ["docker-entrypoint"]
EXPOSE 6082
CMD ["python", "wsgi.py"]
