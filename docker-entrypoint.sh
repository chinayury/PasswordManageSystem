#!/bin/sh
# 密码管理系统 Docker 入口:
#   1) 首次启动生成 SECRET_KEY / ENCRYPTION_KEY 并持久化到数据卷
#      (应用缺这两个密钥拒绝启动;ENCRYPTION_KEY 丢失=已存密码无法解密)
#   2) 以 root 起步时修好数据目录属主,降权到 appuser 运行
set -e

SECRETS_FILE="${SECRETS_FILE:-/app/data/.secrets.env}"

if [ ! -s "$SECRETS_FILE" ]; then
    mkdir -p "$(dirname "$SECRETS_FILE")"
    python - "$SECRETS_FILE" <<'PY'
import secrets
import sys
from cryptography.fernet import Fernet

path = sys.argv[1]
with open(path, "w", encoding="utf-8") as f:
    f.write("SECRET_KEY=%s\n" % secrets.token_hex(32))
    f.write("ENCRYPTION_KEY=%s\n" % Fernet.generate_key().decode())
PY
    chmod 600 "$SECRETS_FILE"
    echo "[entrypoint] 已生成密钥: $SECRETS_FILE"
    echo "[entrypoint] 请务必将该文件纳入备份 — 丢失 ENCRYPTION_KEY 将无法解密历史数据"
fi

# 载入密钥(环境变量已显式提供时不覆盖)
set -a
# shellcheck disable=SC1090
. "$SECRETS_FILE"
set +a

if [ "$(id -u)" = "0" ]; then
    mkdir -p /app/data || true
    chown appuser:appuser /app/data 2>/dev/null || true
    exec gosu appuser "$@"
fi

exec "$@"
