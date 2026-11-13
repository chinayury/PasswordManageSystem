#!/usr/bin/env bash
# ============================================================
# PasswordManageSystem 密码管理系统 · 独立 Docker 部署脚本
# 用法:  ./deploy.sh
#        docker compose logs -f password-manager   跟踪日志
#        docker compose down                       停止
# 端口:  宿主 6084 -> 容器 6082 (改 docker-compose.yml ports 左半边)
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p data
docker compose up -d --build

echo
echo "=============================================="
echo " PasswordManager 已启动:  http://127.0.0.1:6084"
echo " 初始管理员: admin / admin123 (登录后系统会持续提示, 请立即修改!)"
echo " 密钥文件:   ./data/.secrets.env 首启自动生成 — 务必备份!"
echo "             丢失 ENCRYPTION_KEY = 已存密码永久无法解密"
echo " 数据目录: ./data (数据库/上传/备份/日志/密钥) — 备份即打包"
echo "=============================================="
