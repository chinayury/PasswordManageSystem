@echo off
rem ============================================================
rem PasswordManageSystem 密码管理系统 · 独立 Docker 部署脚本 (Windows)
rem 端口: 宿主 6084 -> 容器 6082
rem ============================================================
cd /d %~dp0
if not exist data mkdir data
docker compose up -d --build
echo.
echo PasswordManager: http://127.0.0.1:6084
echo 初始管理员: admin / admin123 (登录后立即修改!)
echo 密钥文件 data\.secrets.env 首启自动生成 - 务必备份, 丢失=已存密码无法解密
