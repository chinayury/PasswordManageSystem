"""生产 WSGI 入口：waitress（纯 Python、跨平台、Windows 友好）。

启动：python wsgi.py
监听地址/端口/线程数通过环境变量 HOST / PORT / THREADS 配置。

v0.1.0 第六轮修复 BU-11：PORT / THREADS 原先裸 `int(os.getenv(...))`，
环境变量手滑写成 8000t / eight 就在启动期崩溃且无任何提示。
现统一走 config.serve_port_env() / serve_threads_env()，与
_int/_float/_log_level_env 同一套"非法值告警 + 回退 + 上下限钳制"机制。
"""
import os
import sys

# 源码布局（未 pip install）时把 src 加入 sys.path，保证 `python wsgi.py` 可定位 app 包
if __package__ in (None, ""):
    _SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
    if _SRC not in sys.path:
        sys.path.insert(0, _SRC)

from waitress import serve

from app import create_app
from app.config import serve_port_env, serve_threads_env

app = create_app()

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = serve_port_env("8000")
    threads = serve_threads_env("8")
    print(f"密码管理系统 PasswordManageSystem (PDM) v{app.config.get('VERSION', '')} 已启动: http://{host}:{port}")
    serve(app, host=host, port=port, threads=threads)
