"""开发/演示启动入口。

生产部署请使用 wsgi.py（waitress），或交由 gunicorn/uwsgi 托管。

v0.1.0 第六轮修复 BU-11：端口原先裸 `int(os.getenv("PORT", "5000"))`，
环境变量手滑写成 8000t 就在启动期崩溃且没有任何"哪个配置项错了"的提示。
现统一走 config.serve_port_env()，与 _int/_float/_log_level_env 同一套
"非法值告警 + 回退 + 上下限钳制"机制。
"""
import os
import sys

# 源码布局（未 pip install）时把 src 加入 sys.path，保证 `python run.py` 可定位 app 包
if __package__ in (None, ""):
    _SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
    if _SRC not in sys.path:
        sys.path.insert(0, _SRC)

from app import create_app
from app.config import serve_port_env

app = create_app()

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = serve_port_env("5000")
    debug = os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    if debug:
        print("[警告] 调试模式已开启，严禁用于对外生产环境！")
    app.run(host=host, port=port, debug=debug)
