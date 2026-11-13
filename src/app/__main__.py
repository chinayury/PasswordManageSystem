"""``python -m app`` / ``password-manager`` 命令入口。

生产部署默认使用 waitress；设 ``FLASK_DEBUG=1`` 时走 Flask 开发服务器（严禁对外）。
生产 WSGI 入口亦可直接执行根目录 ``python wsgi.py``。

调用链与 ``wsgi.py`` 一致：``create_app()`` 装配 Flask 应用后由 waitress 托管。
"""
import os
import sys

# 源码布局（未安装）时把 src 加入 sys.path，保证 `python -m app` / 直接运行可定位包
if __package__ in (None, ""):
    _SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _SRC not in sys.path:
        sys.path.insert(0, _SRC)

from app import __version__, create_app
from app.config import serve_port_env, serve_threads_env

USAGE = """用法: password-manager [选项]

不带参数时启动服务（默认 waitress）。
监听地址/端口/线程数由环境变量 HOST / PORT / THREADS 配置；
设 FLASK_DEBUG=1 时改用 Flask 开发服务器（严禁对外）。

选项:
  -V, --version   显示版本号后退出
  -h, --help      显示本帮助后退出
"""


def main() -> None:
    """启动服务：默认 waitress，FLASK_DEBUG=1 时走开发服务器。"""
    argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help"):
        print(USAGE, end="")
        return
    if argv and argv[0] in ("-V", "--version"):
        print(f"PasswordManageSystem (PDM) {__version__}")
        return
    if argv:
        sys.stderr.write(f"未知参数: {' '.join(argv)}\n\n{USAGE}")
        raise SystemExit(2)

    app = create_app()
    host = os.getenv("HOST", "0.0.0.0")
    port = serve_port_env("8000")
    debug = os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    if debug:
        print("[警告] 调试模式已开启，严禁用于对外生产环境！")
        app.run(host=host, port=port, debug=True)
        return
    from waitress import serve

    threads = serve_threads_env("8")
    print(
        f"密码管理系统 PasswordManageSystem (PDM) v{app.config.get('VERSION', '')}"
        f" 已启动: http://{host}:{port}"
    )
    serve(app, host=host, port=port, threads=threads)


if __name__ == "__main__":
    main()
