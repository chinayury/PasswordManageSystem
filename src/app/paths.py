"""路径解析模块。

统一解决两类运行形态下的可写数据目录问题：
- 源码运行：项目根目录 = 从本文件逐级向上查找，最先包含 ``pyproject.toml``
  或 ``run.py`` / ``wsgi.py`` 的目录（兼容 ``src/app`` 标准布局与旧扁平布局，
  布局调整无需改本文件）；
- PyInstaller 打包运行：可执行文件所在目录（而 *不是* sys._MEIPASS
  临时解压目录——旧版把数据库/上传目录放进 _MEIPASS，重启后数据全部丢失）
"""
import os
import sys

# 用于判定"项目根"的标记文件（任一存在即视为项目根）
_ROOT_MARKERS = ("pyproject.toml", "run.py", "wsgi.py")


def _base_dir() -> str:
    if getattr(sys, "frozen", False):  # PyInstaller 打包环境
        return os.path.dirname(os.path.abspath(sys.executable))
    # 源码运行：从本文件所在目录逐级向上，定位项目根
    here = os.path.dirname(os.path.abspath(__file__))
    cur = here
    while True:
        if any(os.path.exists(os.path.join(cur, m)) for m in _ROOT_MARKERS):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:  # 已到文件系统根仍未命中，回退到 app 包的上一级
            return os.path.dirname(os.path.dirname(here))
        cur = parent


BASE_DIR = _base_dir()

# 可写数据目录（均可用环境变量覆盖）
DATABASE_PATH = os.getenv(
    "DATABASE_PATH", os.path.join(BASE_DIR, "password_manager.db")
)
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", os.path.join(BASE_DIR, "uploads"))
BACKUP_FOLDER = os.getenv("BACKUP_FOLDER", os.path.join(BASE_DIR, "backups"))
LOG_FOLDER = os.getenv("LOG_FOLDER", os.path.join(BASE_DIR, "logs"))


def ensure_runtime_dirs() -> None:
    """确保运行期需要的目录存在（幂等）。"""
    for folder in (UPLOAD_FOLDER, BACKUP_FOLDER, LOG_FOLDER):
        os.makedirs(folder, exist_ok=True)
