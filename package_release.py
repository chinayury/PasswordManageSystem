"""v0.1.0 第七轮交付打包脚本（无 Git 仓库方案）。

按全局开发规范 §三 3.2 与 §5.4：
- 产物命名 app_YYYYMMDD_HHMMSS.zip
- 敏感文件双排除（.env / 密钥 / 证书 / 日志 / 数据库 / __pycache__ / 临时目录）
- 仅归档正式交付产物，不含原始素材与历史交付包
"""
import os
import sys
import zipfile
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
STAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUT_NAME = f"app_{STAMP}.zip"
OUT_PATH = os.path.join(os.path.dirname(ROOT), OUT_NAME)

# 目录级排除（相对项目根）
EXCLUDE_DIRS = {
    "__pycache__", ".pytest_cache", ".zcode", ".mimosa",
    ".tmpsearch", ".tmpsearch2", "node_modules",
    "logs", "uploads", "backups", "legacy_v0", "data", ".git", "instance",
    "build", "dist", "_tmp_run", "docs-archive",
}

# 文件级排除（精确名 / 后缀）
EXCLUDE_FILES = {
    ".env", "password_manager.db", "password_manager.db-wal",
    "password_manager.db-shm", ".DS_Store", "Thumbs.db",
}
EXCLUDE_SUFFIX = (".pyc", ".log", ".pyd", ".zip", ".db", ".db-wal", ".db-shm")

# 文件级精确排除：PyInstaller 构建配置按惯例不入交付包（源码运行/Docker 不依赖）
EXCLUDE_EXACT = {"password_manager.spec"}


def should_exclude(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").split("/")
    for part in parts:
        if part in EXCLUDE_DIRS:
            return True
    name = parts[-1]
    if name in EXCLUDE_FILES or name in EXCLUDE_EXACT:
        return True
    if name.endswith(EXCLUDE_SUFFIX):
        return True
    return False


def main() -> int:
    added, skipped = [], []
    with zipfile.ZipFile(OUT_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(ROOT):
            # 原地剪枝，避免进入排除目录
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, ROOT)
                if should_exclude(rel):
                    skipped.append(rel)
                    continue
                zf.write(full, os.path.join("PasswordManageSystem", rel))
                added.append(rel)

    size_mb = os.path.getsize(OUT_PATH) / (1024 * 1024)
    print(f"交付包已生成：{OUT_PATH}")
    print(f"  纳入文件：{len(added)} 个，包体 {size_mb:.2f} MB")
    print(f"  排除文件：{len(skipped)} 个")
    # 敏感文件自检：包内不得出现任何敏感名
    with zipfile.ZipFile(OUT_PATH) as zf:
        names = zf.namelist()
    leaked = [n for n in names
              if n.endswith((".env", ".db", ".db-wal", ".db-shm", ".log", ".pyc"))
              or n.endswith("__pycache__")]
    if leaked:
        print("[FAIL] 包内发现敏感/临时文件：")
        for n in leaked[:20]:
            print("   ", n)
        return 1
    print("[OK] 敏感文件零泄露（.env / 数据库 / 日志 / __pycache__ 均不在包内）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
