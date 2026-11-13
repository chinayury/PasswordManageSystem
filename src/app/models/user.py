"""模型层：Flask-Login 用户身份。"""
from flask_login import UserMixin

from ..db import get_db


class User(UserMixin):
    """登录用户。is_active 覆盖 UserMixin 默认值，联动账户禁用状态。"""

    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.email = row["email"]
        self.password_hash = row["password"]
        self.is_admin = bool(row["is_admin"])
        self._account_active = bool(row["is_active"]) if "is_active" in row.keys() else True
        # v2.2 管理员重置/新建后的强制改密标记
        self.must_change_password = bool(
            row["must_change_password"]) if "must_change_password" in row.keys() else False
        # v0.1.0 会话纪元：改密/重置/注销时递增，用于把该用户其它设备踢下线
        self.session_epoch = int(
            row["session_epoch"]) if "session_epoch" in row.keys() else 0

    @property
    def is_active(self):
        return self._account_active


def load_user_by_id(user_id: str):
    """flask-login 回调：按 id 加载用户。"""
    row = get_db().execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return User(row) if row else None


def get_user_row(user_id: int):
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
