"""工具层：输入校验。

所有外部输入（表单/API/导入文件）统一在此校验，业务代码不重复实现。
"""
import re

# 用户名：字母/数字/下划线/短横线，3~50 位
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,50}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# 记录搜索字段白名单：根治旧版把 filter_field 直接拼接进 SQL 的注入风险
RECORD_SEARCH_FIELDS = (
    "device_model", "serial_number", "location", "node_name", "ip_address", "username",
)

PROJECT_TYPES = ("集成项目", "运维项目", "日常办公", "其它")


# bcrypt 算法上限：仅处理口令的前 72 字节，超长部分被静默截断。
# 5.0 起对超过 72 字节的输入直接抛 ValueError，若不显式拦截会在
# 改密/重置路径上抛成未捕获异常（HTTP 500）。
BCRYPT_MAX_BYTES = 72

# 面向用户的口令长度上限：同时约束字符数与 UTF-8 字节数，避免
# 「128 个汉字（384 字节）」这类输入在策略层通过、在哈希层炸掉。
ACCOUNT_PASSWORD_MAX_CHARS = 72
ACCOUNT_PASSWORD_MAX_BYTES = 72


class ValidationError(Exception):
    """带用户可读信息的校验异常。"""


def valid_username(name: str) -> bool:
    return bool(name) and bool(USERNAME_RE.match(name))


def valid_email(email: str) -> bool:
    return bool(email) and len(email) <= 100 and bool(_EMAIL_RE.match(email))


def password_byte_len(password: str) -> int:
    """口令的 UTF-8 字节长度（bcrypt 实际参与运算的长度）。"""
    return len((password or "").encode("utf-8"))


def check_account_password(password: str) -> None:
    """账户密码策略：至少 8 位且同时包含字母与数字。不满足抛 ValidationError。

    长度上限同时按字符数与字节数校验（v0.1.0 修复 B-01）：bcrypt 只处理
    前 72 字节，超长口令此前会在哈希层抛 ValueError 变成 HTTP 500。
    """
    if not password or len(password) < 8:
        raise ValidationError("密码长度至少 8 位")
    if len(password) > ACCOUNT_PASSWORD_MAX_CHARS:
        raise ValidationError(f"密码长度不能超过 {ACCOUNT_PASSWORD_MAX_CHARS} 位")
    if password_byte_len(password) > ACCOUNT_PASSWORD_MAX_BYTES:
        raise ValidationError(
            f"密码长度不能超过 {ACCOUNT_PASSWORD_MAX_BYTES} 字节"
            "（中文等字符按多字节计算，请适当缩短）")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
        raise ValidationError("密码必须同时包含字母和数字")


def valid_port(port: str) -> bool:
    if not port:
        return True  # 允许留空
    if not re.fullmatch(r"\d{1,5}", str(port)):
        return False
    return 1 <= int(port) <= 65535


def clean_str(value, field: str, max_len: int, required: bool = False) -> str:
    """文本字段统一清洗：去首尾空白、限长、必填检查。"""
    s = (str(value) if value is not None else "").strip()
    if required and not s:
        raise ValidationError(f"{field} 不能为空")
    if len(s) > max_len:
        raise ValidationError(f"{field} 长度不能超过 {max_len} 个字符")
    return s


def clean_record_form(form) -> dict:
    """新增/编辑记录的表单校验，返回标准化字段 dict。"""
    data = {
        "device_model": clean_str(form.get("device_model"), "设备型号", 100, required=True),
        "serial_number": clean_str(form.get("serial_number"), "序列号", 100),
        "location": clean_str(form.get("location"), "位置", 100),
        "node_name": clean_str(form.get("node_name"), "节点名", 100),
        "ip_address": clean_str(form.get("ip_address"), "IP地址", 50),
        "username": clean_str(form.get("username"), "用户名", 100),
        "port": clean_str(form.get("port"), "端口", 20),
        "access_method": clean_str(form.get("access_method"), "访问方式", 50),
        "remark1": clean_str(form.get("remark1"), "备注1", 5000),
        "remark2": clean_str(form.get("remark2"), "备注2", 5000),
    }
    if not valid_port(data["port"]):
        raise ValidationError("端口必须是 1-65535 之间的数字")
    project_id = form.get("project_id") or None
    if project_id is not None:
        try:
            project_id = int(project_id) or None
        except (TypeError, ValueError):
            project_id = None
    data["project_id"] = project_id
    data["password"] = (form.get("password") or "").strip()
    return data
