"""业务层：邮件发送（smtplib 直发，超时保护，未配置时优雅降级）。

配置来源：在线配置（系统设置页保存，数据库）优先，回退 .env。
"""
import logging
import smtplib
from email.header import Header
from email.mime.text import MIMEText

from .mail_settings import get_mail_config, mail_configured

logger = logging.getLogger(__name__)

__all__ = ["mail_configured", "send_verification_email", "send_test_email"]


def _open_smtp(c: dict):
    """按配置建立 SMTP 连接（465 直连 SSL，其余明文+可选 STARTTLS）。"""
    use_ssl = c["port"] == 465
    if use_ssl:
        server = smtplib.SMTP_SSL(c["server"], c["port"], timeout=15)
    else:
        server = smtplib.SMTP(c["server"], c["port"], timeout=15)
        if c["use_tls"]:
            server.starttls()
    return server


def send_verification_email(to_email: str, code: str, purpose: str = "register") -> bool:
    """发送验证码邮件。返回是否成功；失败细节只进日志，不回显给用户。"""
    if not mail_configured():
        logger.warning("SMTP 未配置，无法向 %s 发送验证码", to_email)
        return False

    c = get_mail_config()
    subject_map = {"register": "注册验证码", "reset_password": "重置密码验证码"}
    subject = f"密码管理系统(PDM) - {subject_map.get(purpose, '验证码')}"
    body = (
        f"您的验证码是：{code}\n\n"
        f"10 分钟内有效。请勿将验证码泄露给他人。\n"
        f"如果这不是您本人的操作，请忽略本邮件。"
    )
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = c["sender"]
    msg["To"] = to_email

    try:
        # v0.1.0：不再调用 socket.setdefaulttimeout（进程级全局副作用，
        # 会波及同进程其他网络连接）；SMTP 客户端构造时已显式传 timeout=15
        server = _open_smtp(c)
        try:
            server.login(c["username"], c["password"])
            server.sendmail(msg["From"], [to_email], msg.as_string())
        finally:
            server.quit()
        logger.info("验证码邮件已发送至 %s (purpose=%s)", to_email, purpose)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("验证码邮件发送失败 (%s:%s): %s", c["server"], c["port"], exc)
        return False


def send_test_email(to_email: str) -> tuple:
    """发送测试邮件（系统设置页「测试发送」用）。返回 (是否成功, 提示信息)。

    与验证码邮件不同：失败原因回显给操作者——只有管理员能调用（路由层
    admin_required），排障正是需要看到 SMTP 握手/认证的具体错误。
    """
    if not mail_configured():
        return False, "邮件服务未配置完整（服务器/账号/密码缺一不可），请先填写并保存"

    c = get_mail_config()
    msg = MIMEText(
        "这是一封测试邮件。\n\n收到本邮件即表示 PDM 的 SMTP 配置可用，"
        "注册 / 找回密码的验证码邮件将发送到此邮箱。",
        "plain", "utf-8")
    msg["Subject"] = Header("密码管理系统(PDM) - 邮件服务测试", "utf-8")
    msg["From"] = c["sender"]
    msg["To"] = to_email

    try:
        server = _open_smtp(c)
        try:
            server.login(c["username"], c["password"])
            server.sendmail(msg["From"], [to_email], msg.as_string())
        finally:
            server.quit()
        logger.info("测试邮件已发送至 %s", to_email)
        return True, f"测试邮件已发送到 {to_email}，请查收（注意垃圾箱）"
    except Exception as exc:  # noqa: BLE001
        logger.error("测试邮件发送失败 (%s:%s): %s", c["server"], c["port"], exc)
        return False, f"发送失败：{exc}"
