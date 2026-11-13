"""安全层：全局安全响应头（CSP / 防嗅探 / 防点击劫持 / 隐私）。

CSP 说明：脚本全部外置到静态文件（script-src 'self'）；备注图片使用
data: 内联（img-src data:）；模板保留少量内联 style 属性
（style-src 'unsafe-inline'，样式注入风险远低于脚本，属可接受权衡）。
"""
from flask import request


def apply_security_headers(response):
    """after_request 钩子：为所有响应附加安全头。"""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-XSS-Protection", "0")  # 现代浏览器已废弃，显式关闭
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'",
    )

    # 页面（非静态资源）不缓存，防止密码明文残留在浏览器/代理缓存
    if request.path.startswith("/static/") is False and (
        response.content_type and response.content_type.startswith("text/html")
    ):
        response.headers.setdefault("Cache-Control", "no-store, max-age=0")

    # 开发环境禁用 CSP 之外的额外头？——不，安全头在开发环境同样保留，
    # 便于尽早发现 CSP 违规问题。
    return response


def init_security_headers(app):
    app.after_request(apply_security_headers)
