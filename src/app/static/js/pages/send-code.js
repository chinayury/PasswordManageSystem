/**
 * 注册/找回密码页：发送验证码（60 秒倒计时 + 失败恢复）。
 *
 * v0.1.0 修复：按钮文字改用 setBtnLabel()——旧代码直接赋 textContent，
 * 会把按钮内的 SVG 图标抹掉（"获取验证码"按钮进入倒计时后图标消失）。
 * 同时 503（SMTP 未配置）给出可操作的明确提示。
 */
"use strict";

function setBtnLabel(btn, label) {
    if (!btn) return;
    const svg = btn.querySelector("svg");
    btn.textContent = "";
    if (svg) btn.appendChild(svg);
    btn.appendChild(document.createTextNode(label));
}

document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("send-code-btn");
    if (!btn) return;
    const emailInput = document.getElementById("email");
    let timer = null;
    const ORIGIN_LABEL = btn.dataset.label || "获取验证码";

    function startCountdown(seconds) {
        let left = seconds;
        btn.disabled = true;
        setBtnLabel(btn, `${left}秒后重试`);
        timer = setInterval(() => {
            left -= 1;
            if (left <= 0) {
                clearInterval(timer);
                timer = null;
                btn.disabled = false;
                setBtnLabel(btn, ORIGIN_LABEL);
            } else {
                setBtnLabel(btn, `${left}秒后重试`);
            }
        }, 1000);
    }

    btn.addEventListener("click", async () => {
        const email = (emailInput.value || "").trim();
        if (!email) { showToast("请先输入邮箱地址", "error"); return; }

        btn.disabled = true;
        setBtnLabel(btn, "发送中…");
        let res;
        try {
            res = await apiFetch("/send-code", {
                method: "POST",
                json: { email, purpose: btn.dataset.purpose || "register" },
            });
        } catch (_) {
            btn.disabled = false;
            setBtnLabel(btn, ORIGIN_LABEL);
            showToast("网络异常，请稍后重试", "error");
            return;
        }

        if (res.data && res.data.success) {
            showToast(res.data.message || "验证码已发送", "success");
            startCountdown(60);
            return;
        }
        btn.disabled = false;
        setBtnLabel(btn, ORIGIN_LABEL);
        const msg = (res.data && res.data.message) || "发送失败，请稍后重试";
        showToast(msg, res.status === 503 ? "warning" : "error");
    });
});
