/**
 * 注册页：确认密码前端一致性校验 + 强度提示联动（v0.1.0 新增）。
 * 服务端仍做完整校验，此处仅提前给出友好反馈、减少无效提交。
 */
"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const pw = document.getElementById("password");
    const confirm = document.getElementById("confirm_password");
    const err = document.getElementById("pw-mismatch");
    const form = document.getElementById("register-form");
    if (!pw || !confirm || !form) return;

    function sync() {
        const mismatch = confirm.value.length > 0 && pw.value !== confirm.value;
        if (err) err.hidden = !mismatch;
        confirm.setAttribute("aria-invalid", mismatch ? "true" : "false");
    }
    pw.addEventListener("input", () => {
        if (typeof checkPasswordStrength === "function") checkPasswordStrength(pw.value);
        sync();
    });
    confirm.addEventListener("input", sync);

    form.addEventListener("submit", e => {
        if (pw.value !== confirm.value) {
            e.preventDefault();
            if (err) err.hidden = false;
            confirm.focus();
            showToast("两次输入的密码不一致", "error");
        }
    });
});
