/**
 * 修改密码页：确认密码前端一致性校验（v0.1.0 新增）。
 * 服务端仍做完整校验，此处仅提前给出友好反馈。
 */
"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const pw = document.getElementById("new_password");
    const confirm = document.getElementById("confirm_password");
    const err = document.getElementById("pw-mismatch");
    const form = document.getElementById("change-password-form");
    if (!pw || !confirm || !form) return;

    function sync() {
        const mismatch = confirm.value.length > 0 && pw.value !== confirm.value;
        if (err) err.hidden = !mismatch;
        confirm.setAttribute("aria-invalid", mismatch ? "true" : "false");
    }
    pw.addEventListener("input", sync);
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
