/**
 * 通用：把密码输入框与强度条提示绑定（v0.1.0 新增）。
 *
 * 用法：给密码输入框加 data-strength-for="1"，
 * 页面需同时引入 password-strength.js（提供 checkPasswordStrength）。
 * 本文件独立存在是为了避免在模板里写内联 <script>——
 * CSP 为 script-src 'self'，内联脚本会被浏览器直接拦截。
 */
"use strict";

document.addEventListener("DOMContentLoaded", () => {
    if (typeof checkPasswordStrength !== "function") return;
    document.querySelectorAll("input[data-strength-for]").forEach(input => {
        input.addEventListener("input", () => checkPasswordStrength(input.value));
    });
});
