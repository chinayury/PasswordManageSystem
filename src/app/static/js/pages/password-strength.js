/**
 * 修改密码页：前端实时强度提示（服务端仍做强校验）。
 *
 * v0.1.0 修复：
 * 1. 色板改用 CSS 类（.s1~.s5）而非内联硬编码 Bootstrap 遗留色
 *    （#dc3545/#ffc107/#28a745），与新版视觉体系的青/琥珀配色对齐。
 * 2. 文案细化为五档，与后端五档评分口径（Bad/Poor/Weak/Good/Excellent）对应。
 */
"use strict";

function checkPasswordStrength(password) {
    const bar = document.getElementById("strength-bar-fill");
    const text = document.getElementById("password-strength");
    if (!bar || !text) return;

    if (!password.length) {
        bar.style.width = "0%";
        bar.className = "strength-bar-fill";
        text.textContent = "";
        text.className = "";
        return;
    }
    let score = 0;
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    // 五档：s1 弱 / s2 偏弱 / s3 中 / s4 良好 / s5 强
    let level, width, message;
    if (score <= 2) {
        level = "s1"; width = "20%";
        message = "弱 - 建议混合大小写字母、数字和符号，至少 8 位";
    } else if (score === 3) {
        level = "s2"; width = "40%";
        message = "偏弱 - 增加长度或加入符号可显著提升强度";
    } else if (score === 4) {
        level = "s3"; width = "60%";
        message = "中 - 强度尚可，建议继续加长";
    } else if (score === 5) {
        level = "s4"; width = "82%";
        message = "良好 - 已具备较强的抗爆破能力";
    } else {
        level = "s5"; width = "100%";
        message = "强 - 密码强度极佳";
    }
    bar.style.width = width;
    bar.className = "strength-bar-fill " + level;
    text.textContent = message;
    text.className = "strength-text " + level;
}
