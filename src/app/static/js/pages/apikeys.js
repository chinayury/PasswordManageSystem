/**
 * API 密钥页：复制新生成的密钥（仅展示一次）。
 * v0.1.0：复制失败时给出明确提示（旧版静默失败仍提示成功）。
 */
"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const copyBtn = document.getElementById("copy-new-key");
    if (!copyBtn) return;
    copyBtn.addEventListener("click", async () => {
        const code = document.getElementById("new-api-key");
        if (!code) return;
        const text = code.textContent.trim();
        if (!text) { showToast("没有可复制的密钥", "warning"); return; }
        try {
            await navigator.clipboard.writeText(text);
            showToast("密钥已复制，请妥善保存", "success");
            return;
        } catch (_) { /* 降级到旧方案 */ }
        try {
            const range = document.createRange();
            range.selectNodeContents(code);
            const sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
            document.execCommand("copy");
            sel.removeAllRanges();
            showToast("密钥已复制，请妥善保存", "success");
        } catch (_) {
            showToast("复制失败，请手动选中复制", "error");
        }
    });
});
