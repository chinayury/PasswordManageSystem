/**
 * 密码列表页（主页 + 共享给我）：按需查看/复制密码。
 * 明文密码不再随页面下发，点击时调用受审计、限流的 reveal 接口获取。
 *
 * v0.1.0 修复：
 * 1. 「查看/隐藏」按钮文字改用 setBtnLabel()——旧代码直接赋 textContent，
 *    会把按钮内的 SVG 图标抹掉，点击一次后图标永久消失。
 * 2. 自动重新遮蔽的定时器在手动切换时正确取消，避免"点开后 15 秒又被
 *    强制点一次"的怪异行为（旧版会触发一次无谓的重复点击）。
 */
"use strict";

/**
 * 安全地设置按钮文字：保留按钮内的 <svg> 图标节点，只替换文本部分。
 */
function setBtnLabel(btn, label) {
    if (!btn) return;
    const svg = btn.querySelector("svg");
    btn.textContent = "";
    if (svg) btn.appendChild(svg);
    btn.appendChild(document.createTextNode(label));
}

document.addEventListener("DOMContentLoaded", () => {
    // 查看密码：短暂显示后自动重新遮蔽
    document.querySelectorAll(".btn-reveal").forEach(btn => {
        let hideTimer = null;

        function clearHideTimer() {
            if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
        }

        btn.addEventListener("click", async () => {
            const id = btn.dataset.record;
            const mask = document.querySelector(`.pw-mask[data-record="${id}"]`);
            if (!mask) return;
            if (btn.dataset.shown === "1") {
                clearHideTimer();
                mask.textContent = "••••••••";
                setBtnLabel(btn, "查看");
                btn.dataset.shown = "0";
                btn.setAttribute("aria-label", "查看密码");
                return;
            }
            btn.disabled = true;
            const res = await apiFetch(`/records/${id}/reveal`, { method: "POST" });
            btn.disabled = false;
            if (!res.ok || !res.data || !res.data.success) {
                showToast((res.data && res.data.message) || "获取密码失败", "error");
                return;
            }
            mask.textContent = res.data.password || "（空）";
            setBtnLabel(btn, "隐藏");
            btn.dataset.shown = "1";
            btn.setAttribute("aria-label", "隐藏密码");
            // 15 秒后自动重新遮蔽，降低肩窥风险
            clearHideTimer();
            hideTimer = setTimeout(() => {
                if (btn.dataset.shown === "1") btn.click();
            }, 15000);
        });
    });

    // 复制密码：不展示，直接进剪贴板
    document.querySelectorAll(".btn-copy").forEach(btn => {
        btn.addEventListener("click", async () => {
            const id = btn.dataset.record;
            btn.disabled = true;
            const res = await apiFetch(`/records/${id}/reveal`, { method: "POST" });
            btn.disabled = false;
            if (!res.ok || !res.data || !res.data.success) {
                showToast((res.data && res.data.message) || "获取密码失败", "error");
                return;
            }
            const pw = res.data.password || "";
            if (navigator.clipboard && navigator.clipboard.writeText) {
                try {
                    await navigator.clipboard.writeText(pw);
                    showToast("密码已复制到剪贴板", "success");
                    return;
                } catch (_) { /* 降级到旧方案 */ }
            }
            const ta = document.createElement("textarea");
            ta.value = pw;
            ta.setAttribute("readonly", "");
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            ta.remove();
            showToast("密码已复制到剪贴板", "success");
        });
    });
});
