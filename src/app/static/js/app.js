/**
 * 密码管理系统 v0.1.0 - 全局共享脚本
 * 职责：CSRF 请求封装、Toast、图片粘贴/预览/放大、删除确认、文件选择提示
 *
 * v0.1.0 视觉重构同步修复的前端缺陷：
 * 1. 图片放大模态完全失效——旧代码用 classList.add("show")，而 CSS 里
 *    只有 [hidden] 规则，.show 从未定义，模态永远不显示。改为操作 hidden 属性。
 * 2. bindConfirms 空指针——btn.closest("form") 为 null 时直接 addEventListener 崩溃，
 *    导致同页后续按钮的确认绑定全部中断。改为判空 + 事件委托，动态节点也生效。
 * 3. 文件选择提示用硬编码 #333 且覆盖服务端文案——改为跟随新版令牌色，
 *    并保留服务端已渲染的当前附件说明（不再无脑覆写）。
 * 4. 401 跳转硬编码 /login——改为 url_for 注入的登录地址（见 base.html data 属性）。
 * 5. 模态无可访问性支持——补 role/aria、Esc 关闭、焦点回归。
 * 说明：所有页面脚本均为外部文件（CSP script-src 'self'），无内联 JS。
 */
"use strict";

/* ---------- CSRF 请求封装 ---------- */
function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : "";
}

/* 登录页地址：由模板通过 .shell[data-login-url] 注入，避免硬编码 */
function loginUrl() {
    const shell = document.querySelector(".shell");
    return (shell && shell.dataset.loginUrl) || "/login";
}

async function apiFetch(url, options = {}) {
    const opts = Object.assign({ method: "POST", headers: {} }, options);
    opts.headers["X-CSRFToken"] = csrfToken();
    opts.headers["X-Requested-With"] = "XMLHttpRequest";
    if (opts.json !== undefined) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(opts.json);
        delete opts.json;
    }
    const resp = await fetch(url, opts);
    // 会话过期：服务端对 AJAX 请求统一返回 401 JSON，给出明确提示并回登录页
    if (resp.status === 401) {
        showToast("登录已过期，请重新登录", "error");
        setTimeout(() => { window.location.href = loginUrl() + "?expired=1"; }, 1200);
        return { ok: false, status: 401, data: null };
    }
    let data = null;
    try { data = await resp.json(); } catch (_) { /* 非 JSON 响应 */ }
    return { ok: resp.ok, status: resp.status, data };
}

/* ---------- Toast ---------- */
/* Toast 图标内联 SVG（与 partials/icons.html 同一套「Cobalt Bay 钴湾」
   双色调图标：1.7 描边 + 16% 不透明度填充实心形状；
   此处独立定义以避免为几个图标多发一次请求；CSP script-src 'self' 允许外部文件） */
window.__PDM_ICONS = {
    "check-circle": '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><g fill="currentColor" fill-opacity=".16" stroke="none"><circle cx="12" cy="12" r="8.7"/></g><circle cx="12" cy="12" r="8.7"/><path d="M8.2 12.2l2.5 2.5 5-5.2"/></svg>',
    "x-circle": '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><g fill="currentColor" fill-opacity=".16" stroke="none"><circle cx="12" cy="12" r="8.7"/></g><circle cx="12" cy="12" r="8.7"/><path d="M9.1 9.1l5.8 5.8M14.9 9.1l-5.8 5.8"/></svg>',
    "alert": '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><g fill="currentColor" fill-opacity=".16" stroke="none"><path d="M12 3.9L2.6 19.8h18.8z"/></g><path d="M12 3.9L2.6 19.8h18.8z"/><path d="M12 9.8v4.4M12 17.1v.3"/></svg>',
    "info": '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><g fill="currentColor" fill-opacity=".16" stroke="none"><circle cx="12" cy="12" r="8.7"/></g><circle cx="12" cy="12" r="8.7"/><path d="M12 11v5.2M12 7.8v.3"/></svg>'
};

function showToast(message, type = "info") {
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.setAttribute("role", "status");
    const svg = type === "success" ? "check-circle"
        : type === "error" ? "x-circle"
        : type === "warning" ? "alert" : "info";
    toast.innerHTML = "";
    const iconEl = document.createElement("span");
    iconEl.className = "toast-icon";
    iconEl.innerHTML = window.__PDM_ICONS[svg] || "";
    toast.appendChild(iconEl);
    const text = document.createElement("span");
    text.textContent = message;
    toast.appendChild(text);
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 500);
    }, 2600);
}

/* ---------- 删除/危险操作确认（含输入型确认） ----------
   v0.1.0 第二轮修复 FU-01 [HIGH]：
   旧实现把整句提示文案同时当作「prompt 提示语」和「期望答案」
   （prompt(dataset.confirmInput) === dataset.confirmInput），导致用户
   按提示输入 DELETE 被静默拦截、照抄整句又被后端 confirm != "DELETE"
   打回——注销用户在 UI 上完全不可用。
   现拆为两个属性：
     data-confirm-input = 提示文案（prompt 显示内容）
     data-confirm-token = 期望答案（缺省 "DELETE"，与后端校验值一致）
   旧模板只写 data-confirm-input 时，token 回退为 DELETE，
   与 admin.py 现有校验值吻合，向后兼容。
   另：改为事件委托 + 判空，动态节点也生效；按钮不在表单内时不再崩溃。 */
function bindConfirms(root = document) {
    if (root._confirmDelegated) return;
    root._confirmDelegated = true;
    document.addEventListener("submit", e => {
        const form = e.target;
        if (!form || form.tagName !== "FORM") return;
        // 表单内任意带 data-confirm 的提交按钮即触发确认
        const btn = form.querySelector("[data-confirm]");
        if (btn && !confirm(btn.dataset.confirm)) {
            e.preventDefault();
            return;
        }
        const inputBtn = form.querySelector("[data-confirm-input]");
        if (inputBtn) {
            // 期望令牌独立存放；未显式声明时回退 DELETE（与后端一致）
            const expected = (inputBtn.dataset.confirmToken || "DELETE").trim();
            const message = inputBtn.dataset.confirmInput || `请输入 ${expected} 确认：`;
            const answer = prompt(message);
            if (answer !== null && answer.trim() === expected) {
                const field = form.querySelector('input[name="confirm"]');
                if (field) field.value = expected;
            } else {
                e.preventDefault();
            }
        }
    });
}

/* ---------- 图片放大模态 ----------
   v0.1.0：旧实现 add/remove classList "show"，但样式表从未定义 .show，
   模态实际永远无法显示。现统一切换 hidden 属性，并补齐可访问性。 */
function initImageModal() {
    const modal = document.getElementById("image-modal");
    if (!modal) return;
    const modalImg = document.getElementById("modal-img");
    const closeBtn = modal.querySelector(".close-modal");
    let lastFocus = null;

    function open(src) {
        if (!modalImg) return;
        lastFocus = document.activeElement;
        modalImg.src = src;
        modal.hidden = false;
        document.body.style.overflow = "hidden";
        if (closeBtn) closeBtn.focus();
    }
    function close() {
        modal.hidden = true;
        document.body.style.overflow = "";
        if (lastFocus && typeof lastFocus.focus === "function") lastFocus.focus();
    }

    document.addEventListener("click", e => {
        const el = e.target;
        if (el && el.classList && el.classList.contains("remark-image")) open(el.src);
    });
    if (closeBtn) {
        closeBtn.addEventListener("click", close);
        closeBtn.addEventListener("keydown", e => {
            if (e.key === "Enter" || e.key === " ") { e.preventDefault(); close(); }
        });
    }
    modal.addEventListener("click", e => { if (e.target === modal) close(); });
    document.addEventListener("keydown", e => {
        if (e.key === "Escape" && !modal.hidden) close();
    });
}

/* ---------- 备注框图片粘贴 ---------- */
function initRemarkPaste() {
    ["remark1", "remark2"].forEach(id => {
        const textarea = document.getElementById(id);
        if (!textarea) return;
        const previewId = `${id}-preview`;

        textarea.addEventListener("paste", e => {
            const items = (e.clipboardData || window.clipboardData).items;
            for (const item of items) {
                if (item.kind === "file" && item.type.indexOf("image/") !== -1) {
                    e.preventDefault();
                    const file = item.getAsFile();
                    if (file.size > 3 * 1024 * 1024) {
                        showToast("图片过大（>3MB），请压缩后粘贴", "error");
                        return;
                    }
                    const reader = new FileReader();
                    reader.onload = ev => {
                        textarea.value = ev.target.result;
                        showImagePreview(previewId, ev.target.result);
                    };
                    reader.readAsDataURL(file);
                    break;
                }
            }
        });

        textarea.addEventListener("input", () => {
            if (textarea.value.startsWith("data:image/")) {
                showImagePreview(previewId, textarea.value);
            } else {
                hideImagePreview(previewId);
            }
        });

        if (textarea.value.startsWith("data:image/")) {
            showImagePreview(previewId, textarea.value);
        }
    });
}

function showImagePreview(previewId, base64Data) {
    let preview = document.getElementById(previewId);
    if (!preview) {
        preview = document.createElement("div");
        preview.id = previewId;
        preview.className = "img-preview";
        const textarea = document.getElementById(previewId.replace("-preview", ""));
        if (!textarea) return;
        textarea.parentNode.insertBefore(preview, textarea.nextSibling);
    }
    const img = document.createElement("img");
    img.src = base64Data;
    img.className = "remark-image";
    img.alt = "预览图片";
    preview.innerHTML = "";
    preview.appendChild(img);
}

function hideImagePreview(previewId) {
    const preview = document.getElementById(previewId);
    if (preview) preview.innerHTML = "";
}

/* ---------- 文件选择提示 ----------
   v0.1.0：不再用硬编码 #333；且不再无脑覆写服务端已渲染的"当前附件"
   说明文案（旧版会把 records/edit 页已有的附件提示直接盖掉）。 */
function initFilePreviews() {
    document.querySelectorAll('input[type="file"]').forEach(input => {
        input.addEventListener("change", () => {
            const preview = document.getElementById(`${input.id}-preview`);
            if (!preview) return;
            // 保留服务端渲染的原始文案，仅在用户确已选择文件时附加选择结果
            if (!preview.dataset.original) {
                preview.dataset.original = preview.textContent || "";
            }
            preview.textContent = input.files.length
                ? `${preview.dataset.original ? preview.dataset.original + " · " : ""}已选择：${input.files[0].name}`
                : preview.dataset.original;
        });
    });
}

/* ---------- 页面初始化 ---------- */
document.addEventListener("DOMContentLoaded", () => {
    bindConfirms();
    initImageModal();
    initRemarkPaste();
    initFilePreviews();
});

