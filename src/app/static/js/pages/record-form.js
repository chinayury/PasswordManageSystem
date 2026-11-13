/**
 * 记录新增/编辑表单：密码生成器（随机字符/易记口令短语两种模式）、
 * 显示/隐藏、泄露即检（HIBP k-匿名）、读取当前密码（编辑页）。
 *
 * v0.1.0 修复：
 * 1. 按钮文字改用 setBtnLabel()——旧代码直接赋 textContent，会把按钮内
 *    的 SVG 图标一并抹掉（"泄露检查"按钮点击后图标永久消失）。
 * 2. 生成结果同步刷新强度提示，并提示 k-匿名边界。
 */
"use strict";

/**
 * 安全地设置按钮文字：保留按钮内的 <svg> 图标节点，只替换文本部分。
 * 旧实现用 textContent = "..."，会把图标一起删掉。
 */
function setBtnLabel(btn, label) {
    if (!btn) return;
    const svg = btn.querySelector("svg");
    btn.textContent = "";
    if (svg) btn.appendChild(svg);
    btn.appendChild(document.createTextNode(label));
}

document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.getElementById("password");
    const generateBtn = document.getElementById("generate-password-btn");
    const toggleBtn = document.getElementById("toggle-password-visibility");
    const fetchBtn = document.getElementById("fetch-password-btn");
    const leakBtn = document.getElementById("leak-check-btn");
    const modeSel = document.getElementById("pw-mode");
    const hint = document.getElementById("pw-hint");

    /* ---- 生成模式切换：随机字符选项 / 口令短语选项 ---- */
    const randomOpts = document.getElementById("pw-random-opts");
    const phraseOpts = document.getElementById("pw-phrase-opts");
    function syncModeUI() {
        if (!modeSel || !randomOpts || !phraseOpts) return;
        const phrase = modeSel.value === "passphrase";
        randomOpts.hidden = phrase;
        phraseOpts.hidden = !phrase;
    }
    if (modeSel) {
        modeSel.addEventListener("change", syncModeUI);
        syncModeUI();
    }

    function setHint(text, tone) {
        if (!hint) return;
        hint.textContent = text || "";
        hint.className = "pw-hint" + (tone ? " " + tone : "");
    }

    /* ---- 生成密码 ---- */
    if (generateBtn && passwordInput) {
        generateBtn.addEventListener("click", async () => {
            let url = "/generate-password";
            if (modeSel && modeSel.value === "passphrase") {
                const words = document.getElementById("pw-words");
                const caps = document.getElementById("pw-caps");
                const digit = document.getElementById("pw-digit");
                const params = new URLSearchParams({
                    mode: "passphrase",
                    words: words ? (parseInt(words.value, 10) || 5) : 5,
                    caps: caps && caps.checked ? "1" : "0",
                    digit: digit && digit.checked ? "1" : "0",
                });
                url += "?" + params.toString();
            } else {
                const lengthInput = document.getElementById("pw-length");
                const get = (id) => {
                    const el = document.getElementById(id);
                    return el && el.checked ? "1" : "0";
                };
                const params = new URLSearchParams({
                    mode: "random",
                    length: lengthInput ? (parseInt(lengthInput.value, 10) || 16) : 16,
                    upper: get("pw-upper"),
                    lower: get("pw-lower"),
                    digits: get("pw-digits"),
                    symbols: get("pw-symbols"),
                    no_similar: get("pw-no-similar"),
                });
                url += "?" + params.toString();
            }
            const res = await apiFetch(url, { method: "GET" });
            if (res.ok && res.data && res.data.success) {
                passwordInput.value = res.data.password;
                passwordInput.type = "text";
                setHint(res.data.kind === "passphrase"
                    ? "已生成易记口令短语（约 5 词 + 数字，适合需要人工记忆的场景）"
                    : "已生成随机密码（每个选中的字符集至少包含一位）", "ok");
                showToast("已生成随机密码", "success");
            } else {
                setHint("", "");
                showToast((res.data && res.data.error && res.data.error.message)
                    || (res.data && res.data.message) || "生成失败", "error");
            }
        });
    }

    /* ---- 泄露即检（HIBP k-匿名：仅发送 SHA-1 前 5 位） ---- */
    if (leakBtn && passwordInput) {
        leakBtn.addEventListener("click", async () => {
            const pw = passwordInput.value;
            if (!pw) {
                showToast("请先填写密码再检查", "warning");
                return;
            }
            leakBtn.disabled = true;
            setBtnLabel(leakBtn, "检查中…");
            const res = await apiFetch("/records/check-leak", { json: { password: pw } });
            leakBtn.disabled = false;
            setBtnLabel(leakBtn, "泄露检查");
            if (!res.ok) {
                showToast((res.data && res.data.message) || "泄露检查失败", "error");
                setHint("泄露库暂不可用或未开启（不影响记录保存）", "warn");
                return;
            }
            if (res.data && res.data.breached) {
                setHint(`⚠ 该密码出现在公开泄露库中（出现 ${res.data.count} 次），强烈建议更换！`, "bad");
                showToast("该密码已泄露，请立即更换", "error");
            } else {
                setHint("未在公开泄露库中发现该密码（截至本次查询）", "ok");
                showToast("未发现泄露记录", "success");
            }
        });
    }

    if (toggleBtn && passwordInput) {
        toggleBtn.addEventListener("click", () => {
            passwordInput.type = passwordInput.type === "password" ? "text" : "password";
        });
    }

    if (fetchBtn && passwordInput) {
        fetchBtn.addEventListener("click", async () => {
            const id = fetchBtn.dataset.record;
            fetchBtn.disabled = true;
            const res = await apiFetch(`/records/${id}/reveal`, { method: "POST" });
            fetchBtn.disabled = false;
            if (!res.ok || !res.data || !res.data.success) {
                showToast((res.data && res.data.message) || "读取失败", "error");
                return;
            }
            passwordInput.value = res.data.password || "";
            passwordInput.type = "text";
            setHint("已填入当前密码（留空提交则保持不变）", "");
            showToast("已填入当前密码（留空提交则保持不变）", "info");
        });
    }
});
