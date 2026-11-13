/**
 * 键盘快捷键（v0.1.0 第六轮，借鉴 GE-02 · password-xl）
 * --------------------------------------------------------------------------
 * 统一快捷键表（仅在非输入态生效，不干扰表单填写）：
 *   Alt + N   新建记录（在记录列表/回收站/健康体检等有"新增"入口的页面）
 *   Ctrl + F  聚焦页面第一个搜索框
 *   /         聚焦搜索框（搜索框未聚焦时；与 GitHub 一致）
 *   Alt + L   跳到修改密码页（"锁定"语义：本系统为服务端会话，无前端锁定态）
 *   Esc       收起已展开的内联表单（项目重命名等）
 *
 * 实现约定：
 * - 全部通过 document 级 keydown 委托，不在模板里写 onkeydown（CSP 合规）；
 * - 只在 event.target 不是 input/textarea/select 且未按修饰组合冲突时响应；
 * - 找不到对应元素时静默返回，不弹错误。
 */
"use strict";

(function () {
    /** 当前焦点是否在可输入元素里（此时不拦截单键快捷键）。 */
    function inEditable(el) {
        if (!el) return false;
        const tag = (el.tagName || "").toLowerCase();
        return tag === "input" || tag === "textarea" || tag === "select"
            || el.isContentEditable === true;
    }

    /** 页面第一个可见的搜索类输入框。 */
    function findSearchBox() {
        const sels = [
            'input[type="search"]',
            'input[name="search"]',
            'input#search',
            'input[name="keyword"]',
        ];
        for (const sel of sels) {
            const nodes = document.querySelectorAll(sel);
            for (const n of nodes) {
                if (n.offsetParent !== null) return n;
            }
        }
        return null;
    }

    /** 页面第一个"新增/新建"入口（按优先级取主操作按钮）。 */
    function findAddButton() {
        const sels = [
            'a[href$="/add"]',
            '.page-actions a.btn-primary',
            '.page-actions a.btn-secondary',
        ];
        for (const sel of sels) {
            const nodes = document.querySelectorAll(sel);
            for (const n of nodes) {
                if (n.offsetParent !== null) return n;
            }
        }
        return null;
    }

    /** 收起页面上所有展开的内联表单（项目重命名等）。 */
    function collapseInlineForms() {
        document.querySelectorAll(".rename-form:not([hidden])").forEach(f => {
            f.hidden = true;
        });
        document.querySelectorAll("[aria-expanded='true']").forEach(b => {
            b.setAttribute("aria-expanded", "false");
        });
    }

    function focusAndSelect(el) {
        if (!el) return false;
        el.focus();
        if (typeof el.select === "function") el.select();
        return true;
    }

    document.addEventListener("keydown", function (e) {
        // 不拦截带 Ctrl/Meta 的组合键（那是浏览器/系统快捷键域），
        // 唯独 Ctrl+F 需要接管以实现"聚焦站内搜索"。
        const mod = e.ctrlKey || e.metaKey;

        // Ctrl+F：聚焦站内搜索框
        if (mod && (e.key === "f" || e.key === "F")) {
            const box = findSearchBox();
            if (box) {
                e.preventDefault();
                focusAndSelect(box);
            }
            return;
        }

        // Alt+N：新建；Alt+L：口令轮换页
        if (e.altKey && !mod) {
            if (e.key === "n" || e.key === "N") {
                const btn = findAddButton();
                if (btn) { e.preventDefault(); btn.click(); }
                return;
            }
            if (e.key === "l" || e.key === "L") {
                const link = document.querySelector('a[href$="/change-password"]');
                if (link) { e.preventDefault(); link.click(); }
                return;
            }
        }

        // 单键快捷键：输入态不拦截
        if (mod || e.altKey || e.shiftKey) return;
        if (inEditable(e.target)) return;

        if (e.key === "/") {
            const box = findSearchBox();
            if (box) { e.preventDefault(); focusAndSelect(box); }
            return;
        }
        if (e.key === "Escape") {
            collapseInlineForms();
        }
    });
}());
