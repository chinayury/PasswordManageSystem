/**
 * 项目分组页：重命名折叠表单切换（v0.1.0 新增，F-02 前端半边）。
 *
 * 每行一个「重命名」按钮 + 一个隐藏的内联表单。点击按钮展开该行的
 * 表单并聚焦输入框；再次点击或按 Esc 收起。展开时自动收起其它行，
 * 避免多行同时展开把表格撑乱。
 */
"use strict";

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".rename-toggle").forEach(btn => {
        const form = document.getElementById(btn.dataset.target);
        if (!form) return;
        const input = form.querySelector('input[name="name"]');

        btn.addEventListener("click", () => {
            const willOpen = form.hidden;
            // 先收起其它所有行
            document.querySelectorAll(".rename-form").forEach(f => {
                if (f !== form) f.hidden = true;
            });
            document.querySelectorAll(".rename-toggle").forEach(b => {
                if (b !== btn) b.setAttribute("aria-expanded", "false");
            });
            form.hidden = !willOpen;
            btn.setAttribute("aria-expanded", willOpen ? "true" : "false");
            if (willOpen && input) {
                input.focus();
                input.select();
            }
        });

        form.addEventListener("keydown", e => {
            if (e.key === "Escape") {
                form.hidden = true;
                btn.setAttribute("aria-expanded", "false");
                btn.focus();
            }
        });
    });
});
