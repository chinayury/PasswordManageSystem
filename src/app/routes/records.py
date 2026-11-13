"""表现层：密码记录路由（主页/增删改查/回收站/附件/导入导出/密码工具）。"""
import hashlib
import logging
import math
import os

from flask import (Blueprint, abort, current_app, flash, jsonify,
                   redirect, render_template, request, send_file, url_for)
from flask_login import current_user, login_required

from ..security.ratelimit import limiter
from ..services import excelio, hibp, projects as project_svc
from ..services import records as record_svc
from ..services.audit import log_operation
from ..services.crypto import (CryptoError, generate_passphrase,
                               generate_secure_password)
from ..utils.validators import (RECORD_SEARCH_FIELDS, ValidationError,
                                clean_record_form)

bp = Blueprint("records", __name__)
logger = logging.getLogger(__name__)


def _int_arg(name: str, default: int = 1) -> int:
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


@bp.route("/")
@login_required
def index():
    search = (request.args.get("search") or "").strip()[:100]
    field = request.args.get("filter_field", "device_model")
    if field not in RECORD_SEARCH_FIELDS:
        field = "device_model"
    project_id = _int_arg("filter_project", 0)
    # 即将到期快捷筛选（借鉴 Padloc 快捷筛选 Chips）：30 天内到期或已过期
    filter_expiring = (request.args.get("filter_expiring", "") or "") in ("1", "true")
    page = max(1, _int_arg("page", 1))
    per_page = current_app.config["RECORDS_PER_PAGE"]

    rows, total = record_svc.list_records(
        current_user.id, search, field, project_id or None, page, per_page,
        expiring=filter_expiring)
    records = record_svc.mask_record_list(rows)
    pages = max(1, math.ceil(total / per_page))
    all_projects = project_svc.user_projects(current_user.id)

    return render_template(
        "records/index.html",
        records=records, total=total, page=page, pages=pages,
        search_query=search, filter_field=field,
        all_projects=all_projects, filter_project=project_id,
        filter_expiring=filter_expiring,
    )


@bp.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        try:
            data = clean_record_form(request.form)
            record_svc.create_record(
                current_user.id, data,
                request.files.get("file1"), request.files.get("file2"))
            flash("记录添加成功！", "success")
            return redirect(url_for("records.index"))
        except ValidationError as exc:
            flash(str(exc), "danger")
        except Exception:  # noqa: BLE001
            logger.exception("添加记录失败")
            flash("保存失败，请稍后重试或联系管理员", "danger")

    return render_template(
        "records/add.html",
        default_password=generate_secure_password(),
        projects=project_svc.user_projects(current_user.id),
    )


def _load_editable_record(record_id: int):
    """加载记录并校验编辑权限（所有者 或 被共享且 can_edit）。"""
    record = record_svc.get_record(record_id)
    if record is None or record["deleted_at"] is not None:
        flash("记录不存在或已在回收站中！", "danger")
        return None, None
    perm = record_svc.get_record_permission(record, current_user.id)
    if perm not in ("owner", "shared_edit"):
        flash("无权限编辑该记录！", "danger")
        return None, None
    return record, perm


@bp.route("/edit/<int:record_id>", methods=["GET", "POST"])
@login_required
def edit(record_id):
    record, perm = _load_editable_record(record_id)
    if record is None:
        return redirect(url_for("records.index"))

    # 共享可编辑者只能改内容，不能动附件/项目归属
    is_owner = perm == "owner"

    if request.method == "POST":
        try:
            data = clean_record_form(request.form)
            if not is_owner:
                data["project_id"] = record["project_id"]
            record_svc.update_record(
                record, data,
                request.files.get("file1") if is_owner else None,
                request.files.get("file2") if is_owner else None,
                current_user.id,
                keep_old_password=not data["password"],
            )
            flash("记录更新成功！", "success")
            if is_owner:
                return redirect(url_for("records.index"))
            return redirect(url_for("shares.shared_with_me"))
        except ValidationError as exc:
            flash(str(exc), "danger")
        except Exception:  # noqa: BLE001
            logger.exception("更新记录失败 id=%s", record_id)
            flash("保存失败，请稍后重试或联系管理员", "danger")
        return redirect(url_for("records.edit", record_id=record_id))

    record_dict = dict(record)
    record_dict["permission"] = perm
    try:
        record_dict["plain_password"] = (
            record_svc.decrypt_record_password(record) if record["password"] else "")
        record_dict["password_broken"] = False
    except CryptoError:
        record_dict["plain_password"] = ""
        record_dict["password_broken"] = True

    return render_template(
        "records/edit.html",
        record=record_dict,
        projects=project_svc.user_projects(record["user_id"]) if is_owner else [],
    )


@bp.route("/delete/<int:record_id>", methods=["POST"])
@login_required
def delete(record_id):
    record = record_svc.get_record(record_id)
    if record is None:
        flash("记录不存在！", "danger")
        return redirect(url_for("records.index"))
    if record["user_id"] != current_user.id and not current_user.is_admin:
        flash("无权限删除该记录！", "danger")
        return redirect(url_for("records.index"))
    if record["deleted_at"] is not None:
        flash("该记录已在回收站中！", "warning")
        return redirect(url_for("records.index"))
    record_svc.soft_delete_record(record, current_user.id)
    flash("记录已移入回收站（30 天内可恢复）", "success")
    return redirect(url_for("records.index"))


@bp.route("/records/<int:record_id>/reveal", methods=["POST"])
@login_required
def reveal(record_id):
    """按需解密查看密码（替代旧版把全部明文密码渲染进列表页 HTML 的做法）。"""
    ok, wait = limiter.hit(f"reveal:{current_user.id}", 60, 60)
    if not ok:
        return jsonify(success=False, message=f"操作过于频繁，请 {wait} 秒后再试"), 429

    record = record_svc.get_record(record_id)
    perm = record_svc.get_record_permission(record, current_user.id)
    if record is None or perm is None or record["deleted_at"] is not None:
        return jsonify(success=False, message="记录不存在或无权限"), 404
    try:
        password = record_svc.decrypt_record_password(record)
    except CryptoError:
        return jsonify(success=False,
                       message="该记录密码无法解密（加密密钥可能已变更）"), 409

    log_operation(current_user.id, "reveal", "password", record_id,
                  f"查看密码: {record['device_model']}"
                  + ("（共享记录）" if perm != "owner" else ""))
    return jsonify(success=True, password=password if password else "")


@bp.route("/records/<int:record_id>/attachment/<int:which>")
@login_required
def download_attachment(record_id, which):
    """附件安全下载（修复旧版直接拼接本地路径导致 404 的问题）。"""
    if which not in (1, 2):
        abort(404)
    record = record_svc.get_record(record_id)
    perm = record_svc.get_record_permission(record, current_user.id)
    if record is None or perm is None:
        abort(404)
    path = record_svc.attachment_disk_path(record, which)
    if path is None:
        flash("附件文件不存在（可能已被移动或清理）", "warning")
        return redirect(request.referrer or url_for("records.index"))

    from flask import send_from_directory

    directory = os.path.dirname(path)
    filename = os.path.basename(path)
    log_operation(current_user.id, "download", "attachment", record_id,
                  f"下载附件: {filename}")
    return send_from_directory(
        directory, filename, as_attachment=True,
        download_name=_friendly_name(record, which, filename))


def _friendly_name(record, which: int, stored_name: str) -> str:
    """下载时还原可读文件名（截掉 uuid 前缀）。"""
    stored = record[f"file{which}_path"] or stored_name
    base = os.path.basename(stored)
    if base.startswith("legacy") or len(base) < 40:
        return base or stored_name
    # uuid(32位hex)_原名.ext -> 原名.ext
    parts = base[33:] if base[32] == "_" else base
    return parts or stored_name


@bp.route("/recycle-bin")
@login_required
def recycle_bin():
    page = max(1, _int_arg("page", 1))
    per_page = current_app.config["RECORDS_PER_PAGE"]
    rows, total = record_svc.list_records(
        current_user.id, page=page, per_page=per_page, include_deleted=True)
    records = record_svc.mask_record_list(rows)
    pages = max(1, math.ceil(total / per_page))
    return render_template("records/recycle_bin.html",
                           records=records, total=total, page=page, pages=pages)


@bp.route("/records/<int:record_id>/restore", methods=["POST"])
@login_required
def restore_record(record_id):
    record = record_svc.get_record(record_id)
    if record is None or record["user_id"] != current_user.id:
        flash("记录不存在或无权限！", "danger")
    elif record["deleted_at"] is None:
        flash("该记录不在回收站中", "warning")
    else:
        record_svc.restore_record(record, current_user.id)
        flash("记录已恢复！", "success")
    return redirect(url_for("records.recycle_bin"))


@bp.route("/records/<int:record_id>/purge", methods=["POST"])
@login_required
def purge_record(record_id):
    record = record_svc.get_record(record_id)
    if record is None or (record["user_id"] != current_user.id
                          and not current_user.is_admin):
        flash("记录不存在或无权限！", "danger")
    elif record["deleted_at"] is None:
        flash("请先将记录移入回收站，再彻底删除", "warning")
    else:
        record_svc.purge_record(record, current_user.id)
        flash("记录已彻底删除，无法恢复", "success")
    return redirect(url_for("records.recycle_bin"))


@bp.route("/generate-password")
@login_required
def generate_password():
    """密码生成器：random（长度/字符集/排除易混淆）与 passphrase 两种模式。

    参数异常一律 400 明确报错（不 500）；选项开关接受 1/true/yes。
    """
    try:
        if request.args.get("mode", "random") == "passphrase":
            words = int(request.args.get("words", 5))
            return jsonify(
                success=True, kind="passphrase",
                password=generate_passphrase(
                    words,
                    separator=request.args.get("sep", "-"),
                    capitalize=request.args.get("caps", "1") in ("1", "true", "yes"),
                    append_digit=request.args.get("digit", "1") in ("1", "true", "yes"),
                ))
        length = int(request.args.get("length", 16))
        if not 8 <= length <= 64:
            return jsonify(success=False, message="长度必须在 8-64 之间"), 400

        def _opt(name: str) -> bool:
            return request.args.get(name, "1") in ("1", "true", "yes")

        return jsonify(
            success=True, kind="random",
            password=generate_secure_password(
                length, _opt("upper"), _opt("lower"), _opt("digits"),
                _opt("symbols"), no_similar=_opt("no_similar")))
    except (TypeError, ValueError):
        return jsonify(success=False, message="参数格式不正确"), 400


@bp.route("/records/check-leak", methods=["POST"])
@login_required
def check_leak():
    """单条口令泄露即检（借鉴 Bitwarden 健康报告的单条即检场景）。

    复用 HIBP k-匿名服务：仅发送口令 SHA-1 前 5 位，明文只存在于
    本次请求内存，绝不落库、绝不写日志；限流 10 次/分钟/用户。
    """
    ok, wait = limiter.hit(f"leakchk:{current_user.id}", 10, 60)
    if not ok:
        return jsonify(success=False, message=f"请求过于频繁，请 {wait} 秒后再试"), 429

    payload = request.get_json(silent=True) or {}
    pw = str(payload.get("password") or "")
    if not pw or len(pw) > 1024:
        return jsonify(success=False, message="请先填写密码再检查"), 400

    client = hibp.client_from_config()
    if client is None:
        return jsonify(
            success=False, available=False,
            message="泄露查询未开启：需管理员在配置中启用 HIBP_ENABLED"), 503
    counts, available = client.query_counts([pw])
    if not available:
        return jsonify(success=False, available=False,
                       message="泄露库暂时不可用，请稍后再试"), 503
    count = counts.get(hashlib.sha1(pw.encode("utf-8")).hexdigest().upper(), 0)
    return jsonify(success=True, breached=count > 0, count=count)


@bp.route("/export/<any(xlsx, csv):fmt>")
@login_required
def export_data(fmt):
    try:
        buf, mimetype, filename = excelio.build_export(current_user.id, fmt)
    except ValidationError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("records.index"))
    return send_file(buf, mimetype=mimetype, as_attachment=True,
                     download_name=filename)


@bp.route("/import", methods=["GET", "POST"])
@login_required
def import_data():
    if request.method == "POST":
        file = request.files.get("file")
        try:
            rows = excelio.read_import_file(file)
            result = excelio.import_rows(current_user.id, rows)
            flash(
                f"导入完成：成功 {result['imported']} 条，"
                f"跳过 {result['skipped']} 条", "success")
            for err in result["errors"]:
                flash(err, "warning")
        except ValidationError as exc:
            flash(str(exc), "danger")
        except Exception:  # noqa: BLE001
            logger.exception("导入失败")
            flash("导入失败：文件无法解析，请使用标准模板", "danger")
    return render_template(
        "records/import.html",
        import_max_rows=current_app.config["IMPORT_MAX_ROWS"],
        import_max_mb=current_app.config["IMPORT_MAX_FILE_MB"],
    )


@bp.route("/download-example")
@login_required
def download_example():
    """下载导入模板。

    v0.1.0 修复 B-04：此前直接 send_file 一个并不存在的静态文件
    （app/static/files/password_import_template.xlsx），该目录从未入库，
    导致"下载模板"必然 500——而导入失败文案恰恰引导用户去点它。
    现改为按 excelio 的同一套表头约定**动态生成**模板（含一行示例），
    从根本上保证模板与实际导入校验永不脱节。
    """
    import io

    try:
        content = excelio.build_import_template()
    except Exception:  # noqa: BLE001
        logger.exception("生成导入模板失败")
        flash("模板生成失败，请参考页面上的表头说明手动构造", "danger")
        # v0.1.0 第二轮修复 FU-09：原 url_for("records.import_records")
        # 指向不存在的端点（实际端点为 records.import_data），模板生成
        # 失败时本应友好跳回导入页，却会先抛 BuildError 变 500。
        return redirect(url_for("records.import_data"))
    return send_file(
        io.BytesIO(content),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="password_import_template.xlsx",
    )
