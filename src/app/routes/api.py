"""表现层：REST API v1（API 密钥认证，供脚本/自动化集成使用）。

认证方式：Authorization: Bearer pmk_xxx
密钥只在创建时展示一次，服务端仅保存 SHA-256 摘要。
所有接口返回统一结构：{"success": true/false, "data"|"error": ...}
"""
import logging
import math

from flask import Blueprint, current_app, jsonify, request

from ..extensions import csrf
from ..services import apikeys as apikey_svc
from ..services import records as record_svc
from ..services.audit import log_operation
from ..services.crypto import CryptoError
from ..utils.validators import (RECORD_SEARCH_FIELDS, ValidationError,
                                clean_record_form, clean_str, valid_port)

bp = Blueprint("api", __name__, url_prefix="/api/v1")
csrf.exempt(bp)  # API 使用 Bearer 密钥认证而非 Cookie，不适用 CSRF
logger = logging.getLogger(__name__)

# v0.1.0 修复 S-04：reveal=true 会一次返回全部明文口令，此前无限流，
# 与 Web 端"查看密码 60 次/分钟"明显不对等。此处按用户维度限流。
# v0.1.0 第六轮修复 BU-03：原实现按"请求次数"计量，而单请求 per_page
# 最大 100，密钥泄露时每分钟最多可拖走 60×100=6000 条明文，
# 与注释宣称的"最多 60 条"差 100 倍。现改为：
#   ① 明文本次返回条数从额度里扣减（按条数计量，与 Web 端"每次 1 条"对齐）；
#   ② reveal=true 时单页条数压到 REVEAL_MAX_PER_PAGE（20）；
#   ③ 单次返回 ≥50 条明文时补一条审计告警。
REVEAL_LIMIT_PER_MINUTE = 60       # 每分钟可返回的明条文数上限
REVEAL_MAX_PER_PAGE = 20           # reveal=true 时的单页条数硬上限
REVEAL_AUDIT_ALERT_THRESHOLD = 50  # 单次返回达到该条数即记审计告警


def _error(message: str, status: int, code: str = "bad_request"):
    return jsonify(success=False, error={"code": code, "message": message}), status


def _require_api_user():
    """认证拦截：返回 user_id 或 (错误响应, 状态码)。"""
    user_id, err = apikey_svc.authenticate_api_key(request)
    if user_id is None:
        return None, _error(err or "认证失败", 401, "unauthorized")
    return user_id, None


@bp.get("/records")
def list_records():
    user_id, err = _require_api_user()
    if err:
        return err
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 20))))
    except (TypeError, ValueError):
        return _error("page/per_page 必须是整数", 400)
    search = (request.args.get("search") or "").strip()[:100]
    field = request.args.get("field", "device_model")
    if field not in RECORD_SEARCH_FIELDS:
        field = "device_model"
    project_id = request.args.get("project_id", type=int)

    include_pw = request.args.get("reveal") == "true"
    if include_pw:
        # v0.1.0 第六轮修复 BU-03：明文批量导出按"条数"计量。
        # 单页条数压到 REVEAL_MAX_PER_PAGE，再按本次将返回的条数预扣额度，
        # 杜绝"每分钟 60 次请求 × 每页 100 条 = 6000 条明文"的外泄面。
        per_page = min(per_page, REVEAL_MAX_PER_PAGE)

    rows, total = record_svc.list_records(
        user_id, search, field, project_id, page, per_page)

    if include_pw:
        # 先按本次实际返回条数扣减额度（不足则整包拒绝，不返回部分明文）
        from ..security.ratelimit import limiter

        cost = max(1, len(rows))
        for _ in range(cost):
            ok, wait = limiter.hit(f"api:reveal:user:{user_id}",
                                   REVEAL_LIMIT_PER_MINUTE, 60)
            if not ok:
                return _error(
                    f"明文查询额度不足（每分钟 {REVEAL_LIMIT_PER_MINUTE} 条），"
                    f"请 {wait} 秒后再试", 429, "rate_limited")
        if cost >= REVEAL_AUDIT_ALERT_THRESHOLD:
            log_operation(user_id, "api_reveal_bulk", "record", None,
                          f"API 单次返回 {cost} 条明文口令（阈值 "
                          f"{REVEAL_AUDIT_ALERT_THRESHOLD}）")
    items = []
    for row in rows:
        plain = None
        if include_pw:
            try:
                plain = record_svc.decrypt_record_password(row) if row["password"] else ""
            except CryptoError:
                plain = None
        items.append(record_svc.record_to_api_dict(row, plain))

    if include_pw:
        log_operation(user_id, "export", "system", None,
                      f"API 列表查询（含明文密码 {len(items)} 条）")
    return jsonify(success=True, data={
        "items": items, "total": total, "page": page, "per_page": per_page,
        "pages": max(1, math.ceil(total / per_page)),
    })


@bp.post("/records")
def create_record():
    user_id, err = _require_api_user()
    if err:
        return err
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("请求体必须是 JSON 对象", 400)
    try:
        data = _clean_api_payload(body)
        record_id = record_svc.create_record(user_id, data, None, None)
    except ValidationError as exc:  # 含项目归属校验（v0.1.0）
        return _error(str(exc), 422, "validation_failed")
    row = record_svc.get_record(record_id)
    return jsonify(success=True,
                   data=record_svc.record_to_api_dict(row)), 201


@bp.get("/records/<int:record_id>")
def get_record(record_id):
    user_id, err = _require_api_user()
    if err:
        return err
    row = record_svc.get_record(record_id)
    perm = record_svc.get_record_permission(row, user_id)
    if row is None or perm is None or row["deleted_at"] is not None:
        return _error("记录不存在", 404, "not_found")
    plain = None
    if request.args.get("reveal") == "true":
        try:
            plain = record_svc.decrypt_record_password(row) if row["password"] else ""
            log_operation(user_id, "reveal", "password", record_id,
                          f"API 查看密码: {row['device_model']}")
        except CryptoError:
            return _error("密码无法解密（密钥可能已变更）", 409, "crypto_error")
    return jsonify(success=True,
                   data=record_svc.record_to_api_dict(row, plain))


@bp.patch("/records/<int:record_id>")
def update_record(record_id):
    user_id, err = _require_api_user()
    if err:
        return err
    row = record_svc.get_record(record_id)
    perm = record_svc.get_record_permission(row, user_id)
    if row is None or perm is None or row["deleted_at"] is not None:
        return _error("记录不存在", 404, "not_found")
    if perm not in ("owner", "shared_edit"):
        return _error("无编辑权限", 403, "forbidden")

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("请求体必须是 JSON 对象", 400)
    if perm != "owner":
        # 共享可编辑者无权变更记录的项目归属（v0.1.0：忽略其 project_id 字段）
        body = {k: v for k, v in body.items() if k != "project_id"}
    try:
        data = _clean_api_payload(body, partial=True, base_row=row)
        record_svc.update_record(row, data, None, None, user_id,
                                 keep_old_password=not data.get("password"))
    except ValidationError as exc:  # 含项目归属校验（v0.1.0）
        return _error(str(exc), 422, "validation_failed")
    fresh = record_svc.get_record(record_id)
    return jsonify(success=True, data=record_svc.record_to_api_dict(fresh))


@bp.delete("/records/<int:record_id>")
def delete_record(record_id):
    user_id, err = _require_api_user()
    if err:
        return err
    row = record_svc.get_record(record_id)
    if row is None or row["deleted_at"] is not None:
        return _error("记录不存在", 404, "not_found")
    if row["user_id"] != user_id:
        return _error("无删除权限", 403, "forbidden")
    record_svc.soft_delete_record(row, user_id)
    return jsonify(success=True, data={"id": record_id, "deleted": True})


def _clean_api_payload(body: dict, partial: bool = False, base_row=None) -> dict:
    """API 载荷校验：与表单同一套规则；partial 模式未提供的字段沿用原值。"""
    def pick(name: str) -> str | None:
        return body[name] if name in body else None

    if partial and base_row is not None:
        merged = {k: base_row[k] for k in
                  ("device_model", "serial_number", "location", "node_name",
                   "ip_address", "username", "port", "access_method",
                   "remark1", "remark2")}
        merged["password"] = ""
        merged["project_id"] = base_row["project_id"]
        for key in ("device_model", "serial_number", "location", "node_name",
                    "ip_address", "username", "port", "access_method",
                    "remark1", "remark2", "password"):
            val = pick(key)
            if val is not None:
                merged[key] = val
        if "project_id" in body:
            merged["project_id"] = body["project_id"]
    else:
        merged = {key: (pick(key) or "") for key in
                  ("device_model", "serial_number", "location", "node_name",
                   "ip_address", "username", "port", "access_method",
                   "remark1", "remark2", "password")}
        merged["project_id"] = body.get("project_id")

    result = {
        "device_model": clean_str(merged["device_model"], "设备型号", 100,
                                  required=not partial or "device_model" in body),
        "serial_number": clean_str(merged["serial_number"], "序列号", 100),
        "location": clean_str(merged["location"], "位置", 100),
        "node_name": clean_str(merged["node_name"], "节点名", 100),
        "ip_address": clean_str(merged["ip_address"], "IP地址", 50),
        "username": clean_str(merged["username"], "用户名", 100),
        "port": clean_str(merged["port"], "端口", 20),
        "access_method": clean_str(merged["access_method"], "访问方式", 50),
        "remark1": clean_str(merged["remark1"], "备注1", 5000),
        "remark2": clean_str(merged["remark2"], "备注2", 5000),
        "password": (merged.get("password") or "").strip(),
        "project_id": merged.get("project_id"),
    }
    if not valid_port(result["port"]):
        raise ValidationError("端口必须是 1-65535 之间的数字")
    pid = result["project_id"]
    if pid in ("", None, 0):
        result["project_id"] = None
    else:
        try:
            result["project_id"] = int(pid)
        except (TypeError, ValueError):
            result["project_id"] = None
    return result
