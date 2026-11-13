"""表现层：记录共享路由。"""
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..services import records as record_svc
from ..services import shares as share_svc
from ..utils.validators import ValidationError

bp = Blueprint("shares", __name__)


@bp.route("/share-record/<int:record_id>", methods=["GET", "POST"])
@login_required
def share_record(record_id):
    record = record_svc.get_record(record_id)
    if record is None or record["user_id"] != current_user.id \
            or record["deleted_at"] is not None:
        flash("记录不存在或无权限共享！", "danger")
        return redirect(url_for("records.index"))

    if request.method == "POST":
        try:
            expires_hours = int(request.form.get("expires_hours", 0) or 0)
            if expires_hours < 0 or expires_hours > 24 * 365:
                raise ValidationError("有效期参数不合法")
            share_svc.share_record(
                record_id, current_user.id,
                request.form.get("shared_username", ""),
                bool(request.form.get("can_edit")),
                expires_hours,
            )
            flash("记录共享成功！", "success")
            return redirect(url_for("records.index"))
        except ValidationError as exc:
            flash(str(exc), "danger")
        except ValueError:
            flash("有效期参数不合法", "danger")

    shared_users = share_svc.list_shares_for_record(record_id)
    return render_template("shares/share.html",
                           record=record, shared_users=shared_users)


@bp.route("/share-record/<int:record_id>/revoke/<int:share_id>", methods=["POST"])
@login_required
def revoke_share(record_id, share_id):
    try:
        share_svc.revoke_share(share_id, record_id, current_user.id)
        flash("已取消该共享！", "success")
    except ValidationError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("shares.share_record", record_id=record_id))


@bp.route("/shared-with-me")
@login_required
def shared_with_me():
    rows = share_svc.shared_with_me(current_user.id)
    records = []
    for row in rows:
        item = dict(row)
        item.pop("password", None)
        # 修复：此前恒为 True，未设密码的记录也会显示"查看/复制"按钮
        item["has_password"] = bool(row["password"])
        records.append(item)
    return render_template("shares/shared_with_me.html", records=records)
