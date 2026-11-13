"""表现层：项目管理路由。"""
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..services import projects as project_svc
from ..utils.validators import ValidationError

bp = Blueprint("projects", __name__)


@bp.route("/projects")
@login_required
def list_projects():
    projects = project_svc.list_projects_with_counts(
        current_user.id, admin_view=False)
    return render_template("projects/list.html", projects=projects)


@bp.route("/projects/add", methods=["POST"])
@login_required
def add_project():
    try:
        project_svc.create_project(
            current_user.id,
            request.form.get("name", ""),
            request.form.get("type", ""),
        )
        flash("项目添加成功！", "success")
    except ValidationError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("projects.list_projects"))


@bp.route("/projects/<int:project_id>/rename", methods=["POST"])
@login_required
def rename_project(project_id):
    """v0.1.0 新增（修复 F-02）：重命名项目。

    此前项目只有"新增/删除"两个入口，名错且已有关联记录的项目
    （删除被业务规则拒绝）永久无法修正。重命名不触碰关联记录，
    仅创建者或管理员可操作。
    """
    project = project_svc.get_project(project_id)
    if project is None:
        flash("项目不存在！", "danger")
        return redirect(url_for("projects.list_projects"))
    if project["owner_id"] != current_user.id and not current_user.is_admin:
        flash("无权限修改该项目！只有创建者或管理员可以操作。", "danger")
        return redirect(url_for("projects.list_projects"))
    try:
        # v0.1.0 第六轮修复 BU-12：传入操作者 id，审计日志归因到操作者
        # 而非项目 owner（管理员代改他人项目时不再显示成 owner 自己改的）
        project_svc.rename_project(project, request.form.get("name", ""),
                                   operator_id=current_user.id)
        flash("项目已重命名！", "success")
    except ValidationError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("projects.list_projects"))


@bp.route("/projects/delete/<int:project_id>", methods=["POST"])
@login_required
def delete_project(project_id):
    project = project_svc.get_project(project_id)
    if project is None:
        flash("项目不存在！", "danger")
        return redirect(url_for("projects.list_projects"))
    if project["owner_id"] != current_user.id and not current_user.is_admin:
        flash("无权限删除该项目！只有创建者或管理员可以删除。", "danger")
        return redirect(url_for("projects.list_projects"))
    try:
        project_svc.delete_project(project, current_user.id, current_user.is_admin)
        flash("项目已删除！", "success")
    except ValidationError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("projects.list_projects"))
