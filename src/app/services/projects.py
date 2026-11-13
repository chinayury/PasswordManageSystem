"""业务层：项目管理。"""
from ..db import get_db
from ..utils.validators import PROJECT_TYPES, ValidationError, clean_str


def list_projects_with_counts(user_id: int | None = None, admin_view: bool = False):
    """项目列表 + 关联密码数（单条聚合查询，修复旧版 N+1 性能问题）。
    普通用户仅见自己创建的项目；管理员可见全部。"""
    conn = get_db()
    if admin_view:
        rows = conn.execute(
            "SELECT p.*, u.username AS owner_name,"
            " (SELECT COUNT(*) FROM passwords pw"
            "  WHERE pw.project_id = p.id AND pw.deleted_at IS NULL) AS count"
            " FROM projects p LEFT JOIN users u ON p.owner_id = u.id"
            " ORDER BY p.id DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT p.*, u.username AS owner_name,"
            " (SELECT COUNT(*) FROM passwords pw"
            "  WHERE pw.project_id = p.id AND pw.deleted_at IS NULL) AS count"
            " FROM projects p LEFT JOIN users u ON p.owner_id = u.id"
            " WHERE p.owner_id = ? ORDER BY p.id DESC",
            (user_id,),
        ).fetchall()
    return rows


def user_projects(user_id: int):
    return get_db().execute(
        "SELECT * FROM projects WHERE owner_id = ? ORDER BY name ASC", (user_id,)
    ).fetchall()


def create_project(user_id: int, name: str, ptype: str) -> None:
    from .audit import log_operation

    name = clean_str(name, "项目名称", 100, required=True)
    ptype = clean_str(ptype, "项目类型", 20, required=True)
    if ptype not in PROJECT_TYPES:
        raise ValidationError("项目类型不合法")

    conn = get_db()
    dup = conn.execute(
        "SELECT id FROM projects WHERE owner_id=? AND name=?", (user_id, name)
    ).fetchone()
    if dup:
        raise ValidationError("已存在同名项目")
    cur = conn.execute(
        "INSERT INTO projects (name, type, owner_id) VALUES (?,?,?)",
        (name, ptype, user_id),
    )
    conn.commit()
    log_operation(user_id, "create", "project", cur.lastrowid, f"创建项目: {name}")


def get_project(project_id: int):
    return get_db().execute(
        "SELECT * FROM projects WHERE id=?", (project_id,)
    ).fetchone()


def rename_project(project, name: str, operator_id: int | None = None) -> None:
    """重命名项目（v0.1.0 新增，修复 F-02）。

    仅改名称，不触碰关联的密码记录。同一创建者下名称不可与既有项目重复。

    v0.1.0 第六轮修复 BU-12：旧实现审计日志记 `project["owner_id"]`，
    管理员代改他人项目时日志显示"是 owner 自己改的"，代操作事实丢失
    （同文件 delete_project 用的就是 operator_id，两处口径不一致）。
    现新增 operator_id 参数并以其记日志；为兼容旧调用方，缺省时回退
    为 owner_id（行为与旧版一致）。
    """
    from .audit import log_operation

    name = clean_str(name, "项目名称", 100, required=True)
    conn = get_db()
    dup = conn.execute(
        "SELECT id FROM projects WHERE owner_id=? AND name=? AND id!=?",
        (project["owner_id"], name, project["id"]),
    ).fetchone()
    if dup:
        raise ValidationError("已存在同名项目")
    old_name = project["name"]
    if old_name == name:
        return  # 名称未变：无需写库、无需记日志
    conn.execute("UPDATE projects SET name=? WHERE id=?", (name, project["id"]))
    conn.commit()
    # BU-12：归因到操作者；管理员代操作时在明细里注明"代 owner 操作"
    actor = operator_id if operator_id is not None else project["owner_id"]
    suffix = (f"（代 owner id={project['owner_id']} 操作）"
              if actor != project["owner_id"] else "")
    log_operation(actor, "update", "project", project["id"],
                  f"项目重命名: {old_name} -> {name}{suffix}")


def delete_project(project, operator_id: int, is_admin: bool) -> None:
    """删除项目：仅创建者或管理员；有任何记录（含回收站）引用时拒绝，
    避免外键置空导致记录失去归属。"""
    from .audit import log_operation

    conn = get_db()
    used = conn.execute(
        "SELECT COUNT(*) AS c FROM passwords WHERE project_id=?", (project["id"],)
    ).fetchone()["c"]
    if used:
        raise ValidationError(
            f"该项目下仍有 {used} 条密码记录（含回收站），请先处理这些记录")
    conn.execute("DELETE FROM projects WHERE id=?", (project["id"],))
    conn.commit()
    log_operation(operator_id, "delete", "project", project["id"],
                  f"删除项目: {project['name']}（操作者{'为管理员' if is_admin else '为创建者'}）")
