"""业务层：Excel/CSV 导入导出（openpyxl 直读直写，替代旧版 pandas 重依赖）。

导出直接写入内存 BytesIO 流式下发——根治旧版"导出文件落在工作目录
且永不清理"的问题，同时保证导出内容与列结构对导入完全友好。
v0.1.0：导入表头按真实单元格内容校验（旧实现恒通过）；导出统一
做公式注入防护（CSV 公式杀手的业界标准处置）。
"""
import csv
import io
import logging

from flask import current_app
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter
from werkzeug.datastructures import FileStorage

from ..db import get_db
from ..utils.timefmt import utcnow_str
from ..utils.validators import ValidationError, valid_port
from . import records as record_svc
from .crypto import CryptoError, crypto

logger = logging.getLogger(__name__)

IMPORT_COLUMNS = [
    "device_model", "serial_number", "location", "node_name", "ip_address",
    "username", "password", "port", "access_method", "project_name", "remark1", "remark2",
]
EXPORT_COLUMNS = IMPORT_COLUMNS  # 导入导出列完全对称，可往返

# 在 Excel/WPS 中会被解释为公式的首字符（OWASP CSV Injection 标准清单）
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# 模板示例行（第 2 行）：与 IMPORT_COLUMNS 一一对应，仅作格式示范。
# 口令列留空——模板不应诱导用户把真实口令写进一个会到处流传的文件。
_TEMPLATE_SAMPLE = {
    "device_model": "示例：Huawei CE6850",
    "serial_number": "示例：2102351A2B3C",
    "location": "示例：A栋3楼核心机房",
    "node_name": "示例：core-sw-01",
    "ip_address": "示例：10.0.0.1",
    "username": "示例：opsadmin",
    "password": "",
    "port": "示例：22",
    "access_method": "示例：SSH",
    "project_name": "示例：集成项目（留空表示不分组）",
    "remark1": "",
    "remark2": "",
}


def build_import_template() -> bytes:
    """动态生成标准导入模板 xlsx（v0.1.0 新增，修复 B-04）。

    直接复用 IMPORT_COLUMNS 作为表头，从根上保证"模板"与"实际导入校验"
    不会脱节；第 2 行给出示例值，第 3 行起留空供填写。
    """
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "密码记录"
    ws.append(list(IMPORT_COLUMNS))
    ws.append([_TEMPLATE_SAMPLE.get(c, "") for c in IMPORT_COLUMNS])
    # 表头加粗，便于肉眼确认列序
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for idx, _col in enumerate(IMPORT_COLUMNS, start=1):
        ws.column_dimensions[get_column_letter(idx)].width = max(12, len(_col) + 6)
    ws.freeze_panes = "A2"
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _sanitize_csv_cell(value) -> str:
    """CSV 单元格公式注入防护：危险首字符前加单引号强制按文本解释。"""
    s = "" if value is None else str(value)
    if s[:1] in _FORMULA_PREFIXES:
        return "'" + s
    return s


def _sanitize_xlsx_row(ws, row_values: list) -> None:
    """xlsx 行写入 + 公式注入防护：对危险单元格强制 string 类型。

    openpyxl 默认把以 = 开头的字符串当公式写入（data_type='f'），
    打开导出文件即执行；显式置 data_type='s' 后按纯文本存储，
    且单元格数据逐字保留（往返导入不失真）。
    """
    ws.append(row_values)
    for cell in ws[ws.max_row]:
        if isinstance(cell.value, str) and cell.value[:1] in _FORMULA_PREFIXES:
            cell.data_type = "s"


def read_import_file(file: FileStorage) -> list[dict]:
    """解析上传的 xlsx/csv 为行列表。文件类型/大小/行数/表头超限直接抛 ValidationError。"""
    if file is None or not file.filename:
        raise ValidationError("请选择要导入的文件")
    name = file.filename.lower()
    max_bytes = current_app.config["IMPORT_MAX_FILE_MB"] * 1024 * 1024

    # 先读入内存并限制大小，防止超大文件耗尽内存
    blob = file.read(max_bytes + 1)
    if len(blob) > max_bytes:
        raise ValidationError(
            f"文件超过 {current_app.config['IMPORT_MAX_FILE_MB']}MB 上限")
    if not blob:
        raise ValidationError("文件为空")

    raw_rows: list[tuple] = []
    if name.endswith(".xlsx"):
        try:
            wb = load_workbook(io.BytesIO(blob), read_only=True, data_only=True)
        except Exception as exc:  # noqa: BLE001
            raise ValidationError(f"无法解析 Excel 文件: {exc}") from exc
        ws = wb.active
        if ws is None:  # 空工作簿（无任何工作表）防御，避免 AttributeError 500
            raise ValidationError("无法解析 Excel 文件：工作簿中没有工作表")
        for values in ws.iter_rows(values_only=True):
            raw_rows.append(tuple(values))
        wb.close()
    elif name.endswith(".csv"):
        try:
            text = blob.decode("utf-8-sig", errors="replace")
            for values in csv.reader(io.StringIO(text)):
                raw_rows.append(tuple(values))
        except Exception as exc:  # noqa: BLE001
            raise ValidationError(f"无法解析 CSV 文件: {exc}") from exc
    else:
        raise ValidationError("仅支持 Excel (.xlsx) 和 CSV 文件")

    if not raw_rows:
        raise ValidationError("文件内容为空")

    # 表头校验（v0.1.0 修复）：按真实单元格内容与标准模板逐列比对。
    # 旧实现把首行也按列名映射成 dict 后检查 key，恒为真——任何乱表头
    # 的文件都会被按位置错误导入。列顺序错乱/中文表头都会在此被拦下。
    header = ["" if v is None else str(v).strip().lower()
              for v in raw_rows[0]]
    expected = [c.lower() for c in IMPORT_COLUMNS]
    if header[:len(expected)] != expected:
        raise ValidationError(
            "表头与标准模板不一致（应依次为 " + ", ".join(IMPORT_COLUMNS[:3])
            + " ... 共 12 列），请先下载页面提供的标准模板填写")

    data_rows = raw_rows[1:]
    if len(data_rows) > current_app.config["IMPORT_MAX_ROWS"]:
        raise ValidationError(
            f"单次最多导入 {current_app.config['IMPORT_MAX_ROWS']} 行，"
            "请分批上传")
    return [_zip_columns(values) for values in data_rows]


def _zip_columns(values) -> dict:
    row = {}
    for idx, col in enumerate(IMPORT_COLUMNS):
        if idx < len(values):
            # 借鉴 GB-58 · TeamPass 3.2.4.4：口令逐字保留——旧实现把口令
            # 列也 strip()，首尾空格被静默剥除，导入后与原凭据不一致且
            # 用户无从察觉。其余字段维持剥首尾空白（表格手填常态）。
            if col == "password":
                row[col] = "" if values[idx] is None else str(values[idx])
            else:
                row[col] = "" if values[idx] is None else str(values[idx]).strip()
        else:
            row[col] = ""
    return row


def import_rows(user_id: int, rows: list[dict]) -> dict:
    """逐行校验并入库。返回统计与错误明细（错误行跳过，不中断整体导入）。

    事务语义（v0.1.0 第二轮修复）：单行写入失败只回滚该行（SAVEPOINT），
    不再连带回滚之前已成功的行——旧实现对失败行直接 conn.rollback()，
    会把本轮已入库的全部行一起回滚，而 imported 计数器照常累加，
    造成"提示成功 N 条、库里实际为空"的数据丢失。
    """
    from .audit import log_operation

    conn = get_db()
    imported, skipped = 0, 0
    errors: list[str] = []

    user_projects = {
        r["name"]: r["id"] for r in conn.execute(
            "SELECT id, name FROM projects WHERE owner_id=?", (user_id,))
    }

    for line_no, row in enumerate(rows, start=2):  # Excel 行号从 2 开始（1 为表头）
        device = row.get("device_model", "")
        if not device:
            skipped += 1
            if len(errors) < 20:
                errors.append(f"第 {line_no} 行：设备型号为空，已跳过")
            continue
        if len(device) > 100:
            skipped += 1
            if len(errors) < 20:
                errors.append(f"第 {line_no} 行：设备型号超长，已跳过")
            continue
        port = row.get("port", "")
        if not valid_port(port):
            skipped += 1
            if len(errors) < 20:
                errors.append(f"第 {line_no} 行：端口不合法，已跳过")
            continue

        project_name = row.get("project_name", "")
        project_id = user_projects.get(project_name) if project_name else None
        password = row.get("password", "")

        # 单行保存点：处于事务中时用 SAVEPOINT 隔离失败行；
        # 不在事务中（首行即失败）时 INSERT 自启事务后回滚即可
        nested = conn.in_transaction
        if nested:
            conn.execute("SAVEPOINT import_row")
        try:
            conn.execute(
                "INSERT INTO passwords"
                " (user_id, project_id, device_model, serial_number, location, node_name,"
                "  ip_address, username, password, port, access_method, remark1, remark2,"
                "  created_at, updated_at, password_changed_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    user_id, project_id, device,
                    row.get("serial_number", "")[:100], row.get("location", "")[:100],
                    row.get("node_name", "")[:100], row.get("ip_address", "")[:50],
                    row.get("username", "")[:100],
                    crypto().encrypt(password) if password else "",
                    port[:20], row.get("access_method", "")[:50],
                    row.get("remark1", "")[:5000], row.get("remark2", "")[:5000],
                    utcnow_str(), utcnow_str(),
                    utcnow_str() if password else None,
                ),
            )
            if nested:
                conn.execute("RELEASE import_row")
            imported += 1
        except Exception as exc:  # noqa: BLE001
            if nested:
                conn.execute("ROLLBACK TO import_row")
                conn.execute("RELEASE import_row")
            else:
                conn.rollback()
            skipped += 1
            if len(errors) < 20:
                errors.append(f"第 {line_no} 行：写入失败（{exc}），已跳过")

    conn.commit()
    log_operation(user_id, "import", "system", None,
                  f"批量导入完成：成功 {imported} 条，跳过 {skipped} 条")
    return {"imported": imported, "skipped": skipped, "errors": errors}


def build_export(user_id: int, fmt: str):
    """导出当前用户全部有效记录（含明文密码，操作已审计）。"""
    from ..db import get_db
    from ..utils.timefmt import utcnow_str
    from .audit import log_operation

    conn = get_db()
    rows = conn.execute(
        "SELECT p.*, pr.name AS project_name FROM passwords p"
        " LEFT JOIN projects pr ON p.project_id = pr.id"
        " WHERE p.user_id=? AND p.deleted_at IS NULL ORDER BY p.id DESC",
        (user_id,),
    ).fetchall()

    data: list[list] = []
    undecryptable = 0
    for row in rows:
        try:
            plain_pw = crypto().decrypt(row["password"]) if row["password"] else ""
        except CryptoError:
            plain_pw = ""
            undecryptable += 1
        data.append([
            row["device_model"], row["serial_number"], row["location"],
            row["node_name"], row["ip_address"], row["username"], plain_pw,
            row["port"], row["access_method"], row["project_name"] or "",
            row["remark1"] or "", row["remark2"] or "",
        ])

    stamp = utcnow_str().replace(":", "").replace("-", "").replace(" ", "_")
    filename = f"password_export_{stamp}.{fmt}"

    if fmt == "xlsx":
        wb = Workbook()
        ws = wb.active
        ws.title = "密码记录"
        _sanitize_xlsx_row(ws, list(EXPORT_COLUMNS))
        for row in data:
            _sanitize_xlsx_row(ws, row)
        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        mimetype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(list(EXPORT_COLUMNS))
        writer.writerows([[_sanitize_csv_cell(v) for v in row] for row in data])
        byte_buf = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
        byte_buf.seek(0)
        buf = byte_buf
        mimetype = "text/csv"
    else:
        raise ValidationError("不支持的导出格式")

    log_operation(user_id, "export", "system", None,
                  f"导出 {len(data)} 条记录为 {fmt.upper()}"
                  + (f"（{undecryptable} 条因密钥变更无法解密，密码列为空）"
                     if undecryptable else ""))
    return buf, mimetype, filename
