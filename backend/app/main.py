"""FastAPI 应用。

所有接口都挂在本机 127.0.0.1 上——这是个单机桌面工具，不应该监听公网。
"""

from __future__ import annotations

import json
import logging
import secrets
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlmodel import select

from . import orchestrator
from .config import settings
from .db import init_db, session_scope
from .engines.registry import describe_engines
from .models import ScanRecord

log = logging.getLogger(__name__)

app = FastAPI(title="PE Insight", version="0.1.0")

# 开发时 Vite 在 5173；局域网给别的机器用时来源不固定，需显式放行
_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
if settings.allow_lan_cors:
    _origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _require_api_key(request: Request, call_next):
    """共享密钥鉴权。

    这个接口接收任意文件上传并把它送进多个杀毒引擎和模拟器，还会把样本
    落盘。放到内网上不设防，等于给整个网段开了一个投毒和横向移动的入口。
    设置 PEINSIGHT_API_KEY 后，除健康检查和首页外全部要求 X-API-Key。

    刻意不保护 /api/health：负载均衡和监控探活需要一个免鉴权端点。
    """
    if settings.api_key:
        path = request.url.path
        exempt = path == "/api/health" or not path.startswith("/api/")
        if not exempt:
            provided = request.headers.get("x-api-key", "")
            # 用 compare_digest 避免按字符比较带来的时序侧信道
            if not secrets.compare_digest(provided, settings.api_key):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "缺少或错误的 X-API-Key"},
                )
    return await call_next(request)

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")


def _autostart_clamd() -> None:
    """在后台拉起 clamd。加载签名库要十几秒，不能阻塞服务启动。"""
    from . import clamd_manager

    try:
        if not clamd_manager.is_installed():
            return
        if clamd_manager.ping():
            log.info("clamd 已在运行")
            return
        ok, msg = clamd_manager.start(wait_s=120)
        log.info("clamd 自启动：%s", msg if ok else f"失败 — {msg}")
    except Exception:  # noqa: BLE001 - 守护进程起不来不该拖垮整个服务
        log.exception("clamd 自启动异常（其他引擎不受影响）")


def _auto_update() -> None:
    """后台更新签名库与规则集。

    几个刻意的取舍：
    - **延迟启动**：服务刚起来时在初始化数据库、拉 clamd，这时再抢磁盘和带宽
      只会让启动更慢。
    - **只在过期时才下载**：否则重启十次服务就下载十次上百 MB 的签名库。
    - **全程静默、失败无害**：更新拿不到网络是很常见的情况，绝不能影响服务。
    """
    import time as _time

    from . import updater

    if settings.auto_update_delay_s > 0:
        _time.sleep(settings.auto_update_delay_s)

    try:
        stale = updater.status()
        due = [s for s in stale if s.age_hours is None or s.age_hours >= settings.auto_update_max_age_hours]
        if not due:
            log.info(
                "签名库均为最新（阈值 %.0f 小时），跳过后台更新",
                settings.auto_update_max_age_hours,
            )
            return

        log.info("后台更新签名库：%s", "、".join(s.label for s in due))
        results = updater.update(
            max_age_hours=settings.auto_update_max_age_hours,
            progress=lambda _msg: None,  # 后台更新不刷屏
        )
        for r in results:
            label = r.get("label", r["name"])
            if r.get("skipped"):
                continue
            if r["updated"]:
                log.info("签名库已更新：%s（%s）", label, r["message"])
            else:
                log.warning("签名库更新失败：%s（%s）", label, r["message"])
    except Exception:  # noqa: BLE001 - 后台任务绝不能把异常抛出去
        log.exception("后台更新异常（不影响服务）")


def _warm_privacy_cache() -> None:
    """预热 Defender 设置缓存。

    引擎过滤要先查证 Defender 的云通道状态，而首次查询要拉起 PowerShell
    （1~2 秒）。放在启动时预热，避免第一次扫描和首次打开页面卡这一下。
    """
    from . import privacy

    try:
        audit = privacy.audit_defender()
        if audit.get("available") and audit.get("cloud_enabled"):
            log.warning(
                "Defender 云保护为「%s」，样本提交为「%s」——"
                "该引擎将默认不启用（除非关闭云通道或设置 PEINSIGHT_ALLOW_ONLINE=1）",
                audit.get("maps_text"),
                audit.get("submit_text"),
            )
    except Exception:  # noqa: BLE001
        log.exception("预热 Defender 审计失败")


@app.on_event("startup")
def _startup() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    init_db()
    log.info("数据目录：%s", settings.data_dir)
    log.info("网络策略：%s", settings.network_policy)
    threading.Thread(target=_warm_privacy_cache, daemon=True).start()
    if settings.auto_start_clamd:
        threading.Thread(target=_autostart_clamd, daemon=True).start()
    if settings.auto_update:
        threading.Thread(target=_auto_update, daemon=True).start()


# --------------------------------------------------------------------------
# 后台任务
# --------------------------------------------------------------------------


def _run_scan_job(scan_id: str, temp_path: Path, filename: str, run_dynamic: bool) -> None:
    """在后台线程里跑完整扫描并回写数据库。"""
    from .db import session_scope as scope

    try:
        with scope() as session:
            record = session.get(ScanRecord, scan_id)
            if record:
                record.status = "running"

        report = orchestrator.scan_file(
            temp_path, filename=filename, run_dynamic=run_dynamic
        )

        with scope() as session:
            record = session.get(ScanRecord, scan_id)
            if not record:
                return
            record.status = "done"
            record.sha256 = report["sha256"]
            record.md5 = report["md5"]
            record.sha1 = report["sha1"]
            record.size = report["size"]
            record.verdict = report["verdict"]
            record.detection_ratio = report["detection_ratio"]
            record.detections = report["detections"]
            record.engine_total = report["engine_total"]
            record.static_json = json.dumps(report["static"], ensure_ascii=False)
            record.engines_json = json.dumps(report["engines"], ensure_ascii=False)
            record.dynamic_json = json.dumps(report["dynamic"], ensure_ascii=False)
            record.network_json = json.dumps(report.get("network"), ensure_ascii=False)
            record.finished_at = datetime.now(timezone.utc)
    except OSError as exc:
        # Errno 22 在 Windows 上几乎总是"文件被安全软件的实时防护锁定"。
        # 直接抛原始信息的话，用户看到的是一个反引号包裹的临时路径，
        # 完全不知道该怎么办。
        if getattr(exc, "errno", None) == 22:
            log.error("扫描任务失败（文件被锁定）：%s", scan_id)
            detail = (
                "样本文件被安全软件锁定，无法读取。这通常是因为它所在的目录"
                "没有被加入 Defender 排除列表。执行 "
                "`python -m app.cli setup-exclusions --yes`（需管理员）后重试。"
            )
        else:
            log.exception("扫描任务失败：%s", scan_id)
            detail = f"{type(exc).__name__}: {exc}"
        with scope() as session:
            record = session.get(ScanRecord, scan_id)
            if record:
                record.status = "failed"
                record.error = detail
                record.finished_at = datetime.now(timezone.utc)
    except Exception as exc:  # noqa: BLE001 - 后台任务不能把异常抛给任何调用方
        log.exception("扫描任务失败：%s", scan_id)
        with scope() as session:
            record = session.get(ScanRecord, scan_id)
            if record:
                record.status = "failed"
                record.error = f"{type(exc).__name__}: {exc}"
                record.finished_at = datetime.now(timezone.utc)
    finally:
        temp_path.unlink(missing_ok=True)


def _new_record(filename: str) -> str:
    scan_id = str(uuid.uuid4())
    with session_scope() as session:
        session.add(ScanRecord(id=scan_id, filename=filename, status="pending"))
    return scan_id


# --------------------------------------------------------------------------
# 接口
# --------------------------------------------------------------------------


class LocalScanRequest(BaseModel):
    path: str
    run_dynamic: bool = True


@app.get("/api/health")
def health() -> dict:
    return {
        "ok": True,
        "network_policy": settings.network_policy,
        "enforce_offline": settings.enforce_offline,
        "auth_required": bool(settings.api_key),
    }


@app.get("/api/engines")
def engines() -> list[dict]:
    return describe_engines()


@app.get("/api/privacy")
def privacy_audit() -> dict:
    """审计是否存在把样本送出本机的通道。

    这个接口存在的意义是让"样本不外传"变成一个可查看的事实，
    而不是印在文档里的一句承诺。
    """
    from . import privacy

    return {
        "defender": privacy.audit_defender(),
        "network_guard": {
            "enforced": settings.enforce_offline,
            "description": "扫描期间强制拦截一切外部网络连接",
        },
        "inbox_dir": str(settings.inbox_dir),
    }


@app.post("/api/scans/upload")
async def create_scan_from_upload(
    file: UploadFile,
    run_dynamic: bool = True,
) -> dict:
    """上传样本文件扫描。

    注意：即使叫"上传"，文件也只是写到本机数据目录，不会离开这台机器。
    """
    max_bytes = settings.max_upload_mb * 1024 * 1024
    suffix = Path(file.filename or "sample.bin").suffix or ".bin"

    # 必须写进 data/ 内部，不能用默认的 %TEMP%。
    # %TEMP% 不在 Defender 的排除列表里，上传的样本一落盘就被实时防护
    # 检出并锁定，随后的 hash_file 会抛出 OSError [Errno 22]，
    # 整个扫描任务失败。data/ 是排除区，那里不会被实时防护动。
    upload_dir = settings.inbox_dir / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, dir=upload_dir
    ) as tmp:
        size = 0
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                tmp.close()
                Path(tmp.name).unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"文件超过 {settings.max_upload_mb} MB 上限",
                )
            tmp.write(chunk)
        temp_path = Path(tmp.name)

    scan_id = _new_record(file.filename or temp_path.name)
    _executor.submit(_run_scan_job, scan_id, temp_path, file.filename or temp_path.name, run_dynamic)
    return {"id": scan_id, "status": "pending"}


@app.post("/api/scans/local")
def create_scan_from_path(payload: LocalScanRequest) -> dict:
    """直接扫描本机路径，不经过 HTTP 上传。

    单机桌面工具的主要用法——分析员手上的样本本来就在本机。
    """
    path = Path(payload.path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"文件不存在：{payload.path}")

    scan_id = _new_record(path.name)
    _executor.submit(_run_scan_job, scan_id, path, path.name, payload.run_dynamic)
    return {"id": scan_id, "status": "pending"}


@app.get("/api/scans")
def list_scans(limit: int = 50) -> list[dict]:
    with session_scope() as session:
        rows = session.exec(
            select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit)  # type: ignore[attr-defined]
        ).all()
    return [_record_summary(r) for r in rows]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> JSONResponse:
    with session_scope() as session:
        record = session.get(ScanRecord, scan_id)
        if not record:
            raise HTTPException(status_code=404, detail="扫描记录不存在")

        payload = _record_summary(record)
        payload.update(
            {
                "static": _load_json(record.static_json),
                "engines": _load_json(record.engines_json),
                "dynamic": _load_json(record.dynamic_json),
                "network": _load_json(record.network_json),
            }
        )
        return JSONResponse(payload)


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str) -> dict:
    with session_scope() as session:
        record = session.get(ScanRecord, scan_id)
        if not record:
            raise HTTPException(status_code=404, detail="扫描记录不存在")
        session.delete(record)
    return {"deleted": scan_id}


def _record_summary(record: ScanRecord) -> dict:
    return {
        "id": record.id,
        "filename": record.filename,
        "sha256": record.sha256,
        "md5": record.md5,
        "sha1": record.sha1,
        "size": record.size,
        "status": record.status,
        "verdict": record.verdict,
        "detection_ratio": record.detection_ratio,
        "detections": record.detections,
        "engine_total": record.engine_total,
        "error": record.error,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "finished_at": record.finished_at.isoformat() if record.finished_at else None,
    }


def _load_json(raw: str | None):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------
# 前端静态资源（构建后由后端一并提供，实现单文件桌面工具的分发形态）
# --------------------------------------------------------------------------

_DIST = settings.base_dir / "frontend" / "dist"
if _DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/")
    def _index() -> FileResponse:
        return FileResponse(_DIST / "index.html")
