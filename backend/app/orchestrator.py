"""扫描调度与结果聚合。

一轮完整扫描分三层，互相独立：
  1. 静态解析（快，毫秒级）
  2. 多引擎并行查杀（慢，取决于引擎）
  3. 动态模拟执行（最慢，秒到分钟级，可选）

任何一层失败都不应影响其他层——一件可疑样本不该因为 YARA 规则有语法错误
就丢掉 Defender 的检出结果。
"""

from __future__ import annotations

import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path

from . import netguard
from .config import settings
from .dynamic import speakeasy_runner
from .engines.base import EngineAdapter, EngineResult, ScanContext, Verdict
from .engines.registry import build_engines
from .static import pe_analyzer
from .static.hashing import hash_file, store_sample

log = logging.getLogger(__name__)


def _severity(verdict: Verdict) -> int:
    return {
        Verdict.MALICIOUS: 3,
        Verdict.SUSPICIOUS: 2,
        Verdict.PUP: 1,
    }.get(verdict, 0)


def aggregate(results: list[EngineResult]) -> dict:
    """把所有引擎的结论聚合成一个总分。

    MVP 用最保守的规则：任一引擎报毒即为恶意。真实产品还应该做加权
    （不同引擎的误报率不同）和引擎同源去重（很多杀软共用同一家 OEM 引擎）。
    """
    scored = [r for r in results if r.verdict != Verdict.SKIPPED]
    usable = [r for r in scored if r.verdict != Verdict.ERROR]
    detections = [r for r in usable if r.verdict.is_detection]
    errors = [r for r in scored if r.verdict == Verdict.ERROR]

    if not usable:
        verdict = Verdict.UNKNOWN.value
    elif any(r.verdict == Verdict.MALICIOUS for r in usable):
        verdict = Verdict.MALICIOUS.value
    elif detections:
        verdict = Verdict.SUSPICIOUS.value
    else:
        verdict = Verdict.CLEAN.value

    total = len(usable)
    return {
        "verdict": verdict,
        "detections": len(detections),
        "engine_total": total,
        "detection_ratio": f"{len(detections)}/{total}" if total else "0/0",
        "errored_engines": [r.engine for r in errors],
        "max_severity": max((_severity(r.verdict) for r in usable), default=0),
    }


def _run_engines(engines: list[EngineAdapter], ctx: ScanContext) -> list[EngineResult]:
    """两档调度：轻量引擎并发跑，重量引擎串行跑，两档同时进行。

    为什么不是一个线程池跑全部——实测数据说话（cmd.exe，单核 6 GB 机器）：

        ClamAV（无 clamd）  峰值 1126 MB      CAPA   404 MB      Emsisoft  120 MB
        DIE                    37 MB          Manalyze 8 MB      Defender/YARA  0 MB

    把 ClamAV 和 CAPA 放进同一个并发池，两个加起来 1.5 GB，在 6 GB 的机器上
    直接把系统推进换页——实测其它引擎从 20 秒被拖到 120 秒。按内存分档后，
    峰值被压到单个重引擎的量级（~1.2 GB），而轻量引擎仍然并发，不损失速度。

    分档依据是**内存**而不是耗时：把机器拖垮的是内存压力，不是 CPU 时间。
    """
    results: list[EngineResult] = []

    # resource_class 可能是动态属性（ClamAV 要看 clamd 在不在），
    # 在这里求值一次，避免调度过程中反复触发探测。
    light: list[EngineAdapter] = []
    heavy: list[EngineAdapter] = []

    for engine in engines:
        if not engine.available():
            results.append(
                EngineResult(
                    engine=engine.name,
                    verdict=Verdict.SKIPPED,
                    error=engine.unavailable_reason(),
                )
            )
            continue
        if engine.resource_class == "heavy":
            heavy.append(engine)
        else:
            light.append(engine)

    def collect(future, engine: EngineAdapter) -> None:
        try:
            results.append(future.result())
        except Exception as exc:  # noqa: BLE001 - timed_scan 已兜底，此处是双保险
            log.exception("引擎 %s 异常", engine.name)
            results.append(
                EngineResult(
                    engine=engine.name,
                    verdict=Verdict.ERROR,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    # 两个池同时进行：轻量的并发，重量的队列里永远只有一个在执行
    with (
        ThreadPoolExecutor(max_workers=settings.engine_workers) as light_pool,
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="heavy") as heavy_pool,
    ):
        futures: dict = {}
        for engine in light:
            futures[light_pool.submit(engine.timed_scan, ctx)] = engine
        for engine in heavy:
            futures[heavy_pool.submit(engine.timed_scan, ctx)] = engine

        if heavy:
            log.info(
                "调度：%d 个轻量引擎并发，%d 个重量引擎串行（%s）",
                len(light),
                len(heavy),
                "、".join(e.name for e in heavy),
            )

        for future in as_completed(futures):
            collect(future, futures[future])

    # 保持与注册顺序一致的展示顺序
    order = {engine.name: i for i, engine in enumerate(engines)}
    results.sort(key=lambda r: order.get(r.engine, 999))
    return results


def scan_file(
    source: Path,
    *,
    filename: str | None = None,
    run_dynamic: bool = True,
    dynamic_timeout_s: int = 120,
) -> dict:
    """对单个文件执行三层扫描，返回完整报告字典。

    注意：本函数是同步阻塞的，调用方（API/CLI）负责把它丢到后台线程。
    """
    if not source.is_file():
        raise FileNotFoundError(f"文件不存在：{source}")

    hashes = hash_file(source)
    sample_path = store_sample(source, hashes.sha256, settings.samples_dir)

    ctx = ScanContext(
        sample_path=sample_path,
        sha256=hashes.sha256,
        md5=hashes.md5,
        size=hashes.size,
        timeout_s=settings.scan_timeout_s,
    )

    # 整轮扫描在出网守卫下执行：任何试图向外发起连接的行为都会被拦截并记录。
    # 这让"样本不出本机"从一句承诺变成可验证的强制约束。
    netguard.clear_violations()
    guard = netguard.offline_guard() if settings.enforce_offline else nullcontext()

    with guard:
        # ---- 第 1 层：静态 ----
        static_report: dict = {"error": None}
        try:
            static_report = pe_analyzer.analyze(sample_path)
        except Exception as exc:  # noqa: BLE001
            log.exception("静态分析失败")
            static_report = {"error": f"{type(exc).__name__}: {exc}"}

        # ---- 第 2 层：多引擎 ----
        engines = build_engines()
        engine_results = _run_engines(engines, ctx)
        summary = aggregate(engine_results)

        # ---- 第 3 层：动态（默认模拟执行） ----
        # PE 判定独立进行，不复用静态报告——静态解析失败时动态分析仍须启动，
        # 否则一个解析 bug 就能让整条动态链路被静默跳过。
        dynamic_report: dict | None = None
        if run_dynamic:
            if pe_analyzer.looks_like_pe(sample_path):
                dynamic_report = speakeasy_runner.emulate(
                    sample_path, timeout_s=dynamic_timeout_s
                )
            else:
                dynamic_report = {
                    "available": True,
                    "success": False,
                    "error": "非 PE 文件，模拟执行仅支持 Windows PE",
                }

        blocked = netguard.violations()

    return {
        "id": str(uuid.uuid4()),
        "filename": filename or source.name,
        "sha256": hashes.sha256,
        "md5": hashes.md5,
        "sha1": hashes.sha1,
        "size": hashes.size,
        "sample_path": str(sample_path),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "verdict": summary["verdict"],
        "detection_ratio": summary["detection_ratio"],
        "detections": summary["detections"],
        "engine_total": summary["engine_total"],
        "errored_engines": summary["errored_engines"],
        "static": static_report,
        "engines": [r.to_dict() for r in engine_results],
        "dynamic": dynamic_report,
        # 出网守卫的执行记录——这是"样本未外传"的实证
        "network": {
            "enforced": settings.enforce_offline,
            "blocked_attempts": blocked,
        },
    }


def dumps(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)
