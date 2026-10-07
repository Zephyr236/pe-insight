"""引擎自检。

扫描一个干净样本只会得到"全部干净"，这无法区分两件事：
引擎真的在正常工作，还是它根本没跑起来。
自检通过已知会被检出的测试样本，验证每个引擎确实在查杀。

EICAR 测试串是反病毒行业的通用标准（EICAR 组织发布的无害测试文件），
所有正规引擎都必须检出它。它不是病毒，不包含任何可执行代码。

一个绕不开的复杂情况：**Defender 实时防护会锁死它检出的文件**，
包括我们刚写下的测试样本。文件仍在磁盘上，但任何读取都被拒绝
（Windows 上表现为 Errno 22）。这时：
  - 对 Defender 而言，这本身就是检出证据；
  - 对其他引擎而言，意味着无法扫描，必须如实上报而不是假装通过。
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from .engines.base import EngineAdapter, EngineKind, ScanContext, Verdict
from .engines.registry import build_engines
from .static.hashing import hash_file

# EICAR 反病毒测试文件标准串（68 字节，行业通用，无害）
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

#: 网络不可达时 QuickLook 相关的占位
FILE_OK = "ok"
FILE_LOCKED = "locked"
FILE_ERROR = "error"


def _make_context(path: Path) -> ScanContext:
    hashes = hash_file(path)
    return ScanContext(
        sample_path=path,
        sha256=hashes.sha256,
        md5=hashes.md5,
        size=hashes.size,
        timeout_s=120,
    )


def probe_file(path: Path, data: bytes) -> str:
    """写入测试文件并确认它是否可读。

    'locked' 是 Defender 实时防护的典型表现：文件还在，但读不了。
    它说明实时防护已经检出并接管了这个文件——对 Defender 是检出证据，
    对其他引擎则是"无法扫描"。
    """
    try:
        path.write_bytes(data)
    except OSError:
        return FILE_ERROR
    try:
        path.read_bytes()
        return FILE_OK
    except OSError:
        return FILE_LOCKED


def _find_benign_pe() -> Path | None:
    """找一个系统自带的干净 PE 作为载体。"""
    for candidate in (
        r"C:\Windows\System32\calc.exe",
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\attrib.exe",
    ):
        path = Path(candidate)
        if path.is_file():
            return path
    return None


def _check_engine(
    engine: EngineAdapter,
    path: Path | None,
    state: str,
    *,
    expect_detection: bool = True,
) -> dict:
    """按文件可用状态产出一个检查项。

    expect_detection=False 用于"链路健康"检查：目标文件本来就是干净的，
    判定标准是引擎有没有正常返回结论，而不是有没有检出。
    """
    if state == FILE_OK and path is not None:
        result = engine.timed_scan(_make_context(path))
        if expect_detection:
            passed = result.verdict.is_detection
        else:
            # 干净载体上不报错地跑完，就说明这条链路是通的
            passed = result.verdict != Verdict.ERROR
        return {
            "state": FILE_OK,
            "verdict": result.verdict.value,
            "signature": result.signature,
            "error": result.error,
            "passed": passed,
            "expect_detection": expect_detection,
        }

    if state == FILE_LOCKED:
        return {
            "state": FILE_LOCKED,
            "verdict": "locked",
            "passed": None,
            "note": "测试文件被实时防护锁定，本引擎无法扫描",
        }

    if state == "skipped":
        return {"state": "skipped", "verdict": "skipped", "passed": None}

    return {
        "state": FILE_ERROR,
        "verdict": "error",
        "passed": None,
        "note": "测试文件写入失败",
    }


def run_selftest(engines: list[EngineAdapter] | None = None) -> dict:
    engines = engines or build_engines()

    results: list[dict] = []
    # 被实时防护锁定的文件在目录清理时会报错，直接忽略
    with tempfile.TemporaryDirectory(
        prefix="peinsight-selftest-", ignore_cleanup_errors=True
    ) as tmp:
        tmpdir = Path(tmp)

        eicar_file = tmpdir / "eicar.bin"
        eicar_state = probe_file(eicar_file, EICAR.encode())

        pe_file: Path | None = None
        pe_state = "skipped"
        benign = _find_benign_pe()
        if benign:
            candidate = tmpdir / "carrier.exe"
            try:
                payload = benign.read_bytes() + b"\r\n" + EICAR.encode() + b"\r\n"
            except OSError:
                payload = b""
            if payload:
                pe_state = probe_file(candidate, payload)
                if pe_state == FILE_OK:
                    pe_file = candidate

        for engine in engines:
            entry: dict = {"engine": engine.name, "checks": {}}

            if not engine.available():
                entry["skipped"] = True
                entry["reason"] = engine.unavailable_reason()
                results.append(entry)
                continue

            entry["checks"]["eicar"] = _check_engine(engine, eicar_file, eicar_state)
            # 规则引擎（YARA）本就不针对 EICAR，不参与检出能力判定；
            # PE 载体是干净文件，这里测的是"PE 扫描链路是否通"，不是检出
            if engine.kind is not EngineKind.RULE:
                entry["checks"]["pe_path"] = _check_engine(
                    engine, pe_file, pe_state, expect_detection=False
                )

            results.append(entry)

    return {
        "eicar": EICAR,
        "eicar_state": eicar_state,
        "pe_state": pe_state,
        "results": results,
    }
