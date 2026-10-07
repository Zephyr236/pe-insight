"""PE 文件静态解析。

不依赖任何杀毒引擎就能拿到的信息：结构、节区熵、导入表、编译时间戳、
加壳嫌疑、数字签名等。这些既是给人看的报告，也是给动态分析的关键输入。

设计要点：各子分析器互相隔离。畸形样本经常只有某一张表是坏的，
不能让一处解析失败把整份报告清空。
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from pathlib import Path

import pefile

log = logging.getLogger(__name__)


def looks_like_pe(path: Path) -> bool:
    """廉价的 PE 识别，不依赖 pefile 解析成功。

    动态分析是否启动必须由这个函数决定，而不是由静态报告决定——
    否则静态解析一旦失败，动态分析会被连带跳过。
    """
    try:
        with path.open("rb") as handle:
            if handle.read(2) != b"MZ":
                return False
            handle.seek(0x3C)
            raw = handle.read(4)
            if len(raw) != 4:
                return False
            e_lfanew = int.from_bytes(raw, "little")
            # 合法范围之外说明是畸形/伪造的 PE 头
            if not 0 < e_lfanew < 0x10000000:
                return False
            handle.seek(e_lfanew)
            return handle.read(4) == b"PE\x00\x00"
    except OSError:
        return False


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def _format_timestamp(ts: int | None) -> str | None:
    if not ts:
        return None
    try:
        # 该字段可能被恶意样本伪造，仅作参考
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _section_entropy(section) -> float:
    try:
        return round(_entropy(section.get_data()), 3)
    except Exception:  # noqa: BLE001 - 畸形节区（如 raw 偏移越界）
        return 0.0


def analyze(path: Path) -> dict:
    """解析 PE 文件。非 PE 文件返回 {'is_pe': False}，不抛异常。"""
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        return {"is_pe": False, "reason": f"不是有效的 PE 文件：{exc}"}
    except Exception as exc:  # noqa: BLE001 - 畸形样本可能触发各种解析错误
        return {"is_pe": False, "reason": f"解析失败：{type(exc).__name__}: {exc}"}

    with pe:
        report: dict = {
            "is_pe": True,
            "machine": pefile.MACHINE_TYPE.get(
                pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)
            ),
            "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
            "is_driver": bool(pe.FILE_HEADER.Characteristics & 0x1000),
            "subsystem": pefile.SUBSYSTEM_TYPE.get(
                pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem)
            ),
            "compile_timestamp": _format_timestamp(pe.FILE_HEADER.TimeDateStamp),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        }

        # 每项独立兜底：某一张表坏掉不影响其余部分
        components = (
            ("imphash", lambda: pe.get_imphash()),
            ("sections", lambda: _sections(pe)),
            ("imports", lambda: _imports(pe)),
            ("exports", lambda: _exports(pe)),
            ("resources", lambda: _resources(pe)),
            ("signature", lambda: _signature(pe)),
        )
        problems: list[str] = []
        for key, fn in components:
            try:
                report[key] = fn()
            except Exception as exc:  # noqa: BLE001
                log.warning("静态分析子项 %s 失败：%s", key, exc)
                report[key] = [] if key in ("sections", "imports", "exports") else {}
                problems.append(f"{key}: {type(exc).__name__}: {exc}")

        if problems:
            report["partial_errors"] = problems

        report["indicators"] = _indicators(pe, report)
        return report


def _sections(pe: pefile.PE) -> list[dict]:
    out = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", "replace")
        entropy = _section_entropy(section)
        out.append(
            {
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                # 熵 > 7.0 通常意味着加密或压缩——加壳的强信号
                "entropy": entropy,
                "high_entropy": entropy > 7.0,
                "characteristics": hex(section.Characteristics),
                # W+X 是可写可执行，自修改代码/壳的常见特征
                "writable_and_executable": bool(
                    section.Characteristics & 0x80000000
                    and section.Characteristics & 0x20000000
                ),
            }
        )
    return out


def _imports(pe: pefile.PE) -> list[dict]:
    # 注意：DIRECTORY_ENTRY_IMPORT 是列表，而 EXPORT / RESOURCE 是单个对象
    out = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []:
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode("utf-8", "replace"))
            else:
                funcs.append(f"ordinal_{imp.ordinal}")
        out.append({"dll": entry.dll.decode("utf-8", "replace"), "functions": funcs})
    return out


def _exports(pe: pefile.PE) -> list[str]:
    # DIRECTORY_ENTRY_EXPORT 是单个 ExportDirData，不是列表
    entry = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if entry is None:
        return []
    return [
        exp.name.decode("utf-8", "replace")
        for exp in (entry.symbols or [])
        if exp.name
    ]


def _resources(pe: pefile.PE) -> dict:
    """只统计资源类型与数量，不 dump 内容（体积可能很大）。"""
    # DIRECTORY_ENTRY_RESOURCE 是单个 ResourceDirData，入口在 .entries
    directory = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if directory is None:
        return {}

    types: dict[str, int] = {}
    for entry in directory.entries:
        type_name = pefile.RESOURCE_TYPE.get(entry.struct.Id, str(entry.struct.Id))
        count = len(entry.directory.entries) if entry.directory else 0
        types[type_name] = count
    return types


def _signature(pe: pefile.PE) -> dict:
    """检查是否存在 Authenticode 签名的数据目录项。

    只判断"有没有签名"；验证签名有效性需要另调 WinVerifyTrust。
    """
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    return {
        "present": directory.VirtualAddress != 0 and directory.Size != 0,
        "size": directory.Size,
    }


def _indicators(pe: pefile.PE, report: dict) -> list[str]:
    """一组轻量的打包/可疑特征启发式判断。

    这些是线索，不是结论——单独任何一条都不足以定性。
    """
    flags: list[str] = []

    packed_names = {
        ".upx", "upx0", "upx1", "aspack", ".aspack",
        ".themida", ".vmp0", ".vmp1", ".mpress1", ".petite",
    }
    section_names = {
        s["name"].lower() for s in report.get("sections", []) if s.get("name")
    }
    if section_names & packed_names:
        flags.append("存在已知加壳器节区名")

    if not report.get("imports"):
        flags.append("无导入表（可能通过 LoadLibrary/GetProcAddress 动态解析）")

    high_entropy = sum(1 for s in report.get("sections", []) if s.get("high_entropy"))
    if high_entropy >= 2:
        flags.append(f"{high_entropy} 个高熵节区（疑似加密/压缩）")

    if any(s.get("writable_and_executable") for s in report.get("sections", [])):
        flags.append("存在可写且可执行节区")

    try:
        if pe.FILE_HEADER.PointerToSymbolTable:
            flags.append("含调试符号（可能未剥离）")
    except Exception:  # noqa: BLE001
        pass

    return flags
