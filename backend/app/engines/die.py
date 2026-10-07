"""Detect It Easy 适配器（加壳/编译器/保护器识别）。

DIE 不是杀毒引擎，它回答的是另一个问题：**这个文件是用什么造的、
有没有被壳保护过**。

为什么这对恶意样本分析很关键：加壳是绕过签名引擎最廉价的手段。
一个 UPX 加壳的样本可以让所有签名引擎失明，但 DIE 一眼就能指出
"UPX 3.96"。反过来说，看到"未加壳 + MSVC 编译"也能排除掉一整类误判。

对像 final_x86.exe 那种自实现虚拟机的样本，DIE 会标出
"Virtualization" 类特征——这是签名引擎全都失效时唯一的线索来源。

完全本地，无网络行为。命令行：``diec.exe -j <文件>``
"""

from __future__ import annotations

import json
from pathlib import Path

from ..config import settings
from .base import (
    EngineAdapter,
    EngineKind,
    EngineResult,
    ScanContext,
    Verdict,
    run_process,
)

#: DIE 报告里的 "type" 字段取值中，这些意味着"文件被处理过"
_PROTECTION_TYPES = {
    "packer",
    "protector",
    "crypter",
    "virtualization",
    "installer",
    "joiner",
    "obfuscator",
}

#: 这些只是说明文件是怎么造的，不构成可疑
_NEUTRAL_TYPES = {
    "linker",
    "compiler",
    "library",
    "tool",
    "format",
    "filetype",
    "language",
}


def _candidate_paths() -> list[Path]:
    base = settings.base_dir / "tools" / "die"
    return [base / "diec.exe", base / "diec"]


def find_diec() -> Path | None:
    for path in _candidate_paths():
        if path.is_file():
            return path
    return None


class DieEngine(EngineAdapter):
    name = "DIE"
    kind = EngineKind.ANALYSIS
    offline = True  # 纯本地静态分析

    def __init__(self) -> None:
        self._exe = find_diec()

    def available(self) -> bool:
        return self._exe is not None

    def unavailable_reason(self) -> str:
        return (
            "未找到 diec.exe。请运行 `python -m app.cli setup-tools` "
            "下载 Detect It Easy"
        )

    def scan(self, ctx: ScanContext) -> EngineResult:
        assert self._exe is not None

        proc = run_process(
            [str(self._exe), "-j", str(ctx.sample_path)],
            timeout_s=min(ctx.timeout_s, 120),
            cwd=str(self._exe.parent),  # DIE 需要相对定位它的数据库目录
        )

        if not proc.stdout.strip():
            return EngineResult(
                engine=self.name,
                verdict=Verdict.ERROR,
                error=f"diec 无输出（退出码 {proc.returncode}）",
                raw_output=proc.stderr or "",
            )

        # 只解析**第一个** JSON 文档，忽略尾随内容。
        #
        # diec 会把签名脚本的报错直接打到 stdout，紧跟在 JSON 后面：
        #     { ... "detects": [...] }      ← 有效 JSON
        #     _init: 363: TypeError: ...
        #     Nuitka.1.sg: 443: RangeError: Maximum call stack size exceeded.
        # 用 json.loads 会抛 "Extra data"。这些报错来自 DIE 自己的规则脚本，
        # 跟我们无关，但会让整个引擎失效——2026-10 更新检测库后才暴露出来。
        text = proc.stdout.lstrip()
        brace = text.find("{")
        if brace > 0:
            text = text[brace:]

        try:
            data, _end = json.JSONDecoder().raw_decode(text)
        except json.JSONDecodeError as exc:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.ERROR,
                error=f"无法解析 diec 输出：{exc}",
                raw_output=proc.stdout[:2000],
            )

        # 按 type 归类所有识别结果
        by_type: dict[str, list[str]] = {}
        for detect in data.get("detects") or []:
            for value in detect.get("values") or []:
                kind = (value.get("type") or "").strip()
                if not kind:
                    continue
                label = (value.get("string") or value.get("name") or "").strip()
                if label:
                    by_type.setdefault(kind, []).append(label)

        protections = {
            kind: labels
            for kind, labels in by_type.items()
            if kind.lower() in _PROTECTION_TYPES
        }
        toolchain = {
            kind: labels
            for kind, labels in by_type.items()
            if kind.lower() in _NEUTRAL_TYPES
        }

        if protections:
            summary = "；".join(
                f"{kind}: {', '.join(dict.fromkeys(labels))}"
                for kind, labels in protections.items()
            )
            return EngineResult(
                engine=self.name,
                verdict=Verdict.SUSPICIOUS,
                signature=summary[:120],
                detail="检测到加壳/保护/虚拟化特征——静态字符串与导入表可能不可信",
                meta={"protections": protections, "toolchain": toolchain},
            )

        summary = "；".join(
            f"{kind}: {', '.join(dict.fromkeys(labels))}"
            for kind, labels in toolchain.items()
        )
        return EngineResult(
            engine=self.name,
            verdict=Verdict.CLEAN,
            signature=summary[:120] or None,
            detail="未检测到加壳或保护特征",
            meta={"toolchain": toolchain},
        )
