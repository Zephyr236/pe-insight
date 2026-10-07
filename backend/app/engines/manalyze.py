"""Manalyze 适配器（PE 结构分析）。

Manalyze 通过一组插件从 PE 结构本身找问题，而不是比对签名：
加壳痕迹、可疑导入组合、反虚拟机字符串、内嵌加密常量、**勒索钱包地址**、
PE 边界外的叠加数据、签名有效性。

其中 `findcrypt`（内嵌加密常量）和 `cryptoaddress`（BTC/XMR 地址）
对勒索样本特别有用——勒索软件几乎必然要内嵌加密算法和收款地址，
这两项是签名引擎看不见的结构性证据。

**注意**：Manalyze 自带一个 `plugin_virustotal.dll`。本产品在安装时
会把它**物理删除**——它是上传通道，留着就等于给"样本不外传"开了个口子。
另外这里刻意不启用它的 `clamav` 插件（我们已经有独立的 ClamAV 引擎，
重复跑一遍没有意义还慢一倍）。

完全本地。命令行：``manalyze.exe -o json -p <插件> <文件>``
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

#: 启用的插件。刻意排除 clamav（已有独立引擎）和 virustotal（已删除）。
_PLUGINS = "packer,imports,strings,findcrypt,cryptoaddress,overlay,authenticode"

#: 命中即视为可疑的插件。密钥是插件名小写。
_SUSPICIOUS_PLUGINS = {
    "packer": "检测到加壳结构",
    "cryptoaddress": "内嵌加密货币地址（勒索特征）",
    "findcrypt": "内嵌加密算法常量",
    "strings": "包含可疑字符串（反虚拟机/安全工具名等）",
}


def find_manalyze() -> Path | None:
    root = settings.base_dir / "tools" / "manalyze"
    if not root.is_dir():
        return None
    # 发布包解压后可能多一层目录
    for path in [root / "manalyze.exe", *root.glob("*/manalyze.exe")]:
        if path.is_file():
            return path
    return None


def _summarize_section(section) -> str:
    """把插件输出压成一句人话。"""
    if isinstance(section, str):
        return section[:150]
    if isinstance(section, list):
        return "; ".join(str(x)[:60] for x in section[:4])
    if isinstance(section, dict):
        parts = []
        for key, value in list(section.items())[:4]:
            if isinstance(value, (list, dict)):
                value = str(value)[:60]
            parts.append(f"{key}: {value}")
        return "; ".join(parts)[:200]
    return str(section)[:150]


class ManalyzeEngine(EngineAdapter):
    name = "Manalyze"
    kind = EngineKind.ANALYSIS
    offline = True  # VirusTotal 插件已物理删除，无任何网络路径

    def __init__(self) -> None:
        self._exe = find_manalyze()

    def network_note(self) -> str:
        return "VirusTotal 插件已在安装时删除；所有检查均为本地结构分析"

    def available(self) -> bool:
        return self._exe is not None

    def unavailable_reason(self) -> str:
        return (
            "未找到 manalyze.exe。请运行 `python -m app.cli setup-tools` "
            "下载 Manalyze"
        )

    def scan(self, ctx: ScanContext) -> EngineResult:
        assert self._exe is not None

        proc = run_process(
            [
                str(self._exe),
                "-o",
                "json",
                "-p",
                _PLUGINS,
                str(ctx.sample_path),
            ],
            timeout_s=min(ctx.timeout_s, 180),
            cwd=str(self._exe.parent),
        )

        stdout = proc.stdout.strip()
        if not stdout:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.ERROR,
                error=f"manalyze 无输出（退出码 {proc.returncode}）",
                raw_output=proc.stderr[:2000],
            )

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.ERROR,
                error=f"无法解析 manalyze 输出：{exc}",
                raw_output=stdout[:2000],
            )

        # 顶层键是文件路径，取第一个值
        inner = next(iter(data.values()), {}) if isinstance(data, dict) else {}
        if not isinstance(inner, dict):
            inner = {}

        # 收集各插件结论（键名大小写不固定）
        findings: dict[str, str] = {}
        for key, value in inner.items():
            name = key.strip().lower()
            if name == "summary":
                continue
            if value in (None, [], {}, ""):
                continue
            findings[key] = _summarize_section(value)

        hits = [
            (key, reason)
            for key, reason in (
                (k.lower(), r) for k, r in
                ((k, _SUSPICIOUS_PLUGINS.get(k.lower(), "")) for k in findings)
            )
            if reason
        ]

        if hits:
            label = "、".join(_SUSPICIOUS_PLUGINS[k] for k, _ in hits)
            return EngineResult(
                engine=self.name,
                verdict=Verdict.SUSPICIOUS,
                signature="; ".join(findings[k] for k, _ in hits)[:120],
                detail=f"结构分析发现：{label}",
                meta={"findings": findings},
            )

        return EngineResult(
            engine=self.name,
            verdict=Verdict.CLEAN,
            detail=f"结构分析未发现异常特征（检查了 {len(_PLUGINS.split(','))} 个插件）",
            meta={"findings": findings},
        )
