"""Windows Defender 引擎适配器。

使用系统自带的 MpCmdRun.exe 做单文件按需扫描。

关键点：
- `-DisableRemediation` 必须加，否则 Defender 会把样本直接隔离或删除，
  导致后续引擎和动态分析拿不到文件。
- MpCmdRun 的退出码：0 = 无威胁，2 = 检出威胁。
- 样本所在目录应当排除在实时防护之外，否则文件在扫描前就被实时防护处理掉了。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from .base import (
    NETWORK_LOCAL,
    NETWORK_METADATA,
    NETWORK_SAMPLE,
    EngineAdapter,
    EngineKind,
    EngineResult,
    ScanContext,
    Verdict,
    run_process,
)

# Defender 的 Platform 目录带版本号，需要挑最新的那个
_PLATFORM_GLOB = "Microsoft/Windows Defender/Platform/*/MpCmdRun.exe"


def _find_mpcmdrun() -> str | None:
    if sys.platform != "win32":
        return None

    bases = [
        Path(r"C:\ProgramData"),
        Path(r"C:\Program Files\Windows Defender"),
        Path(r"C:\Program Files (x86)\Windows Defender"),
    ]
    candidates: list[Path] = []
    for base in bases:
        if base.name == "ProgramData":
            candidates.extend(base.glob(_PLATFORM_GLOB))
        else:
            candidate = base / "MpCmdRun.exe"
            if candidate.exists():
                candidates.append(candidate)

    if not candidates:
        return None

    # 目录名形如 4.18.24090.11-0，按版本号排序取最新
    def version_key(path: Path) -> tuple[int, ...]:
        raw = path.parent.name.split("-")[0]
        parts = []
        for chunk in raw.split("."):
            parts.append(int(chunk) if chunk.isdigit() else 0)
        return tuple(parts)

    return str(max(candidates, key=version_key))


# 输出中形如： Threat                : Trojan:Win32/Wacatac.B!ml
_THREAT_RE = re.compile(r"^\s*Threat\s*:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)


class DefenderEngine(EngineAdapter):
    name = "Windows Defender"
    kind = EngineKind.SIGNATURE

    def __init__(self) -> None:
        self._exe = _find_mpcmdrun()

    def network_level(self) -> str:
        """按 Defender 的实际设置判定外传等级。

        必须说清楚：**本产品的出网守卫拦不住 Defender**。netguard 劫持的是
        Python 的 socket 层，而 MpCmdRun.exe 是独立的原生进程（它还会把扫描
        请求转交给 Defender 服务执行），Python 层面的拦截对它毫无作用。

        所以这里不写死，而是运行时查证 MAPS 与样本提交设置：
          - 云保护关闭                → 完全本地
          - 云保护开启但不传样本      → 仅元数据（哈希等仍会上传）
          - 云保护开启且会传样本      → 可能外传样本
          - 读不到设置                → 按最坏情况处理
        """
        from ..privacy import audit_defender

        audit = audit_defender()
        if not audit.get("available"):
            return NETWORK_SAMPLE  # 查不到就不做无法兑现的承诺
        if not audit.get("cloud_enabled"):
            return NETWORK_LOCAL
        if audit.get("sends_samples"):
            return NETWORK_SAMPLE
        return NETWORK_METADATA

    @property
    def offline(self) -> bool:  # type: ignore[override]
        return self.network_level() == NETWORK_LOCAL

    def network_note(self) -> str:
        from ..privacy import audit_defender

        audit = audit_defender()
        level = self.network_level()

        if level == NETWORK_LOCAL:
            return "云保护与样本提交均已关闭，可确认不外传任何数据"

        if level == NETWORK_METADATA:
            return (
                f"样本内容不会外传（样本提交：{audit.get('submit_text')}），"
                "但云保护仍开启，文件哈希等元数据会上传给微软 MAPS。"
                "要彻底零外传，再执行 Set-MpPreference -MAPSReporting Disabled。"
            )

        return (
            f"云保护与样本提交均开启（{audit.get('maps_text')}／{audit.get('submit_text')}），"
            "可能向微软提交文件元数据或样本内容。本产品的出网守卫对原生进程无效，无法拦截。"
        )

    def available(self) -> bool:
        return self._exe is not None

    def unavailable_reason(self) -> str:
        if sys.platform != "win32":
            return "仅 Windows 平台可用"
        return "未找到 MpCmdRun.exe（Defender 可能被第三方杀软接管或已移除）"

    def scan(self, ctx: ScanContext) -> EngineResult:
        assert self._exe is not None
        args = [
            self._exe,
            "-Scan",
            "-ScanType",
            "3",  # 3 = 自定义扫描（指定文件）
            "-File",
            str(ctx.sample_path),
            "-DisableRemediation",  # 不要隔离/删除，我们要留着样本继续分析
        ]
        proc = run_process(args, timeout_s=ctx.timeout_s)
        output = f"{proc.stdout}\n{proc.stderr}"

        threat = _THREAT_RE.search(output)
        signature = threat.group(1) if threat else None

        if proc.returncode == 2 or signature:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.MALICIOUS,
                signature=signature or "未命名威胁",
                detail="Defender 检出威胁",
                raw_output=output,
            )

        if proc.returncode == 0:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.CLEAN,
                detail="未检出威胁",
                raw_output=output,
            )

        return EngineResult(
            engine=self.name,
            verdict=Verdict.ERROR,
            error=f"MpCmdRun 退出码 {proc.returncode}",
            raw_output=output,
        )
