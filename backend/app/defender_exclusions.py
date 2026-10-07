"""Windows Defender 排除项管理。

实时防护会锁定并隔离它检出的任何文件——**包括我们正在分析的样本**。
没有排除项，本产品读不到真实恶意样本，"多引擎查杀"就无从谈起。

这是每个恶意代码分析工作站的标准配置步骤，但它确实降低了本机防护强度：
被排除的目录里的文件不会被实时防护拦截，误双击即感染。所以本模块只提供
**显式、可撤销**的操作，绝不自动执行。

需要管理员权限。
"""

from __future__ import annotations

import subprocess
import sys

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _powershell(script: str, timeout: int = 60) -> tuple[int, str]:
    if sys.platform != "win32":
        return 1, "仅 Windows 平台支持"
    try:
        proc = subprocess.run(  # noqa: S603
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"{type(exc).__name__}: {exc}"
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def is_admin() -> bool:
    code, out = _powershell(
        "([Security.Principal.WindowsPrincipal]"
        "[Security.Principal.WindowsIdentity]::GetCurrent()"
        ").IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    )
    return code == 0 and out.strip().lower() == "true"


def current_exclusions() -> list[str] | None:
    """读取当前排除路径。无管理员权限时返回 None。"""
    code, out = _powershell("(Get-MpPreference).ExclusionPath")
    if code != 0 or "administrator" in out.lower():
        return None
    return [line.strip() for line in out.splitlines() if line.strip()]


def add_exclusion(path: str) -> tuple[bool, str]:
    code, out = _powershell(f"Add-MpPreference -ExclusionPath '{path}'")
    if code == 0:
        return True, f"已添加排除项：{path}"
    return False, out


def remove_exclusion(path: str) -> tuple[bool, str]:
    code, out = _powershell(f"Remove-MpPreference -ExclusionPath '{path}'")
    if code == 0:
        return True, f"已移除排除项：{path}"
    return False, out


def is_realtime_enabled() -> bool | None:
    code, out = _powershell("(Get-MpComputerStatus).RealTimeProtectionEnabled")
    if code != 0:
        return None
    return out.strip().lower() == "true"
