"""隐私审计。

本产品承诺"样本不上传云端"。这个承诺对自研代码和 ClamAV/YARA/Speakeasy
成立，但 **Windows Defender 是个例外**：它内置的云保护（MAPS）和自动样本
提交会把可疑文件发给微软。那是微软的功能，不是我们的代码能拦住的。

所以这里的职责是：把这件事查出来、说清楚，而不是假装不存在。
"""

from __future__ import annotations

import subprocess
import sys
import time

# SubmitSamplesConsent 的取值含义
_SUBMIT_CONSENT = {
    0: "总是询问（可能提交）",
    1: "自动发送安全样本",  # 注意：微软定义的"安全"仍可能包含你的文件
    2: "从不发送（推荐用于离线分析）",
    3: "自动发送全部样本",
}

# 读一次 Defender 设置要拉起一次 PowerShell，耗时可达秒级，而设置几乎不变。
# 不缓存的话每次页面加载都要卡这一下。
_CACHE_TTL_S = 300
_cache: tuple[float, dict] | None = None

#: 上一次**成功**读取的结果。
#:
#: 读取会偶发失败（这台单核机器上拉 PowerShell 经常超时）。失败时如果直接
#: 判"读不到→按最坏情况→排除引擎"，就会出现同一台机器时而 7 个引擎、
#: 时而 6 个引擎的抖动。Defender 设置几乎不变，用上次成功的结果兜底更合理。
_last_good: dict | None = None

_MAPS = {
    0: "已关闭",
    1: "基本",
    2: "高级（会提交可疑文件）",
}


def _powershell(script: str, attempts: int = 3) -> str | None:
    """执行 PowerShell 片段并返回输出。仅在 Windows 上有效。

    带重试：拉起 PowerShell 本身就不便宜，在负载高的机器上偶发超时是常态，
    重试一两次比直接判失败划算得多。
    """
    if sys.platform != "win32":
        return None

    for attempt in range(attempts):
        try:
            proc = subprocess.run(  # noqa: S603
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode == 0 and (proc.stdout or "").strip():
                return proc.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
        if attempt < attempts - 1:
            time.sleep(0.6)

    return None


def audit_defender(use_cache: bool = True) -> dict:
    """审计 Defender 的云端相关设置（结果缓存 5 分钟）。

    返回结构：
        available    — 能否读到设置（非 Windows 或权限不足时为 False）
        maps         — 云保护级别
        submit       — 样本提交策略
        cloud_enabled— 是否存在把样本送出本机的通道
        warning      — 给用户看的人话说明
    """
    global _cache
    now = time.time()
    if use_cache and _cache and now - _cache[0] < _CACHE_TTL_S:
        return _cache[1]

    result = _audit_defender_uncached()
    _cache = (now, result)
    return result


def _audit_defender_uncached() -> dict:
    if sys.platform != "win32":
        return {"available": False, "reason": "仅 Windows 平台可审计 Defender"}

    raw = _powershell(
        "$p = Get-MpPreference; "
        "'{0}|{1}' -f $p.MAPSReporting, $p.SubmitSamplesConsent"
    )
    if not raw or "|" not in raw:
        return {
            "available": False,
            "reason": "读取 Defender 设置失败（可能需要管理员权限）",
        }

    try:
        maps_raw, submit_raw = raw.split("|", 1)
        maps = int(maps_raw.strip())
        submit = int(submit_raw.strip())
    except ValueError:
        return {"available": False, "reason": f"无法解析 Defender 输出：{raw!r}"}

    # 只要云保护开着，文件信息就可能离开本机
    cloud_enabled = maps > 0
    sends_samples = submit in (0, 1, 3) and cloud_enabled

    result = {
        "available": True,
        "maps": maps,
        "maps_text": _MAPS.get(maps, f"未知({maps})"),
        "submit": submit,
        "submit_text": _SUBMIT_CONSENT.get(submit, f"未知({submit})"),
        "cloud_enabled": cloud_enabled,
        "sends_samples": sends_samples,
        # 外传等级：local / metadata / sample（见 engines/base.py）
        "network_level": (
            "local"
            if not cloud_enabled
            else ("sample" if sends_samples else "metadata")
        ),
    }

    if sends_samples:
        result["warning"] = (
            "Windows Defender 的云保护处于开启状态，可能把可疑样本提交给微软。"
            "这不经过本产品，是本产品无法拦截的通道。"
            "如需彻底的样本不外传，请关闭 Defender 云保护与样本自动提交，"
            "或改用 ClamAV + YARA + Speakeasy 组合（这三者完全本地）。"
        )
    elif cloud_enabled:
        result["warning"] = (
            "Defender 云保护已开启，但样本提交策略为「从不发送」。"
            "样本内容不会外传；文件哈希等元数据仍会上传给 MAPS。"
            "要彻底零外传，再执行 Set-MpPreference -MAPSReporting Disabled。"
        )
    else:
        result["warning"] = None

    return result


def harden_script() -> list[str]:
    """返回关闭 Defender 云端通道所需的命令（不自动执行）。

    这会削弱系统防护能力，属于用户的安全决策，不能替用户做。
    """
    return [
        "Set-MpPreference -MAPSReporting Disabled",
        "Set-MpPreference -SubmitSamplesConsent NeverSend",
    ]
