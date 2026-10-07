"""ClamAV 引擎适配器。

优先使用 clamdscan（连接常驻的 clamd 守护进程），因为 clamscan 每扫一个文件
都要重新加载几百 MB 的签名库，速度慢到无法接受。

ClamAV 退出码：0 = 干净，1 = 检出，2 = 错误。
输出格式： <path>: <Signature.Name> FOUND
"""

from __future__ import annotations

import re
from pathlib import Path

from .. import clamd_manager
from ..config import settings
from .base import (
    EngineAdapter,
    EngineKind,
    EngineResult,
    ScanContext,
    Verdict,
    run_process,
    which,
)

CLAMAV_HINT = (
    "未找到 ClamAV。请运行 `python -m app.cli setup-clamav` 自动下载便携版，"
    "或从 https://www.clamav.net/downloads 手动安装并执行 freshclam 更新签名库。"
)

_FOUND_RE = re.compile(r":\s*(?P<sig>[^\s:]+)\s+FOUND", re.IGNORECASE)

#: 便携版放置位置（相对项目根），以及常见的手动安装路径
_VENDORED = "tools/clamav"
_STANDARD_DIRS = (r"C:\Program Files\ClamAV", r"C:\ClamAV")


def _candidate_dirs() -> list[Path]:
    dirs = [settings.base_dir / _VENDORED, settings.base_dir / "tools" / "clamav"]
    dirs += [Path(p) for p in _STANDARD_DIRS]
    return dirs


def find_clamav_binary(name: str) -> str | None:
    """按 项目内置 → 标准安装 → PATH 的顺序查找 ClamAV 可执行文件。

    内置优先，这样桌面工具可以自包含，不依赖系统里装了什么。
    """
    for directory in _candidate_dirs():
        exe = directory / f"{name}.exe"
        if exe.is_file():
            return str(exe)
    return which(name, f"{name}.exe")


class ClamAVEngine(EngineAdapter):
    name = "ClamAV"
    kind = EngineKind.SIGNATURE
    offline = True

    def __init__(self) -> None:
        self._clamdscan = find_clamav_binary("clamdscan")
        self._clamscan = find_clamav_binary("clamscan")

    @property
    def resource_class(self) -> str:  # type: ignore[override]
        """有没有 clamd 常驻，ClamAV 的资源画像完全不同。

        实测（cmd.exe，单核机器）：
            clamd 未运行 → clamscan 加载签名库，**峰值 1126 MB**、26 秒
            clamd 常驻   → clamdscan 只发个查询，约 1 秒、几乎不额外占内存

        所以在没有守护进程时必须当重引擎串行跑，否则单它一个就能把
        6 GB 的机器推进换页，把其它引擎一起拖垮。
        """
        return "light" if self._use_daemon() else "heavy"

    def available(self) -> bool:
        return self._clamdscan is not None or self._clamscan is not None

    def unavailable_reason(self) -> str:
        return CLAMAV_HINT

    def _config_args(self) -> list[str]:
        """把 clamdscan 指向我们自己的 clamd.conf（内含 TCPSocket 3310）。

        不传这个参数的话，clamdscan 会去找系统默认路径的配置，连不上 clamd
        就静默退化成每次重载签名库的慢速模式。
        """
        conf = settings.base_dir / "tools" / "clamav" / "clamd.conf"
        return [f"--config-file={conf}"] if conf.is_file() else []

    def _use_daemon(self) -> bool:
        """每次都实测 clamd 是否在线，而不是记一个黏性标志。

        黏性标志会在 clamd 后来启动时永远不再重试；一次回环 ping 只要
        亚毫秒级，换来的是"守护进程一旦起来就能用上"。
        """
        if self._clamdscan is None:
            return False
        return clamd_manager.ping()

    def scan(self, ctx: ScanContext) -> EngineResult:
        if self._use_daemon():
            result = self._run(self._clamdscan, ctx, daemon=True)
            # clamdscan 返回 2 通常是连不上守护进程，回退到独立 clamscan
            if result is not None:
                return result

        if self._clamscan is not None:
            result = self._run(self._clamscan, ctx, daemon=False)
            if result is not None:
                return result

        return EngineResult(
            engine=self.name,
            verdict=Verdict.ERROR,
            error=CLAMAV_HINT,
        )

    def _run(
        self,
        exe: str | None,
        ctx: ScanContext,
        *,
        daemon: bool,
    ) -> EngineResult | None:
        """返回 None 表示这个可执行文件不可用，调用方应尝试下一个。"""
        if exe is None:
            return None

        args = [exe]
        # clamd.conf 只给 clamdscan 用：它含 TCPSocket/PidFile 等守护进程选项，
        # 独立的 clamscan 读到会直接报错退出（退出码 2）
        if daemon:
            args.extend(self._config_args())
        args.extend(["--no-summary", str(ctx.sample_path)])
        if not daemon:
            args.append("--stdout")

        proc = run_process(args, timeout_s=ctx.timeout_s)
        output = f"{proc.stdout}\n{proc.stderr}"

        if proc.returncode == 1:
            match = _FOUND_RE.search(output)
            return EngineResult(
                engine=self.name,
                verdict=Verdict.MALICIOUS,
                signature=match.group("sig") if match else "未命名签名",
                detail="ClamAV 检出威胁",
                raw_output=output,
            )

        if proc.returncode == 0:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.CLEAN,
                detail="未检出威胁",
                raw_output=output,
            )

        # 退出码 2：守护进程不可达或签名库缺失
        if daemon:
            return None
        return EngineResult(
            engine=self.name,
            verdict=Verdict.ERROR,
            error=f"clamscan 退出码 {proc.returncode}",
            raw_output=output,
        )
