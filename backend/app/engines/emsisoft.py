"""Emsisoft 引擎适配器。

使用 Emsisoft Emergency Kit 自带的 ``a2cmd.exe``。

关键参数::

    /f=<path>    扫描指定文件
    /cloud=0     关闭云端请求
    /la=<file>   ANSI 日志

**`/cloud=0` 是必须的。** a2cmd 的云端请求默认是开启的（帮助里写着
"If it is 1 then scanner will use cloud requests (default value is 1)"），
即会把文件信息（甚至文件本身）发往 Emsisoft 云端做查询。加上这个参数后
扫描完全在本地完成。

**刻意不加 `/d`（删除）和 `/q=`（隔离）**——a2cmd 默认只报告、不碰文件。
如果让它隔离了样本，后续引擎和动态分析就拿不到文件了（Defender 那边
我们靠 `-DisableRemediation` 解决，这里是靠不加参数）。

退出码：
    0  未发现威胁
    1  发现威胁
    2  无法连接网络
    3  权限不足
    5  无法初始化扫描引擎（通常是签名库缺失）
    9  需要更高权限

授权说明：EEP/EEK 免费版仅限**私人非商业用途**，无时间限制；
商用需购买 EEK Pro 或 Emsisoft 商业授权。
"""

from __future__ import annotations

import re
import sys
import tempfile
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

#: 退出码
_RC_CLEAN = 0
_RC_DETECTED = 1
_RC_NO_ENGINE = 5

_RC_MEANING = {
    2: "无法连接网络",
    3: "权限不足或操作不完整",
    4: "参数不正确",
    5: "扫描引擎无法初始化（签名库缺失？）",
    6: "找不到程序文件",
    8: "更新失败",
    9: "需要更高权限",
    10: "操作系统版本不受支持",
}

# a2cmd 的检出行实际长这样（路径与检测名之间是一个制表符）：
#
#   C:\path\sample.exe \t detected: Gen:Heur.Ransom.Imps.3 (B)
#
_DETECTION_RE = re.compile(
    r"^\s*[A-Za-z]:\\[^\n]*?\bdetected\s*:\s*(?P<sig>.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
#: 汇总行：Found <n>
_FOUND_RE = re.compile(r"^\s*Found\s+(?P<n>\d+)\s*$", re.IGNORECASE | re.MULTILINE)


def _candidate_paths() -> list[Path]:
    base = settings.base_dir
    return [
        base / "tools" / "eek" / "bin64" / "a2cmd.exe",
        base / "tools" / "eek" / "bin32" / "a2cmd.exe",
        Path(r"C:\Program Files\Emsisoft Anti-Malware") / "a2cmd.exe",
        Path(r"C:\Program Files (x86)\Emsisoft Anti-Malware") / "a2cmd.exe",
    ]


def find_a2cmd() -> Path | None:
    for path in _candidate_paths():
        if path.is_file():
            return path
    return None


class EmsisoftEngine(EngineAdapter):
    name = "Emsisoft"
    kind = EngineKind.SIGNATURE
    # 每次调用都要重新加载 112 MB 签名库，实测峰值增量 120 MB，串行
    resource_class = "heavy"

    def __init__(self) -> None:
        self._exe = find_a2cmd()

    def _elevated(self) -> bool:
        if sys.platform != "win32":
            return True
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False

    def unavailable_reason(self) -> str:
        if sys.platform != "win32":
            return "仅 Windows 平台可用"
        if self._exe is None:
            return (
                "未找到 a2cmd.exe。请运行 `python -m app.cli setup-emsisoft` "
                "下载 Emsisoft Emergency Kit（免费、无时间限制、限私人非商业用途）"
            )
        if not self._elevated():
            return (
                "a2cmd 需要管理员权限。请用项目根目录的 start.ps1 启动"
                "（它会自动请求提权），或直接禁用该引擎："
                "PEINSIGHT_DISABLED_ENGINES=emsisoft"
            )
        return "不可用"

    @property
    def offline(self) -> bool:  # type: ignore[override]
        """加上 /cloud=0 后扫描完全本地。

        这一点是有实据的：a2cmd 的帮助明确写了云端请求由 /cloud 控制且默认为 1,
        我们固定传 /cloud=0。唯一的网络行为是签名更新（/u），那是下载签名，
        与样本无关，且不由扫描路径触发。
        """
        return True

    def network_note(self) -> str:
        return "扫描时使用 /cloud=0，完全本地；签名更新需另行手动触发"

    def available(self) -> bool:
        # 必须同时满足"装了"和"提权了"。非提升会话下 a2cmd 不会快速失败，
        # 而是一声不吭地挂到超时（实测挂满 300 秒），白白浪费五分钟。
        return self._exe is not None and self._elevated()

    def scan(self, ctx: ScanContext) -> EngineResult:
        assert self._exe is not None

        # 日志文件必须可写；放在数据目录下避免污染系统临时目录
        log_dir = settings.data_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            prefix="a2cmd-", suffix=".log", dir=log_dir, delete=False
        ) as handle:
            log_path = Path(handle.name)

        args = [
            str(self._exe),
            f"/f={ctx.sample_path}",
            f"/la={log_path}",   # ANSI 日志，便于解析
            "/cloud=0",          # 关键：关闭云端请求
            # 刻意不加 /d 与 /q= —— 默认只报告，不动样本
        ]

        try:
            proc = run_process(
                args, timeout_s=ctx.timeout_s, cwd=str(self._exe.parent)
            )
            output = f"{proc.stdout}\n{proc.stderr}"
            log_text = ""
            try:
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

            combined = f"{output}\n{log_text}"

            if proc.returncode == _RC_DETECTED:
                sig = self._extract_signature(log_text or output)
                return EngineResult(
                    engine=self.name,
                    verdict=Verdict.MALICIOUS,
                    signature=sig,
                    detail="Emsisoft 检出威胁",
                    raw_output=combined,
                )

            if proc.returncode == _RC_CLEAN:
                return EngineResult(
                    engine=self.name,
                    verdict=Verdict.CLEAN,
                    detail="未检出威胁",
                    raw_output=combined,
                )

            if proc.returncode == _RC_NO_ENGINE:
                return EngineResult(
                    engine=self.name,
                    verdict=Verdict.ERROR,
                    error=(
                        "扫描引擎无法初始化：签名库缺失。"
                        "执行 `a2cmd.exe /u` 更新签名库后重试。"
                    ),
                    raw_output=combined,
                )

            meaning = _RC_MEANING.get(proc.returncode, f"退出码 {proc.returncode}")
            return EngineResult(
                engine=self.name,
                verdict=Verdict.ERROR,
                error=f"a2cmd 执行失败：{meaning}",
                raw_output=combined,
            )
        finally:
            log_path.unlink(missing_ok=True)

    @staticmethod
    def _extract_signature(text: str) -> str | None:
        """从日志里抠出检出名称。"""
        match = _DETECTION_RE.search(text)
        if match:
            sig = match.group("sig").strip()
            # 去掉可能残留的重复前缀
            return re.sub(r"^(?:detected|suspicious)\s*:\s*", "", sig, flags=re.I)

        # 检出名称拿不到时，至少确认是否真有检出，好过误报"干净"
        found = _FOUND_RE.search(text)
        if found and int(found.group("n")) > 0:
            return f"检出 {found.group('n')} 项（签名名未解析）"
        return None
