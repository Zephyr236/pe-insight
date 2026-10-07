"""合成测试样本生成器。

扫描干净文件时所有引擎都会说"干净"——这看不出任何东西，也无法判断
检测链路到底通不通。

这里生成一批**完全无害的合成样本**：拿一个系统自带的干净 PE 作载体，
在尾部附加能触发 YARA 规则的字符串。它们不含任何可执行恶意代码，
但会让检测链路完整地走一遍"命中 → 恶意结论 → UI 展示"。

用途：在没有真实样本、或不想碰真实样本时，验证产品端到端可用。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import settings


@dataclass(frozen=True)
class DemoCase:
    name: str
    description: str
    payload: bytes


#: 每个用例的载荷都刻意命中 rules/ 下的具体规则
CASES: tuple[DemoCase, ...] = (
    DemoCase(
        name="ransomware-sim",
        description="勒索软件特征（勒索信文案 + 卷影副本删除）",
        payload=b"\r\n".join(
            [
                b"vssadmin delete shadows /all /quiet",
                b"wbadmin delete catalog -quiet",
                b"YOUR_FILES_ARE_ENCRYPTED.txt",
                b"All your files are encrypted. To decrypt your files send bitcoin.",
                b"README_FOR_DECRYPT.txt",
                b"bcdedit /set recoveryenabled no",
            ]
        ),
    ),
    DemoCase(
        name="injection-sim",
        description="进程注入特征（分配 + 写入 + 远程执行）",
        payload=b"\r\n".join(
            [
                b"VirtualAllocEx",
                b"WriteProcessMemory",
                b"CreateRemoteThread",
                b"NtUnmapViewOfSection",
                b"SetThreadContext",
            ]
        ),
    ),
    DemoCase(
        name="persistence-sim",
        description="注册表自启动持久化",
        payload=b"\r\n".join(
            [
                b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                b"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ]
        ),
    ),
    DemoCase(
        name="credential-sim",
        description="凭据窃取特征（LSASS 内存转储）",
        payload=b"\r\n".join(
            [
                b"lsass.exe",
                b"MiniDumpWriteDump",
                b"MiniDumpWithFullMemory",
                b"dbghelp.dll",
            ]
        ),
    ),
)

#: 用于渲染前先剥掉，避免误触发的巨长字符串
_MARKER = b"\r\nPEINSIGHT-DEMO-SAMPLE\r\n"


def _carrier() -> Path | None:
    for candidate in (
        r"C:\Windows\System32\calc.exe",
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\attrib.exe",
    ):
        path = Path(candidate)
        if path.is_file():
            return path
    return None


def generate(target_dir: Path | None = None) -> list[dict]:
    """生成全部合成样本，返回 [{name, path, description}]。

    返回空列表表示找不到可用的 PE 载体。
    """
    carrier = _carrier()
    if carrier is None:
        return []

    out_dir = target_dir or (settings.inbox_dir / "demo")
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        base = carrier.read_bytes()
    except OSError:
        return []

    generated: list[dict] = []
    for case in CASES:
        # 附加到 PE 尾部不会破坏文件结构，但字符串可以被规则引擎扫到
        data = base + _MARKER + case.payload + b"\r\n"
        path = out_dir / f"{case.name}.exe"
        try:
            path.write_bytes(data)
        except OSError:
            continue
        generated.append(
            {
                "name": case.name,
                "path": path,
                "description": case.description,
            }
        )

    return generated
