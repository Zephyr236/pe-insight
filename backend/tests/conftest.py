"""共用夹具。"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable

import pytest

from app.engines.base import ScanContext
from app.selftest import EICAR

#: 系统自带的干净 PE。测试"规则零误报"时用它——正常的 Windows 程序
#: 不该被任何检测规则命中。
BENIGN_PE_CANDIDATES = (
    Path(r"C:\Windows\System32\calc.exe"),
    Path(r"C:\Windows\System32\notepad.exe"),
    Path(r"C:\Windows\System32\attrib.exe"),
    Path(r"C:\Windows\System32\cmd.exe"),
)


@pytest.fixture(scope="session")
def benign_pe() -> Path:
    """一个系统自带的干净 PE 文件。缺失则跳过依赖它的测试。"""
    for candidate in BENIGN_PE_CANDIDATES:
        if candidate.is_file():
            return candidate
    pytest.skip("找不到可用的系统 PE 文件")


@pytest.fixture(scope="session")
def benign_pe_bytes(benign_pe: Path) -> bytes:
    return benign_pe.read_bytes()


@pytest.fixture
def minimal_pe(tmp_path: Path, benign_pe_bytes: bytes) -> Path:
    """一个最小的合法 PE（截取系统 PE 的前 4 KB，保证有完整的头）。

    用于测解析器在"结构完整但内容被截断"时的行为。
    """
    target = tmp_path / "minimal.exe"
    target.write_bytes(benign_pe_bytes[:4096])
    return target


@pytest.fixture
def eicar_file(tmp_path: Path) -> Path:
    """EICAR 测试文件。

    EICAR 是反病毒行业的通用测试串，本身无害且不可执行。
    本夹具**只用于测试解析逻辑**（用 mock 的子进程），
    绝不会真的去调用杀毒引擎——那会把文件锁死。
    """
    target = tmp_path / "eicar.com"
    target.write_bytes(EICAR.encode())
    return target


@pytest.fixture
def make_context(tmp_path: Path):
    """构造 ScanContext 的工厂。"""

    def _make(path: Path, timeout_s: int = 60) -> ScanContext:
        from app.static.hashing import hash_file

        hashes = hash_file(path)
        return ScanContext(
            sample_path=path,
            sha256=hashes.sha256,
            md5=hashes.md5,
            size=hashes.size,
            timeout_s=timeout_s,
        )

    return _make


@pytest.fixture
def fake_process(monkeypatch):
    """替换掉 run_process，让引擎适配器拿到预设的进程输出。

    用法：
        fake_process(stdout="Threat : Foo", returncode=2)
    """

    def _install(
        *,
        stdout: str = "",
        stderr: str = "",
        returncode: int = 0,
        raises: Exception | None = None,
    ) -> dict:
        captured: dict = {}

        def fake(args, timeout_s, cwd=None):
            captured["args"] = list(args)
            captured["timeout_s"] = timeout_s
            captured["cwd"] = cwd
            if raises is not None:
                raise raises
            return subprocess.CompletedProcess(
                args=args, returncode=returncode, stdout=stdout, stderr=stderr
            )

        # 适配器是从各自模块 import run_process 的，所以要逐个打补丁
        for module in (
            "app.engines.defender",
            "app.engines.clamav",
            "app.engines.emsisoft",
            "app.engines.die",
            "app.engines.manalyze",
            "app.engines.capa_engine",
        ):
            monkeypatch.setattr(f"{module}.run_process", fake, raising=False)

        return captured

    return _install


def pytest_configure(config) -> None:
    config.addinivalue_line("markers", "windows_only: 仅在 Windows 上有意义的测试")
    config.addinivalue_line("markers", "slow: 耗时较长的测试")


def pytest_collection_modifyitems(items: Iterable) -> None:
    """非 Windows 平台自动跳过 Windows 专有测试。"""
    import sys

    if sys.platform == "win32":
        return
    skip = pytest.mark.skip(reason="本项目仅支持 Windows")
    for item in items:
        if "windows_only" in item.keywords:
            item.add_marker(skip)
