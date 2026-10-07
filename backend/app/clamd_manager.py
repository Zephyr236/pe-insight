"""ClamAV 守护进程（clamd）管理。

clamscan 每扫一个文件都要重新加载 100+ MB 的签名库，实测约 3 秒。
clamd 把签名库常驻内存，扫描降到毫秒级。

本产品优先走 clamdscan + clamd，连不上时才回退到独立的 clamscan。
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

from .config import settings

#: 与 tools/clamav/clamd.conf 中的 TCPSocket 保持一致
CLAMD_PORT = 3310
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_DETACHED = 0x00000008  # DETACHED_PROCESS：进程独立于本程序存活


def clamav_dir() -> Path:
    return settings.base_dir / "tools" / "clamav"


def ping(timeout: float = 1.0) -> bool:
    """用 ClamAV 的原生协议确认 clamd 是否活着。

    连得上端口不代表守护进程已就绪——必须发 PING 并收到 PONG。
    """
    try:
        with socket.create_connection(("127.0.0.1", CLAMD_PORT), timeout=timeout) as sock:
            sock.sendall(b"PING\n")
            return b"PONG" in sock.recv(16)
    except OSError:
        return False


def is_installed() -> bool:
    return (clamav_dir() / "clamd.exe").is_file()


def start(wait_s: int = 60) -> tuple[bool, str]:
    if not is_installed():
        return False, "未找到 clamd.exe，请先执行 setup-clamav"

    if ping():
        return True, "clamd 已在运行"

    exe = clamav_dir() / "clamd.exe"
    conf = clamav_dir() / "clamd.conf"
    if not conf.is_file():
        return False, f"缺少配置文件 {conf}，请重新执行 setup-clamav"

    try:
        subprocess.Popen(  # noqa: S603
            [str(exe), f"--config-file={conf}"],
            cwd=str(clamav_dir()),
            creationflags=_NO_WINDOW | _DETACHED,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        return False, f"启动失败：{exc}"

    # 首次启动要加载签名库，给它足够时间
    deadline = time.time() + wait_s
    while time.time() < deadline:
        if ping():
            return True, "clamd 已启动并就绪"
        time.sleep(0.5)

    log = clamav_dir() / "logs" / "clamd.log"
    return False, f"clamd 在 {wait_s}s 内未就绪，请查看日志：{log}"


def stop() -> tuple[bool, str]:
    """请求 clamd 自行退出（在 Windows 上杀进程会留下 pid 文件）。"""
    if not ping():
        return True, "clamd 未在运行"
    try:
        with socket.create_connection(("127.0.0.1", CLAMD_PORT), timeout=3) as sock:
            sock.sendall(b"SHUTDOWN\n")
        return True, "已发送关闭指令"
    except OSError as exc:
        return False, f"关闭失败：{exc}"


def status() -> dict:
    return {
        "installed": is_installed(),
        "running": ping() if is_installed() else False,
        "port": CLAMD_PORT,
        "platform_ok": sys.platform == "win32",
    }
