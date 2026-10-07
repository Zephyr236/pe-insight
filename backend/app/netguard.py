"""出网守卫。

"样本不上传云端"不能只是一句声明——必须是代码层面可验证的约束。

这个模块在扫描期间劫持 Python 的 socket 层，只放行回环地址
（127.0.0.0/8、::1），任何指向外部主机的连接都会被拦截并记录。
ClamAV 的 clamdscan 连 127.0.0.1:3310 属于回环，正常放行。

局限（必须清楚）：
    它只约束**本进程及其 Python 子进程**。像 MpCmdRun.exe 这种独立的
    原生可执行文件的出网行为，Python 层管不到——那个要靠系统防火墙或
    关闭 Defender 的云保护。参见 privacy.py。
"""

from __future__ import annotations

import socket
import threading
from contextlib import contextmanager

#: 这些主机名/地址视为本地，放行
_LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "0.0.0.0", "::", ""}

_global_violations: list[str] = []

# 守卫可能被并发的扫描同时使用。用引用计数保证只有最后一个退出者才还原，
# 否则先结束的那个扫描会把仍在运行的扫描的防护一起拆掉。
_lock = threading.Lock()
_depth = 0
_saved: tuple | None = None


class OutboundBlocked(RuntimeError):
    """扫描期间尝试访问外部网络。"""


def _host_of(address) -> str:
    if isinstance(address, tuple) and address:
        return str(address[0])
    return str(address)


def _is_local(address) -> bool:
    host = _host_of(address)
    if host in _LOCAL_HOSTS:
        return True
    # 整个 127.0.0.0/8 都是回环
    return host.startswith("127.")


def violations() -> list[str]:
    return list(_global_violations)


def clear_violations() -> None:
    _global_violations.clear()


def _patch() -> tuple:
    saved = (
        socket.socket.connect,
        socket.socket.connect_ex,
        socket.create_connection,
        socket.getaddrinfo,
    )

    def guarded_connect(self, address):
        if not _is_local(address):
            msg = f"已拦截外部连接 → {_host_of(address)}"
            _global_violations.append(msg)
            raise OutboundBlocked(msg)
        return saved[0](self, address)

    def guarded_connect_ex(self, address):
        if not _is_local(address):
            _global_violations.append(f"已拦截外部连接 → {_host_of(address)}")
            return 1  # connect_ex 用返回码表示失败，而不是抛异常
        return saved[1](self, address)

    def guarded_create_connection(address, *args, **kwargs):
        if not _is_local(address):
            msg = f"已拦截外部连接 → {_host_of(address)}"
            _global_violations.append(msg)
            raise OutboundBlocked(msg)
        return saved[2](address, *args, **kwargs)

    def guarded_getaddrinfo(host, *args, **kwargs):
        # DNS 解析同样会泄露情报：查询了哪个域名本身就是信息
        if host is not None and not _is_local((host, 0)):
            msg = f"已拦截 DNS 解析 → {host}"
            _global_violations.append(msg)
            raise OutboundBlocked(msg)
        return saved[3](host, *args, **kwargs)

    socket.socket.connect = guarded_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign]
    socket.create_connection = guarded_create_connection  # type: ignore[assignment]
    socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]
    return saved


def _unpatch(saved: tuple) -> None:
    (
        socket.socket.connect,  # type: ignore[method-assign]
        socket.socket.connect_ex,  # type: ignore[method-assign]
        socket.create_connection,  # type: ignore[assignment]
        socket.getaddrinfo,  # type: ignore[assignment]
    ) = saved


@contextmanager
def offline_guard():
    """在块内禁止一切外部网络连接（可重入）。

    违规记录累积在模块级的 violations() 里，供扫描结束后汇总上报。
    """
    global _depth, _saved

    with _lock:
        if _depth == 0:
            _saved = _patch()
        _depth += 1

    try:
        yield
    finally:
        with _lock:
            _depth -= 1
            if _depth == 0 and _saved is not None:
                _unpatch(_saved)
                _saved = None


def selfcheck() -> tuple[bool, str]:
    """验证守卫真的能拦住出网。

    一个"应该能拦住"的守卫如果实际拦不住，比没有守卫更危险——
    它会给人虚假的安全感。所以这里真的发起一次连接尝试。
    """
    import urllib.request

    clear_violations()
    try:
        with offline_guard():
            try:
                urllib.request.urlopen("http://example.com", timeout=3).close()
            except (OutboundBlocked, OSError):
                pass
    except Exception as exc:  # noqa: BLE001
        return False, f"守卫执行异常：{type(exc).__name__}: {exc}"

    caught = violations()
    if caught:
        return True, f"守卫有效，已拦截：{caught[0]}"
    return False, "守卫未能拦截外部连接——不应信任其保护效果"


def check_loopback_allowed() -> tuple[bool, str]:
    """确认放行回环不会把正常功能一起掐死（clamd 走 127.0.0.1）。"""
    try:
        with offline_guard():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            try:
                sock.connect(("127.0.0.1", 1))  # 端口 1 无人监听，但连接应被放行
            except (ConnectionRefusedError, TimeoutError, OSError):
                pass  # 被拒绝是正常的，说明守卫放行了回环
            finally:
                sock.close()
        return True, "回环连接正常放行"
    except OutboundBlocked:
        return False, "回环连接被误拦——clamd 将无法工作"
