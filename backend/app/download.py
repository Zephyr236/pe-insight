"""统一的 HTTPS 下载入口。

**为什么要有这个模块**：早期每个 `setup_*` 模块各自调
`urllib.request.urlopen()`，于是同一个证书问题在 5 个地方各犯一次。

实测在一台全新的 Windows 上，`uv` 装的 Python 其默认 SSL 上下文拿不到
可用的根证书链，所有下载无一例外失败：

    <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
     unable to get local issuer certificate>

而同一个环境里 `pip install` 是好的——因为 pip 自带 certifi 的根证书包。
所以这里把 certifi 合并进默认上下文兜底，顺带把企业网络/代理软件做 TLS
拦截的情况也留出出口。

两个逃生口（都通过环境变量控制）：

    PEINSIGHT_CA_BUNDLE            指向你信任的根证书文件（推荐）
    PEINSIGHT_INSECURE_DOWNLOAD=1  完全跳过证书校验（会打印警告）

后者只应该在没有别的办法时用——它意味着下载内容可以被中间人替换。
"""

from __future__ import annotations

import os
import ssl
import urllib.error
import urllib.request

_CTX: ssl.SSLContext | None = None
_WARNED = False

_CERT_HINT = """\
{err}

  这通常是证书信任问题，不是网络不通。依次试：
    1. 指定你所在网络的根证书（企业代理、Clash/sing-box 之类的 TLS 拦截）：
         $env:PEINSIGHT_CA_BUNDLE = "C:\\path\\to\\root-ca.crt"
    2. 确认系统证书库可读：把 certifi 的根证书装进当前环境
         .\\.venv\\Scripts\\python.exe -m pip install --upgrade certifi
    3. 实在不行才跳过校验（下载内容可被中间人替换，自行权衡）：
         $env:PEINSIGHT_INSECURE_DOWNLOAD = "1"
"""


def _warn_insecure() -> None:
    global _WARNED
    if not _WARNED:
        _WARNED = True
        print(
            "[!] PEINSIGHT_INSECURE_DOWNLOAD=1：已关闭 TLS 证书校验。\n"
            "    下载的安装包和签名库不再有完整性保证，仅在你清楚风险时使用。"
        )


def ca_count() -> int:
    """当前上下文里加载了多少个根证书。用于诊断。"""
    try:
        return len(ssl_context().get_ca_certs())
    except Exception:  # noqa: BLE001 - 诊断用途，失败不该抛
        return 0


def ssl_context() -> ssl.SSLContext:
    """构造下载用的 SSL 上下文，结果缓存复用。"""
    global _CTX
    if _CTX is not None:
        return _CTX

    ctx = ssl.create_default_context()

    if os.environ.get("PEINSIGHT_INSECURE_DOWNLOAD") == "1":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _warn_insecure()
        _CTX = ctx
        return ctx

    bundle = os.environ.get("PEINSIGHT_CA_BUNDLE")
    if bundle:
        # 用户指定的根证书，与系统库叠加而不是替换
        try:
            ctx.load_verify_locations(bundle)
        except (OSError, ssl.SSLError) as exc:
            raise RuntimeError(
                f"PEINSIGHT_CA_BUNDLE 指向的文件无法加载：{bundle}（{exc}）"
            ) from exc
    else:
        # 系统证书库可能不完整——把 certifi 的根证书合并进来兜底。
        # certifi 是 pip 的依赖，装过任何东西的环境里基本都在。
        try:
            import certifi

            ctx.load_verify_locations(certifi.where())
        except Exception:  # noqa: BLE001 - 没有 certifi 就用系统库，不该因此失败
            pass

    _CTX = ctx
    return ctx


def reset() -> None:
    """丢弃缓存的上下文（测试用）。"""
    global _CTX
    _CTX = None


def urlopen(url, timeout: int = 300):
    """带证书兜底的 urlopen。

    失败时把证书类错误换成一段可操作的提示，但**保持异常类型不变**
    （仍然是 URLError），这样调用方既有的 except 分支不用改。
    """
    try:
        return urllib.request.urlopen(url, timeout=timeout, context=ssl_context())
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(reason):
            raise urllib.error.URLError(_CERT_HINT.format(err=reason)) from exc
        raise
    except ssl.SSLCertVerificationError as exc:
        raise urllib.error.URLError(_CERT_HINT.format(err=exc)) from exc
