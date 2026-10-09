"""下载层的证书兜底测试。

这组测试对应一个真实故障：在一台全新的 Windows 上，`uv` 装的 Python 其
默认 SSL 上下文拿不到可用的根证书链，导致所有 `setup-*` 下载全部失败
（`CERTIFICATE_VERIFY_FAILED`），安装程序从第一步就废掉。

根因是各模块直接用 `urllib.request.urlopen()`。现在统一走
`app/download.py`，把 certifi 的根证书合并进默认上下文。
"""

from __future__ import annotations

import ssl
import urllib.error

import pytest

from app import download


@pytest.fixture(autouse=True)
def _fresh_context(monkeypatch):
    """每个用例都用干净的上下文，避免缓存和残留的环境变量串味。"""
    for name in ("PEINSIGHT_CA_BUNDLE", "PEINSIGHT_INSECURE_DOWNLOAD"):
        monkeypatch.delenv(name, raising=False)
    download.reset()
    yield
    download.reset()


class TestSslContext:
    def test_has_root_certificates(self):
        """上下文里必须有根证书——空了就是那个故障的形态。"""
        ctx = download.ssl_context()
        assert ctx.get_ca_certs(), (
            "SSL 上下文里没有任何根证书，所有 HTTPS 下载都会失败"
        )

    def test_merges_certifi(self):
        """certifi 的根证书要并进来，弥补系统库不全的情况。"""
        pytest.importorskip("certifi")

        before = len(ssl.create_default_context().get_ca_certs())
        after = len(download.ssl_context().get_ca_certs())
        assert after > 0, "上下文里必须至少有一个根证书"
        assert after >= before, "合并 certifi 不应减少可用根证书"

    def test_default_verifies(self):
        ctx = download.ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_insecure_opt_out(self, monkeypatch, capsys):
        monkeypatch.setenv("PEINSIGHT_INSECURE_DOWNLOAD", "1")
        ctx = download.ssl_context()
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False
        assert "已关闭 TLS 证书校验" in capsys.readouterr().out

    def test_custom_bundle_is_loaded(self, monkeypatch, tmp_path):
        """指定自有根证书时，应当被加载进上下文。"""
        monkeypatch.setenv("PEINSIGHT_CA_BUNDLE", str(tmp_path / "missing.crt"))
        with pytest.raises(RuntimeError, match="PEINSIGHT_CA_BUNDLE"):
            download.ssl_context()


class TestErrorHint:
    def test_cert_error_becomes_actionable(self, monkeypatch):
        """证书错误要换成可操作的提示，但异常类型不能变。"""
        def boom(*_args, **_kwargs):
            raise urllib.error.URLError(
                ssl.SSLCertVerificationError(
                    "certificate verify failed: unable to get local issuer certificate"
                )
            )

        monkeypatch.setattr(download.urllib.request, "urlopen", boom)

        with pytest.raises(urllib.error.URLError) as excinfo:
            download.urlopen("https://example.invalid/x")

        message = str(excinfo.value)
        assert "PEINSIGHT_CA_BUNDLE" in message, "提示里要给出指定根证书的办法"
        assert "PEINSIGHT_INSECURE_DOWNLOAD" in message, "提示里要给出跳过校验的开关"

    def test_other_errors_pass_through(self, monkeypatch):
        """不是证书问题就原样抛出，别乱加提示。"""
        def boom(*_args, **_kwargs):
            raise urllib.error.URLError("connection refused")

        monkeypatch.setattr(download.urllib.request, "urlopen", boom)

        with pytest.raises(urllib.error.URLError) as excinfo:
            download.urlopen("https://example.invalid/x")

        assert "PEINSIGHT_CA_BUNDLE" not in str(excinfo.value)
