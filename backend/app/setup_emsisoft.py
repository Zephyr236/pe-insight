"""Emsisoft Emergency Kit 安装。

EEK 是 Emsisoft 的免费便携版：无需安装、无实时防护、无时间限制，
**仅限私人非商业用途**（商用需购买 EEK Pro）。内含命令行扫描器
``a2cmd.exe``，扫描时可用 ``/cloud=0`` 关闭云端请求，做到完全本地。

安装过程有一个坑：官方下载的是 RAR 自解压包，Windows 自带的 tar
（libarchive）能读 RAR5 但对某些条目会报"数据截断"。经实测截断发生在
``bin32``（32 位版）内，而 ``bin64`` 完整——我们只用 bin64，所以可用。
本模块因此不依赖 tar 的退出码，而是以 ``bin64/a2cmd.exe`` 是否存在为准。
"""

from __future__ import annotations

import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from . import download
from .config import settings

DOWNLOAD_URL = "https://dl.emsisoft.com/EmsisoftEmergencyKit.exe"

#: RAR5 归档头
_RAR5 = b"Rar!\x1a\x07\x01\x00"
_RAR4 = b"Rar!\x1a\x07\x00"
_SEARCH_CHUNK = 8 * 1024 * 1024


def eek_dir() -> Path:
    return settings.base_dir / "tools" / "eek"


def a2cmd_path() -> Path:
    return eek_dir() / "bin64" / "a2cmd.exe"


def _download(url: str, dest: Path, progress) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "pe-insight-setup"})
    with download.urlopen(req, timeout=300) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        with dest.open("wb") as handle:
            while block := resp.read(1024 * 256):
                handle.write(block)
                done += len(block)
                if total:
                    progress(f"\r  下载中 {done * 100 / total:5.1f}%  ({done / 1e6:.0f}/{total / 1e6:.0f} MB)")
                else:
                    progress(f"\r  下载中 {done / 1e6:.0f} MB")
    progress("")


def _find_rar_offset(path: Path) -> int | None:
    """在自解压包里定位内嵌 RAR 的起始偏移。"""
    with path.open("rb") as fh:
        offset = 0
        tail = b""
        while chunk := fh.read(_SEARCH_CHUNK):
            buf = tail + chunk
            base = offset - len(tail)
            for sig in (_RAR5, _RAR4):
                idx = buf.find(sig)
                if idx >= 0:
                    return base + idx
            tail = buf[-8:]
            offset += len(chunk)
    return None


def _carve(src: Path, dest: Path, offset: int) -> None:
    with src.open("rb") as fin:
        fin.seek(offset)
        with dest.open("wb") as fout:
            shutil.copyfileobj(fin, fout, 1024 * 1024)


def _extract_with_tar(archive: Path, target: Path) -> bool:
    """用 Windows 自带的 tar 解 RAR。以产出物为准判断成败。"""
    target.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(  # noqa: S603
            ["tar", "-xf", str(archive), "-C", str(target)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    return a2cmd_path().is_file()


def update_signatures(progress) -> tuple[bool, str]:
    """运行 a2cmd /u 拉取签名库。

    这是唯一需要联网的步骤，且用途是**下载签名**，与样本无关。
    """
    exe = a2cmd_path()
    if not exe.is_file():
        return False, "未找到 a2cmd.exe"

    progress("  更新签名库（首次约 100+ MB）…")
    try:
        proc = subprocess.run(  # noqa: S603
            [str(exe), "/u"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(exe.parent),
            timeout=3600,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"更新失败：{type(exc).__name__}: {exc}"

    sig_dir = exe.parent / "Signatures"
    has_sigs = sig_dir.is_dir() and any(sig_dir.rglob("*"))

    # a2cmd 的退出码语义：0 无威胁 / 1 检出 / 8 更新失败
    if proc.returncode == 8:
        return False, "a2cmd 报告更新失败，请检查网络"
    if not has_sigs:
        return False, "更新后仍未找到签名文件"
    return True, "签名库已就绪"


def install(force: bool = False, skip_db: bool = False, progress=print) -> dict:
    result = {"dir": str(eek_dir()), "downloaded": False, "database_ok": False}

    if a2cmd_path().is_file() and not force:
        progress(f"Emsisoft EEK 已存在于 {eek_dir()}，跳过下载")
    else:
        tools = eek_dir().parent
        tools.mkdir(parents=True, exist_ok=True)
        bundle = tools / "EmsisoftEmergencyKit.exe"
        payload = tools / "eek_payload.rar"

        if not bundle.is_file() or force:
            progress("下载 Emsisoft Emergency Kit（约 324 MB）…")
            try:
                _download(DOWNLOAD_URL, bundle, progress)
            except (urllib.error.URLError, OSError) as exc:
                result["error"] = f"下载失败：{exc}"
                return result
            result["downloaded"] = True

        progress("  定位内嵌 RAR…")
        offset = _find_rar_offset(bundle)
        if offset is None:
            result["error"] = "未在自解压包中找到 RAR 归档"
            return result
        progress(f"  归档起始于偏移 {offset}")

        progress("  切出并解压…")
        _carve(bundle, payload, offset)
        ok = _extract_with_tar(payload, eek_dir())
        payload.unlink(missing_ok=True)
        bundle.unlink(missing_ok=True)

        if not ok:
            result["error"] = (
                "解压后未找到 bin64/a2cmd.exe。可能是下载不完整，"
                "请加 --force 重试。"
            )
            return result

    progress(f"  可执行文件：{a2cmd_path()}")

    if skip_db:
        progress("  已跳过签名库更新（--skip-db）")
        return result

    ok, msg = update_signatures(progress)
    result["database_ok"] = ok
    result["db_message"] = msg
    return result
