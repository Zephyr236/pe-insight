"""ClamAV 便携版安装。

把 ClamAV 装进项目自己的 tools/clamav 目录，而不写系统注册表：
桌面工具要能自包含、可整目录搬走、可一键删除。

ClamAV 是唯一免费且允许商用的本地签名引擎，对"不联网的多引擎查杀"
是不可替代的一环。
"""

from __future__ import annotations

import shutil
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from .config import settings

CLAMAV_VERSION = "1.5.4"
DOWNLOAD_URL = (
    f"https://www.clamav.net/downloads/production/"
    f"clamav-{CLAMAV_VERSION}.win.x64.zip"
)
#: freshclam 至少要能连上官方镜像；国内网络可能需要换镜像
_DB_MIRROR = "database.clamav.net"


def clamav_dir() -> Path:
    return settings.base_dir / "tools" / "clamav"


def db_dir() -> Path:
    return clamav_dir() / "database"


def logs_dir() -> Path:
    return clamav_dir() / "logs"


def _download(url: str, dest: Path, progress) -> None:
    """流式下载并回报进度——包体有两百多 MB，必须让用户看到进展。"""
    req = urllib.request.Request(url, headers={"User-Agent": "pe-insight-setup"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - 固定的官方 URL
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        chunk = 1024 * 256
        with dest.open("wb") as handle:
            while True:
                block = resp.read(chunk)
                if not block:
                    break
                handle.write(block)
                done += len(block)
                if total:
                    pct = done * 100 / total
                    progress(f"\r  下载中 {pct:5.1f}%  ({done / 1e6:.0f}/{total / 1e6:.0f} MB)")
                else:
                    progress(f"\r  下载中 {done / 1e6:.0f} MB")
    progress("")


def _extract(archive: Path, target: Path) -> None:
    """解压并抹平可能存在的顶层目录。"""
    tmp = target.parent / "_extract_tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)

    with zipfile.ZipFile(archive) as zf:
        zf.extractall(tmp)

    # 压缩包内可能多包一层目录，统一收敛到 target
    entries = [p for p in tmp.iterdir()]
    source = entries[0] if len(entries) == 1 and entries[0].is_dir() else tmp

    if target.exists():
        shutil.rmtree(target)
    shutil.move(str(source), str(target))
    shutil.rmtree(tmp, ignore_errors=True)


def _write_configs() -> None:
    """生成 freshclam.conf 与 clamd.conf，全部路径指向项目内部。"""
    base = clamav_dir()
    db = db_dir()
    logs = logs_dir()

    (base / "freshclam.conf").write_text(
        "\n".join(
            [
                "# 由 PE Insight 自动生成",
                f"DatabaseDirectory {db}",
                f"UpdateLogFile {logs / 'freshclam.log'}",
                "LogTime yes",
                "LogVerbose no",
                f"DatabaseMirror {_DB_MIRROR}",
                "ConnectTimeout 30",
                "ReceiveTimeout 60",
                "MaxAttempts 5",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (base / "clamd.conf").write_text(
        "\n".join(
            [
                "# 由 PE Insight 自动生成",
                f"DatabaseDirectory {db}",
                f"LogFile {logs / 'clamd.log'}",
                f"PidFile {base / 'clamd.pid'}",
                "LogTime yes",
                # 走本地 TCP：Windows 上比 Unix socket 可靠
                "TCPSocket 3310",
                "TCPAddr 127.0.0.1",
                "MaxThreads 4",
                "MaxScanSize 200M",
                "MaxFileSize 100M",
                "ExcludePath ^/proc",
                "ExcludePath ^/sys",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def update_database(progress) -> bool:
    """执行 freshclam 拉取签名库。没有签名库的 ClamAV 什么都查不出。"""
    exe = clamav_dir() / "freshclam.exe"
    if not exe.is_file():
        progress("  未找到 freshclam.exe")
        return False

    import subprocess

    progress("  更新签名库（首次约 300 MB，请耐心等待）…")
    proc = subprocess.run(  # noqa: S603
        [str(exe), f"--config-file={clamav_dir() / 'freshclam.conf'}", "--stdout"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(clamav_dir()),
        timeout=3600,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    for line in output.splitlines():
        if line.strip():
            progress(f"  {line.strip()[:120]}")

    # freshclam 即使"已是最新"也可能返回非 0，所以以签名库是否存在为准
    ok = any(db_dir().glob("*.c[ul]d")) or any(db_dir().glob("*.cvd"))
    return ok


def install(force: bool = False, skip_db: bool = False, progress=print) -> dict:
    target = clamav_dir()
    result = {"dir": str(target), "downloaded": False, "database_ok": False}

    if target.is_dir() and (target / "clamscan.exe").is_file() and not force:
        progress(f"ClamAV 已存在于 {target}，跳过下载")
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        archive = target.parent / "clamav.zip"

        if not archive.is_file() or force:
            progress(f"下载 ClamAV {CLAMAV_VERSION}（约 215 MB）…")
            try:
                _download(DOWNLOAD_URL, archive, progress)
            except (urllib.error.URLError, OSError) as exc:
                result["error"] = f"下载失败：{exc}"
                return result
            result["downloaded"] = True

        progress("  解压…")
        _extract(archive, target)
        archive.unlink(missing_ok=True)

    db_dir().mkdir(parents=True, exist_ok=True)
    logs_dir().mkdir(parents=True, exist_ok=True)
    _write_configs()
    progress(f"  可执行文件：{target / 'clamscan.exe'}")

    if skip_db:
        progress("  已跳过签名库更新（--skip-db）")
        return result

    result["database_ok"] = update_database(progress)
    return result
