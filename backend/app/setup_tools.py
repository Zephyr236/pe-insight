"""结构/能力分析工具的安装。

装三样东西，全部开源、免费、无试用期、无授权限制、完全本地：

    Detect It Easy  加壳器/编译器/保护器识别
    Manalyze        PE 结构分析（加壳痕迹、可疑导入、内嵌加密常量、钱包地址）
    CAPA            能力识别（这段代码能干什么）+ ATT&CK 映射

**安全处理**：Manalyze 自带一个 ``plugin_virustotal.dll``。它是上传通道，
本模块在解压后**直接物理删除**它——留着它就等于给"样本不外传"开了个口子，
哪怕默认不启用也不放心。

CAPA 用 pip 安装而不是官方 Windows 发布包：官方包是 PyInstaller 打的，
在这台机器上分析时会死锁（1.4s CPU 卡 90s 不返回）。
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from .config import settings
from . import download

DIE_URL = (
    "https://github.com/horsicq/Detect-It-Easy/releases/download/Beta/"
    "die_win64_portable_3.10_x64.zip"
)
DIE_DB_URL = (
    "https://github.com/horsicq/Detect-It-Easy/releases/download/"
    "current-database/db.zip"
)
MANALYZE_URL = (
    "https://github.com/JusticeRage/Manalyze/releases/download/v1.0.0/"
    "manalyze-v1.0.0-windows-x64.zip"
)
CAPA_RULES_URL = (
    "https://github.com/mandiant/capa-rules/archive/refs/heads/master.zip"
)

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def tools_dir() -> Path:
    return settings.base_dir / "tools"


def _download(url: str, dest: Path, progress, label: str) -> bool:
    progress(f"  下载 {label}…")
    req = urllib.request.Request(url, headers={"User-Agent": "pe-insight-setup"})
    try:
        with download.urlopen(req, timeout=300) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            with dest.open("wb") as handle:
                while block := resp.read(1024 * 256):
                    handle.write(block)
                    done += len(block)
                    if total:
                        progress(f"\r    {done * 100 / total:5.1f}%  ({done / 1e6:.0f}/{total / 1e6:.0f} MB)")
                    else:
                        progress(f"\r    {done / 1e6:.0f} MB")
        progress("")
        return True
    except (urllib.error.URLError, OSError) as exc:
        progress(f"    失败：{exc}")
        return False


def _unzip(archive: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(target)


def install_die(force: bool, progress) -> bool:
    root = tools_dir() / "die"
    if (root / "diec.exe").is_file() and not force:
        progress("DIE 已存在，跳过")
        return True

    archive = tools_dir() / "die.zip"
    if not archive.is_file() or force:
        if not _download(DIE_URL, archive, progress, "Detect It Easy (20 MB)"):
            return False
    _unzip(archive, root)
    archive.unlink(missing_ok=True)

    # 用最新检测库覆盖随包自带的（随包的可能是几年前的）
    db_archive = tools_dir() / "die_db.zip"
    if _download(DIE_DB_URL, db_archive, progress, "DIE 检测库 (1.6 MB)"):
        try:
            with zipfile.ZipFile(db_archive) as zf:
                zf.extractall(root)
        except (zipfile.BadZipFile, OSError):
            pass
        db_archive.unlink(missing_ok=True)

    return (root / "diec.exe").is_file()


def install_manalyze(force: bool, progress) -> bool:
    root = tools_dir() / "manalyze"
    exe = next(iter(root.glob("*/manalyze.exe")), None) if root.is_dir() else None
    if exe and not force:
        if exe.with_name("plugin_virustotal.dll").is_file():
            progress("Manalyze 已存在，移除 VirusTotal 插件")
            exe.with_name("plugin_virustotal.dll").unlink()
        else:
            progress("Manalyze 已存在，跳过")
        return True

    archive = tools_dir() / "manalyze.zip"
    if not archive.is_file() or force:
        if not _download(MANALYZE_URL, archive, progress, "Manalyze (2 MB)"):
            return False
    _unzip(archive, root)
    archive.unlink(missing_ok=True)

    found = next(iter(root.glob("*/manalyze.exe")), None) or (root / "manalyze.exe")
    if not found.is_file():
        return False

    # 关键：删掉 VirusTotal 插件，杜绝任何上传可能
    vt = found.with_name("plugin_virustotal.dll")
    if vt.is_file():
        vt.unlink()
        progress("  已删除 plugin_virustotal.dll（上传通道）")
    return True


def install_capa(force: bool, progress) -> bool:
    # 1. pip 安装（绕开官方 PyInstaller 包的死锁）
    try:
        import capa.main  # noqa: F401
        progress("flare-capa 已安装，跳过")
    except ImportError:
        progress("  安装 flare-capa（pip）…")
        exe = Path(sys.executable)
        proc = subprocess.run(  # noqa: S603
            [str(exe), "-m", "pip", "install", "--quiet", "flare-capa"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
            creationflags=_NO_WINDOW,
        )
        if proc.returncode != 0:
            progress(f"    安装失败：{(proc.stderr or '')[:200]}")
            return False

    # 2. 规则集（pip 版不自带规则）
    rules_root = tools_dir() / "capa-rules"
    has_rules = rules_root.is_dir() and any(rules_root.glob("**/*.yml"))
    if not has_rules or force:
        archive = tools_dir() / "capa-rules.zip"
        if not _download(CAPA_RULES_URL, archive, progress, "CAPA 规则集 (0.7 MB)"):
            return False
        _unzip(archive, rules_root)
        archive.unlink(missing_ok=True)

    # 3. 空签名目录（本产品不用 FLIRT 签名，只影响库函数识别速度）
    (tools_dir() / "capa-sigs").mkdir(parents=True, exist_ok=True)
    return True


def install(force: bool = False, progress=print) -> dict:
    tools_dir().mkdir(parents=True, exist_ok=True)
    results: dict[str, bool] = {}

    progress("\n[1/3] Detect It Easy")
    results["DIE"] = install_die(force, progress)

    progress("\n[2/3] Manalyze")
    results["Manalyze"] = install_manalyze(force, progress)

    progress("\n[3/3] CAPA")
    results["CAPA"] = install_capa(force, progress)

    return results
